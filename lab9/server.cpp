#include "common.h"
#include <vector>
#include <cstdlib> // For atoi, exit

volatile sig_atomic_t keep_running = 1; // Global flag for signal handler

void handle_signal(int signal)
{
    // Simple signal handler: set the flag to stop the main loop
    // In more complex apps, you might need more sophisticated handling
    std::cout << "\nCaught signal " << signal << ", setting keep_running to 0." << std::endl;
    keep_running = 0;
}

// Function to handle a single client connection
void handle_connection(SOCKET client_sock, int server_id)
{
    // Use a unique_ptr for automatic closing, although manual close is also fine
    // struct SocketCloser { void operator()(SOCKET* s) { if (*s != INVALID_SOCKET) close_socket(*s); } };
    // std::unique_ptr<SOCKET, SocketCloser> client_sock_ptr(&client_sock);

    char buffer[BUFFER_SIZE];
    ssize_t bytes_received; // Use ssize_t for read/recv return value

    std::cout << "[Server " << server_id << "] Handling connection on socket " << client_sock << std::endl;

    // Receive request number from load balancer
    memset(buffer, 0, BUFFER_SIZE);
    // Use recv() or read() - recv is slightly more portable for socket options
    bytes_received = recv(client_sock, buffer, BUFFER_SIZE - 1, 0);

    if (bytes_received <= 0)
    {
        if (bytes_received == 0)
        {
            // Connection closed by peer (Load Balancer)
            std::cout << "[Server " << server_id << "] Connection closed by peer (socket: " << client_sock << ")." << std::endl;
        }
        else
        {
            // Error occurred
            print_socket_error("Server recv failed");
        }
        close_socket(client_sock); // Ensure socket is closed on error/closure
        return;
    }

    buffer[bytes_received] = '\0'; // Null-terminate received data
    std::cout << "[Server " << server_id << "] Received request: \"" << buffer << "\"" << std::endl;

    // Prepare response
    std::string response = "Request '" + std::string(buffer) + "' serviced by Server " + std::to_string(server_id);

    // Send response back to load balancer
    // Use send() or write()
    ssize_t bytes_sent = send(client_sock, response.c_str(), response.length(), 0); // MSG_NOSIGNAL ? maybe not needed if handled

    if (bytes_sent == SOCKET_ERROR)
    {
        print_socket_error("Server send failed");
        // Error sending, client might have disconnected
    }
    else if (bytes_sent < (ssize_t)response.length())
    {
        std::cerr << "[Server " << server_id << "] Warning: Partial send occurred." << std::endl;
        // Need to handle partial sends in robust applications
    }
    else
    {
        std::cout << "[Server " << server_id << "] Sent response: \"" << response << "\"" << std::endl;
    }

    // Close connection
    close_socket(client_sock);
    std::cout << "[Server " << server_id << "] Closed connection socket " << client_sock << "." << std::endl;
}

int main(int argc, char *argv[])
{
    if (argc != 2)
    {
        std::cerr << "Usage: " << argv[0] << " <server_id (0-" << NUM_SERVERS - 1 << ")>" << std::endl;
        return 1;
    }

    int server_id = std::atoi(argv[1]);
    if (server_id < 0 || server_id >= NUM_SERVERS)
    {
        std::cerr << "Error: Invalid server_id. Must be between 0 and " << NUM_SERVERS - 1 << "." << std::endl;
        return 1;
    }

    int port = BASE_SERVER_PORT + server_id;

    // Setup signal handling for graceful shutdown
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_signal;
    sigaction(SIGINT, &sa, NULL);  // Catch Ctrl+C
    sigaction(SIGTERM, &sa, NULL); // Catch kill/systemctl stop

    // Ignore SIGPIPE - handle write errors directly via return codes
    signal(SIGPIPE, SIG_IGN);

    SOCKET listen_sock = INVALID_SOCKET;
    SOCKET client_sock = INVALID_SOCKET;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_addr_len = sizeof(client_addr);

    // 1. Create socket
    listen_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP); // Or 0 for default protocol
    if (listen_sock == INVALID_SOCKET)
    {
        print_socket_error("Server socket creation failed");
        return 1;
    }

    // Optional: Allow address reuse immediately after server restart
    int opt = 1;
    if (setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0)
    {
        print_socket_error("Server setsockopt(SO_REUSEADDR) failed");
        // Non-fatal, but good practice
    }

    // 2. Bind
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY); // Listen on any interface
    server_addr.sin_port = htons(port);

    if (bind(listen_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) == SOCKET_ERROR)
    {
        print_socket_error("Server bind failed");
        close_socket(listen_sock);
        return 1;
    }

    // 3. Listen
    // SOMAXCONN is a system-defined backlog limit, often 128
    if (listen(listen_sock, SOMAXCONN) == SOCKET_ERROR)
    {
        print_socket_error("Server listen failed");
        close_socket(listen_sock);
        return 1;
    }

    std::cout << "[Server " << server_id << "] Listening on port " << port << "..." << std::endl;

    std::vector<std::thread> worker_threads;

    // 4. Accept connections in a loop - using select for graceful shutdown
    while (keep_running)
    {
        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(listen_sock, &read_fds);

        // Timeout for select allows checking keep_running periodically
        struct timeval timeout;
        timeout.tv_sec = 1; // Check every second
        timeout.tv_usec = 0;

        // select() monitors file descriptors for readiness
        int activity = select(listen_sock + 1, &read_fds, NULL, NULL, &timeout);

        if (activity < 0)
        {
            // EINTR means select was interrupted by a signal (like our SIGINT/SIGTERM)
            if (errno == EINTR)
            {
                std::cout << "[Server " << server_id << "] Select interrupted, checking keep_running..." << std::endl;
                continue; // Loop again to check keep_running
            }
            else
            {
                print_socket_error("Server select failed");
                break; // Exit loop on other select errors
            }
        }

        // If select timed out (activity == 0), loop again to check keep_running
        if (activity == 0)
        {
            continue;
        }

        // If the listening socket is ready, accept the new connection
        if (FD_ISSET(listen_sock, &read_fds))
        {
            client_sock = accept(listen_sock, (struct sockaddr *)&client_addr, &client_addr_len);

            if (client_sock == INVALID_SOCKET)
            {
                if (keep_running)
                { // Don't print error if we are shutting down deliberately
                    print_socket_error("Server accept failed");
                }
                // Decide whether to continue or break based on error (e.g., EMFILE, ENFILE)
                if (errno == EMFILE || errno == ENFILE)
                {
                    std::cerr << "[Server " << server_id << "] Ran out of file descriptors. Stopping accept loop." << std::endl;
                    keep_running = 0; // Stop accepting new connections
                }
                continue; // Try to continue loop unless fatal error
            }

            // Log the accepted connection
            char client_ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);
            std::cout << "[Server " << server_id << "] Accepted connection from "
                      << client_ip << ":" << ntohs(client_addr.sin_port)
                      << " on socket " << client_sock << std::endl;

            // 5. Handle connection in a new thread
            try
            {
                // Detach the thread: Allows the main loop to continue immediately.
                // The thread cleans up itself when done. Good for simple workers.
                // Alternative: store thread objects and join() them on shutdown.
                std::thread(handle_connection, client_sock, server_id).detach();
            }
            catch (const std::system_error &e)
            {
                // This might happen if resources (like memory or thread limits) are exhausted
                std::cerr << "Error creating thread: " << e.what() << " (errno: " << e.code().value() << ")" << std::endl;
                close_socket(client_sock); // Close socket if thread creation failed
                                           // Consider slowing down or stopping accept if this persists
            }
        }
        // Clean up finished detached threads? Not directly possible without joining.
        // OS reclaims resources when thread exits. For long-running servers,
        // thread pooling or joining might be better.
    }

    std::cout << "\n[Server " << server_id << "] Shutting down listener..." << std::endl;

    // Close listening socket - prevents further accepts
    if (listen_sock != INVALID_SOCKET)
    {
        close_socket(listen_sock);
        listen_sock = INVALID_SOCKET; // Mark as closed
    }

    // Note on detached threads: We don't explicitly wait for them here.
    // They will continue running until they finish their current request.
    // A more robust shutdown might signal them to finish early and use join().

    std::cout << "[Server " << server_id << "] Shutdown complete." << std::endl;
    return 0;
}