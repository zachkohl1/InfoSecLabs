#include "common.h"    // Include common definitions   
#include <cstdlib>     // For atoi (convert string to int), exit (though not used directly)
#include <signal.h>    // Include signal handling functions (sigaction, signal)
#include <cstring>     // Include C-style string functions like memset
#include <string>      // Include string manipulation utilities
#include <iostream>    // Include standard input/output stream objects
#include <thread>      // Include threading support
#include <stdexcept>   // Include standard exception types (used indirectly via thread creation)
#include <system_error>// Include system_error for catching thread creation errors

// Global flag used to signal graceful shutdown to the main loop.
// 'volatile' suggests it can be changed unexpectedly (by a signal handler).
// 'sig_atomic_t' ensures reads/writes are atomic concerning signal handlers.
// Initialized to 1 (true) to keep the server running.
volatile sig_atomic_t keep_running = 1;

/**
 * @brief Signal handler function for the Server.
 *
 * Called when specific signals (like SIGINT, SIGTERM) are received by the process.
 * It prints a message indicating the signal and sets the global `keep_running` flag to 0,
 * signaling the main accept loop to terminate gracefully.
 *
 * @param signal The signal number that was caught.
 */
void handle_signal(int signal)
{
    // Simple signal handler: just sets the flag to stop the main loop.
    // More complex applications might perform more cleanup here or signal worker threads.
    std::cout << "\nCaught signal " << signal << ", setting keep_running to 0." << std::endl;
    // Set the global flag to 0. The main loop checks this flag.
    keep_running = 0;
}

// Function to handle a single client connection (expected from the Load Balancer)
/**
 * @brief Handles communication with a single connected client (the Load Balancer).
 *
 * Receives a request (expected to be a request number as a string), constructs
 * a response string indicating which server handled the request, sends the response back,
 * and then closes the connection.
 *
 * @param client_sock The socket descriptor for the connected client (Load Balancer).
 * @param server_id The unique ID of this server instance, used in logging and the response.
 *
 * @note This function closes the `client_sock` before returning.
 */
void handle_connection(SOCKET client_sock, int server_id)
{
    // Comment explaining RAII possibility (commented out in original code):
    // Using a unique_ptr with a custom deleter could automatically close the socket
    // when the function exits, ensuring closure even if exceptions occur (though not used here).
    // struct SocketCloser { void operator()(SOCKET* s) { if (*s != INVALID_SOCKET) close_socket(*s); } };
    // std::unique_ptr<SOCKET, SocketCloser> client_sock_ptr(&client_sock);

    // Buffer to store data received from the client. BUFFER_SIZE defined in common.h.
    char buffer[BUFFER_SIZE];
    // Variable to store the return value of recv(). Use ssize_t as it can be -1 on error.
    ssize_t bytes_received;

    // Log the start of handling this connection.
    std::cout << "[Server " << server_id << "] Handling connection on socket " << client_sock << std::endl;

    // --- Receive Request ---
    // Clear the buffer before receiving data.
    memset(buffer, 0, BUFFER_SIZE);
    // Receive data from the client socket. BUFFER_SIZE - 1 leaves space for a null terminator.
    // recv() is generally preferred over read() for sockets due to the flags argument (though 0 is used here).
    bytes_received = recv(client_sock, buffer, BUFFER_SIZE - 1, 0);

    // Check the result of the receive operation.
    if (bytes_received <= 0)
    {
        // If 0 bytes received, the peer (Load Balancer) closed the connection gracefully.
        if (bytes_received == 0)
        {
            std::cout << "[Server " << server_id << "] Connection closed by peer (socket: " << client_sock << ")." << std::endl;
        }
        // If less than 0, an error occurred during receive.
        else
        {
            // Print the specific socket error using the helper function.
            print_socket_error("Server recv failed");
        }
        // Close the socket since the connection is closed or an error occurred.
        close_socket(client_sock); // Ensure socket is closed on error/closure
        // Exit the handler function for this connection.
        return;
    }

    // Null-terminate the received data to safely treat it as a C-string.
    buffer[bytes_received] = '\0';
    // Log the received request content.
    std::cout << "[Server " << server_id << "] Received request: \"" << buffer << "\"" << std::endl;

    // --- Prepare Response ---
    // Construct the response string, incorporating the received request data and the server's ID.
    std::string response = "Request '" + std::string(buffer) + "' serviced by Server " + std::to_string(server_id);

    // --- Send Response ---
    // Send the prepared response string back to the client (Load Balancer).
    // Use send() or write(). send() is socket-specific.
    // MSG_NOSIGNAL flag could prevent SIGPIPE but is Linux-specific; SIGPIPE is ignored globally instead.
    ssize_t bytes_sent = send(client_sock, response.c_str(), response.length(), 0);

    // Check the result of the send operation.
    if (bytes_sent == SOCKET_ERROR) // SOCKET_ERROR likely defined as -1 in common.h
    {
        // Print the specific socket error. This often happens if the Load Balancer closed the connection
        // after sending the request but before receiving the response.
        print_socket_error("Server send failed");
        // Error sending, client might have disconnected prematurely.
    }
    // Check if not all bytes of the response were sent.
    else if (bytes_sent < (ssize_t)response.length())
    {
        // Log a warning about the partial send.
        std::cerr << "[Server " << server_id << "] Warning: Partial send occurred." << std::endl;
        // Robust applications would typically loop here to send the remaining data.
    }
    // If send was successful and complete.
    else
    {
        // Log the response that was sent.
        std::cout << "[Server " << server_id << "] Sent response: \"" << response << "\"" << std::endl;
    }

    // --- Close Connection ---
    // Close the client socket now that the request has been handled.
    close_socket(client_sock);
    // Log the closure of the connection.
    std::cout << "[Server " << server_id << "] Closed connection socket " << client_sock << "." << std::endl;
}

/**
 * @brief Main entry point for the Backend Server application.
 *
 * Expects a single command-line argument: the server's ID (0 to NUM_SERVERS - 1).
 * Initializes signal handlers, calculates its listening port based on the ID,
 * creates, binds, and listens on a TCP socket.
 * Enters a loop accepting connections from the Load Balancer, using `select` for
 * graceful shutdown checking. For each accepted connection, it spawns a new detached
 * thread running `handle_connection` to process the request.
 * The loop continues until `keep_running` is set to false by a signal handler.
 * Finally, it closes the listening socket and exits.
 *
 * @param argc Argument count (should be 2).
 * @param argv Argument vector (argv[1] should be the server ID).
 * @return int Returns 0 on successful shutdown, 1 on critical errors (bad arguments, socket setup failure).
 */
int main(int argc, char *argv[])
{
    // --- Argument Parsing ---
    // Check if the correct number of command-line arguments is provided.
    if (argc != 2)
    {
        // Print usage instructions to standard error. NUM_SERVERS from common.h.
        std::cerr << "Usage: " << argv[0] << " <server_id (0-" << NUM_SERVERS - 1 << ")>" << std::endl;
        // Exit with an error code.
        return 1;
    }

    // Convert the first argument (server ID string) to an integer.
    int server_id = std::atoi(argv[1]);
    // Validate the parsed server ID is within the expected range [0, NUM_SERVERS - 1].
    if (server_id < 0 || server_id >= NUM_SERVERS)
    {
        // Print an error message if the ID is invalid.
        std::cerr << "Error: Invalid server_id. Must be between 0 and " << NUM_SERVERS - 1 << "." << std::endl;
        // Exit with an error code.
        return 1;
    }

    // Calculate the port number for this server instance based on a base port and its ID.
    // BASE_SERVER_PORT is likely defined in common.h.
    int port = BASE_SERVER_PORT + server_id;

    // --- Signal Handling Setup ---
    // Setup signal handling for graceful shutdown (similar to Load Balancer).
    struct sigaction sa;
    // Zero out the structure.
    memset(&sa, 0, sizeof(sa));
    // Set the handler function.
    sa.sa_handler = handle_signal;
    // Register the handler for SIGINT (Ctrl+C).
    sigaction(SIGINT, &sa, NULL);
    // Register the handler for SIGTERM (termination signal from OS or tools like kill).
    sigaction(SIGTERM, &sa, NULL);

    // Ignore SIGPIPE signals globally for this process. Write errors will be caught via return codes.
    signal(SIGPIPE, SIG_IGN);

    // --- Socket Initialization ---
    // Socket descriptor for listening for incoming Load Balancer connections.
    SOCKET listen_sock = INVALID_SOCKET; // INVALID_SOCKET from common.h
    // Socket descriptor for an accepted connection.
    SOCKET client_sock = INVALID_SOCKET;
    // Address structures for this server and the connecting client (Load Balancer).
    struct sockaddr_in server_addr, client_addr;
    // Variable to store the size of the client address structure, needed for accept().
    socklen_t client_addr_len = sizeof(client_addr);

    // --- 1. Create Listening Socket ---
    // Create a socket (IPv4, TCP). IPPROTO_TCP or 0 specifies the TCP protocol.
    listen_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    // Check if socket creation failed.
    if (listen_sock == INVALID_SOCKET)
    {
        // Print error using helper function from common.h.
        print_socket_error("Server socket creation failed");
        return 1; // Exit with error code 1.
    }

    // --- Optional: Set SO_REUSEADDR ---
    // Allow the socket to bind to an address/port that is in a TIME_WAIT state.
    // Useful for quickly restarting the server without waiting for the OS timeout.
    int opt = 1; // Option value (1 means enable).
    if (setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0)
    {
        // Print error if setsockopt fails. This is usually non-fatal.
        print_socket_error("Server setsockopt(SO_REUSEADDR) failed");
    }

    // --- 2. Bind Socket ---
    // Zero out the server address structure.
    memset(&server_addr, 0, sizeof(server_addr));
    // Set address family to IPv4.
    server_addr.sin_family = AF_INET;
    // Set IP address to INADDR_ANY to listen on all available network interfaces of the machine.
    // htonl converts host byte order to network byte order (long).
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    // Set the port number calculated earlier. htons converts host byte order to network byte order (short).
    server_addr.sin_port = htons(port);

    // Bind the socket to the specified address and port.
    if (bind(listen_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) == SOCKET_ERROR)
    {
        // Print error if bind fails (critical).
        print_socket_error("Server bind failed");
        // Close the created socket before exiting. close_socket from common.h.
        close_socket(listen_sock);
        return 1; // Exit with error code 1.
    }

    // --- 3. Listen for Connections ---
    // Put the socket into listening mode to accept incoming connections.
    // SOMAXCONN is a system-defined constant suggesting a reasonable maximum backlog queue size.
    if (listen(listen_sock, SOMAXCONN) == SOCKET_ERROR)
    {
        // Print error if listen fails (critical).
        print_socket_error("Server listen failed");
        // Close the socket before exiting.
        close_socket(listen_sock);
        return 1; // Exit with error code 1.
    }

    // Log that the server is ready and listening on its assigned port.
    std::cout << "[Server " << server_id << "] Listening on port " << port << "..." << std::endl;

    // --- 4. Accept Loop ---
    // Main loop: continues as long as the keep_running flag is true (1).
    // Uses select() to allow checking the flag periodically and avoid blocking indefinitely on accept().
    while (keep_running)
    {
        // Set of file descriptors to monitor for reading.
        fd_set read_fds;
        // Clear the set.
        FD_ZERO(&read_fds);
        // Add the listening socket to the set. We only need to know when it's ready to accept.
        FD_SET(listen_sock, &read_fds);

        // Timeout structure for select().
        struct timeval timeout;
        // Set timeout to 1 second. Allows the loop to check `keep_running` at least once per second.
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;

        // Wait for activity on the listening socket or until the timeout expires.
        // select() monitors the specified file descriptors.
        // listen_sock + 1 is the highest fd number + 1 required by select().
        int activity = select(listen_sock + 1, &read_fds, NULL, NULL, &timeout);

        // Check the return value of select().
        if (activity < 0)
        {
            // If select() was interrupted by a signal (likely our SIGINT/SIGTERM handler).
            if (errno == EINTR)
            {
                // Log the interruption and continue to the top of the loop to re-check keep_running.
                std::cout << "[Server " << server_id << "] Select interrupted, checking keep_running..." << std::endl;
                continue; // Re-check the while condition.
            }
            // For any other select error.
            else
            {
                // Print the socket error.
                print_socket_error("Server select failed");
                // Break out of the loop to initiate shutdown.
                break;
            }
        }

        // If activity is 0, select() timed out. No incoming connection during the timeout period.
        if (activity == 0)
        {
            // Go back to the start of the loop to call select() again and check keep_running.
            continue;
        }

        // If select() returned > 0 and the listening socket is in the ready set.
        if (FD_ISSET(listen_sock, &read_fds))
        {
            // --- Accept New Connection ---
            // Accept the pending incoming connection. Returns a new socket for this connection.
            client_sock = accept(listen_sock, (struct sockaddr *)&client_addr, &client_addr_len);

            // Check if accept() failed.
            if (client_sock == INVALID_SOCKET)
            {
                // Only print the error if we are not already shutting down (keep_running is true).
                if (keep_running)
                {
                    print_socket_error("Server accept failed");
                }
                // Check for specific errors indicating resource exhaustion (too many open files).
                if (errno == EMFILE || errno == ENFILE)
                {
                    // Log the critical resource error.
                    std::cerr << "[Server " << server_id << "] Ran out of file descriptors. Stopping accept loop." << std::endl;
                    // Signal the loop to stop accepting new connections.
                    keep_running = 0;
                }
                // Continue to the next loop iteration. Might recover from transient errors,
                // or exit gracefully if keep_running was set to 0.
                continue;
            }

            // --- Log Accepted Connection ---
            // Buffer to store the client's IP address string.
            char client_ip[INET_ADDRSTRLEN];
            // Convert the binary client IP address to a readable string.
            inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);
            // Log the details of the accepted connection (IP, port, socket descriptor).
            // ntohs converts network byte order port to host byte order.
            std::cout << "[Server " << server_id << "] Accepted connection from "
                      << client_ip << ":" << ntohs(client_addr.sin_port)
                      << " on socket " << client_sock << std::endl;

            // --- 5. Handle Connection in New Thread ---
            try
            {
                // Create a new thread that will execute the handle_connection function.
                // Pass the new client socket and the server ID to the thread function.
                // .detach() lets the thread run independently. The main loop does not wait for it.
                // The detached thread is responsible for closing its own socket via handle_connection.
                std::thread(handle_connection, client_sock, server_id).detach();
            }
            // Catch potential system errors during thread creation (e.g., exceeding thread limits).
            catch (const std::system_error &e)
            {
                // Log the error, including the system error code.
                std::cerr << "Error creating thread: " << e.what() << " (errno: " << e.code().value() << ")" << std::endl;
                // If thread creation failed, the connection cannot be handled, so close the socket.
                close_socket(client_sock);
                // Consider adding logic here to slow down or stop accepting connections if this error persists.
            }
        } // end if FD_ISSET

        // Note on thread management: With detached threads, the main thread doesn't track them.
        // The OS reclaims resources when a detached thread exits.
        // For servers needing more control over shutdown (e.g., waiting for requests to finish),
        // or using a thread pool would be more appropriate.

    } // end while(keep_running)

    // --- Shutdown Sequence ---
    // The loop has exited (likely because keep_running became 0 due to a signal or critical error).
    std::cout << "\n[Server " << server_id << "] Shutting down listener..." << std::endl;

    // Close the listening socket to stop accepting any new incoming connections.
    if (listen_sock != INVALID_SOCKET)
    {
        close_socket(listen_sock);
        // Mark the socket as invalid after closing.
        listen_sock = INVALID_SOCKET;
    }

    // Log that the shutdown process for this server instance is complete.
    std::cout << "[Server " << server_id << "] Shutdown complete." << std::endl;
    // Return 0 indicating successful execution and shutdown.
    return 0;
}