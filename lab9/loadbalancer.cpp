#include "common.h"
#include <vector>
#include <atomic>
#include <mutex>
#include <cstdlib> // For exit

// --- Global state for Load Balancer ---
std::vector<std::pair<std::string, int>> server_addresses = getServerAddresses();       // List of backend server addresses and ports
std::atomic<unsigned int> next_server_index(0);                                         // Atomic index for round-robin server selection
std::mutex connection_map_mutex;                                                         // Protects connection tracking map
std::map<std::string, ClientConnectionInfo> client_connections;                         // Tracks client connection rates
volatile sig_atomic_t keep_running_lb = 1;

void handle_signal_lb(int signal)
{
    std::cout << "\n[LB] Caught signal " << signal << ", setting keep_running_lb to 0." << std::endl;
    keep_running_lb = 0;
}

// Function to check and update client connection rate
/**
 * @brief Checks if a client connection should be allowed based on rate limiting rules.
 *
 * This function tracks the number of connections from a specific client IP address
 * within a defined time window (RATE_WINDOW). If the number of connections exceeds
 * MAX_CONNECTIONS_PER_IP, the client is considered to be potentially launching a
 * Denial of Service (DoS) attack and is blocked for a specified duration (BLOCK_DURATION).
 *
 * If a client is currently blocked, incoming connections from that IP are rejected
 * until the block duration expires. A 403 Forbidden message is sent to the client
 * socket if the connection is blocked.
 *
 * This function is thread-safe, using a mutex (connection_map_mutex) to protect
 * access to the shared client connection data (client_connections).
 *
 * @param client_ip The IP address of the connecting client.
 * @param client_sock The socket descriptor for the client connection. Used to send
 *                    an error message if the client is blocked.
 * @return true if the connection is allowed, false if the client is blocked due to
 *         rate limiting or is currently under a block duration.
 */
bool check_client_rate(const std::string &client_ip, SOCKET client_sock)
{
    std::lock_guard<std::mutex> lock(connection_map_mutex);
    auto now = std::chrono::system_clock::now();
    auto &info = client_connections[client_ip];

    // Check if client is blocked
    if (info.is_blocked && now < info.block_until)
    {
        std::cout << "[LB] Blocking connection from " << client_ip << " (blocked until "
                  << std::chrono::duration_cast<std::chrono::seconds>(info.block_until - now).count()
                  << "s remain)." << std::endl;
        std::string error_msg = "403 Forbidden: Client blocked due to excessive requests.";
        send(client_sock, error_msg.c_str(), error_msg.length(), 0);
        return false;
    }
    else if (info.is_blocked)
    {
        // Block duration expired, reset
        info.is_blocked = false;
        info.connection_count = 0;
        info.last_reset = now;
    }

    // Reset count if rate window has passed
    if (now - info.last_reset > RATE_WINDOW)
    {
        info.connection_count = 0;
        info.last_reset = now;
    }

    // Increment connection count
    info.connection_count++;

    // Check for DoS behavior
    if (info.connection_count > MAX_CONNECTIONS_PER_IP)
    {
        std::cout << "[LB] Detected DoS from " << client_ip << ": "
                  << info.connection_count << " connections in "
                  << std::chrono::duration_cast<std::chrono::seconds>(RATE_WINDOW).count()
                  << "s. Blocking for " << BLOCK_DURATION.count() << "s." << std::endl;
        info.is_blocked = true;
        info.block_until = now + BLOCK_DURATION;
        std::string error_msg = "403 Forbidden: Client blocked due to excessive requests.";
        send(client_sock, error_msg.c_str(), error_msg.length(), 0);
        return false;
    }

    return true; // Allow connection
}

// Function to handle communication with a specific backend server
/**
 * @brief Forwards a client request to a backend server using round-robin load balancing.
 *
 * Selects a backend server from the `server_addresses` pool based on an atomic counter
 * (`next_server_index`) ensuring round-robin distribution. It establishes a new TCP
 * connection to the selected server, sends the `request_number_int` as a string,
 * receives the response from the server, and forwards this response back to the
 * original client via the `client_sock`. Handles socket creation, connection,
 * send/receive operations, and associated error checking/reporting. Closes the
 * connection to the backend server after the transaction.
 *
 * @param client_sock The socket descriptor representing the connection to the original client.
 * @param request_number_int An integer identifying the specific request being processed.
 * @return true if the request was successfully forwarded to a server and the response
 *         was successfully relayed (or attempted to be relayed) back to the client.
 * @return false if a critical error occurred during the process, such as failing to
 *         create a socket, connect to the backend server, or receive a response.
 *         Specific errors are printed to stderr.
 */
bool forward_to_server(SOCKET client_sock, int request_number_int)
{
    unsigned int current_index = next_server_index.fetch_add(1);
    int server_idx = current_index % NUM_SERVERS;

    std::string target_host = server_addresses[server_idx].first;
    int target_port = server_addresses[server_idx].second;

    std::cout << "[LB] Forwarding request " << request_number_int
              << " to Server " << server_idx << " (" << target_host << ":" << target_port << ")" << std::endl;

    SOCKET server_sock = INVALID_SOCKET;
    struct sockaddr_in server_addr;
    char buffer[BUFFER_SIZE];

    server_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (server_sock == INVALID_SOCKET)
    {
        print_socket_error("LB: Failed to create server socket");
        return false;
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(target_port);
    if (inet_pton(AF_INET, target_host.c_str(), &server_addr.sin_addr) <= 0)
    {
        print_socket_error("LB: Invalid server address format");
        close_socket(server_sock);
        return false;
    }

    if (connect(server_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) == SOCKET_ERROR)
    {
        std::string context = "[LB] Failed to connect to Server " + std::to_string(server_idx) + " (" + target_host + ":" + std::to_string(target_port) + ")";
        print_socket_error(context.c_str());
        close_socket(server_sock);
        return false;
    }

    std::string request_str = std::to_string(request_number_int);
    ssize_t bytes_sent = send(server_sock, request_str.c_str(), request_str.length(), 0);

    if (bytes_sent == SOCKET_ERROR)
    {
        print_socket_error(("LB: Failed to send data to Server " + std::to_string(server_idx)).c_str());
        close_socket(server_sock);
        return false;
    }
    if (bytes_sent < (ssize_t)request_str.length())
    {
        std::cerr << "[LB] Warning: Partial send to server " << server_idx << std::endl;
    }

    memset(buffer, 0, BUFFER_SIZE);
    ssize_t bytes_received = recv(server_sock, buffer, BUFFER_SIZE - 1, 0);

    close_socket(server_sock);

    if (bytes_received <= 0)
    {
        if (bytes_received == 0)
        {
            std::cerr << "[LB] Server " << server_idx << " closed connection unexpectedly." << std::endl;
        }
        else
        {
            print_socket_error(("LB: Failed to receive data from Server " + std::to_string(server_idx)).c_str());
        }
        return false;
    }
    buffer[bytes_received] = '\0';

    ssize_t client_bytes_sent = send(client_sock, buffer, bytes_received, 0);

    if (client_bytes_sent == SOCKET_ERROR)
    {
        print_socket_error("LB: Failed to send response back to client");
    }
    else if (client_bytes_sent < bytes_received)
    {
        std::cerr << "[LB] Warning: Partial send to client." << std::endl;
    }
    else
    {
        std::cout << "[LB] Relayed response from Server " << server_idx << " to client." << std::endl;
    }

    return true;
}

// Function to handle a single client connection to the Load Balancer
/**
 * @brief Handles an incoming connection from a client.
 *
 * This function manages the interaction with a single connected client. It first checks
 * if the client is exceeding the connection rate limit using `check_client_rate`.
 * If the client is rate-limited, the connection is closed immediately. Otherwise,
 * it attempts to receive data from the client, expecting an integer request number.
 *
 * The received data is parsed as an integer. If the data is invalid (non-numeric or
 * out of range), an appropriate error message (400 Bad Request) is sent back to the
 * client. If the data is valid, the function attempts to forward the request number
 * to a backend server via the `forward_to_server` function.
 *
 * If forwarding fails (e.g., no backend servers available), a 503 Service Unavailable
 * error is sent to the client. Any unexpected exceptions during processing result
 * in a 500 Internal Server Error message being sent.
 *
 * The function handles client disconnections and socket receive errors gracefully.
 * Regardless of the outcome (successful forwarding, error, rate limiting), the
 * client socket is closed before the function returns.
 *
 * @param client_sock The socket descriptor for the connected client.
 * @param client_ip The IP address string of the connected client, used for logging and rate limiting.
 *
 * @note This function closes the `client_sock` before returning.
 * @note Assumes the client sends a single message containing only an integer request number.
 */
void handle_client_connection(SOCKET client_sock, const std::string &client_ip)
{
    char buffer[BUFFER_SIZE];
    ssize_t bytes_received;

    std::cout << "[LB] Handling client connection from " << client_ip << " on socket " << client_sock << std::endl;

    // Check client connection rate
    if (!check_client_rate(client_ip, client_sock))
    {
        close_socket(client_sock);
        std::cout << "[LB] Client connection closed (socket: " << client_sock << ") due to rate limiting." << std::endl;
        return;
    }

    memset(buffer, 0, BUFFER_SIZE);
    bytes_received = recv(client_sock, buffer, BUFFER_SIZE - 1, 0);

    if (bytes_received <= 0)
    {
        if (bytes_received == 0)
        {
            std::cout << "[LB] Client disconnected (socket: " << client_sock << ")." << std::endl;
        }
        else
        {
            print_socket_error("LB recv from client failed");
        }
    }
    else
    {
        buffer[bytes_received] = '\0';
        try
        {
            int request_number = std::stoi(buffer);
            std::cout << "[LB] Received request number " << request_number << " from client (socket: " << client_sock << ")." << std::endl;

            if (!forward_to_server(client_sock, request_number))
            {
                std::cerr << "[LB] Failed to forward request " << request_number << " to any server." << std::endl;
                std::string error_msg = "503 Service Unavailable: Failed to connect to backend server.";
                send(client_sock, error_msg.c_str(), error_msg.length(), 0);
            }
        }
        catch (const std::invalid_argument &e)
        {
            std::cerr << "[LB] Received invalid (non-numeric) data from client: \"" << buffer << "\"" << std::endl;
            std::string error_msg = "400 Bad Request: Invalid request format.";
            send(client_sock, error_msg.c_str(), error_msg.length(), 0);
        }
        catch (const std::out_of_range &e)
        {
            std::cerr << "[LB] Received out-of-range number from client: \"" << buffer << "\"" << std::endl;
            std::string error_msg = "400 Bad Request: Request number out of range.";
            send(client_sock, error_msg.c_str(), error_msg.length(), 0);
        }
        catch (const std::exception &e)
        {
            std::cerr << "[LB] Unexpected exception processing client request: " << e.what() << std::endl;
            std::string error_msg = "500 Internal Server Error.";
            send(client_sock, error_msg.c_str(), error_msg.length(), 0);
        }
    }

    close_socket(client_sock);
    std::cout << "[LB] Client connection closed (socket: " << client_sock << ")." << std::endl;
}

/**
 * @brief Main entry point for the Load Balancer application.
 *
 * Initializes signal handlers for graceful shutdown (SIGINT, SIGTERM) and ignores SIGPIPE.
 * Creates a TCP listening socket, sets the SO_REUSEADDR option, binds it to the
 * specified LB_PORT on any interface, and starts listening for incoming connections.
 * Enters a loop that waits for incoming connections using `select` with a timeout.
 * When a new connection is detected, it accepts the connection, retrieves the client's
 * IP address and port, prints this information, and spawns a new detached thread
 * running `handle_client_connection` to handle communication with that specific client.
 * The loop continues as long as the `keep_running_lb` flag is true.
 * Handles potential errors during socket operations, accept, select, and thread creation.
 * If `select` is interrupted by a signal, it checks the `keep_running_lb` flag.
 * If `accept` fails due to running out of file descriptors, it sets `keep_running_lb` to false.
 * Upon exiting the loop (e.g., due to a signal setting `keep_running_lb` to false),
 * it closes the listening socket and prints shutdown messages.
 *
 * @param argc Argument count (unused).
 * @param argv Argument vector (unused).
 * @return int Returns 0 on successful shutdown, 1 if critical errors occur during initialization (socket creation, bind, listen).
 */
int main()
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_signal_lb;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    signal(SIGPIPE, SIG_IGN);

    SOCKET listen_sock_lb = INVALID_SOCKET;
    SOCKET client_sock_lb = INVALID_SOCKET;
    struct sockaddr_in lb_addr, client_addr;
    socklen_t client_addr_len = sizeof(client_addr);

    listen_sock_lb = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listen_sock_lb == INVALID_SOCKET)
    {
        print_socket_error("LB socket creation failed");
        return 1;
    }

    int opt = 1;
    if (setsockopt(listen_sock_lb, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0)
    {
        print_socket_error("LB setsockopt(SO_REUSEADDR) failed");
    }

    memset(&lb_addr, 0, sizeof(lb_addr));
    lb_addr.sin_family = AF_INET;
    lb_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    lb_addr.sin_port = htons(LB_PORT);

    if (bind(listen_sock_lb, (struct sockaddr *)&lb_addr, sizeof(lb_addr)) == SOCKET_ERROR)
    {
        print_socket_error("LB bind failed");
        close_socket(listen_sock_lb);
        return 1;
    }

    if (listen(listen_sock_lb, SOMAXCONN) == SOCKET_ERROR)
    {
        print_socket_error("LB listen failed");
        close_socket(listen_sock_lb);
        return 1;
    }

    std::cout << "[LB] Load Balancer listening on port " << LB_PORT << "..." << std::endl;

    while (keep_running_lb)
    {
        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(listen_sock_lb, &read_fds);

        struct timeval timeout;
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;

        int activity = select(listen_sock_lb + 1, &read_fds, NULL, NULL, &timeout);

        if (activity < 0)
        {
            if (errno == EINTR)
            {
                std::cout << "[LB] Select interrupted, checking keep_running_lb..." << std::endl;
                continue;
            }
            else
            {
                print_socket_error("LB select failed");
                break;
            }
        }

        if (activity == 0)
        {
            continue;
        }

        if (FD_ISSET(listen_sock_lb, &read_fds))
        {
            client_sock_lb = accept(listen_sock_lb, (struct sockaddr *)&client_addr, &client_addr_len);

            if (client_sock_lb == INVALID_SOCKET)
            {
                if (keep_running_lb)
                {
                    print_socket_error("LB accept failed");
                }
                if (errno == EMFILE || errno == ENFILE)
                {
                    std::cerr << "[LB] Ran out of file descriptors. Stopping accept loop." << std::endl;
                    keep_running_lb = 0;
                }
                continue;
            }

            char client_ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);
            std::cout << "[LB] Accepted connection from client " << client_ip << ":"
                      << ntohs(client_addr.sin_port) << " on socket " << client_sock_lb << std::endl;

            try
            {
                std::thread(handle_client_connection, client_sock_lb, std::string(client_ip)).detach();
            }
            catch (const std::system_error &e)
            {
                std::cerr << "Error creating client handler thread: " << e.what() << " (errno: " << e.code().value() << ")" << std::endl;
                close_socket(client_sock_lb);
            }
        }
    }

    std::cout << "\n[LB] Shutting down listener..." << std::endl;

    if (listen_sock_lb != INVALID_SOCKET)
    {
        close_socket(listen_sock_lb);
        listen_sock_lb = INVALID_SOCKET;
    }

    std::cout << "[LB] Shutdown complete." << std::endl;
    return 0;
}