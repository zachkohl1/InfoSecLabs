#include "common.h"     // Include common definitions
#include <vector>      // Include the vector container
#include <atomic>      // Include atomic types for thread-safe operations
#include <mutex>       // Include mutex for protecting shared resources
#include <cstdlib>     // For exit() - though not used directly here, might be used by functions in common.h or for general utilities
#include <map>         // Include the map container for client connection tracking
#include <chrono>      // Include time-related utilities for rate limiting
#include <string>      // Include string manipulation utilities
#include <iostream>    // Include standard input/output stream objects
#include <thread>      // Include threading support
#include <signal.h>    // Include signal handling functions (sigaction, signal)
#include <cstring>     // Include C-style string functions like memset
#include <stdexcept>   // Include standard exception types like invalid_argument, out_of_range

// --- Global state for Load Balancer ---

// List of backend server addresses (IP or hostname) and their corresponding ports.
// Returns a std::vector of std::pair<std::string, int>.
std::vector<std::pair<std::string, int>> server_addresses = getServerAddresses();

// Atomic integer used as an index to select the next backend server in a round-robin fashion.
// Being atomic ensures that increments are thread-safe when multiple threads handle requests concurrently.
std::atomic<unsigned int> next_server_index(0);

// Mutex to protect access to the `client_connections` map. This is crucial because multiple
// threads (one per client connection) might try to access and modify this map concurrently.
std::mutex connection_map_mutex;

// Map to store connection rate information for each client IP address.
// The key is the client's IP address (string).
// The value is a ClientConnectionInfo struct contains:
// - connection count within the current window
// - timestamp of the last count reset
// - boolean indicating if the client is currently blocked
// - timestamp until which the client is blocked
std::map<std::string, ClientConnectionInfo> client_connections;

// Volatile sig_atomic_t flag used to signal graceful shutdown.
// 'volatile' suggests it might be changed unexpectedly (by a signal handler).
// 'sig_atomic_t' ensures that reads/writes are atomic with respect to signal handlers.
// Initialized to 1 (true) to keep the main loop running.
volatile sig_atomic_t keep_running_lb = 1;

/**
 * @brief Signal handler function for the Load Balancer.
 *
 * This function is called when the process receives specific signals (like SIGINT, SIGTERM).
 * It prints a message indicating the signal received and sets the global `keep_running_lb`
 * flag to 0, which signals the main loop to terminate gracefully.
 *
 * @param signal The signal number that was caught.
 */
void handle_signal_lb(int signal)
{
    // Print a message indicating which signal was caught.
    std::cout << "\n[LB] Caught signal " << signal << ", setting keep_running_lb to 0." << std::endl;
    // Set the global flag to 0 to signal the main loop to stop accepting new connections and shut down.
    keep_running_lb = 0;
}

// Function to check and update client connection rate
/**
 * @brief Checks if a client connection should be allowed based on rate limiting rules.
 *
 * This function tracks the number of connections from a specific client IP address
 * within a defined time window (RATE_WINDOW). If the number of connections exceeds
 * MAX_CONNECTIONS_PER_IP (likely defined), the client is considered to be potentially launching a
 * Denial of Service (DoS) attack and is blocked for a specified duration (BLOCK_DURATION).
 *
 * If a client is currently blocked, incoming connections from that IP are rejected
 * until the block duration expires. A 403 Forbidden message is sent to the client
 * socket if the connection is blocked.
 *
 * This function is thread-safe, using a mutex (connection_map_mutex) to protect
 * access to the shared client connection data (client_connections).
 *
 * @param client_ip The IP address of the connecting client (std::string).
 * @param client_sock The socket descriptor (SOCKET, likely a typedef for int or platform-specific handle)
 * for the client connection. Used to send an error message if the client is blocked.
 * @return true if the connection is allowed, false if the client is blocked due to
 * rate limiting or is currently under a block duration.
 */
bool check_client_rate(const std::string &client_ip, SOCKET client_sock)
{
    // Acquire a lock on the mutex protecting the client_connections map.
    // The lock_guard automatically releases the mutex when it goes out of scope (RAII).
    std::lock_guard<std::mutex> lock(connection_map_mutex);

    // Get the current time point.
    auto now = std::chrono::system_clock::now();

    // Get a reference to the connection info for this client IP.
    // If the IP is not already in the map, it will be default-constructed.
    auto &info = client_connections[client_ip]; // info is likely of type ClientConnectionInfo

    // Check if the client is currently marked as blocked AND the block duration has not yet expired.
    if (info.is_blocked && now < info.block_until)
    {
        // Log that the connection is being blocked.
        std::cout << "[LB] Blocking connection from " << client_ip << " (blocked until "
                  // Calculate and display remaining block time.
                  << std::chrono::duration_cast<std::chrono::seconds>(info.block_until - now).count()
                  << "s remain)." << std::endl;
        // Prepare a 403 Forbidden error message.
        std::string error_msg = "403 Forbidden: Client blocked due to excessive requests.";
        // Attempt to send the error message to the client.
        send(client_sock, error_msg.c_str(), error_msg.length(), 0); // Note: Error checking for send is omitted here.
        // Return false, indicating the connection should be dropped.
        return false;
    }
    // Else if the client was blocked, but the block duration has now expired.
    else if (info.is_blocked)
    {
        // Unblock the client.
        info.is_blocked = false;
        // Reset the connection count for the new window.
        info.connection_count = 0;
        // Reset the window start time.
        info.last_reset = now;
        // (Fall through to check connection count for the current connection)
    }

    // Check if the time elapsed since the last reset is greater than the defined rate window.
    // RATE_WINDOW is likely a std::chrono::duration defined in common.h.
    if (now - info.last_reset > RATE_WINDOW)
    {
        // If the window has passed, reset the connection count.
        info.connection_count = 0;
        // Update the last reset time to the current time.
        info.last_reset = now;
    }

    // Increment the connection count for this client within the current window.
    info.connection_count++;

    // Check if the connection count now exceeds the maximum allowed connections per IP.
    // MAX_CONNECTIONS_PER_IP is likely an integer constant defined in common.h.
    if (info.connection_count > MAX_CONNECTIONS_PER_IP)
    {
        // Log that potential DoS behavior is detected and the client is being blocked.
        std::cout << "[LB] Detected DoS from " << client_ip << ": "
                  << info.connection_count << " connections in "
                  // Display the rate window duration.
                  << std::chrono::duration_cast<std::chrono::seconds>(RATE_WINDOW).count()
                  // Display the block duration. BLOCK_DURATION is likely a std::chrono::duration.
                  << "s. Blocking for " << BLOCK_DURATION.count() << "s." << std::endl;
        // Mark the client as blocked.
        info.is_blocked = true;
        // Set the time until which the client will remain blocked.
        info.block_until = now + BLOCK_DURATION;
        // Prepare a 403 Forbidden error message.
        std::string error_msg = "403 Forbidden: Client blocked due to excessive requests.";
        // Attempt to send the error message to the client.
        send(client_sock, error_msg.c_str(), error_msg.length(), 0); // Note: Error checking for send is omitted here.
        // Return false, indicating the connection should be dropped.
        return false;
    }

    // If none of the blocking conditions were met, allow the connection.
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
 * was successfully relayed (or attempted to be relayed) back to the client.
 * @return false if a critical error occurred during the process, such as failing to
 * create a socket, connect to the backend server, or receive a response.
 * Specific errors are printed to stderr via print_socket_error (defined in common.h).
 */
bool forward_to_server(SOCKET client_sock, int request_number_int)
{
    // Atomically fetch the current index and then increment it for the next call.
    // This ensures each thread gets a unique index value even under concurrent access.
    unsigned int current_index = next_server_index.fetch_add(1);

    // Calculate the actual server index within the bounds of the server list using the modulo operator.
    // NUM_SERVERS is likely a constant defined in common.h, equal to server_addresses.size().
    int server_idx = current_index % NUM_SERVERS;

    // Retrieve the hostname/IP and port for the selected backend server.
    std::string target_host = server_addresses[server_idx].first;
    int target_port = server_addresses[server_idx].second;

    // Log the forwarding action.
    std::cout << "[LB] Forwarding request " << request_number_int
              << " to Server " << server_idx << " (" << target_host << ":" << target_port << ")" << std::endl;

    // Initialize server socket descriptor. INVALID_SOCKET is likely defined in common.h.
    SOCKET server_sock = INVALID_SOCKET;
    // Structure to hold the server address information.
    struct sockaddr_in server_addr;
    // Buffer to store data received from the server. BUFFER_SIZE is likely defined in common.h.
    char buffer[BUFFER_SIZE];

    // Create a new socket for connecting to the backend server (IPv4, TCP).
    server_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    // Check if socket creation failed.
    if (server_sock == INVALID_SOCKET)
    {
        // Print an error message using a helper function (likely defined in common.h).
        print_socket_error("LB: Failed to create server socket");
        // Return false indicating failure.
        return false;
    }

    // Zero out the server address structure.
    memset(&server_addr, 0, sizeof(server_addr));
    // Set the address family to IPv4.
    server_addr.sin_family = AF_INET;
    // Set the server port number, converting to network byte order.
    server_addr.sin_port = htons(target_port);
    // Convert the server IP address string to binary form.
    // inet_pton returns 1 on success, 0 if the format is invalid, -1 on error.
    if (inet_pton(AF_INET, target_host.c_str(), &server_addr.sin_addr) <= 0)
    {
        // Print an error message.
        print_socket_error("LB: Invalid server address format");
        // Close the socket that was created. close_socket is likely defined in common.h.
        close_socket(server_sock);
        // Return false indicating failure.
        return false;
    }

    // Attempt to connect to the backend server.
    // SOCKET_ERROR is likely defined in common.h (often -1).
    if (connect(server_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) == SOCKET_ERROR)
    {
        // Create a context-specific error message.
        std::string context = "[LB] Failed to connect to Server " + std::to_string(server_idx) + " (" + target_host + ":" + std::to_string(target_port) + ")";
        // Print the socket error with the context.
        print_socket_error(context.c_str());
        // Close the socket.
        close_socket(server_sock);
        // Return false indicating failure.
        return false;
    }

    // Convert the integer request number to its string representation.
    std::string request_str = std::to_string(request_number_int);
    // Send the request string to the connected backend server.
    ssize_t bytes_sent = send(server_sock, request_str.c_str(), request_str.length(), 0);

    // Check if the send operation failed.
    if (bytes_sent == SOCKET_ERROR)
    {
        // Print an error message.
        print_socket_error(("LB: Failed to send data to Server " + std::to_string(server_idx)).c_str());
        // Close the socket.
        close_socket(server_sock);
        // Return false indicating failure.
        return false;
    }
    // Check if not all bytes were sent (partial send).
    if (bytes_sent < (ssize_t)request_str.length())
    {
        // Log a warning about the partial send.
        std::cerr << "[LB] Warning: Partial send to server " << server_idx << std::endl;
        // Proceed anyway, as some data was sent. Depending on the protocol, this might be an issue.
    }

    // Clear the receive buffer before receiving data.
    memset(buffer, 0, BUFFER_SIZE);
    // Receive the response from the backend server. Wait for data.
    // BUFFER_SIZE - 1 leaves space for a null terminator.
    ssize_t bytes_received = recv(server_sock, buffer, BUFFER_SIZE - 1, 0);

    // Close the connection to the backend server as we are done with it for this request.
    close_socket(server_sock);

    // Check the result of the receive operation.
    if (bytes_received <= 0)
    {
        // If bytes_received is 0, the server closed the connection gracefully but possibly prematurely.
        if (bytes_received == 0)
        {
            std::cerr << "[LB] Server " << server_idx << " closed connection unexpectedly." << std::endl;
        }
        // If bytes_received is negative, a socket error occurred.
        else
        {
            print_socket_error(("LB: Failed to receive data from Server " + std::to_string(server_idx)).c_str());
        }
        // Return false indicating failure to get a response.
        return false;
    }
    // Null-terminate the received data to treat it as a C-string (optional, depends on usage).
    buffer[bytes_received] = '\0';

    // Forward the received response (buffer) back to the original client.
    ssize_t client_bytes_sent = send(client_sock, buffer, bytes_received, 0);

    // Check if sending the response back to the client failed.
    if (client_bytes_sent == SOCKET_ERROR)
    {
        // Print an error message.
        print_socket_error("LB: Failed to send response back to client");
        // Even if sending back fails, we consider the server interaction part successful.
        // The function aims to report success/failure of *forwarding*, so return true here.
        // The calling function (`handle_client_connection`) will handle the client socket closure.
    }
    // Check if the send to the client was incomplete.
    else if (client_bytes_sent < bytes_received)
    {
        // Log a warning.
        std::cerr << "[LB] Warning: Partial send to client." << std::endl;
    }
    // If sending to the client was successful.
    else
    {
        // Log the successful relay action.
        std::cout << "[LB] Relayed response from Server " << server_idx << " to client." << std::endl;
    }

    // Return true indicating the forwarding and relay process was initiated successfully
    // (even if the final send back to the client had issues, the core task was done).
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
 * If forwarding fails (e.g., no backend servers available or they fail to respond),
 * a 503 Service Unavailable error is sent to the client. Any unexpected exceptions
 * during processing result in a 500 Internal Server Error message being sent.
 *
 * The function handles client disconnections and socket receive errors gracefully.
 * Regardless of the outcome (successful forwarding, error, rate limiting), the
 * client socket is closed before the function returns.
 *
 * @param client_sock The socket descriptor for the connected client.
 * @param client_ip The IP address string of the connected client, used for logging and rate limiting.
 *
 * @note This function closes the `client_sock` before returning.
 * @note Assumes the client sends a single message containing only an integer request number as a string.
 */
void handle_client_connection(SOCKET client_sock, const std::string &client_ip)
{
    // Buffer to store data received from the client.
    char buffer[BUFFER_SIZE];
    // Variable to store the number of bytes received.
    ssize_t bytes_received;

    // Log the start of handling this specific client connection.
    std::cout << "[LB] Handling client connection from " << client_ip << " on socket " << client_sock << std::endl;

    // --- Rate Limiting Check ---
    // Call the rate limiting function. If it returns false, the client is blocked.
    if (!check_client_rate(client_ip, client_sock))
    {
        // If blocked, close the client socket immediately.
        close_socket(client_sock);
        // Log the reason for closure.
        std::cout << "[LB] Client connection closed (socket: " << client_sock << ") due to rate limiting." << std::endl;
        // Exit the handler function for this client.
        return;
    }

    // --- Receive Request from Client ---
    // Clear the buffer.
    memset(buffer, 0, BUFFER_SIZE);
    // Attempt to receive data from the client socket.
    bytes_received = recv(client_sock, buffer, BUFFER_SIZE - 1, 0);

    // Check the result of the receive operation.
    if (bytes_received <= 0)
    {
        // If 0 bytes received, the client closed the connection gracefully.
        if (bytes_received == 0)
        {
            std::cout << "[LB] Client disconnected (socket: " << client_sock << ")." << std::endl;
        }
        // If less than 0, an error occurred during receive.
        else
        {
            print_socket_error("LB recv from client failed");
        }
        // No request received or error occurred, processing ends here for this client.
        // Socket will be closed at the end of the function.
    }
    // If data was successfully received (bytes_received > 0).
    else
    {
        // Null-terminate the received data to treat it as a string.
        buffer[bytes_received] = '\0';
        // --- Process Request ---
        try
        {
            // Attempt to convert the received buffer content to an integer.
            // std::stoi throws std::invalid_argument if conversion fails,
            // and std::out_of_range if the number is too large/small for an int.
            int request_number = std::stoi(buffer);
            // Log the successfully parsed request number.
            std::cout << "[LB] Received request number " << request_number << " from client (socket: " << client_sock << ")." << std::endl;

            // --- Forward Request ---
            // Attempt to forward the request number to a backend server.
            // `forward_to_server` handles communication with the backend and sends the response back to client_sock.
            if (!forward_to_server(client_sock, request_number))
            {
                // If forwarding failed (e.g., couldn't connect to any server, server didn't respond).
                std::cerr << "[LB] Failed to forward request " << request_number << " to any server." << std::endl;
                // Prepare a 503 Service Unavailable error message.
                std::string error_msg = "503 Service Unavailable: Failed to connect to backend server.";
                // Attempt to send the 503 error back to the client.
                // Note: If forward_to_server failed because the client disconnected, this send might also fail.
                send(client_sock, error_msg.c_str(), error_msg.length(), 0);
            }
            // If forward_to_server returned true, the response was already relayed (or attempted) within that function.
        }
        // Catch exceptions during parsing (stoi).
        catch (const std::invalid_argument &e)
        {
            // Log the error: received data wasn't a valid integer.
            std::cerr << "[LB] Received invalid (non-numeric) data from client: \"" << buffer << "\"" << std::endl;
            // Prepare a 400 Bad Request error message.
            std::string error_msg = "400 Bad Request: Invalid request format.";
            // Send the 400 error back to the client.
            send(client_sock, error_msg.c_str(), error_msg.length(), 0);
        }
        catch (const std::out_of_range &e)
        {
            // Log the error: received number was outside the range of int.
            std::cerr << "[LB] Received out-of-range number from client: \"" << buffer << "\"" << std::endl;
            // Prepare a 400 Bad Request error message.
            std::string error_msg = "400 Bad Request: Request number out of range.";
            // Send the 400 error back to the client.
            send(client_sock, error_msg.c_str(), error_msg.length(), 0);
        }
        // Catch any other standard exceptions that might occur.
        catch (const std::exception &e)
        {
            // Log the unexpected error.
            std::cerr << "[LB] Unexpected exception processing client request: " << e.what() << std::endl;
            // Prepare a generic 500 Internal Server Error message.
            std::string error_msg = "500 Internal Server Error.";
            // Send the 500 error back to the client.
            send(client_sock, error_msg.c_str(), error_msg.length(), 0);
        }
    }

    // --- Close Client Connection ---
    // Close the client socket regardless of how the handling proceeded (success, error, rate limit handled earlier).
    close_socket(client_sock);
    // Log the closure of the client connection.
    std::cout << "[LB] Client connection closed (socket: " << client_sock << ")." << std::endl;
}

/**
 * @brief Main entry point for the Load Balancer application.
 *
 * Initializes signal handlers for graceful shutdown (SIGINT, SIGTERM) and ignores SIGPIPE.
 * Creates a TCP listening socket, sets the SO_REUSEADDR option, binds it to the
 * specified LB_PORT (defined in common.h) on any interface (INADDR_ANY), and starts listening
 * for incoming connections with a maximum backlog queue size (SOMAXCONN).
 * Enters a loop that waits for incoming connections using `select` with a short timeout (1 second).
 * When a new connection is detected on the listening socket, it accepts the connection,
 * retrieves the client's IP address and port, prints this information, and spawns a new detached
 * thread running `handle_client_connection` to manage communication with that specific client.
 * The loop continues as long as the `keep_running_lb` flag is true (set to false by the signal handler).
 * Handles potential errors during socket operations (socket, setsockopt, bind, listen), accept, select,
 * and thread creation.
 * If `select` is interrupted by a signal (EINTR), it checks the `keep_running_lb` flag again.
 * If `accept` fails due to running out of file descriptors (EMFILE or ENFILE), it sets `keep_running_lb`
 * to false to initiate shutdown.
 * Upon exiting the loop (e.g., due to a signal setting `keep_running_lb` to false or a critical error),
 * it closes the listening socket and prints shutdown messages.
 *
 * @param argc Argument count (unused).
 * @param argv Argument vector (unused).
 * @return int Returns 0 on successful shutdown, 1 if critical errors occur during initialization
 * (socket creation, bind, listen).
 */
int main(void) // void parameter list indicates no command-line arguments are expected by main itself
{
    // --- Signal Handling Setup ---
    // Structure to define signal handling actions.
    struct sigaction sa;
    // Zero out the structure.
    memset(&sa, 0, sizeof(sa));
    // Set the handler function for the signals.
    sa.sa_handler = handle_signal_lb;
    // Register the handler for SIGINT (Ctrl+C).
    sigaction(SIGINT, &sa, NULL);
    // Register the handler for SIGTERM (termination signal).
    sigaction(SIGTERM, &sa, NULL);

    // Ignore SIGPIPE signals. SIGPIPE occurs when writing to a socket whose read end has been closed.
    // Ignoring it prevents the program from terminating; the write call will instead return an error (EPIPE).
    signal(SIGPIPE, SIG_IGN);

    // --- Socket Initialization ---
    // Socket descriptor for listening for incoming client connections.
    SOCKET listen_sock_lb = INVALID_SOCKET;
    // Socket descriptor for an accepted client connection.
    SOCKET client_sock_lb = INVALID_SOCKET;
    // Address structures for the load balancer (server) and the connecting client.
    struct sockaddr_in lb_addr, client_addr;
    // Variable to store the size of the client address structure, needed for accept().
    socklen_t client_addr_len = sizeof(client_addr);

    // Create the listening socket (IPv4, TCP).
    listen_sock_lb = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    // Check for socket creation failure.
    if (listen_sock_lb == INVALID_SOCKET)
    {
        print_socket_error("LB socket creation failed");
        return 1; // Exit with error code 1
    }

    // --- Configure Listening Socket ---
    // Set socket option to allow reuse of the local address (port).
    // This is useful to avoid "Address already in use" errors upon restarting the server quickly.
    int opt = 1; // Option value (1 means enable).
    if (setsockopt(listen_sock_lb, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0)
    {
        // Print error if setsockopt fails (non-critical, so we just print and continue).
        print_socket_error("LB setsockopt(SO_REUSEADDR) failed");
    }

    // --- Bind Socket ---
    // Zero out the load balancer address structure.
    memset(&lb_addr, 0, sizeof(lb_addr));
    // Set address family to IPv4.
    lb_addr.sin_family = AF_INET;
    // Set IP address to INADDR_ANY, meaning listen on all available network interfaces.
    // htonl converts host byte order to network byte order (long).
    lb_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    // Set the port number from the constant LB_PORT (defined in common.h).
    // htons converts host byte order to network byte order (short).
    lb_addr.sin_port = htons(LB_PORT);

    // Bind the socket to the specified address and port.
    if (bind(listen_sock_lb, (struct sockaddr *)&lb_addr, sizeof(lb_addr)) == SOCKET_ERROR)
    {
        // Print error if bind fails (critical error).
        print_socket_error("LB bind failed");
        // Close the socket before exiting.
        close_socket(listen_sock_lb);
        return 1; // Exit with error code 1
    }

    // --- Listen for Connections ---
    // Put the socket into listening mode to accept incoming connections.
    // SOMAXCONN is a system-defined constant for the maximum backlog queue size.
    if (listen(listen_sock_lb, SOMAXCONN) == SOCKET_ERROR)
    {
        // Print error if listen fails (critical error).
        print_socket_error("LB listen failed");
        // Close the socket before exiting.
        close_socket(listen_sock_lb);
        return 1; // Exit with error code 1
    }

    // Log that the load balancer is ready and listening.
    std::cout << "[LB] Load Balancer listening on port " << LB_PORT << "..." << std::endl;

    // --- Main Accept Loop ---
    // Loop continues as long as the keep_running_lb flag is true (1).
    while (keep_running_lb)
    {
        // Set of file descriptors to monitor for reading.
        fd_set read_fds;
        // Clear the set.
        FD_ZERO(&read_fds);
        // Add the listening socket to the set.
        FD_SET(listen_sock_lb, &read_fds);

        // Timeout structure for select().
        struct timeval timeout;
        // Set timeout to 1 second.
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;

        // Use select() to wait for activity on the listening socket or until the timeout expires.
        // select() monitors file descriptors for readiness (read, write, except).
        // listen_sock_lb + 1 is the highest file descriptor number plus one.
        // We only care about readability (read_fds). Write and except sets are NULL.
        int activity = select(listen_sock_lb + 1, &read_fds, NULL, NULL, &timeout);

        // Check the return value of select().
        if (activity < 0)
        {
            // If select() was interrupted by a signal (e.g., SIGINT handled by handle_signal_lb).
            if (errno == EINTR)
            {
                // Log the interruption and continue the loop to re-check the keep_running_lb flag.
                std::cout << "[LB] Select interrupted, checking keep_running_lb..." << std::endl;
                continue; // Check the while condition again.
            }
            // For any other select error.
            else
            {
                // Print the socket error.
                print_socket_error("LB select failed");
                // Break out of the loop to shut down.
                break;
            }
        }

        // If activity is 0, select() timed out, meaning no connection arrived within 1 second.
        if (activity == 0)
        {
            // Continue the loop to call select() again.
            continue;
        }

        // If select() returned > 0, check if the listening socket is the one with activity.
        // FD_ISSET checks if a specific descriptor is part of the set returned by select().
        if (FD_ISSET(listen_sock_lb, &read_fds))
        {
            // --- Accept New Connection ---
            // Accept the incoming connection. accept() blocks if no connection is pending.
            // It returns a new socket descriptor for the client connection.
            // client_addr will be filled with the client's address information.
            client_sock_lb = accept(listen_sock_lb, (struct sockaddr *)&client_addr, &client_addr_len);

            // Check if accept() failed.
            if (client_sock_lb == INVALID_SOCKET)
            {
                // Check if we are still supposed to be running (shutdown might have been triggered
                // between select returning and accept being called).
                if (keep_running_lb)
                {
                    // Print the error if accept failed while we should be running.
                    print_socket_error("LB accept failed");
                }
                // Check for specific errors indicating resource exhaustion (too many open files).
                if (errno == EMFILE || errno == ENFILE)
                {
                    // Log the critical error.
                    std::cerr << "[LB] Ran out of file descriptors. Stopping accept loop." << std::endl;
                    // Set the flag to stop the loop gracefully.
                    keep_running_lb = 0;
                }
                // Continue to the next loop iteration (or exit if keep_running_lb is now 0).
                continue;
            }

            // --- Handle New Connection ---
            // Buffer to store the client's IP address string. INET_ADDRSTRLEN is max length for IPv4 addr string.
            char client_ip[INET_ADDRSTRLEN];
            // Convert the binary client IP address (in client_addr.sin_addr) to a human-readable string.
            inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);
            // Log the accepted connection details. ntohs converts network byte order port to host byte order.
            std::cout << "[LB] Accepted connection from client " << client_ip << ":"
                      << ntohs(client_addr.sin_port) << " on socket " << client_sock_lb << std::endl;

            // --- Create Handler Thread ---
            try
            {
                // Create a new thread to handle this client connection.
                // Pass the client socket and IP address to the handler function.
                // .detach() allows the main loop to continue immediately without waiting for the thread to finish.
                // The detached thread is responsible for its own resources (like closing the client socket).
                std::thread(handle_client_connection, client_sock_lb, std::string(client_ip)).detach();
            }
            // Catch potential system errors during thread creation (e.g., resource limits).
            catch (const std::system_error &e)
            {
                // Log the thread creation error.
                std::cerr << "Error creating client handler thread: " << e.what() << " (errno: " << e.code().value() << ")" << std::endl;
                // Close the client socket as no thread will handle it.
                close_socket(client_sock_lb);
                // Continue the main loop.
            }
        } // end if FD_ISSET
    } // end while(keep_running_lb)

    // --- Shutdown Sequence ---
    // The loop has exited, either due to a signal or an error.
    std::cout << "\n[LB] Shutting down listener..." << std::endl;

    // Check if the listening socket is still valid (it might have been closed earlier on error).
    if (listen_sock_lb != INVALID_SOCKET)
    {
        // Close the main listening socket.
        close_socket(listen_sock_lb);
        // Mark the socket as invalid.
        listen_sock_lb = INVALID_SOCKET;
    }

    // Log completion of shutdown.
    std::cout << "[LB] Shutdown complete." << std::endl;
    // Return 0 indicating successful execution and shutdown.
    return 0;
}