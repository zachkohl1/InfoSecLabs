#include "common.h"
#include <string>
#include <chrono>  // For sleep
#include <cstdlib> // For stoi, exit

/**
 * @brief Main entry point for the client application.
 *
 * This function simulates a client connecting to a load balancer. It can operate in two modes:
 * 1. Normal Mode: Sends a specified number of requests (default 15) to the load balancer
 *    with a delay between each request.
 * 2. Attack Mode: Activated by the `--attack` command-line flag. Sends a large number
 *    of requests (1000) with minimal delay to simulate a Denial-of-Service (DoS) attack.
 *
 * The client performs the following steps in a loop for each request:
 * 1. Creates a TCP socket.
 * 2. Prepares the address structure for the load balancer (defined by SERVER_HOST and LB_PORT).
 * 3. Connects to the load balancer.
 * 4. Sends the current request number (1 to num_requests) as a string message.
 * 5. Waits for and receives a response message from the load balancer.
 * 6. Prints the sent request and received response to the console.
 * 7. Closes the socket connection.
 * 8. Pauses for a short duration before the next request (duration depends on the mode).
 *
 * Includes error handling for command-line argument parsing and socket operations
 * (creation, connection, send, receive). Prints error messages to stderr and may exit
 * or retry connection attempts after a delay.
 *
 * @param argc The number of command-line arguments.
 * @param argv An array of C-style strings representing the command-line arguments.
 *             Expected arguments:
 *             - (Optional) A positive integer specifying the number of requests.
 *             - (Optional) "--attack" to enable DoS simulation mode.
 * @return int Returns 0 on successful completion of all requests, or 1 if an error occurs
 *             during argument parsing or initial setup. Socket errors during the loop
 *             are logged but may not cause the program to exit immediately.
 */
int main(int argc, char *argv[])
{
    int num_requests = 15;    // Default number of requests
    bool attack_mode = false; // Flag for DoS attack simulation

    // Parse command-line arguments
    for (int i = 1; i < argc; ++i)
    {
        std::string arg = argv[i];
        if (arg == "--attack")
        {
            attack_mode = true;
            num_requests = 1000; // Large number for attack mode
        }
        else
        {
            try
            {
                num_requests = std::stoi(arg);
                if (num_requests <= 0)
                {
                    std::cerr << "Error: Number of requests must be positive." << std::endl;
                    return 1;
                }
            }
            catch (const std::invalid_argument &e)
            {
                std::cerr << "Error: Invalid number format for requests." << std::endl;
                std::cerr << "Usage: " << argv[0] << " [number_of_requests | --attack]" << std::endl;
                return 1;
            }
            catch (const std::out_of_range &e)
            {
                std::cerr << "Error: Number of requests out of range." << std::endl;
                return 1;
            }
        }
    }

    for (int i = 1; i <= num_requests; ++i)
    {
        SOCKET client_sock = INVALID_SOCKET;
        struct sockaddr_in lb_addr;
        char buffer[BUFFER_SIZE];

        // 1. Create socket
        client_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (client_sock == INVALID_SOCKET)
        {
            print_socket_error("Client socket creation failed");
            std::this_thread::sleep_for(std::chrono::seconds(1));
            continue;
        }

        // 2. Prepare Load Balancer address
        memset(&lb_addr, 0, sizeof(lb_addr));
        lb_addr.sin_family = AF_INET;
        lb_addr.sin_port = htons(LB_PORT);
        if (inet_pton(AF_INET, SERVER_HOST.c_str(), &lb_addr.sin_addr) <= 0)
        {
            print_socket_error("Client invalid LB address format");
            close_socket(client_sock);
            std::this_thread::sleep_for(std::chrono::seconds(1));
            continue;
        }

        // 3. Connect to Load Balancer
        if (connect(client_sock, (struct sockaddr *)&lb_addr, sizeof(lb_addr)) == SOCKET_ERROR)
        {
            if (errno == ECONNREFUSED)
            {
                std::cerr << "[Client] Connection refused. Is the Load Balancer running on "
                          << SERVER_HOST << ":" << LB_PORT << "?" << std::endl;
            }
            else
            {
                print_socket_error("Client connect to LB failed");
            }
            close_socket(client_sock);
            std::this_thread::sleep_for(std::chrono::seconds(2));
            continue;
        }

        std::cout << "[Client] Connected to Load Balancer (socket: " << client_sock << ")." << std::endl;

        // 4. Send request number
        std::string request_msg = std::to_string(i);
        ssize_t bytes_sent = send(client_sock, request_msg.c_str(), request_msg.length(), 0);

        if (bytes_sent == SOCKET_ERROR)
        {
            print_socket_error("Client send failed");
            close_socket(client_sock);
            continue;
        }
        if (bytes_sent < (ssize_t)request_msg.length())
        {
            std::cerr << "[Client] Warning: Partial send occurred." << std::endl;
        }

        std::cout << "[Client] Sent request: \"" << request_msg << "\"" << std::endl;

        // 5. Receive response
        memset(buffer, 0, BUFFER_SIZE);
        ssize_t bytes_received = recv(client_sock, buffer, BUFFER_SIZE - 1, 0);

        if (bytes_received < 0)
        {
            print_socket_error("Client recv failed");
        }
        else if (bytes_received == 0)
        {
            std::cout << "[Client] Connection closed by Load Balancer prematurely." << std::endl;
        }
        else
        {
            buffer[bytes_received] = '\0';
            std::cout << "[Client] Received response: \"" << buffer << "\"" << std::endl;
        }

        // 6. Close connection
        close_socket(client_sock);
        std::cout << "[Client] Connection closed (socket: " << client_sock << ")." << std::endl
                  << std::endl;

        // Delay between requests: minimal in attack mode, normal otherwise
        if (attack_mode)
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(10)); // Fast requests for DoS
        }
        else
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(500)); // Normal pace
        }
    }

    return 0;
}