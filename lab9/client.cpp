#include "common.h"
#include <string>
#include <chrono>
#include <cstdlib>

int main(int argc, char *argv[])
{
    int num_requests = 15;    // Default number of requests
    bool attack_mode = false; // Flag for DoS attack simulation
    std::string lb_host = SERVER_HOST; // Default from common.h

    // Parse command-line arguments
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <load_balancer_ip> [number_of_requests | --attack]" << std::endl;
        std::cerr << "Using default LB host: " << lb_host << std::endl;
        // Optionally exit(1) if default shouldn't be allowed
        exit(1);
    } else {
        lb_host = argv[1]; // First argument is the load balancer IP
        std::cout << "[Client] Target Load Balancer IP: " << lb_host << std::endl;

        // Check for optional second argument (number of requests or --attack)
        if (argc > 2) {
            std::string arg = argv[2];
            if (arg == "--attack") {
                attack_mode = true;
                num_requests = 1000; // Large number for attack mode
            } else {
                try {
                    num_requests = std::stoi(arg);
                    if (num_requests <= 0) {
                        std::cerr << "Error: Number of requests must be positive." << std::endl;
                        return 1;
                    }
                } catch (const std::invalid_argument &e) {
                    std::cerr << "Error: Invalid number format for requests." << std::endl;
                    std::cerr << "Usage: " << argv[0] << " <load_balancer_ip> [number_of_requests | --attack]" << std::endl;
                    return 1;
                } catch (const std::out_of_range &e) {
                    std::cerr << "Error: Number of requests out of range." << std::endl;
                    return 1;
                }
            }
        }
    }

    // Rest of the code remains unchanged
    for (int i = 1; i <= num_requests; ++i) {
        SOCKET client_sock = INVALID_SOCKET;
        struct sockaddr_in lb_addr;
        char buffer[BUFFER_SIZE];

        // 1. Create socket
        client_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        // ... (error check) ...

        // 2. Prepare Load Balancer address using lb_host
        memset(&lb_addr, 0, sizeof(lb_addr));
        lb_addr.sin_family = AF_INET;
        lb_addr.sin_port = htons(LB_PORT);
        if (inet_pton(AF_INET, lb_host.c_str(), &lb_addr.sin_addr) <= 0) {
            print_socket_error("Client invalid LB address format");
            close_socket(client_sock);
            std::this_thread::sleep_for(std::chrono::seconds(1));
            continue;
        }

        // 3. Connect to Load Balancer
        if (connect(client_sock, (struct sockaddr*)&lb_addr, sizeof(lb_addr)) == SOCKET_ERROR) {
            if (errno == ECONNREFUSED) {
                std::cerr << "[Client] Connection refused. Is the Load Balancer running on "
                          << lb_host << ":" << LB_PORT << "?" << std::endl;
            } else {
                print_socket_error(("Client connect to LB (" + lb_host + ") failed").c_str());
            }
            close_socket(client_sock);
            std::this_thread::sleep_for(std::chrono::seconds(2));
            continue;
        }

        std::cout << "[Client] Connected to Load Balancer (socket: " << client_sock << ")." << std::endl;

        // 4. Send request number
        std::string request_msg = std::to_string(i);
        ssize_t bytes_sent = send(client_sock, request_msg.c_str(), request_msg.length(), 0);

        if (bytes_sent == SOCKET_ERROR) {
            print_socket_error("Client send failed");
            close_socket(client_sock);
            continue;
        }
        if (bytes_sent < (ssize_t)request_msg.length()) {
            std::cerr << "[Client] Warning: Partial send occurred." << std::endl;
        }

        std::cout << "[Client] Sent request: \"" << request_msg << "\"" << std::endl;

        // 5. Receive response
        memset(buffer, 0, BUFFER_SIZE);
        ssize_t bytes_received = recv(client_sock, buffer, BUFFER_SIZE - 1, 0);

        if (bytes_received < 0) {
            print_socket_error("Client recv failed");
        } else if (bytes_received == 0) {
            std::cout << "[Client] Connection closed by Load Balancer prematurely." << std::endl;
        } else {
            buffer[bytes_received] = '\0';
            std::cout << "[Client] Received response: \"" << buffer << "\"" << std::endl;
        }

        // 6. Close connection
        close_socket(client_sock);
        std::cout << "[Client] Connection closed (socket: " << client_sock << ")." << std::endl
                  << std::endl;

        // Delay between requests
        if (attack_mode) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        } else {
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
        }
    }

    return 0;
}