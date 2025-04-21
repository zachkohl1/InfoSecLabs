#ifndef COMMON_H
#define COMMON_H

#include <string>
#include <vector>
#include <stdexcept> // For runtime_error
#include <map>       // For tracking client connections
#include <chrono>    // For time-based rate limiting

// POSIX Includes
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>     // For close()
#include <sys/errno.h>  // For errno
#include <sys/select.h> // For select()
#include <netdb.h>      // For gethostbyname etc. (though inet_pton is preferred)

#include <iostream>
#include <cstring> // For memset, strerror
#include <thread>  // For std::thread
#include <mutex>   // For std::mutex
#include <atomic>  // For std::atomic
#include <csignal> // For sig_atomic_t

// --- Configuration ---
#define NUM_SERVERS 5 // Number of backend servers
#define LB_PORT 8080 // Port the Load Balancer listens on
#define BASE_SERVER_PORT 9000 // Starting port for backend servers
#define BUFFER_SIZE 1024 // Max message size

const std::string SERVER_HOST = "172.27.11.127"; // Assuming all run on localhost

// DoS Detection Parameters
const int MAX_CONNECTIONS_PER_IP = 10;         // Max connections allowed per IP in the time window
const std::chrono::seconds RATE_WINDOW(5);     // Time window for rate limiting (5 seconds)
const std::chrono::seconds BLOCK_DURATION(30); // Duration to block an attacker

// Structure to track client connection rates
struct ClientConnectionInfo
{
    int connection_count;
    std::chrono::system_clock::time_point last_reset;
    bool is_blocked;
    std::chrono::system_clock::time_point block_until;

    ClientConnectionInfo() : connection_count(0), last_reset(std::chrono::system_clock::now()),
                             is_blocked(false), block_until(std::chrono::system_clock::now()) {}
};

// --- POSIX Specific Type Definitions ---
using SOCKET = int;
const int INVALID_SOCKET = -1;
const int SOCKET_ERROR = -1;

// Macro for closing sockets
#define close_socket(s) close(s)

// Helper function to get server addresses
inline std::vector<std::pair<std::string, int>> getServerAddresses()
{
    std::vector<std::pair<std::string, int>> addresses;
    for (int i = 0; i < NUM_SERVERS; ++i)
    {
        addresses.push_back({SERVER_HOST, BASE_SERVER_PORT + i});
    }
    return addresses;
}

// Helper for printing socket errors using perror
inline void print_socket_error(const char *context)
{
    std::string error_message = std::string(context) + ": " + strerror(errno);
    perror(error_message.c_str());
}

#endif // COMMON_H