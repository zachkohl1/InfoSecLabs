#ifndef CLIENT_HPP
#define CLIENT_HPP

#include <string>           // For std::string
#include <array>
#include <sys/socket.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include "aes.hpp"          // Assuming this provides encrypt/decrypt functions

#define AES_KEY_SIZE 32
#define BUFFER_SIZE 256
#define DEFAULT_SERVER_IP "127.0.0.1"
#define DEFAULT_SERVER_PORT 8081
#define DEFAULT_VERSION "1.0.0"

// Defines a class for a client that connects to a server, communicates securely, and checks for updates
class Client {
    public:
        // Constructor: Initializes client with server IP, port, and version (defaults provided)
        Client(const std::string &server_ip = DEFAULT_SERVER_IP, int server_port = DEFAULT_SERVER_PORT,
               const std::string &version = DEFAULT_VERSION);
        // Destructor: Cleans up socket and ECDSA key resources
        ~Client(void);
        // Sets up the socket and connects to the server
        void initialize(void);
        // Main loop: Checks for updates and handles server communication
        void run(void);
        // Returns whether an update is available
        bool isUpdateAvailable(void) const { return update_available_; }
    
    private:
        // Handles user input and server communication
        void communicateWithServer(void);
        // Checks the updates directory for a valid new version
        bool checkForUpdates(void);
        // Verifies the signature of an update file using ECDSA
        bool verifySignature(const std::string& file_path, const std::string& signature_path);
        // Replaces the current executable with the updated version
        void performUpdate(const std::string& new_executable);
        // Encrypts a message with AES and sends it to the server
        int encryptAndSend(const std::string &message);
        // Receives and decrypts a response from the server
        std::string receiveAndDecrypt(void);
    
        int sock_;                                    // Socket for server communication
        std::string server_ip_;                       // Server IP address
        int server_port_;                             // Server port number
        std::string version_;                         // Client version (e.g., "1.0.0")
        struct sockaddr_in server_addr_;              // Server address structure
        std::array<unsigned char, AES_KEY_SIZE> key_; // AES encryption key (32 bytes)
        bool update_available_;                       // Flag indicating if an update is available
        EC_KEY* ecdsa_key_;                           // ECDSA public key for verifying signatures
    };

#endif // CLIENT_HPP