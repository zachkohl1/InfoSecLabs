#ifndef CLIENT_HPP
#define CLIENT_HPP

#include <string>
#include <array>
#include <sys/socket.h>
#include <netinet/in.h>
#include <openssl/ecdsa.h>
#include <iostream>
#include <cstring>
#include <unistd.h>
#include <limits>
#include <arpa/inet.h>
#include <openssl/rand.h>
#include <dirent.h>
#include <openssl/sha.h>
#include <fstream>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ecdsa.h>
#include <vector>
#include <sys/stat.h>
#include "aes.hpp"
#include "srp.hpp"
using namespace std;

#define AES_KEY_SIZE 32
#define BUFFER_SIZE 1024
#define DEFAULT_SERVER_IP "127.0.0.1"
#define DEFAULT_SERVER_PORT 8081
#define DEFAULT_VERSION "1.0.0"
#define UPDATES_DIR "../updates"
#define ACTIVE_DIR "./active"

// Defines a class for a client that connects to a server, communicates securely, and checks for updates
class Client
{
public:
    // Constructor: Initializes client with server IP, port, and version (defaults provided)
    Client(const std::string &server_ip = DEFAULT_SERVER_IP, int server_port = DEFAULT_SERVER_PORT,
           const std::string &version = DEFAULT_VERSION) : server_ip_(server_ip), server_port_(server_port), version_(version)
    {
        // Hardcoded AES key (replace in production)
        const unsigned char temp[AES_KEY_SIZE + 1] = "01234567890123456789012345678901";
        std::copy(temp, temp + AES_KEY_SIZE, key_.begin());

        // Load ECDSA public key
        FILE *pub_key_file = fopen("../client_public.pem", "r");
        if (!pub_key_file)
        {
            throw std::runtime_error("Failed to open ../client_public.pem");
        }
        ecdsa_key_ = PEM_read_EC_PUBKEY(pub_key_file, nullptr, nullptr, nullptr);
        fclose(pub_key_file);
        if (!ecdsa_key_)
        {
            throw std::runtime_error("Failed to load ECDSA public key");
        }
    }
    // Destructor: Cleans up socket and ECDSA key resources
    ~Client(void)
    {
        if (sock_ >= 0)
            close(sock_);
        if (ecdsa_key_)
            EC_KEY_free(ecdsa_key_);
    }
    // Sets up the socket and connects to the server
    void initialize(void)
    {
        std::cout << "Create stream socket\n";
        sock_ = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock_ < 0)
            throw std::runtime_error("Socket creation failed");

        std::cout << "Fill server address with host IP and port number\n";
        server_addr_.sin_family = AF_INET;
        if (inet_pton(AF_INET, server_ip_.c_str(), &server_addr_.sin_addr) <= 0)
            throw std::runtime_error("Invalid server IP address");

        server_addr_.sin_port = htons(server_port_);

        std::cout << "Connect to server\n";
        if (connect(sock_, (struct sockaddr *)&server_addr_, sizeof(server_addr_)) < 0)
            throw std::runtime_error("Connection failed");
        std::cout << "Connected successfully\n";

        // Perform SRP authentication
        if (!performSRPAuthentication())
            throw std::runtime_error("SRP authentication failed");
    }

    // Main loop: Checks for updates and handles server communication
    void run(void)
    {
        std::cout << "Client Version: " << version_ << "\n";

        if (checkForUpdates())
        {
            std::cout << "An update is available.\nUpdate? (y/n): ";
            char choice;
            std::cin >> choice;
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

            if (choice == 'y' || choice == 'Y')
            {
                if (encryptAndSend("update") < 0)
                {
                    std::cerr << "Failed to notify server of update\n";
                    exit(1);
                }
                std::string response = receiveAndDecrypt();
                std::cout << "Server response: " << response << "\n";

                if (response == "Update OK")
                {
                    std::cout << "Client will now exit for update...\n";
                    close(sock_);
                    sleep(3);
                    execlp("./client", "./client", nullptr);
                }
            }
            else
            {
                std::cout << "Update skipped.\n";
            }
        }
        else
        {
            std::cout << "No updates found.\n";
        }

        communicateWithServer();
    }
    // Returns whether an update is available
    bool isUpdateAvailable(void) const { return update_available_; }

private:
    // Handles user input and server communication
    void communicateWithServer(void)
    {
        std::string account_number;
        std::cout << "Enter account number: ";
        std::getline(std::cin, account_number);

        if (encryptAndSend(account_number) < 0)
        {
            std::cerr << "Failed to send account number\n";
            return;
        }
        std::string response = receiveAndDecrypt();
        std::cout << "Server response: " << response << "\n";

        // Adjust prompt based on version
        std::string prompt = "Enter command (withdraw <amount>, deposit <amount>, balance, exit ";
        if (version_ >= "2.0.0")
        {
            prompt += ", loan <amount>, repay <amount>";
        }
        prompt += "): ";

        while (true)
        {
            std::cout << prompt;
            std::string command;
            std::getline(std::cin, command);

            if (encryptAndSend(command) < 0)
            {
                std::cerr << "Failed to send command\n";
                return;
            }

            response = receiveAndDecrypt();
            std::cout << "Server response: " << response << "\n";

            if (command == "exit")
            {
                std::cout << "Exiting...\n";
                break;
            }
        }
    }

    // Checks the updates directory for a valid new version
    bool checkForUpdates(void)
    {
        if (version_ == "2.0.0")
            return false;

        DIR *dir = opendir("../updates");
        if (!dir)
        {
            std::cerr << "Failed to open ./updates directory: " << strerror(errno) << "\n";
            return false;
        }

        struct dirent *entry;
        while ((entry = readdir(dir)) != nullptr)
        {
            std::string filename = entry->d_name;
            if (filename.find("client_v2") != std::string::npos && filename != "client_v2.sig") // Check for v2 update
            {
                std::string file_path = std::string("../updates/") + filename;
                std::string sig_path = file_path + ".sig";
                if (verifySignature(file_path, sig_path))
                {
                    update_available_ = true;
                    closedir(dir);
                    return true;
                }
            }
        }
        closedir(dir);
        std::cout << "No valid updates found.\n";
        return false;
    }
    // Verifies the signature of an update file using ECDSA
    bool verifySignature(const std::string &file_path, const std::string &signature_path)
    {
        // Read the file content
        std::ifstream file(file_path, std::ios::binary);
        if (!file)
        {
            std::cerr << "Failed to open file: " << file_path << "\n";
            return false;
        }
        std::vector<unsigned char> file_content((std::istreambuf_iterator<char>(file)),
                                                std::istreambuf_iterator<char>());
        file.close();

        // Compute SHA-256 hash of the file
        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256(&file_content[0], file_content.size(), hash);

        // Read the signature
        std::ifstream sig_file(signature_path, std::ios::binary);
        if (!sig_file)
        {
            std::cerr << "Failed to open signature file: " << signature_path << "\n";
            return false;
        }
        std::vector<unsigned char> signature((std::istreambuf_iterator<char>(sig_file)),
                                             std::istreambuf_iterator<char>());
        sig_file.close();

        // Verify the signature using ECDSA
        int verify_result = ECDSA_verify(0, hash, SHA256_DIGEST_LENGTH,
                                         signature.data(), signature.size(), ecdsa_key_);
        if (verify_result == 1)
        {
            std::cout << "Signature verification passed for " << file_path << "\n";
            return true;
        }
        else if (verify_result == 0)
        {
            std::cerr << "Signature verification failed: signature does not match\n";
        }
        else
        {
            std::cerr << "Signature verification error: " << verify_result << "\n";
        }
        return false;
    }
    // Encrypts a message with AES and sends it to the server
    int encryptAndSend(const std::string &message)
    {
        unsigned char buffer[BUFFER_SIZE];
        unsigned char iv[EVP_MAX_IV_LENGTH];

        RAND_bytes(iv, EVP_MAX_IV_LENGTH);
        int encrypted_length = encrypt(
            reinterpret_cast<const unsigned char *>(message.c_str()),
            message.length(),
            key_.data(),
            iv,
            buffer + EVP_MAX_IV_LENGTH);
        if (encrypted_length < 0)
        {
            return -1;
        }

        std::memcpy(buffer, iv, EVP_MAX_IV_LENGTH);
        int total_length = encrypted_length + EVP_MAX_IV_LENGTH;

        if (send(sock_, buffer, total_length, 0) < 0)
        {
            return -1;
        }
        return total_length;
    }
    // Receives and decrypts a response from the server
    std::string receiveAndDecrypt(void)
    {
        unsigned char buffer[BUFFER_SIZE];
        unsigned char iv[EVP_MAX_IV_LENGTH];

        int n = read(sock_, buffer, BUFFER_SIZE);
        if (n < 0)
        {
            throw std::runtime_error("Error reading from socket");
        }

        std::memcpy(iv, buffer, EVP_MAX_IV_LENGTH);
        int decrypted_length = decrypt(
            buffer + EVP_MAX_IV_LENGTH,
            n - EVP_MAX_IV_LENGTH,
            key_.data(),
            iv,
            buffer);
        if (decrypted_length < 0)
        {
            throw std::runtime_error("Decryption failed");
        }

        buffer[decrypted_length] = '\0';
        return std::string(reinterpret_cast<char *>(buffer));
    }
    bool performSRPAuthentication()
    {
        // Enter a user name and password to compare with data base
        std::string username, password;
        std::cout << "Enter username: ";
        std::getline(std::cin, username);
        std::cout << "Enter password: ";
        std::getline(std::cin, password);

        // Initialize SRP client -  
        // 1. Stores the username, 
        // 2. Generates a random private key 'a' (256 bits), 
        // 3. Computes a hash of username:password for later use in deriving x, 
        // 4. Computes the client's public key A = g^a % N
        if (!srp_.clientInit(username, password))
        {
            std::cerr << "SRP client initialization failed\n";
            return false;
        }

        std::string A_hex = srp_.clientStep1();         // Get the public key A in hex format
        std::string auth_msg = "SRP_AUTH:" + username + ":" + A_hex;

        // Step 1. Send client public key 'A' to the server
        if (encryptAndSend(auth_msg) < 0)
        {
            std::cerr << "Failed to send SRP auth message\n";
            return false;
        }

        // Server responds with salt and B
        std::string salt_and_B = receiveAndDecrypt();
        if (salt_and_B.empty() || salt_and_B.find(':') == std::string::npos)
        {
            std::cerr << "Received empty or invalid SRP response\n";
            return false;
        }
        if (salt_and_B.empty())
        {
            std::cerr << "Received empty or invalid SRP response\n";
            return false;
        }

        // Step 2: Process salt and B, compute M1
        /*
            * The function performs the following calculations:
            * 1. Parses salt and B from the input string.
            * 2. Converts B from hex to BIGNUM and validates it (B % N != 0).
            * 3. Computes u = H(A | B), where H is SHA256 and A, B are padded to the same length.
            * 4. Computes x = H(salt | H(username | ":" | password)). (Uses precomputed identity_hash_ for H(username | ":" | password)).
            * 5. Computes the client's session key S = (B - k * g^x) ^ (a + u * x) % N.
            * 6. Computes the final shared key K = H(S).
            * 7. Computes the client proof M1 = H(H(N) xor H(g) | H(username) | salt | A | B | K).
        */
        if (!srp_.clientStep2(salt_and_B))
        {
            std::cerr << "SRP client step 2 failed\n";
            return false;
        }

        // Send M1 proof to server
        std::string M1 = srp_.clientGetProof();
        if (encryptAndSend("SRP_M1:" + M1) < 0)
        {
            std::cerr << "Failed to send SRP M1 proof\n";
            return false;
        }

        // Receive server proof 'M2'
        std::string server_response = receiveAndDecrypt();
        if (server_response.find("SRP_M2:") != 0)
        {
            std::cerr << "Invalid SRP M2 response from server\n";
            return false;
        }

        // Verify the server proof
        std::string M2 = server_response.substr(7);
        if (!srp_.clientVerifyServerProof(M2))
        {
            std::cerr << "SRP authentication failed\n";
            return false;
        }

        std::cout << "SRP authentication successful\n";
        return true;
    }

    int sock_;                                    // Socket for server communication
    std::string server_ip_;                       // Server IP address
    int server_port_;                             // Server port number
    std::string version_;                         // Client version (e.g., "1.0.0")
    struct sockaddr_in server_addr_;              // Server address structure
    std::array<unsigned char, AES_KEY_SIZE> key_; // AES encryption key (32 bytes)
    bool update_available_;                       // Flag indicating if an update is available
    EC_KEY *ecdsa_key_;                           // ECDSA public key for verifying signatures
    SRP srp_;                                     // SRP object for authentication
};

#endif // CLIENT_HPP