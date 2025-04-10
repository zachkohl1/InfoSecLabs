#include "client_v2.hpp"
#include <iostream>
#include <cstring>
#include <unistd.h>
#include <limits>
#include <arpa/inet.h>
#include <dirent.h>
#include <openssl/sha.h>
#include <fstream>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include "aes.hpp"
#include <vector>
#include <sys/stat.h>
#include <fcntl.h>

#define ACTIVE_DIR "./active"
/**
 * @brief Constructs a new Client object
 * 
 * Initializes a client with server connection details and cryptographic keys.
 * The constructor sets up a hardcoded AES key (which should be replaced in production)
 * and loads the client's ECDSA public key from a PEM file.
 * 
 * @param server_ip The IP address of the server to connect to
 * @param server_port The port number of the server
 * @param version The client version string
 * 
 * @throws std::runtime_error If the client_public.pem file cannot be opened or the ECDSA key cannot be loaded
 * 
 * @note The AES key is hardcoded in this implementation;
 */
Client::Client(const std::string &server_ip, int server_port, const std::string &version)
    : sock_(-1), server_ip_(server_ip), server_port_(server_port), version_(version),
      update_available_(false), ecdsa_key_(nullptr) {
    const unsigned char temp[AES_KEY_SIZE + 1] = "01234567890123456789012345678901";
    std::copy(temp, temp + AES_KEY_SIZE, key_.begin());

    FILE* pub_key_file = fopen("../client_public.pem", "r");
    if (!pub_key_file) throw std::runtime_error("Failed to open ../client_public.pem");
    ecdsa_key_ = PEM_read_EC_PUBKEY(pub_key_file, nullptr, nullptr, nullptr);
    fclose(pub_key_file);
    if (!ecdsa_key_) throw std::runtime_error("Failed to load ECDSA public key for client");
}

Client::~Client() {
    if (sock_ >= 0) close(sock_);
    if (ecdsa_key_) EC_KEY_free(ecdsa_key_);
}

void Client::initialize() {
    sock_ = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock_ < 0) throw std::runtime_error("Socket creation failed");

    server_addr_.sin_family = AF_INET;
    if (inet_pton(AF_INET, server_ip_.c_str(), &server_addr_.sin_addr) <= 0)
        throw std::runtime_error("Invalid server IP address");

    server_addr_.sin_port = htons(server_port_);

    if (connect(sock_, (struct sockaddr *)&server_addr_, sizeof(server_addr_)) < 0)
        throw std::runtime_error("Connection failed");
}

void Client::run() {
    std::cout << "Client Version: " << version_ << "\n";

    if (checkForUpdates()) {
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
            else
            {
                std::cout << "Notified server to update\n";
                // Wait for server confirmation
                std::string response = receiveAndDecrypt(); // <-- read server reply to account number
                std::cout << "Server response: " << response << "\n";

                if (response == "Update OK")
                {
                    std::cout << "Client will now exit for update...\n";
                    close(sock_);
                    sleep(1);
                    execlp("./client", "./client", nullptr);
                }
            }
        }
        else
        {
            std::cout << "Update skipped.\n";
        }
    }

    communicateWithServer();
}

void Client::communicateWithServer() {
    std::string account_number;
    std::cout << "Enter account number: ";
    std::getline(std::cin, account_number);

    encryptAndSend(account_number);
    std::string response = receiveAndDecrypt();         // <-- read server reply to account number
    std::cout << "Server response: " << response << "\n";

    while (true) {
        std::string command;
        std::cout << "Enter command (withdraw <amount>, deposit <amount>, loan <amount>, repay <amount>, balance, exit): ";
        std::getline(std::cin, command);

        if (encryptAndSend(command) < 0) {
            std::cerr << "Failed to send to server\n";
            return;
        }

        response = receiveAndDecrypt();                // <-- always read response after sending
        std::cout << "Server response: " << response << "\n";

        if (command == "exit") {
            std::cout << "Exiting...\n";
            break;
        }
    }
}

/**
 * @brief Checks for available client updates in the updates directory
 *
 * This function scans the directory specified by UPDATES_DIR for potential
 * update files containing "client2" in their filename (excluding signature files).
 * For each candidate file, it verifies the digital signature by checking the 
 * corresponding .sig file with the same base name.
 *
 * If a valid update is found (file exists and signature verification passes),
 * the update_available_ flag is set to true.
 *
 * @return true if a valid update file with verified signature is found,
 *         false if no updates are available or directory cannot be accessed
 * 
 * @note The function properly closes the directory handle before returning
 */
bool Client::checkForUpdates(void)
{
    if(version_ == "2.0.0")
        return false;

    DIR* dir = opendir(UPDATES_DIR);
    if (!dir) return false;

    struct dirent* entry;
    while ((entry = readdir(dir)) != nullptr)
    {
        std::string filename = entry->d_name;
        if (filename.find("client_v2") != std::string::npos && filename != "client_v2.sig")
        {
            std::string file_path = std::string(UPDATES_DIR) + "/" + filename;
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
    return false;
}

/**
 * @brief Verifies the digital signature of a file using ECDSA with SHA-256 hashing
 *
 * This method verifies whether a digital signature is valid for a given file.
 * It performs the following steps:
 * 1. Reads the content of the specified file
 * 2. Computes a SHA-256 hash of the file content
 * 3. Reads the signature from the signature file
 * 4. Verifies the signature against the hash using ECDSA
 *
 * @param file_path Path to the file whose signature needs to be verified
 * @param signature_path Path to the file containing the digital signature
 * @return true if the signature is valid for the file, false if the signature is invalid
 *         or if there was an error reading either file
 */
bool Client::verifySignature(const std::string& file_path, const std::string& signature_path)
{
    // Read the file content
    std::ifstream file(file_path, std::ios::binary);
    if (!file) return false;
    std::vector<unsigned char> file_content((std::istreambuf_iterator<char>(file)),
                                            std::istreambuf_iterator<char>());
    file.close();

    // Compute SHA-256 hash of the file
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(&file_content[0], file_content.size(), hash);

    // Read the signature
    std::ifstream sig_file(signature_path, std::ios::binary);
    if (!sig_file) return false;
    std::vector<unsigned char> signature((std::istreambuf_iterator<char>(sig_file)),
                                         std::istreambuf_iterator<char>());
    sig_file.close();

    // Verify the signature
    return ECDSA_verify(0, hash, SHA256_DIGEST_LENGTH, signature.data(), signature.size(), ecdsa_key_) == 1;
}

/**
 * @brief Replaces the current process with a new executable.
 * 
 * This function attempts to update the client by replacing the current process
 * with the specified executable using execv(). If successful, this function
 * never returns as the current process is replaced. If the update fails,
 * an error message is printed to stderr with the reason for failure.
 * 
 * @param new_executable The path to the new executable file
 * @note This function will terminate the current process if successful
 * @note No cleanup operations after this call will be executed if successful
 */
void Client::performUpdate(const std::string& new_executable)
{
    std::cout << "Restarting with updated client: " << new_executable << "...\n";
    close(sock_);
    char* args[] = {const_cast<char*>(new_executable.c_str()), nullptr};
    execv(new_executable.c_str(), args);
    std::cerr << "Restart failed: " << strerror(errno) << "\n";
}

/**
 * @brief Encrypts a message and sends it over the network.
 *
 * This function generates a random initialization vector (IV), encrypts the 
 * given message using the client's key and the IV, then sends both the IV 
 * and encrypted message over the socket connection.
 *
 * @param message The message to encrypt and send
 * @return Total length of data sent (IV + encrypted message) on success,
 *         -1 on encryption or sending failure
 */
int Client::encryptAndSend(const std::string &message)
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
    if (encrypted_length < 0) return -1;

    std::memcpy(buffer, iv, EVP_MAX_IV_LENGTH);
    int total_length = encrypted_length + EVP_MAX_IV_LENGTH;

    if (send(sock_, buffer, total_length, 0) < 0) return -1;
    return total_length;
}

/**
 * @brief Receives encrypted data from the socket and decrypts it
 * 
 * This method reads data from the socket, extracts the initialization vector (IV)
 * from the beginning of the received data, and then decrypts the remaining data
 * using the stored encryption key.
 * 
 * @return std::string The decrypted message as a string
 * 
 * @throws std::runtime_error If there is an error reading from the socket
 * @throws std::runtime_error If the decryption process fails
 */
std::string Client::receiveAndDecrypt(void)
{
    unsigned char buffer[BUFFER_SIZE];
    unsigned char iv[EVP_MAX_IV_LENGTH];

    int n = read(sock_, buffer, BUFFER_SIZE);
    if (n < 0) throw std::runtime_error("Error reading from socket");

    std::memcpy(iv, buffer, EVP_MAX_IV_LENGTH);
    int decrypted_length = decrypt(
        buffer + EVP_MAX_IV_LENGTH,
        n - EVP_MAX_IV_LENGTH,
        key_.data(),
        iv,
        buffer);
    if (decrypted_length < 0) throw std::runtime_error("Decryption failed");

    buffer[decrypted_length] = '\0';
    return std::string(reinterpret_cast<char *>(buffer));
}

int main() {
    try {
        Client client(DEFAULT_SERVER_IP, 8082, "2.0.0");
        client.initialize();
        client.run();
    } catch (const std::exception &e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }
    return 0;
}