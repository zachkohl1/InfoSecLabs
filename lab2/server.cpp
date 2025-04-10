#include "server.hpp"
#include "aes.hpp"
#include <iostream>
#include <stdexcept>
#include <chrono>
#include <iomanip>
#include <fstream>
#include <sstream>
#include <vector>
#include <arpa/inet.h>
#include <openssl/rand.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cstring>
#include <dirent.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <sys/stat.h>
#include <cstdlib>
#include <algorithm>

Server::Server(int port, const std::string &version)
    : sock_(-1), port_(port), version_(version), update_available_(false), ecdsa_key_(nullptr)
{
    const unsigned char temp[AES_KEY_SIZE + 1] = "01234567890123456789012345678901";
    std::copy(temp, temp + AES_KEY_SIZE, key_);
    std::memset(&server_addr_, 0, sizeof(server_addr_));

    FILE *pub_key_file = fopen("../server_public.pem", "r");
    if (!pub_key_file)
        throw std::runtime_error("Failed to open ../server_public.pem");
    ecdsa_key_ = PEM_read_EC_PUBKEY(pub_key_file, nullptr, nullptr, nullptr);
    fclose(pub_key_file);
    if (!ecdsa_key_)
        throw std::runtime_error("Failed to load ECDSA public key for server");
}

Server::~Server(void)
{
    if (sock_ >= 0)
        close(sock_);
    if (ecdsa_key_)
        EC_KEY_free(ecdsa_key_);
}

void Server::initialize(void)
{
    sock_ = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock_ < 0)
        throw std::runtime_error("Failed to create socket");

    server_addr_.sin_family = AF_INET;
    server_addr_.sin_addr.s_addr = htonl(INADDR_ANY);
    server_addr_.sin_port = htons(port_);

    int opt = 1;
    if (setsockopt(sock_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0)
        throw std::runtime_error("Failed to set socket options");

    if (bind(sock_, (struct sockaddr *)&server_addr_, sizeof(server_addr_)) < 0)
        throw std::runtime_error("Bind failed");

    if (listen(sock_, 5) < 0)
        throw std::runtime_error("Listen failed");

    std::cout << "Server initialized on port " << port_ << "\n";
}

void Server::run(void)
{
    std::cout << "Server Version: " << version_ << "\n";
    std::cout << "Server listening for connections...\n";

    while (true)
    {
        sockaddr_in client_addr{};
        socklen_t client_len = sizeof(client_addr);

        int client_sock = accept(sock_, (struct sockaddr *)&client_addr, &client_len);
        if (client_sock < 0)
        {
            std::cerr << "Accept failed: " << strerror(errno) << "\n";
            continue;
        }

        std::cout << "Accepted connection from "
                  << inet_ntoa(client_addr.sin_addr) << ":"
                  << ntohs(client_addr.sin_port) << "\n";

        try
        {
            handleClient(client_sock);
        }
        catch (const std::exception &e)
        {
            std::cerr << "Error handling client: " << e.what() << "\n";
        }
    }
}

void Server::acceptClients(void)
{
    while (true)
    {
        sockaddr_in client_addr{};
        socklen_t client_len = sizeof(client_addr);

        int client_sock = accept(sock_, (struct sockaddr *)&client_addr, &client_len);
        if (client_sock < 0)
        {
            std::cerr << "Accept failed: " << strerror(errno) << "\n";
            continue;
        }

        std::cout << "Accepted connection from "
                  << inet_ntoa(client_addr.sin_addr) << ":"
                  << ntohs(client_addr.sin_port) << "\n";

        try
        {
            handleClient(client_sock);
        }
        catch (const std::exception &e)
        {
            std::cerr << "Error handling client: " << e.what() << "\n";
        }
    }
}

bool Server::checkForUpdates(std::string version)
{
    if (version == "2.0.0")
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
        if (filename.find("server_v2") != std::string::npos && filename != "server_v2.sig") // Check for v2 update
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

bool Server::verifySignature(const std::string &file_path, const std::string &signature_path)
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

void Server::handleClient(int client_sock)
{
    std::vector<unsigned char> buffer(BUFFER_SIZE + EVP_MAX_IV_LENGTH);
    unsigned char iv[EVP_MAX_IV_LENGTH];
    std::string account; // Account will be set by a numeric account number

    while (true)
    {
        int recv_len = recv(client_sock, buffer.data(), buffer.size(), 0);
        if (recv_len <= 0)
        {
            break;
        }

        std::memcpy(iv, buffer.data(), EVP_MAX_IV_LENGTH);
        std::vector<unsigned char> decrypted(BUFFER_SIZE);
        int dec_len = decrypt(buffer.data() + EVP_MAX_IV_LENGTH,
                              recv_len - EVP_MAX_IV_LENGTH,
                              key_, iv, decrypted.data());
        if (dec_len < 0)
        {
            break;
        }

        std::string command(reinterpret_cast<char *>(decrypted.data()), dec_len);
        std::string response;

        if (command == "update")
        {
            response = "Update OK";
            std::vector<unsigned char> encrypted(BUFFER_SIZE + EVP_MAX_IV_LENGTH);
            RAND_bytes(iv, EVP_MAX_IV_LENGTH);
            int enc_len = encrypt(reinterpret_cast<const unsigned char *>(response.c_str()),
                                  response.length(), key_, iv, encrypted.data() + EVP_MAX_IV_LENGTH);
            std::memcpy(encrypted.data(), iv, EVP_MAX_IV_LENGTH);
            send(client_sock, encrypted.data(), enc_len + EVP_MAX_IV_LENGTH, 0);

            close(client_sock);
            if (checkForUpdates(version_)) 
            {
                response = "Update OK";
                std::vector<unsigned char> enc_resp(BUFFER_SIZE + EVP_MAX_IV_LENGTH);
                RAND_bytes(iv, EVP_MAX_IV_LENGTH);
                int enc_len = encrypt(reinterpret_cast<const unsigned char*>(response.c_str()), response.length(), key_, iv, enc_resp.data() + EVP_MAX_IV_LENGTH);
                std::memcpy(enc_resp.data(), iv, EVP_MAX_IV_LENGTH);
                send(client_sock, enc_resp.data(), enc_len + EVP_MAX_IV_LENGTH, 0);
                close(client_sock);
                
                system("cd ..&& ./move.sh");
                sleep(1);
                execlp("./server", "./server", nullptr);                    
            }
            else
            {
                std::cout << "No valid server update found. Closing anyway.\n";
                close(sock_);
                exit(0);
            }
            return; // Exit after update
        }
        else if (std::all_of(command.begin(), command.end(), ::isdigit)) // Check if command is all digits
        {
            account = command;
            response = "Account number set to: " + account;
        }
        else if (command.find("withdraw ") == 0)
        {
            if (account.empty())
            {
                response = "Please set account number first by sending just the account number";
            }
            else
            {
                double amount = std::stod(command.substr(9));
                if (accounts_[account] >= amount)
                {
                    accounts_[account] -= amount;
                    response = "Withdrawal accepted. New balance: $" +
                               std::to_string(accounts_[account]);
                    logTransaction(account, "withdraw", amount, accounts_[account]);
                }
                else
                {
                    response = "Insufficient funds";
                }
            }
        }
        else if (command.find("deposit ") == 0)
        {
            if (account.empty())
            {
                response = "Please set account number first by sending just the account number";
            }
            else
            {
                double amount = std::stod(command.substr(8));
                accounts_[account] += amount;
                response = "Deposit successful. New balance: $" +
                           std::to_string(accounts_[account]);
                logTransaction(account, "deposit", amount, accounts_[account]);
            }
        }
        else if (command == "balance")
        {
            if (account.empty())
            {
                response = "Please set account number first by sending just the account number";
            }
            else
            {
                response = "Your balance: $" + std::to_string(accounts_[account]);
                logTransaction(account, "balance", 0.0, accounts_[account]);
            }
        }
        else if (command == "exit")
        {
            response = "exit";
            std::vector<unsigned char> encrypted(BUFFER_SIZE + EVP_MAX_IV_LENGTH);
            RAND_bytes(iv, EVP_MAX_IV_LENGTH);
            int enc_len = encrypt(reinterpret_cast<const unsigned char *>(response.c_str()),
                                  response.length(), key_, iv, encrypted.data() + EVP_MAX_IV_LENGTH);
            std::memcpy(encrypted.data(), iv, EVP_MAX_IV_LENGTH);
            send(client_sock, encrypted.data(), enc_len + EVP_MAX_IV_LENGTH, 0);
            break;
        }
        else
        {
            response = "Invalid command";
        }

        std::vector<unsigned char> encrypted(BUFFER_SIZE + EVP_MAX_IV_LENGTH);
        RAND_bytes(iv, EVP_MAX_IV_LENGTH);
        int enc_len = encrypt(reinterpret_cast<const unsigned char *>(response.c_str()),
                              response.length(), key_, iv, encrypted.data() + EVP_MAX_IV_LENGTH);
        std::memcpy(encrypted.data(), iv, EVP_MAX_IV_LENGTH);
        send(client_sock, encrypted.data(), enc_len + EVP_MAX_IV_LENGTH, 0);
    }

    close(client_sock);
    std::cout << "Client disconnected\n";
}

void Server::logTransaction(const std::string &account, const std::string &action,
                            double amount, double balance)
{
    auto now = std::chrono::system_clock::now();
    std::time_t current_time = std::chrono::system_clock::to_time_t(now);

    std::stringstream time_ss;
    time_ss << std::put_time(std::localtime(&current_time), "%Y-%m-%d %H:%M:%S");

    std::ofstream log("transactions.log", std::ios::app);
    if (!log)
    {
        std::cerr << "Failed to open transactions.log\n";
        return;
    }

    log << time_ss.str() << ","
        << account << ","
        << action << ","
        << std::fixed << std::setprecision(2) << amount << ","
        << std::fixed << std::setprecision(2) << balance;

    // Add monthly_payment field as 0.00 for non-loan actions
    log << ",0.00\n";

    log.close();
}

void Server::initializeAccounts(void)
{
    std::ifstream file("transactions.log");
    if (!file)
    {
        std::ofstream init_file("transactions.log");
        if (!init_file)
        {
            throw std::runtime_error("Failed to create transactions.log");
        }

        init_file << "Account Initialization:\n"
                  << "2024-02-05 12:00:00,1,init,0.00,1000.00\n"
                  << "2024-02-05 12:00:00,2,init,0.00,1500.00\n"
                  << "2024-02-05 12:00:00,3,init,0.00,2000.00\n";
        init_file.close();

        parseTransactionLog("transactions.log");
    }
    else
    {
        file.seekg(0, std::ios::end);
        if (file.tellg() == 0)
        {
            file.close();
            std::ofstream init_file("transactions.log");
            if (!init_file)
            {
                throw std::runtime_error("Failed to create transactions.log");
            }

            init_file << "Account Initialization:\n"
                      << "2024-02-05 12:00:00,1,init,0.00,1000.00\n"
                      << "2024-02-05 12:00:00,2,init,0.00,1500.00\n"
                      << "2024-02-05 12:00:00,3,init,0.00,2000.00\n";
            init_file.close();

            parseTransactionLog("transactions.log");
        }
        else
        {
            file.close();
            parseTransactionLog("transactions.log");
        }
    }
}

void Server::parseTransactionLog(const std::string &filename)
{
    std::ifstream file(filename);
    if (!file)
    {
        throw std::runtime_error("Failed to open " + filename);
    }

    std::string line;
    while (std::getline(file, line))
    {
        if (line.find("Account Initialization") != std::string::npos)
        {
            continue;
        }

        std::stringstream ss(line);
        std::string timestamp, account, action;
        double amount, balance;

        std::getline(ss, timestamp, ',');
        std::getline(ss, account, ',');
        std::getline(ss, action, ',');
        ss >> amount;
        ss.ignore();
        ss >> balance;

        accounts_[account] = balance;
    }
}

void Server::update(void)
{
    std::cout << "Updating server...\n";
}

int main(void)
{
    // Ensure active directory exists
    struct stat st;
    try
    {
        Server server(DEFAULT_SERVER_PORT, DEFAULT_VERSION);
        server.initialize();
        server.run();
    }
    catch (const std::exception &e)
    {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }
    return 0;
}