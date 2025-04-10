#include "server.hpp"
#include <fstream>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <openssl/sha.h>
#include <openssl/ecdsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <dirent.h>
#include <cstring>
#include <sys/stat.h>
#include <vector>
#include <map>
#include <chrono>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "aes.hpp"
using namespace std;

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

Server::~Server()
{
    if (sock_ >= 0)
        close(sock_);
    if (ecdsa_key_)
        EC_KEY_free(ecdsa_key_);
}

void Server::initialize()
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
    setsockopt(sock_, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));

    if (bind(sock_, (struct sockaddr *)&server_addr_, sizeof(server_addr_)) < 0)
        throw std::runtime_error("Bind failed");

    if (listen(sock_, 5) < 0)
        throw std::runtime_error("Listen failed");

    std::cout << "Server initialized on port " << port_ << "\n";
}

bool Server::checkForUpdates(std::string version)
{

    if (version == "2.0.0")
        return false;

    DIR *dir = opendir(UPDATES_DIR);
    if (!dir)
    {
        std::cerr << "Failed to open ./updates directory: " << strerror(errno) << "\n";
        return false;
    }

    struct dirent *entry;
    while ((entry = readdir(dir)) != nullptr)
    {
        std::string filename = entry->d_name;
        if (filename.find("server_v2") != std::string::npos && filename != "server_v2.sig")
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

bool Server::verifySignature(const std::string &file_path, const std::string &signature_path)
{
    std::ifstream file(file_path, std::ios::binary);
    if (!file)
        return false;
    std::vector<unsigned char> file_content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    file.close();

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(&file_content[0], file_content.size(), hash);

    std::ifstream sig_file(signature_path, std::ios::binary);
    if (!sig_file)
        return false;
    std::vector<unsigned char> signature((std::istreambuf_iterator<char>(sig_file)), std::istreambuf_iterator<char>());
    sig_file.close();

    return ECDSA_verify(0, hash, SHA256_DIGEST_LENGTH, signature.data(), signature.size(), ecdsa_key_) == 1;
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

    if (action == "loan" || action == "repay")
    {
        log << "," << std::fixed << std::setprecision(2) << loans_[account].monthly_payment;
    }
    else
    {
        log << ",0.00";
    }

    log << "\n";
    log.close();
}

void Server::initializeAccounts()
{
    std::ifstream file("transactions.log");
    if (!file || file.peek() == std::ifstream::traits_type::eof())
    {
        std::ofstream init_file("transactions.log");
        init_file << "Account Initialization:\n"
                  << "2024-02-05 12:00:00,1,init,0.00,1000.00\n"
                  << "2024-02-05 12:00:00,2,init,0.00,1500.00\n"
                  << "2024-02-05 12:00:00,3,init,0.00,2000.00\n";
        init_file.close();
    }
    parseTransactionLog("transactions.log");
}

void Server::parseTransactionLog(const std::string &filename)
{
    std::ifstream file(filename);
    std::string line;
    while (std::getline(file, line))
    {
        if (line.find("Account Initialization") != std::string::npos)
            continue;

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
void Server::run()
{
    throw std::runtime_error("Server::run() should be overridden in derived class");
}

void Server::handleClient(int)
{
    throw std::runtime_error("Server::handleClient() should be overridden in derived class");
}