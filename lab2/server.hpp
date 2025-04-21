#ifndef SERVER_HPP
#define SERVER_HPP

#include <string> // Add this for std::string
#include <map>
#include <sys/socket.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
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
#include <openssl/ecdsa.h>
#include <openssl/ec.h>
#include "aes.hpp" // Assuming this provides encrypt/decrypt functions
#include "srp.hpp"
using namespace std;

#define AES_KEY_SIZE 32
#define BUFFER_SIZE 1024
#define DEFAULT_SERVER_PORT 8081
#define DEFAULT_VERSION "1.0.0"
#define UPDATES_DIR "../updates"

typedef struct
{
    double amount = 0.0;
    double monthly_payment = 0.0;
} LoanData;

typedef struct
{
    std::string salt;
    std::string verifier;
} UserData;

class Server
{
public:
    // Constructor with optional parameters
    Server(int port = DEFAULT_SERVER_PORT, const std::string &version = DEFAULT_VERSION) : sock_(-1), port_(port), version_(version), update_available_(false), ecdsa_key_(nullptr)
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

        // Initialize user database (for testing)
        initializeUserDatabase();
        initializeAccounts();
    }

    // Destructor to clean up resources
    ~Server(void)
    {
        if (sock_ >= 0)
            close(sock_);
        if (ecdsa_key_)
            EC_KEY_free(ecdsa_key_);
    }

    // Initialize the server
    void initialize(void)
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

    // Run the server's main loop
    void run(void)
    {
        std::cout << "Server Version: " << version_ << "\n";
        std::cout << "Server listening for connections...\n";
        acceptClients();
    }

private:
    void initializeUserDatabase()
    {
        // For testing: Add a sample user
        std::string username = "user1";
        std::string password = "pass1"; // In production, password wouldn't be hardcoded
        std::string salt = SRP::generateSalt();
        std::string verifier = SRP::generateVerifier(username, password, salt);
        users_[username] = {salt, verifier};

        username = "user2";
        password = "pass2";
        salt = SRP::generateSalt();
        verifier = SRP::generateVerifier(username, password, salt);
        users_[username] = {salt, verifier};

        username = "user3";
        password = "pass3";
        salt = SRP::generateSalt();
        verifier = SRP::generateVerifier(username, password, salt);
        users_[username] = {salt, verifier};
    }
    // Private member functions
    void handleClient(int client_sock)
    {
        std::vector<unsigned char> buffer(BUFFER_SIZE + EVP_MAX_IV_LENGTH);
        unsigned char iv[EVP_MAX_IV_LENGTH];
        std::string account;
        bool authenticated = false;
        SRP srp;
        std::string username;

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

            // 1. Look for SRP_AUTH command before any other command
            if (command.find("SRP_AUTH:") == 0)
            {
                // Parse username and A
                std::string auth_data = command.substr(9);
                size_t sep = auth_data.find(':');
                if (sep == std::string::npos || sep == 0 || sep == auth_data.length() - 1)
                {
                    response = "Invalid SRP auth format";
                    sendEncryptedResponse(client_sock, response, iv);
                    continue;
                }

                username = auth_data.substr(0, sep);
                std::string A_hex = auth_data.substr(sep + 1);

                // Verify user exists by checking in database
                if (users_.find(username) == users_.end())
                {
                    response = "Unknown user";
                    sendEncryptedResponse(client_sock, response, iv);
                    continue;
                }

                // Initialize SRP server by
                // 1. Storing the username
                // 2. Generating a random private key 'b' (256 bits)
                // 3. Computing the server's public key B = k * g^x + g^b % N
                if (!srp.serverInit(username, users_[username].verifier, users_[username].salt))
                {
                    response = "SRP server initialization failed";
                    sendEncryptedResponse(client_sock, response, iv);
                    continue;
                }

                // Step 1: Send salt and B
                // serverStep1 receives the client's public ephemeral value A (as a hex string),
                //validates it (A mod N != 0), computes the scrambling parameter u = H(PAD(A) | PAD(B)),
                // calculates the server's session key S = (A * v^u)^b mod N, and derives the
                //shared secret key K = H(S). The padding ensures that A and B are the same length
                // before hashing.
                std::string salt_and_B = srp.serverStep1(A_hex);

                if (salt_and_B.empty())
                {
                    response = "Invalid SRP A value";
                    sendEncryptedResponse(client_sock, response, iv);
                    continue;
                }

                response = salt_and_B;
                sendEncryptedResponse(client_sock, response, iv);
                continue;
            }
            else if (command.find("SRP_M1:") == 0)      // Process client proof
            {
                std::string M1 = command.substr(7);
                if (!srp.serverStep2(M1))       // Verify client proof
                {
                    response = "SRP authentication failed";
                    sendEncryptedResponse(client_sock, response, iv);
                    continue;
                }

                // Send M2 proof
                response = "SRP_M2:" + srp.serverGetProof();
                sendEncryptedResponse(client_sock, response, iv);
                authenticated = true;
                std::cout << "Client authenticated as " << username << "\n";
                continue;
            }

            if (!authenticated)
            {
                response = "Authentication required";
                sendEncryptedResponse(client_sock, response, iv);
                continue;
            }

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
                    int enc_len = encrypt(reinterpret_cast<const unsigned char *>(response.c_str()), response.length(), key_, iv, enc_resp.data() + EVP_MAX_IV_LENGTH);
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
                        logTransaction(account, "withdraw", amount, accounts_[account], loans_[account].amount, loans_[account].monthly_payment);
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
                    logTransaction(account, "deposit", amount, accounts_[account], loans_[account].amount, loans_[account].monthly_payment);
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
                    if (version_ == "2.0.0")
                        response = "Your balance: $" + std::to_string(accounts_[account]) + ", Loan amount: $" +
                                   std::to_string(loans_[account].amount) +
                                   ", Monthly payment: $" +
                                   std::to_string(loans_[account].monthly_payment);
                    else
                        response = "Your balance: $" + std::to_string(accounts_[account]);
                    logTransaction(account, "balance", 0.0, accounts_[account], loans_[account].amount, loans_[account].monthly_payment);
                }
            }
            else if (command.find("loan ") == 0 && version_ == "2.0.0")
            {
                if (account.empty())
                {
                    response = "Please set account number first by sending just the account number";
                }
                else
                {
                    double amount;
                    try
                    {
                        amount = std::stod(command.substr(5));
                        if (amount <= 0)
                            throw std::invalid_argument("Loan amount must be positive");
                    }
                    catch (const std::exception &e)
                    {
                        response = "Invalid loan amount";
                        std::vector<unsigned char> encrypted(BUFFER_SIZE + EVP_MAX_IV_LENGTH);
                        RAND_bytes(iv, EVP_MAX_IV_LENGTH);
                        int enc_len = encrypt(reinterpret_cast<const unsigned char *>(response.c_str()),
                                              response.length(), key_, iv, encrypted.data() + EVP_MAX_IV_LENGTH);
                        std::memcpy(encrypted.data(), iv, EVP_MAX_IV_LENGTH);
                        send(client_sock, encrypted.data(), enc_len + EVP_MAX_IV_LENGTH, 0);
                        continue;
                    }
                    accounts_[account] += amount;
                    loans_[account].amount += amount; // Accumulate loan amount
                    loans_[account].monthly_payment = loans_[account].amount / 12.0;
                    response = "Loan granted. New balance: $" +
                               std::to_string(accounts_[account]) +
                               ", Total loan amount: $" +
                               std::to_string(loans_[account].amount) +
                               ", Monthly payment: $" +
                               std::to_string(loans_[account].monthly_payment);
                    logTransaction(account, "loan", amount, accounts_[account], loans_[account].amount, loans_[account].monthly_payment);
                }
            }
            else if (command.find("repay ") == 0 && version_ == "2.0.0")
            {
                if (account.empty())
                {
                    response = "Please set account number first by sending just the account number";
                }
                else
                {
                    double amount;
                    try
                    {
                        amount = std::stod(command.substr(6));
                        if (amount <= 0)
                            throw std::invalid_argument("Repayment amount must be positive");
                    }
                    catch (const std::exception &e)
                    {
                        response = "Invalid repayment amount";
                        std::vector<unsigned char> encrypted(BUFFER_SIZE + EVP_MAX_IV_LENGTH);
                        RAND_bytes(iv, EVP_MAX_IV_LENGTH);
                        int enc_len = encrypt(reinterpret_cast<const unsigned char *>(response.c_str()),
                                              response.length(), key_, iv, encrypted.data() + EVP_MAX_IV_LENGTH);
                        std::memcpy(encrypted.data(), iv, EVP_MAX_IV_LENGTH);
                        send(client_sock, encrypted.data(), enc_len + EVP_MAX_IV_LENGTH, 0);
                        continue;
                    }
                    if (accounts_[account] >= amount && loans_[account].amount >= amount)
                    {
                        accounts_[account] -= amount;
                        loans_[account].amount -= amount;
                        loans_[account].monthly_payment = loans_[account].amount / 12.0;
                        response = "Repayment accepted. New balance: $" +
                                   std::to_string(accounts_[account]) +
                                   ", Remaining loan amount: $" +
                                   std::to_string(loans_[account].amount) +
                                   ", Monthly payment: $" +
                                   std::to_string(loans_[account].monthly_payment);
                        logTransaction(account, "repay", amount, accounts_[account], loans_[account].amount, loans_[account].monthly_payment);
                    }
                    else
                    {
                        response = "Insufficient funds or loan amount for repayment";
                    }
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
    void acceptClients(void)
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
    void sendEncryptedResponse(int client_sock, const std::string &response, unsigned char *iv)
    {
        std::vector<unsigned char> encrypted(BUFFER_SIZE + EVP_MAX_IV_LENGTH);
        RAND_bytes(iv, EVP_MAX_IV_LENGTH);
        int enc_len = encrypt(reinterpret_cast<const unsigned char *>(response.c_str()),
                              response.length(), key_, iv, encrypted.data() + EVP_MAX_IV_LENGTH);
        std::memcpy(encrypted.data(), iv, EVP_MAX_IV_LENGTH);
        send(client_sock, encrypted.data(), enc_len + EVP_MAX_IV_LENGTH, 0);
    }
    void logTransaction(const std::string &account, const std::string &action, double amount, double balance, double total_loan_amount, double monthly_payment)
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

        if (version_ == "2.0.0")
        {
            log << "," << std::fixed << std::setprecision(2) << total_loan_amount
                << "," << std::fixed << std::setprecision(2) << monthly_payment;
        }

        log << "\n";
        log.close();
    }
    void initializeAccounts(void)
    {
        std::ifstream file("transactions.log");
        if (!file)
        {
            std::ofstream init_file("transactions.log");
            if (!init_file)
                throw std::runtime_error("Failed to create transactions.log");

            std::string header = version_ == "2.0.0" ? "Datetime,Account,Action,Amount,Balance,TotalLoanAmount,MonthlyPayment\n" : "Datetime,Account,Action,Amount,Balance\n";
            init_file << "Account Initialization:\n"
                      << header
                      << "2024-02-05 12:00:00,1,init,0.00,1000.00" << (version_ == "2.0.0" ? ",0.00,0.00\n" : "\n")
                      << "2024-02-05 12:00:00,2,init,0.00,1500.00" << (version_ == "2.0.0" ? ",0.00,0.00\n" : "\n")
                      << "2024-02-05 12:00:00,3,init,0.00,2000.00" << (version_ == "2.0.0" ? ",0.00,0.00\n" : "\n");
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
                    throw std::runtime_error("Failed to create transactions.log");

                std::string header = version_ == "2.0.0" ? "Datetime,Account,Action,Amount,Balance,TotalLoanAmount,MonthlyPayment\n" : "Datetime,Account,Action,Amount,Balance\n";
                init_file << "Account Initialization:\n"
                          << header
                          << "2024-02-05 12:00:00,1,init,0.00,1000.00" << (version_ == "2.0.0" ? ",0.00,0.00\n" : "\n")
                          << "2024-02-05 12:00:00,2,init,0.00,1500.00" << (version_ == "2.0.0" ? ",0.00,0.00\n" : "\n")
                          << "2024-02-05 12:00:00,3,init,0.00,2000.00" << (version_ == "2.0.0" ? ",0.00,0.00\n" : "\n");
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

    void parseTransactionLog(const std::string &filename)
    {
        std::ifstream file(filename);
        if (!file)
        {
            initializeAccounts();
            return;
        }

        std::string line;
        std::getline(file, line); // Skip "Account Initialization"
        std::getline(file, line); // Skip header
        while (std::getline(file, line))
        {
            if (line.empty())
                continue;

            std::stringstream ss(line);
            std::string timestamp, account, action;
            double amount, balance, total_loan_amount = 0.0, monthly_payment = 0.0;

            std::getline(ss, timestamp, ',');
            std::getline(ss, account, ',');
            std::getline(ss, action, ',');
            ss >> amount;
            ss.ignore(1);
            ss >> balance;

            // For version 2.0.0, attempt to read loan fields if they exist
            if (version_ == "2.0.0")
            {
                if (ss.peek() == ',')
                {
                    ss.ignore(1);
                    ss >> total_loan_amount;
                    if (ss.peek() == ',')
                    {
                        ss.ignore(1);
                        ss >> monthly_payment;
                    }
                }
            }

            accounts_[account] = balance;
            if (version_ == "2.0.0")
            {
                loans_[account].amount = total_loan_amount;
                loans_[account].monthly_payment = monthly_payment;
            }
        }
        file.close();
    }

    bool checkForUpdates(std::string version)
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

    // Member variables
    int sock_;                               // Socket file descriptor
    int port_;                               // Server port
    std::string version_;                    // Server version
    struct sockaddr_in server_addr_;         // Server address structure
    unsigned char key_[AES_KEY_SIZE];        // AES key (C-style array to match original)
    bool update_available_;                  // Update flag
    std::map<std::string, double> accounts_; // Account balances
    EC_KEY *ecdsa_key_;                      // Added for ECDSA public key
    std::map<std::string, LoanData> loans_;
    std::map<std::string, UserData> users_;
};

#endif // SERVER_HPP