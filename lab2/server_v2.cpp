#include "server.hpp"
#include "aes.hpp"
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <vector>
#include <map>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <dirent.h>
#include <algorithm>


class ServerV2 : public Server {
public:

    ServerV2(int port, const std::string& version) : Server(port, version) {}

    /**
     * @brief Initializes user accounts and loan records for the banking system
     * 
     * This function performs the following operations:
     * 1. Checks if a transaction log file exists
     * 2. If not, creates a new log file with default initial accounts
     * 3. Sets up default account balances if no accounts are currently loaded
     * 4. Sets up default loan records if no loans are currently loaded
     * 5. Parses the transaction log to reconstruct account state from transaction history
     * 
     * The function ensures system state is properly initialized either from existing
     * transaction logs or with default values when starting fresh.
     * 
     * Side effects:
     * - May create a new transactions.log file
     * - Modifies the accounts_ and loans_ member variables
     * - Outputs confirmation message to console
     */
    void initalizeAccounts()
    {
        std::ifstream file_check("transactions.log");
        bool file_exists = file_check.good();
        file_check.close();
        
        if (!file_exists) {
            std::ofstream log_file("transactions.log");
            log_file << "timestamp,account,action,amount,balance,monthly_payment\n"
                     << "2024-02-05 12:00:00,1,init,0.00,1000.00,0.00\n"
                     << "2024-02-05 12:00:00,2,init,0.00,2500.00,0.00\n"
                     << "2024-02-05 12:00:00,3,init,0.00,5000.00,0.00\n";
            log_file.close();
        }
        
        // Initialize default values if not already set by log
        if (accounts_.empty()) {
            accounts_["1"] = 1000.0;
            accounts_["2"] = 2500.0;
            accounts_["3"] = 5000.0;
        }
        if (loans_.empty()) {
            loans_["1"] = {0.0, 0.0};
            loans_["2"] = {0.0, 0.0};
            loans_["3"] = {0.0, 0.0};
        }
        
        parseTransactionLog("transactions.log");
        std::cout << "Accounts initialized.\n";
        
    }
    /**
     * @brief Runs the server's main loop
     *
     * This method initializes user accounts, displays the server version, and
     * begins listening for client connections. Once started, it runs in an infinite
     * loop, continuously accepting new client connections and handling them.
     * Each client connection is processed in a try-catch block to prevent errors
     * from crashing the server.
     *
     * The server will print status messages to stdout including:
     * - Server version information
     * - Connection acceptance notifications
     * - Client IP address and port information
     *
     * Error messages are output to stderr, but the server will continue running
     * after encountering errors.
     */
    void run() override {
        std::cout << "Server Version: " << version_ << "\n";
        initializeAccounts();
        std::cout << "Server listening for connections...\n";

        while (true) {
            sockaddr_in client_addr{};
            socklen_t client_len = sizeof(client_addr);
            int client_sock = accept(sock_, (struct sockaddr*)&client_addr, &client_len);
            if (client_sock < 0) {
                std::cerr << "Accept failed: " << strerror(errno) << "\n";
                continue;
            }

            std::cout << "Accepted connection from " << inet_ntoa(client_addr.sin_addr) << ":" << ntohs(client_addr.sin_port) << "\n";
            try {
                handleClient(client_sock);
            } catch (const std::exception& e) {
                std::cerr << "Error handling client: " << e.what() << "\n";
            }
        }
    }

protected:
    std::map<std::string, LoanData> loans__;

    /**
     * @brief Handles client connections and processes encrypted banking commands
     *
     * This method establishes an encrypted communication channel with a client and processes
     * banking-related commands. It implements a protocol where each message includes an
     * initialization vector (IV) followed by encrypted data. The method supports various
     * banking operations including:
     *   - Setting account numbers
     *   - Processing loan requests
     *   - Handling loan repayments
     *   - Checking account/loan status
     *   - Server update functionality
     *
     * The communication continues until the client disconnects or an error occurs.
     * For the "update" command, the method will initiate a server update process
     * which terminates the current process and starts a new server instance.
     *
     * @param client_sock The socket file descriptor for the client connection
     * @note This method will close the client socket before returning
     * @warning The update command executes shell commands and replaces the current process
     */
    void handleClient(int client_sock) override {
        std::string account;
        std::string command, response;
        std::vector<unsigned char> buffer(BUFFER_SIZE + EVP_MAX_IV_LENGTH);
        unsigned char iv[EVP_MAX_IV_LENGTH];

        while (true) {
            int recv_len = recv(client_sock, buffer.data(), buffer.size(), 0);
            if (recv_len <= 0) break;

            std::memcpy(iv, buffer.data(), EVP_MAX_IV_LENGTH);
            std::vector<unsigned char> decrypted(BUFFER_SIZE);
            int dec_len = decrypt(buffer.data() + EVP_MAX_IV_LENGTH, recv_len - EVP_MAX_IV_LENGTH, key_, iv, decrypted.data());
            if (dec_len < 0) break;

            command = std::string(reinterpret_cast<char*>(decrypted.data()), dec_len);

            if (command == "update") {
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
                    execlp("server", "server", nullptr);           
                }
            } else if (std::all_of(command.begin(), command.end(), ::isdigit)) {
                account = command;
                response = "Account number set to: " + account;
            } else if (command.find("loan") == 0) {
                double amt = std::stod(command.substr(5));
                loans_[account].amount += amt;
                loans_[account].monthly_payment = loans_[account].amount / 12;
                accounts_[account] += amt;
                response = "Loan granted.\n  - Total loan: $" + std::to_string(loans_[account].amount) +
                           "\n  - Monthly repayment: $" + std::to_string(loans_[account].monthly_payment);
                logTransaction(account, "loan", amt, accounts_[account]);
            } else if (command.find("repay") == 0) {
                double amt = std::stod(command.substr(6));
                if (loans_[account].amount <= 0) {
                    response = "No loan to repay.";
                } else {
                    loans_[account].amount -= amt;
                    loans_[account].monthly_payment = loans_[account].amount > 0 ? loans_[account].amount / 12 : 0.0;
                    response = "Repayment accepted.\n  - Remaining loan: $" + std::to_string(loans_[account].amount) +
                               "\n  - Updated monthly repayment: $" + std::to_string(loans_[account].monthly_payment);
                    logTransaction(account, "repay", amt, accounts_[account]);
                }
            } else if (command == "status") {
                response = "Current loan status:\n  - Outstanding loan: $" + std::to_string(loans_[account].amount) +
                           "\n  - Monthly payment: $" + std::to_string(loans_[account].monthly_payment);
            } else {
                response = handleBankCommand(account, command);
            }

            std::vector<unsigned char> enc_resp(BUFFER_SIZE + EVP_MAX_IV_LENGTH);
            RAND_bytes(iv, EVP_MAX_IV_LENGTH);
            int enc_len = encrypt(reinterpret_cast<const unsigned char*>(response.c_str()), response.size(), key_, iv, enc_resp.data() + EVP_MAX_IV_LENGTH);
            std::memcpy(enc_resp.data(), iv, EVP_MAX_IV_LENGTH);
            send(client_sock, enc_resp.data(), enc_len + EVP_MAX_IV_LENGTH, 0);
        }

        close(client_sock);
    }

    /**
     * @brief Processes banking commands for a specified account
     *
     * This function handles various banking operations including withdrawals,
     * deposits, loans, repayments, and balance inquiries. It validates the
     * account and command format before processing.
     *
     * @param account The account identifier/number to perform operations on
     * @param command The banking command to execute (withdraw, deposit, loan, repay, balance, exit)
     *
     * @return A string response indicating the result of the operation:
     *   - For withdrawals: Confirmation or insufficient funds message
     *   - For deposits: Confirmation with updated balance
     *   - For loans: Confirmation with loan details
     *   - For repayments: Confirmation with updated loan details
     *   - For balance inquiries: Current account and loan balance information
     *   - For exit: "exit" string to terminate session
     *   - For errors: Appropriate error message
     *
     * @note All monetary transactions are logged via the logTransaction method
     * @note The account parameter must be set before any command can be processed
     * @throws std::invalid_argument Implicitly through std::stod when parsing invalid numeric input
     */
    std::string handleBankCommand(const std::string& account, const std::string& command) {
        if (account.empty()) {
            return "Please set account number first by sending just the account number";
        }
        if (command.find("withdraw ") == 0) {
            double amount = std::stod(command.substr(9));
            if (accounts_[account] >= amount) {
                accounts_[account] -= amount;
                logTransaction(account, "withdraw", amount, accounts_[account]);
                return "Withdrawal accepted. Balance: $" + std::to_string(accounts_[account]);
            }
            return "Insufficient funds.";
        } else if (command.find("deposit ") == 0) {
            double amount = std::stod(command.substr(8));
            accounts_[account] += amount;
            logTransaction(account, "deposit", amount, accounts_[account]);
            return "Deposit successful. Balance: $" + std::to_string(accounts_[account]);
        } else if (command.find("loan ") == 0) { // Note the space
            double amt = std::stod(command.substr(5));
            loans_[account].amount += amt;
            loans_[account].monthly_payment = loans_[account].amount / 12;
            logTransaction(account, "loan", amt, loans_[account].amount);
            return "Loan granted.\n  - Total loan: $" + std::to_string(loans_[account].amount) +
                   "\n  - Monthly repayment: $" + std::to_string(loans_[account].monthly_payment);
        } else if (command.find("repay ") == 0) { // Note the space
            double amt = std::stod(command.substr(6));
            if (loans_[account].amount <= 0) {
                return "No loan to repay.";
            }
            loans_[account].amount -= amt;
            loans_[account].monthly_payment = loans_[account].amount > 0 ? loans_[account].amount / 12 : 0.0;
            logTransaction(account, "repay", amt, loans_[account].amount);
            return "Repayment accepted.\n  - Remaining loan: $" + std::to_string(loans_[account].amount) +
                   "\n  - Updated monthly repayment: $" + std::to_string(loans_[account].monthly_payment);
        } else if (command == "balance") {
            return "Balance: $" + std::to_string(accounts_[account]) +
            " | Loan balance: $" + std::to_string(loans_[account].amount) +
            " | Monthly payment: $" + std::to_string(loans_[account].monthly_payment);
             } else if (command == "exit") {
            return "exit";
        }
        return "Invalid command.";
    }


    /**
     * @brief Encrypts the given response and sends it over the specified socket.
     * 
     * This function performs the following steps:
     * 1. Generates a random initialization vector (IV)
     * 2. Encrypts the response string using the stored encryption key
     * 3. Prepends the IV to the encrypted data
     * 4. Sends the combined IV and encrypted data over the socket
     * 
     * @param sock The socket descriptor to send the encrypted data over
     * @param response The plaintext response to encrypt and send
     * 
     * @note The encryption key (key_) must be properly initialized before calling this function
     * @note The IV is sent along with the encrypted data to allow for decryption by the recipient
     */
    void sendEncrypted(int sock, const std::string& response) {
        std::vector<unsigned char> encrypted(BUFFER_SIZE + EVP_MAX_IV_LENGTH);
        unsigned char iv[EVP_MAX_IV_LENGTH];
        RAND_bytes(iv, EVP_MAX_IV_LENGTH);
        int enc_len = encrypt(reinterpret_cast<const unsigned char*>(response.c_str()),
                              response.length(), key_, iv, encrypted.data() + EVP_MAX_IV_LENGTH);
        std::memcpy(encrypted.data(), iv, EVP_MAX_IV_LENGTH);
        send(sock, encrypted.data(), enc_len + EVP_MAX_IV_LENGTH, 0);
    }

    /**
     * @brief Parses a transaction log file and updates account and loan information
     *
     * This function reads a CSV-formatted transaction log file and updates the internal 
     * accounts and loans maps based on the transaction data. The first line of the file 
     * is assumed to be a header and is skipped. Each subsequent line should contain 
     * transaction data in the format: timestamp, account, action, amount, balance,
     * monthly_payment (optional).
     *
     * Supported action types:
     * - deposit: Updates the account balance
     * - withdraw: Updates the account balance
     * - init: Initializes an account with a balance
     * - loan: Creates or updates a loan with balance and monthly payment
     * - repay: Updates a loan balance and monthly payment
     *
     * @param filename Path to the transaction log file to be parsed
     *
     * @note If the file cannot be opened, a warning is displayed and the function returns
     * @note Lines with parsing errors are skipped, and an error message is printed
     */
    void parseTransactionLog(const std::string& filename) {
        std::ifstream log_file(filename);
        if (!log_file.is_open()) {
            std::cerr << "Warning: Could not open transaction log file.\n";
            return;
        }
        
        std::string line;
        std::getline(log_file, line); // Skip header
        
        while (std::getline(log_file, line)) {
            if (line.empty()) continue;
            
            std::stringstream ss(line);
            std::string timestamp, account, action, amount_str, balance_str, monthly_payment_str;
            
            std::getline(ss, timestamp, ',');
            std::getline(ss, account, ',');
            std::getline(ss, action, ',');
            std::getline(ss, amount_str, ',');
            std::getline(ss, balance_str, ',');
            std::getline(ss, monthly_payment_str, ','); // May be empty
            
            try {
                double amount = std::stod(amount_str);
                double balance = std::stod(balance_str);
                double monthly_payment = monthly_payment_str.empty() ? 0.0 : std::stod(monthly_payment_str);
                
                if (action == "deposit" || action == "withdraw" || action == "init") {
                    accounts_[account] = balance;
                } else if (action == "loan" || action == "repay") {
                    loans_[account].amount = balance;
                    loans_[account].monthly_payment = monthly_payment;
                }
            } catch (const std::exception& e) {
                std::cerr << "Error parsing line: " << line << " - " << e.what() << "\n";
                continue;
            }
        }
        log_file.close();
    }
};

int main() {
    try {
        ServerV2 server(8082, "2.0.0");
        server.initialize();
        server.run();
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }
    return 0;
}
