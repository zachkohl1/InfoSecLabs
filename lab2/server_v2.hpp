#ifndef SERVER_V2_HPP
#define SERVER_V2_HPP

#include <string>
#include <map>
#include <sys/socket.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/ecdsa.h>
#include <openssl/rand.h>
#include "aes.hpp"     // Assuming this provides encrypt/decrypt functions

#define AES_KEY_SIZE 32
#define BUFFER_SIZE 256
#define DEFAULT_SERVER_PORT 8081
#define DEFAULT_VERSION "2.0.0"
#define UPDATES_DIR "../updates"

class Server
{
public:
    Server(int port = DEFAULT_SERVER_PORT, const std::string &version = DEFAULT_VERSION);
    virtual ~Server(void);
    void initialize(void);
    void run(void);

private:
    virtual void handleClient(int client_sock);
    void logTransaction(const std::string& account, const std::string& action, 
                       double amount, double balance);
    void initializeAccounts(void);
    void parseTransactionLog(const std::string& filename);
    bool checkForUpdates(void);
    bool verifySignature(const std::string& file_path, const std::string& signature_path);
    void performUpdate(const std::string& new_executable);
    std::string processLoanRequest(const std::string& account, double amount);

    int sock_;
    int port_;
    std::string version_;
    struct sockaddr_in server_addr_;
    unsigned char key_[AES_KEY_SIZE];
    bool update_available_;
    std::map<std::string, double> accounts_;
    EC_KEY* ecdsa_key_;  // ECDSA key for signature verification
    // Loan parameters (could be made configurable)
    const double annual_interest_rate_ = 0.05; // 5% annual interest
    const int loan_term_months_ = 12;          // 1-year term
};

#endif // SERVER_V2_HPP