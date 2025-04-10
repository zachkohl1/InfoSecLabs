#ifndef SERVER_HPP
#define SERVER_HPP

#include <string>           // Add this for std::string
#include <map>
#include <sys/socket.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include "aes.hpp"          // Assuming this provides encrypt/decrypt functions

#define AES_KEY_SIZE 32
#define BUFFER_SIZE 256
#define DEFAULT_SERVER_PORT 8081
#define DEFAULT_VERSION "1.0.0"
#define UPDATES_DIR "../updates"
struct LoanData {
    double amount = 0.0;
    double monthly_payment = 0.0;
};

class Server
{
public:
    // Constructor with optional parameters
    Server(int port = DEFAULT_SERVER_PORT,
           const std::string &version = DEFAULT_VERSION);

    // Destructor to clean up resources
    virtual ~Server(void);

    // Initialize the server
    void initialize(void);

    // Run the server's main loop
    virtual void run(void);

protected:
    // Private member functions
    virtual void handleClient(int client_sock);
    virtual void logTransaction(const std::string& account, const std::string& action, 
                       double amount, double balance);
    virtual void initializeAccounts(void);
    virtual void parseTransactionLog(const std::string& filename);
    void update(void);
    void acceptClients(void);  // Added declaration
    bool checkForUpdates(std::string version);  // Added declaration
    bool verifySignature(const std::string& file_path, const std::string& signature_path);  // Added declaration
    void performUpdate(const std::string& new_executable);  // Added declaration

    // Member variables
    int sock_;                             // Socket file descriptor
    int port_;                             // Server port
    std::string version_;                  // Server version
    struct sockaddr_in server_addr_;       // Server address structure
    unsigned char key_[AES_KEY_SIZE];      // AES key (C-style array to match original)
    bool update_available_;                // Update flag
    std::map<std::string, double> accounts_; // Account balances
    EC_KEY* ecdsa_key_; // Added for ECDSA public key
    std::map<std::string, LoanData> loans_;

};

#endif // SERVER_HPP