#ifndef CLIENT_V2_HPP
#define CLIENT_V2_HPP

#include <string>
#include <array>
#include <sys/socket.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/ecdsa.h>
#include <openssl/rand.h>
#include "aes.hpp"     // Assuming this provides encrypt/decrypt functions

#define AES_KEY_SIZE 32
#define BUFFER_SIZE 256
#define DEFAULT_SERVER_IP "127.0.0.1"
#define DEFAULT_SERVER_PORT 8081
#define DEFAULT_VERSION "2.0.0"
#define UPDATES_DIR "../updates"

class Client
{
public:
    Client(const std::string &server_ip = DEFAULT_SERVER_IP,
           int server_port = DEFAULT_SERVER_PORT,
           const std::string &version = DEFAULT_VERSION);
    ~Client(void);
    void initialize(void);
    void run(void);
    bool isUpdateAvailable(void) const { return update_available_; }

private:
    void communicateWithServer(void);
    bool checkForUpdates(void);
    bool verifySignature(const std::string& file_path, const std::string& signature_path);
    void performUpdate(const std::string& new_executable);
    int encryptAndSend(const std::string &message);
    std::string receiveAndDecrypt(void);

    int sock_;
    std::string server_ip_;
    int server_port_;
    std::string version_;
    struct sockaddr_in server_addr_;
    std::array<unsigned char, AES_KEY_SIZE> key_;
    bool update_available_;
    EC_KEY* ecdsa_key_;  // ECDSA key for signature verification
};

#endif // CLIENT_V2_HPP