#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <time.h>

#define SERVER_HOST "localhost"
#define SERVER_IP "172.27.0.1"
#define BUFFER_SIZE 512
#define SERVER_PORT 1111    
#define PASSPHRASE "hello"

static unsigned char response[BUFFER_SIZE];
static unsigned char encrypted[BUFFER_SIZE];
static unsigned char decrypted[BUFFER_SIZE];
static struct sockaddr_in server_addr, client_addr;
static int mysock, csock, r;
static socklen_t len;
static RSA* rsa;

static bool server_init(void);
static bool handle_client(int sock);
static RSA *load_private_key(const char *filename);
static RSA *load_public_key(const char *filename);
static void get_message(unsigned char* response, size_t size);
static int rsa_decrypt(RSA *rsa, unsigned char *encrypted, unsigned char *decrypted);
static int rsa_encrypt(RSA *rsa, unsigned char *message, unsigned char *encrypted);

int main(void)
{
    if (!server_init()) {
        printf("Server initialization failed\n");
        return -1;
    }
    
    while (1) {
        printf("Server: accepting new connection ...\n");
        len = sizeof(client_addr);
        csock = accept(mysock, (struct sockaddr *)&client_addr, &len);
        if (csock < 0) {
            printf("Server accept error\n");
            continue;
        }
        printf("Server accepted a client connection from IP= %s port=%d\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
        
        bool no_error = handle_client(csock);
        close(csock);
        if (!no_error) break;
    }
    
    close(mysock);
    return 0;
}

static void get_message(unsigned char* response, size_t size)
{
    printf("Enter response: ");
    fgets((char*)response, size, stdin);
    size_t len = strlen((char*)response);
    if (len > 0 && response[len - 1] == '\n') {
        response[len - 1] = '\0';
    }
}

static RSA *load_private_key(const char *filename) {
    FILE *fp = fopen(filename, "r");
    if (!fp) {
        perror("Unable to open private key file");
        exit(EXIT_FAILURE);
    }
    RSA *rsa = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    return rsa;
}

static RSA *load_public_key(const char *filename) {
    FILE *fp = fopen(filename, "r");
    if (!fp) {
        perror("Unable to open public key file");
        exit(EXIT_FAILURE);
    }
    RSA *rsa = PEM_read_RSA_PUBKEY(fp, NULL, NULL, NULL);
    fclose(fp);
    return rsa;
}

static bool server_init(void)
{
    printf("Creating stream socket\n");
    mysock = socket(AF_INET, SOCK_STREAM, 0);
    if (mysock < 0) {
        perror("Socket creation failed");
        return false;
    }
    
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    server_addr.sin_port = htons(SERVER_PORT);
    
    if (bind(mysock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        return false;
    }
    
    if (listen(mysock, 5) < 0) {
        perror("Listen failed");
        return false;
    }
    
    printf("Server initialized and listening on port %d\n", SERVER_PORT);
    return true;
}

static bool handle_client(int sock)
{
    RSA *rsa_priv = load_private_key("private_server.pem");
    RSA *rsa_pub = load_public_key("public.pem");
    
    ssize_t bytes_read = recv(sock, encrypted, sizeof(encrypted), 0);
    if (bytes_read < 0) {
        perror("Failed to receive data");
        return false;
    }
    
    int decrypted_length = rsa_decrypt(rsa_priv, encrypted, decrypted);
    if (decrypted_length == -1) {
        perror("Failed to decrypt message");
        return false;
    }
    
    printf("Decrypted message: %s\n", decrypted);
    
    get_message(response, BUFFER_SIZE);
    
    int encrypted_length = rsa_encrypt(rsa_pub, response, encrypted);
    if (encrypted_length == -1) {
        perror("Failed to encrypt message");
        return false;
    }
    
    if (send(sock, encrypted, encrypted_length, 0) < 0) {
        perror("Failed to send data");
        return false;
    }
    
    RSA_free(rsa_priv);
    RSA_free(rsa_pub);
    
    return strcmp((char *)response, "quit") != 0;
}

static int rsa_encrypt(RSA *rsa, unsigned char *message, unsigned char *encrypted) {
    return RSA_public_encrypt(strlen((char *)message) + 1, message, encrypted, rsa, RSA_PKCS1_OAEP_PADDING);
}

static int rsa_decrypt(RSA *rsa, unsigned char *encrypted, unsigned char *decrypted) {
    return RSA_private_decrypt(RSA_size(rsa), encrypted, decrypted, rsa, RSA_PKCS1_OAEP_PADDING);
}
