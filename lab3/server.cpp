/**********************************************
 *  Filename: TCP Server.c
 *  Description: Basic TCP comms
 *  Author: Bob Turney
 *  Date: 3/7/2024
 *  Note: gcc -o Server Server.c
 *        ./Client
 *        ./Server
 ***********************************************/
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
#include <iostream>
using namespace std;

// openssl genpkey -algorithm RSA -out private_server.pem -aes256
// openssl rsa -pubout -in private_server.pem -out public_server.pem
// Pass phraes: hello
// gcc -o client client.c -l ssl -l crypto

// define some constants
#define SERVER_HOST "localhost"
#define SERVER_IP "172.27.0.1" //"127.0.0.1" $hostname -I
#define BUFFER_SIZE 256
#define SERVER_PORT 1234    
#define PASSPHRASE "hello"

static unsigned char response[BUFFER_SIZE];
static struct sockaddr_in server_addr, client_addr;
static int mysock, csock, r;
static socklen_t len;
static EVP_PKEY *priv_key;
static EVP_PKEY *pub_key;


static bool handle_client(int client_sock);
static bool server_init(void);
static void log_message(const char *client_message, const char* server_response);
static bool load_keys(void);
static unsigned char* get_message(unsigned char* response, size_t size);

int main(void)
{
    bool no_error = true; 

    // Only copy the numbers as key
    if(!server_init())
    {
        printf("server init failed\n");
        return -1;
    }

    if(!load_keys())
    {
        printf("load keys failed\n");
        return -1;
    }

    if (priv_key != NULL) {
        printf("Private key loaded successfully. Size: %d\n", EVP_PKEY_size(priv_key));
    } else {
        printf("Failed to load private key\n");
        ERR_print_errors_fp(stderr);
    }
    
    if (pub_key != NULL) {
        printf("Public key loaded successfully. Size: %d\n", EVP_PKEY_size(pub_key));
    } else {
        printf("Failed to load public key\n");
        ERR_print_errors_fp(stderr);
    }

    while (no_error) // Try to accept a client request
    {
        printf("server: accepting new connection ...\n");
        len = sizeof(client_addr);
        csock = accept(mysock, (struct sockaddr *)&client_addr, &len);
        if (csock < 0)
        {
            printf("server accept error \n");
        }
        printf("server accepted a client connection from \n");
        // printf("Client: IP= %s port=%d", inet_ntoa(client_addr.sin_addr.s_addr), ntohs(client_addr.sin_port));
        printf("Client: IP= %s port=%d \n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));

        while (csock != -1 && no_error)
        {
            no_error = handle_client(csock);
        }
        return 0;
    }
}

static unsigned char* get_message(unsigned char* response, size_t size)
{
    printf("Enter response: ");
    fgets((char*)response, size, stdin);
    return response;
}

static bool load_keys(void)
{
    FILE *fp = fopen("private_server.pem", "r");
    if (!fp)
    {
        perror("Failed to open private key file\n");
        return false;
    }
    priv_key = PEM_read_PrivateKey(fp, NULL, NULL, (void*)PASSPHRASE);
    if (!priv_key)
    {
        perror("Failed to read private key\n");
        fclose(fp);
        return false;
    }
    fclose(fp);

    fp = fopen("public.pem", "r");
    if (!fp)
    {
        perror("Failed to open public key file\n");
        EVP_PKEY_free(priv_key);
        return false;
    }

    pub_key = PEM_read_PUBKEY(fp, NULL, NULL, (void*)PASSPHRASE);
    if (!pub_key)
    {
        perror("Failed to read public key\n");
        fclose(fp);
        EVP_PKEY_free(priv_key);
        return false;
    }
    fclose(fp);
    return true;
}

static bool server_init(void)
{
    printf("create stream socket\n");
    mysock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (mysock < 0)
    {
        printf("socket call failed\n");
    }
    printf("fill server address with host IP and Port number\n");
    server_addr.sin_family = AF_INET;
    // inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr);
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    server_addr.sin_port = htons(SERVER_PORT);
    printf("bind the socket\n");
    r = bind(mysock, (struct sockaddr *)&server_addr, sizeof(server_addr));
    if (r < 0)
    {
        printf("bind failed\n");
        return false;
    }
    printf("server is listening  ...\n");
    listen(mysock, 5); // queue length of 5
    printf("server init done\n");
    return true;
}

static bool handle_client(int client_sock)
{
    // Buffer to receive data from the client
    char buffer[BUFFER_SIZE];
    size_t bytes_read;

    // Receive the encrypted data from the client
    bytes_read = recv(client_sock, buffer, sizeof(buffer), 0);
    if (bytes_read == -1)
    {
        perror("Failed to receive from client");
        return false;
    }
    
    if(bytes_read == 0)
    {
        printf("Client disconnected\n");
        close(client_sock);
        return false;
    }

    // Decrypt the received data with the private key
    EVP_PKEY_CTX *ctx_dec = EVP_PKEY_CTX_new(priv_key, NULL);
    if(!ctx_dec)
    {
        perror("Failed to create context for decryption\n");
        return false;
    }

    if(EVP_PKEY_decrypt_init(ctx_dec) <= 0)
    {
        perror("Failed to initialize decryption\n");
        EVP_PKEY_CTX_free(ctx_dec);
        return false;
    }

    // Add after EVP_PKEY_decrypt_init
    if (EVP_PKEY_CTX_set_rsa_padding(ctx_dec, RSA_PKCS1_OAEP_PADDING) <= 0) {
        perror("Failed to set padding mode for decryption\n");
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(ctx_dec);
        return false;
    }
    // Determine the length of the decrypted data
    size_t decrypt_len;
    if(EVP_PKEY_decrypt(ctx_dec, NULL, &decrypt_len, (unsigned char *)(buffer), bytes_read) <= 0)
    {
        perror("Failed to determine decrypted length\n");
        EVP_PKEY_CTX_free(ctx_dec);
        return false;
    }

    // Allocate memory for decrypted data
    unsigned char *decrypted = (unsigned char *)malloc(decrypt_len);
    if(!decrypted)
    {
        perror("Failed to allocate memory for decrypted data\n");
        EVP_PKEY_CTX_free(ctx_dec);
        return false;
    }

    // Decrypt the data
    if(EVP_PKEY_decrypt(ctx_dec, decrypted, &decrypt_len, (unsigned char *)(buffer), bytes_read) <= 0)
    {
        perror("Failed to decrypt data\n");
        free(decrypted);
        EVP_PKEY_CTX_free(ctx_dec);
        return false;
    }

    decrypted[decrypt_len] = '\0'; // Null-terminate the decrypted string

    // Print the decrypted data
    printf("From client: %s\n", decrypted);

    if(strcmp((const char*)decrypted, "quit") == 0) // Check for exit command
    {
        printf("Client exit\n");
        log_message("quit", "quit");
        free(decrypted);
        EVP_PKEY_CTX_free(ctx_dec);
        close(client_sock);
        return false;
    }

    // Now get server's response
    if(strcmp((const char*)get_message(response, BUFFER_SIZE), "quit") == 0) // Check for exit command
    {
        printf("Server exit\n");
        free(decrypted);
        EVP_PKEY_CTX_free(ctx_dec);
        close(client_sock);
        return false;
    }

    // Remove newline if present
    size_t len = strlen((char *)response);
    if (len > 0 && response[len - 1] == '\n')
    {
        response[len - 1] = '\0';
    }

    // if (strcmp(reinterpret_cast<const char *>(decrypted), "quit") == 0) // Check for exit command
    // {
    //     printf("Client exit\n");
    //     free(decrypted);
    //     EVP_PKEY_CTX_free(ctx_dec);
    //     close(client_sock);
    //     return false;
    // }

    // Encrypt the response with the public key
    EVP_PKEY_CTX *ctx_enc = EVP_PKEY_CTX_new(pub_key, NULL);
    if (!ctx_enc)
    {
        perror("Failed to create context for encryption\n");
        free(decrypted);
        return false;
    }

    size_t encrypt_len;
    if (EVP_PKEY_encrypt_init(ctx_enc) <= 0)
    {
        perror("Failed to initialize encryption\n");
        free(decrypted);
        EVP_PKEY_CTX_free(ctx_enc);
        return false;
    }

    // Set OAEP padding
    if (EVP_PKEY_CTX_set_rsa_padding(ctx_enc, RSA_PKCS1_OAEP_PADDING) <= 0) {
        EVP_PKEY_CTX_free(ctx_enc);
        return false;
    }
    
    if (EVP_PKEY_encrypt(ctx_enc, NULL, &encrypt_len, (unsigned char *)(response), strlen((const char*)response)) <= 0)
    {
        perror("Failed to encrypt data\n");
        free(decrypted);
        EVP_PKEY_CTX_free(ctx_enc);
        return false;
    }

    unsigned char *encrypted = (unsigned char *)malloc(encrypt_len);
    if (!encrypted)
    {
        perror("Failed to allocate memory for encrypted data\n");
        free(decrypted);
        EVP_PKEY_CTX_free(ctx_enc);
        return false;
    }

    if (EVP_PKEY_encrypt(ctx_enc, encrypted, &encrypt_len, (unsigned char *)(response), strlen((const char*)response)) <= 0)
    {
        perror("Failed to encrypt data\n");
        free(decrypted);
        free(encrypted);
        EVP_PKEY_CTX_free(ctx_enc);
        return false;
    }

    // Log transaction
    log_message(reinterpret_cast<const char *>(decrypted), reinterpret_cast<const char *>(response));

    // Send the encrypted response back to the client
    send(client_sock, encrypted, encrypt_len, 0);
    printf("Sent encrypted response to client\n");

    free(decrypted);
    free(encrypted);
    EVP_PKEY_CTX_free(ctx_enc);
    EVP_PKEY_CTX_free(ctx_dec);
    return true;
}

static void log_message(const char *client_message, const char* server_response)
{
    time_t now = time(NULL);
    char *time_str = ctime(&now);
    time_str[strlen(time_str) - 1] = '\0'; // Remove newline character

    FILE *log_file = fopen("server_log.txt", "a");
    if (log_file != NULL)
    {
        fprintf(log_file, "[%s] Client: %s\n", time_str, client_message);
        fprintf(log_file, "[%s] Server: %s\n", time_str, server_response);
        fclose(log_file);
    }
}
