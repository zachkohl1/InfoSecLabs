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

// openssl genpkey -algorithm RSA -out private.pem -aes256
// openssl rsa -pubout -in private.pem -out public.pem
// Pass phraes: hello
// gcc -o client client.c -l ssl -l crypto

// define some constants 
#define SERVER_IP "172.27.0.1" //"127.0.0.1" $hostname -I
#define BUFFER_SIZE 256
#define SERVER_PORT 1234
#define PASSPHRASE "hello"

static struct sockaddr_in server_addr;
static int sock, bytes_read;
static unsigned char buffer[BUFFER_SIZE];
static unsigned char message[BUFFER_SIZE];
static EVP_PKEY *priv_key;
static EVP_PKEY *pub_key;

static int client_init(void);
static bool communicate_with_server(int sock);
static bool load_keys(void);
static unsigned char* get_message(unsigned char* response, size_t size);

int main (void)
{
    sock = client_init();
    if (sock < 0)
    {
        printf("client init failed\n");
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
    bool done = true;
    while(done)
    {
        get_message(message, BUFFER_SIZE);

        // Remove newline if present
        size_t len = strlen((char*)message);
        if (len > 0 && message[len - 1] == '\n') {
            message[len - 1] = '\0';
        }
    
        done = communicate_with_server(sock);  // Return false if "quit" is received from the server
    }

    return 0;
}

static unsigned char* get_message(unsigned char* response, size_t size)
{
    printf("Enter message: ");
    fgets((char*)response, size, stdin);
    return response;
}

static bool load_keys(void)
{
    FILE *fp = fopen("private.pem", "r");
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

    fp = fopen("public_server.pem", "r");
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

static int client_init(void)
{
  int sock;
  printf("create stream socket\n");
  sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (sock < 0)
  {
    printf("socket call failed\n");
    return -1;
  }
  printf("fill server address with host IP and Port number\n");
  server_addr.sin_family = AF_INET;
  inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr);

  //server_addr.sin_addr.s_addr = htonl(INADDR_ANY);//**********
  server_addr.sin_port = htons(SERVER_PORT);
  bytes_read = connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr));
  if (bytes_read < 0)
  {
    printf("connect failed\n");
  }
  printf("connected ok  ...\n");
  
  printf("client init done\n");
  return sock;
}


static bool communicate_with_server(int sock)
{
    // First encrypt and send the message with public key
    EVP_PKEY_CTX *ctx_enc = EVP_PKEY_CTX_new(pub_key, NULL);
    if (!ctx_enc)
    {
        perror("Failed to create context for encryption\n");
        return false;
    }

    size_t encrypt_len;
    if (EVP_PKEY_encrypt_init(ctx_enc) <= 0)
    {
        perror("Failed to initialize encryption\n");
        EVP_PKEY_CTX_free(ctx_enc);
        return false;
    }

    // Set OAEP padding
    if (EVP_PKEY_CTX_set_rsa_padding(ctx_enc, RSA_PKCS1_OAEP_PADDING) <= 0) {
        EVP_PKEY_CTX_free(ctx_enc);
        return false;
    }
    
    if (EVP_PKEY_encrypt(ctx_enc, NULL, &encrypt_len, (unsigned char*)message, strlen((const char*)message)) <= 0)
    {
        perror("Failed to encrypt data\n");
        EVP_PKEY_CTX_free(ctx_enc);
        return false;
    }
    
    unsigned char *encrypted = (unsigned char *)malloc(encrypt_len);
    if (!encrypted)
    {
        perror("Failed to allocate memory for encrypted data\n");
        EVP_PKEY_CTX_free(ctx_enc);
        return false;
    }

    if (EVP_PKEY_encrypt(ctx_enc, encrypted, &encrypt_len, (unsigned char*)message, strlen((const char*)message)) <= 0)
    {
        perror("Failed to encrypt data\n");
        EVP_PKEY_CTX_free(ctx_enc);
        free(encrypted);
        return false;
    }

    printf("Original message length: %zu\n", strlen((const char*)message));
    printf("Encrypted length: %zu\n", encrypt_len);

    // Send the encrypted data to the server
    if (send(sock, encrypted, encrypt_len, 0) < 0) {
        perror("Failed to send data\n");
        free(encrypted);
        EVP_PKEY_CTX_free(ctx_enc);
        return false;
    }
    free(encrypted);
    EVP_PKEY_CTX_free(ctx_enc);

    if(strcmp(reinterpret_cast<const char *>(message), "quit") == 0) // Check for exit command
    {
        printf("Client exit\n");
        close(sock);
        return false;
    }

    // Now wait for server response
    bytes_read = recv(sock, buffer, BUFFER_SIZE, 0);
    if (bytes_read <= 0)
    {
        perror("Failed to receive server response\n");
        return false;
    }

    // Decrypt the received data wth the private key
    EVP_PKEY_CTX *ctx_dec = EVP_PKEY_CTX_new(priv_key, NULL);
    if (!ctx_dec)
    {
        perror("Failed to create context for decryption");
        return false;
    }

    if (EVP_PKEY_decrypt_init(ctx_dec) <= 0)
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

    size_t decrypt_len;
    if (EVP_PKEY_decrypt(ctx_dec, NULL, &decrypt_len, (unsigned char *)(buffer), bytes_read) <= 0)
    {
        perror("Failed to determine decrypted length\n");
        EVP_PKEY_CTX_free(ctx_dec);
        return false;
    }

    unsigned char *decrypted = (unsigned char *)malloc(decrypt_len);
    if (!decrypted)
    {
        perror("Failed to allocate memory for decrypted data\n");
        EVP_PKEY_CTX_free(ctx_dec);
        return false;
    }

    if (EVP_PKEY_decrypt(ctx_dec, decrypted, &decrypt_len, (unsigned char *)(buffer), bytes_read) <= 0)
    {
        perror("Failed to decrypt data\n");
        free(decrypted);
        EVP_PKEY_CTX_free(ctx_dec);
        return false;
    }

    decrypted[decrypt_len] = '\0'; // Null-terminate the decrypted string

    printf("Server response: %s\n", decrypted);

    if(strcmp(reinterpret_cast<const char *>(decrypted), "quit") == 0) // Check for exit command
    {
        printf("Client exit\n");
        free(decrypted);
        EVP_PKEY_CTX_free(ctx_dec);
        close(sock);
        return false;
    }
    
    bool continue_running = (strcmp(reinterpret_cast<const char *>(decrypted), "quit") != 0);
    
    free(decrypted);
    EVP_PKEY_CTX_free(ctx_dec);
    return continue_running;
}
