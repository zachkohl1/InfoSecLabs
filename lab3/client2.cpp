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

#define BUFFER_SIZE 512
#define SERVER_PORT 1111
#define SERVER_IP "172.27.0.1"

static unsigned char message[BUFFER_SIZE];
static unsigned char encrypted[BUFFER_SIZE];
static unsigned char decrypted[BUFFER_SIZE];
static struct sockaddr_in server_addr;
static int sock;

static RSA *load_private_key(const char *filename) {
    FILE *fp = fopen(filename, "r");
    if (!fp) {
        perror("Unable to open private key file");
        return NULL;
    }
    RSA *rsa = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    return rsa;
}

static RSA *load_public_key(const char *filename) {
    FILE *fp = fopen(filename, "r");
    if (!fp) {
        perror("Unable to open public key file");
        return NULL;
    }
    RSA *rsa = PEM_read_RSA_PUBKEY(fp, NULL, NULL, NULL);
    fclose(fp);
    return rsa;
}

static int rsa_encrypt(RSA *rsa, unsigned char *message, unsigned char *encrypted) {
    return RSA_public_encrypt(strlen((char *)message) + 1, message, encrypted, rsa, RSA_PKCS1_OAEP_PADDING);
}

static int rsa_decrypt(RSA *rsa, unsigned char *encrypted, unsigned char *decrypted) {
    return RSA_private_decrypt(RSA_size(rsa), encrypted, decrypted, rsa, RSA_PKCS1_OAEP_PADDING);
}

static void get_message(unsigned char* message, size_t size) {
    printf("Enter message: ");
    fgets((char*)message, size, stdin);
    size_t len = strlen((char*)message);
    if (len > 0 && message[len - 1] == '\n') {
        message[len - 1] = '\0';
    }
}

int main(void) {
    // Load RSA keys
    RSA *rsa_priv = load_private_key("private.pem");
    if (!rsa_priv) return -1;
    
    RSA *rsa_pub = load_public_key("public.pem");
    if (!rsa_pub) {
        RSA_free(rsa_priv);
        return -1;
    }

    // Create socket
    printf("Creating socket...\n");
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Socket creation failed");
        RSA_free(rsa_priv);
        RSA_free(rsa_pub);
        return -1;
    }

    // Set up server address
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    if (inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr) <= 0) {
        perror("Invalid address");
        close(sock);
        RSA_free(rsa_priv);
        RSA_free(rsa_pub);
        return -1;
    }

    // Connect to server
    printf("Connecting to server...\n");
    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Connection failed");
        close(sock);
        RSA_free(rsa_priv);
        RSA_free(rsa_pub);
        return -1;
    }

    printf("Connected to server\n");

    while (1) {
        // Get message from user
        get_message(message, BUFFER_SIZE);

        // Encrypt message
        int encrypted_length = rsa_encrypt(rsa_pub, message, encrypted);
        if (encrypted_length == -1) {
            perror("Encryption failed");
            break;
        }

        // Send encrypted message
        if (send(sock, encrypted, encrypted_length, 0) < 0) {
            perror("Send failed");
            break;
        }

        // Check if user wants to quit
        if (strcmp((char *)message, "quit") == 0) {
            printf("Quitting...\n");
            break;
        }

        // Receive encrypted response
        ssize_t bytes_read = recv(sock, encrypted, sizeof(encrypted), 0);
        if (bytes_read < 0) {
            perror("Receive failed");
            break;
        }

        // Decrypt response
        int decrypted_length = rsa_decrypt(rsa_priv, encrypted, decrypted);
        if (decrypted_length == -1) {
            perror("Decryption failed");
            break;
        }

        printf("Server response: %s\n", decrypted);
    }

    // Clean up
    close(sock);
    RSA_free(rsa_priv);
    RSA_free(rsa_pub);

    return 0;
}