/**********************************************
*  Filename: TCP Client.c
*  Description: Basic TCP comms
*  Author: Bob Turney
*  Date: 3/7/2024
*  Note: gcc -o Client Client.c
*        ./Client
*        ./Server
***********************************************/  
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <iostream>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include "aes.h"
using namespace std;

// define some constants 
#define MAX 256
#define SERVER_HOST "localhost"
#define SERVER_IP "172.27.11.127" //"127.0.0.1" $hostname -I
#define BUFFER_SIZE 256
#define SERVER_PORT 8080

static struct sockaddr_in server_addr;
static int sock, r;
static const unsigned char temp[32 + 1] = "01234567890123456789012345678901";   // 32 bytes key for AES-256
static unsigned char key[32];
// Copy only the numbers as key?

static int client_init(void);
static void communicate_with_server(int sock);

int main (void)
{
  // Only copy the numbers as key
  memcpy(key, temp, 32);

  sock = client_init();
  communicate_with_server(sock);
  return 0;
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
  printf("connect to server");
  r = connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr));
  if (r<0)
  {
    printf("connect failed\n");
  }
  printf("connected ok  ...\n");
  
  printf("client init done\n");
  return sock;
}



static void communicate_with_server(int sock)
{  
  unsigned char buffer[BUFFER_SIZE];
  unsigned char encrypted[BUFFER_SIZE];
  unsigned char iv[EVP_MAX_IV_LENGTH];
  char command[BUFFER_SIZE];
  char account_number[BUFFER_SIZE];

  printf("Enter account number: ");
  fgets(account_number, sizeof(account_number), stdin);
  account_number[strcspn(account_number, "\n")] = '\0';

  RAND_bytes(iv, EVP_MAX_IV_LENGTH);
  int encrypted_length = encrypt((unsigned char*)account_number, strlen(account_number), (unsigned char*)key, iv, encrypted + EVP_MAX_IV_LENGTH);
  memcpy(encrypted, iv, EVP_MAX_IV_LENGTH);
  send(sock, encrypted, encrypted_length + EVP_MAX_IV_LENGTH, 0);

  while (1)
  {
    for(int i = 0; i < BUFFER_SIZE-1; i++)
    {
      command[i] = '\0';
    }
    printf("Enter command (withdraw <amount>, deposit <amount>, balance, exit: ");
    fgets(command, sizeof(command), stdin);
    command[strcspn(command, "\n")] = '\0';

    // if(!strcmp(command, "exit"))
    // {
    //   printf("Exiting...\n");
    //   return;
    // }

    RAND_bytes(iv, EVP_MAX_IV_LENGTH);
    encrypted_length = encrypt((unsigned char*)command, strlen(command), (unsigned char*)key, iv, encrypted + EVP_MAX_IV_LENGTH);
    memcpy(encrypted, iv, EVP_MAX_IV_LENGTH);
    if(send(sock, encrypted, encrypted_length + EVP_MAX_IV_LENGTH, 0) == -1)
    {
      perror("Failed to send to server");
      return;
    }

    int n = read(sock, buffer, sizeof(buffer));
    if(n < 0)
    {
      printf("Error reading from socket\n");
      return;
    }

    memcpy(iv, buffer, EVP_MAX_IV_LENGTH);
    int decrypted_length = decrypt(buffer + EVP_MAX_IV_LENGTH, n - EVP_MAX_IV_LENGTH, (unsigned char*)key, iv, buffer);
    buffer[decrypted_length] = '\0';
    printf("Server response: %s\n", buffer);

    if(!strncmp((char*)buffer, "exit", 4))
    {
      printf("Exiting...\n");
      return;
    }

  }

}