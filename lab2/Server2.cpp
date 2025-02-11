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
#include <time.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <map>
#include "aes.h"
#include <iostream>
#include <fstream>
#include <sstream>
using namespace std;

// define some constants
#define MAX 256
#define SERVER_HOST "localhost"
#define SERVER_IP "172.27.11.127" //"127.0.0.1" $hostname -I
#define BUFFER_SIZE 256
#define SERVER_PORT 8080

char line[BUFFER_SIZE];
static struct sockaddr_in server_addr, client_addr;
static int mysock, csock, r;
static socklen_t len;
static const unsigned char temp[32 + 1] = "01234567890123456789012345678901"; // 32 bytes key for AES-256
static unsigned char key[32];
map<string, double> accounts;

static void log_transaction(const char *acc, const char *action, double amt, double balance);
static void handle_client(int client_sock);
static int server_init();
static void initialize_accounts();
static void parse_transaction_log(const string &filename);

int main(void)
{
  // Only copy the numbers as key
  memcpy(key, temp, 32);
  initialize_accounts();
  server_init();
  
  while (1) // Try to accept a client request
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

    while(csock != -1) {handle_client(csock);}

    // while(1)
    // {
    //   //n = read(csock, line, MAX);
    //   if (csock >= 0) handle_client(csock);
    // }
  }
  return 0;
}

static int server_init()
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
  printf("bind the socket");
  r = bind(mysock, (struct sockaddr *)&server_addr, sizeof(server_addr));
  if (r < 0)
  {
    printf("bind failed\n");
  }
  printf("server is listening  ...\n");
  listen(mysock, 5); // queue length of 5
  printf("server init done\n");
  return 0;
}

static void log_transaction(const char *acc, const char *action, double amt, double balance)
{
  FILE *file = fopen("transactions.log", "a");
  if (!file) {
      perror("Failed to open transactions.log");
      return;
  }
  
  time_t now = time(NULL);
  struct tm *t = localtime(&now);
  char timestamp[32];
  
  // Format: YYYY-MM-DD HH:MM:SS
  strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", t);
  
  fprintf(file, "%s,%s,%s,%.2f,%.2f\n", timestamp, acc, action, amt, balance);
  fclose(file);
}

static void handle_client(int client_sock)
{
  char buffer[BUFFER_SIZE + EVP_MAX_IV_LENGTH], iv[EVP_MAX_IV_LENGTH];
  if(recv(client_sock, buffer, sizeof(buffer), 0) == -1)
  {
    perror("Failed to receive from client");
    return;
  }
  memcpy(iv, buffer, EVP_MAX_IV_LENGTH);
  char account[BUFFER_SIZE];
  decrypt((unsigned char *)buffer + EVP_MAX_IV_LENGTH, strlen(buffer) - EVP_MAX_IV_LENGTH, key, (unsigned char *)iv, (unsigned char *)account);
  account[strcspn(account, "\n")] = 0;

  while (1)
  {
    int recv_len = recv(client_sock, buffer, sizeof(buffer), 0);
    if (recv_len <= 0)
      break;

    memcpy(iv, buffer, EVP_MAX_IV_LENGTH);
    char command[BUFFER_SIZE];
    char response[BUFFER_SIZE];

    for(int i = 0; i < BUFFER_SIZE-1; i++)
    {
      response[i] = '\0';
      command[i] = '\0';
    }

    decrypt((unsigned char *)buffer + EVP_MAX_IV_LENGTH, recv_len - EVP_MAX_IV_LENGTH, key, (unsigned char *)iv, (unsigned char *)command);
    command[strcspn(command, "\n")] = 0;

    if (strncmp(command, "withdraw", 8) == 0)
    {
      printf("Withdraw command\n");
      printf("Account: %s\n", account);
      double amount = atof(command + 9);
      if (accounts[account] >= amount)
      {
        accounts[account] -= amount;
        sprintf(response, "Withdrawal accepted. New balance: $%.2f", accounts[account]);
        log_transaction(account, "withdraw", amount, accounts[account]);
      }
      else
      {
        strcpy(response, "Insufficient funds");
      }
    }
    else if (strncmp(command, "deposit", 7) == 0)
    {
      printf("Deposit command\n");
      printf("Account: %s\n", account);
      double amount = atof(command + 8);
      accounts[account] += amount;
      sprintf(response, "Deposit successful. New balance: $%.2f", accounts[account]);
      log_transaction(account, "deposit", amount, accounts[account]);
    }
    else if (strncmp(command, "balance", 7) == 0)
    {
      sprintf(response, "Your balance: $%.2f", accounts[account]);
      log_transaction(account, "balance", 0.00, accounts[account]);
    }
    else if(!strncmp(command, "exit", 4))
    {
      printf("Client exit\n");
      strcpy(response, "exit");
      send(client_sock, response, strlen(response), 0);
      exit(0);
    }
    else
    {
      strcpy(response, "Invalid command");
    }

    RAND_bytes((unsigned char *)iv, EVP_MAX_IV_LENGTH);
    char encrypted[BUFFER_SIZE + EVP_MAX_IV_LENGTH];
    int enc_len = encrypt((unsigned char *)response, strlen(response), key, (unsigned char *)iv, (unsigned char *)encrypted + EVP_MAX_IV_LENGTH);
    memcpy(encrypted, iv, EVP_MAX_IV_LENGTH);
    send(client_sock, encrypted, enc_len + EVP_MAX_IV_LENGTH, 0);
  }
  close(client_sock);
}

static void initialize_accounts() {
  FILE *file = fopen("transactions.log", "r");
  if (!file) {
      // File does not exist, create and initialize it
      file = fopen("transactions.log", "w");
      if (!file) {
          perror("Failed to create transactions.log");
          return;
      }
  } else {
      // Check if the file is empty
      fseek(file, 0, SEEK_END);
      if (ftell(file) > 0) {
          fclose(file);
          parse_transaction_log("transactions.log"); // Process existing transactions
          return;
      }
      fclose(file);
      
      // Reopen in write mode to initialize
      file = fopen("transactions.log", "w");
      if (!file) {
          perror("Failed to create transactions.log");
          return;
      }
  }

  // File is empty or newly created, initialize accounts
  fprintf(file, "Account Initialization:\n");
  fprintf(file, "2024-02-05 12:00:00,1,init,0.00,1000.00\n");
  fprintf(file, "2024-02-05 12:00:00,2,init,0.00,1500.00\n");
  fprintf(file, "2024-02-05 12:00:00,3,init,0.00,2000.00\n");

  if (fclose(file) != 0) {
      perror("Failed to close transactions.log");
      return;
  }

  parse_transaction_log("transactions.log"); // Process initialized accounts
}


static void parse_transaction_log(const string &filename)
 {
  ifstream file(filename);
  if (!file.is_open()) {
      cerr << "Error opening file: " << filename << endl;
      return;
  }

  string line, timestamp, account, action;
  double amount, balance;

  while (getline(file, line)) {
      stringstream ss(line);
      getline(ss, timestamp, ',');  // Timestamp
      getline(ss, account, ',');    // Account number
      getline(ss, action, ',');     // Action
      ss >> amount;                 // Amount
      ss.ignore();                   // Ignore comma
      ss >> balance;                 // Balance

      accounts[account] = balance; // Update with the latest balance
  }

  file.close();
}