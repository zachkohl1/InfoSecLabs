#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>
#include <iostream>
#include <openssl/rand.h>
#include "aes.hpp"
using namespace std;

int encrypt(const unsigned char *plaintext, int plaintext_len, unsigned char * key, unsigned char *iv, unsigned char *ciphertext)
{
  EVP_CIPHER_CTX *ctx;
  int len;
  int ciphertext_len;

  if(!(ctx = EVP_CIPHER_CTX_new())) return -1;

  if(EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) return -1;
  
  if(EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) != 1) return -1;
  ciphertext_len = len;
  
  if(EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1) return -1;
  ciphertext_len += len;
  
  EVP_CIPHER_CTX_free(ctx);
  
  return ciphertext_len;
}

int decrypt(const unsigned char *ciphertext, int ciphertext_len, unsigned char * key, unsigned char *iv, unsigned char *plaintext)
{
  EVP_CIPHER_CTX *ctx;
  int len;
  int plaintext_len;

  if(!(ctx = EVP_CIPHER_CTX_new())) return -1;

  if(EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) return -1;
  
  if(EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len) != 1) return -1;
  plaintext_len = len;
  
  if(EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1) return -1;
  plaintext_len += len;
  
  EVP_CIPHER_CTX_free(ctx);
  
  return plaintext_len;
}