#ifndef AES_H
#define AES_H

int encrypt(const unsigned char *plaintext, int plaintext_len, unsigned char * key, unsigned char *iv, unsigned char *ciphertext);
int decrypt(const unsigned char *ciphertext, int ciphertext_len, unsigned char * key, unsigned char *iv, unsigned char *plaintext);

#endif