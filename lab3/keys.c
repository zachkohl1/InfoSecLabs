#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <stdio.h>

void generate_rsa_keys() {
    int bits = 2048;
    RSA *rsa = RSA_new();
    BIGNUM *e = BN_new();
    BN_set_word(e, RSA_F4);

    if (!RSA_generate_key_ex(rsa, bits, e, NULL)) {
        fprintf(stderr, "Failed to generate RSA key: %s\n", ERR_error_string(ERR_get_error(), NULL));
        return;
    }

    FILE *priv_file = fopen("private.pem", "wb");
    if (!priv_file) {
        perror("Failed to open private key file");
        return;
    }
    PEM_write_RSAPrivateKey(priv_file, rsa, NULL, NULL, 0, NULL, NULL);
    fclose(priv_file);

    FILE *pub_file = fopen("public.pem", "wb");
    if (!pub_file) {
        perror("Failed to open public key file");
        return;
    }
    PEM_write_RSAPublicKey(pub_file, rsa);
    fclose(pub_file);

    RSA_free(rsa);
    BN_free(e);
    printf("RSA key pair generated successfully.\n");
}

int main() {
    generate_rsa_keys();
    return 0;
}
