// srp.cpp - Secure Remote Password Protocol (SRP-6a) implementation
// The SRP protocol is a secure password-based authentication and key-exchange protocol.
// It allows a client to authenticate to a server without sending the password, protecting
// against eavesdropping and man-in-the-middle attacks. SRP-6a is an improved version that
// includes additional security checks.

#include "srp.hpp"
#include <sstream>
#include <iomanip>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <iostream>
#include <cstring>


/**
 * @brief Constructs an SRP object and initializes common parameters.
 *
 * This constructor initializes the Secure Remote Password (SRP) protocol parameters N, g, and k.
 * - N is a large safe prime standardized in RFC 5054.
 * - g is the generator modulo N, typically a small integer (set to 2).
 * - k is derived from the hash of N and g (k = H(N, g)), using SHA256.
 *   Padding is applied to g to match the length of N before hashing to ensure consistency.
 *
 * It allocates necessary BIGNUM structures for these parameters and performs
 * the required cryptographic hashing to compute k. Other SRP state variables
 * (like a, A, B, u, x, S, b, v) are initialized to nullptr.
 * A temporary BN_CTX is used for BIGNUM operations and freed upon completion.
 */
SRP::SRP() : N(nullptr), g(nullptr), k(nullptr), a(nullptr), A(nullptr), B(nullptr),
             u(nullptr), x(nullptr), S(nullptr), b(nullptr), v(nullptr)
{
    // Create a context for big number operations
    BN_CTX *ctx = BN_CTX_new();

    // Initialize N (safe prime) - Standardized in RFC 5054 for interoperability
    // Using a known safe prime ensures security and consistency across implementations
    N = BN_new();
    BN_hex2bn(&N, "EEAF0AB9ADB38DD69C33F80AFA8FC5E86072618775FF3C0B9EA2314C"
                  "9C256576D674DF7496EA81D3383B4813D692C6E0E0D5D8E250B98BE4"
                  "8E495C1D6089DAD15DC7D7B46154D6B6CE8EF4AD69B15D4982559B29"
                  "7BCF1885C529F566660E57EC68EDBC3C05726CC02FD4CBF4976EAA9A"
                  "FD5138FE8376435B9FC61D2FC0EB06E3");

    // Initialize g (generator) - Typically a small number like 2
    g = BN_new();
    BN_set_word(g, 2);

    // Initialize k = H(N, g) - Prevents attacks by ensuring the server public key is non-trivial
    k = BN_new();

    // Compute k = SHA256(N | g)
    // Convert N and g to bytes for hashing
    std::vector<uint8_t> N_bytes(BN_num_bytes(N));
    BN_bn2bin(N, N_bytes.data());

    std::vector<uint8_t> g_bytes(BN_num_bytes(g));
    BN_bn2bin(g, g_bytes.data());

    // Pad g_bytes to match N_bytes length for consistent hashing
    std::vector<uint8_t> padded_g_bytes(N_bytes.size(), 0);
    std::copy(g_bytes.begin(), g_bytes.end(), padded_g_bytes.end() - g_bytes.size());

    // Compute SHA256(N | g) to derive k
    SHA256_CTX sha_ctx;
    unsigned char k_hash[SHA256_DIGEST_LENGTH];

    SHA256_Init(&sha_ctx);
    SHA256_Update(&sha_ctx, N_bytes.data(), N_bytes.size());
    SHA256_Update(&sha_ctx, padded_g_bytes.data(), padded_g_bytes.size());
    SHA256_Final(k_hash, &sha_ctx);

    BN_bin2bn(k_hash, SHA256_DIGEST_LENGTH, k);

    // Clean up the big number context
    BN_CTX_free(ctx);
}

// Destructor: Frees all allocated big number resources to prevent memory leaks
SRP::~SRP()
{
    // Free each big number if it exists
    if (N)
        BN_free(N);
    if (g)
        BN_free(g);
    if (k)
        BN_free(k);
    if (a)
        BN_free(a);
    if (A)
        BN_free(A);
    if (B)
        BN_free(B);
    if (u)
        BN_free(u);
    if (x)
        BN_free(x);
    if (S)
        BN_free(S);
    if (b)
        BN_free(b);
    if (v)
        BN_free(v);
}


/**
 * @brief Generates a cryptographically secure random salt.
 *
 * This function creates a salt of a predefined length (SALT_LENGTH). It utilizes
 * OpenSSL's RAND_bytes function to fill a byte vector with cryptographically
 * secure random data. The generated salt bytes are then converted into a
 * hexadecimal string format for easier handling and storage.
 *
 * @return std::string A hexadecimal string representation of the generated salt.
 */
std::string SRP::generateSalt()
{
    // Allocate a vector for the salt (16 bytes as defined in SALT_LENGTH)
    std::vector<uint8_t> salt(SALT_LENGTH);
    // Use OpenSSL's secure random number generator
    RAND_bytes(salt.data(), SALT_LENGTH);
    // Convert the salt to a hexadecimal string for storage
    return bytes_to_hex(salt);
}


/**
 * @brief Generates the SRP verifier 'v' for a given user, password, and salt.
 *
 * This function implements the server-side calculation of the verifier 'v'
 * according to the Secure Remote Password (SRP) protocol. The verifier is
 * stored by the server instead of the plaintext password or a simple hash.
 *
 * The process involves:
 * 1. Deriving a private key 'x' from the username, password, and salt using
 *    nested SHA256 hashing: x = SHA256(salt | SHA256(username | ":" | password)).
 * 2. Computing the verifier 'v' using modular exponentiation: v = g^x % N,
 *    where 'g' is the generator and 'N' is the large safe prime modulus
 *    (predefined constants within the SRP class).
 *
 * @param username The user's identifier string.
 * @param password The user's password string.
 * @param salt_hex The salt value provided as a hexadecimal string. This salt
 *                 is typically generated uniquely for each user during registration.
 * @return std::string The calculated verifier 'v' represented as a hexadecimal string.
 *                     This value is intended to be stored on the server.
 */
std::string SRP::generateVerifier(const std::string &username, const std::string &password, const std::string &salt_hex)
{
    // Convert the salt from hex string to bytes
    std::vector<uint8_t> salt = hex_to_bytes(salt_hex);

    // Compute x = SHA256(salt | SHA256(username | ":" | password))
    // This derives a private key from the password and salt
    SHA256_CTX ctx;
    unsigned char hash_up[SHA256_DIGEST_LENGTH];

    // First hash: SHA256(username | ":" | password)
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, username.c_str(), username.length());
    SHA256_Update(&ctx, ":", 1);
    SHA256_Update(&ctx, password.c_str(), password.length());
    SHA256_Final(hash_up, &ctx);

    // Second hash: SHA256(salt | hash_up)
    unsigned char hash_x[SHA256_DIGEST_LENGTH];
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, salt.data(), salt.size());
    SHA256_Update(&ctx, hash_up, SHA256_DIGEST_LENGTH);
    SHA256_Final(hash_x, &ctx);

    // Compute v = g^x % N
    // The verifier v is the core value stored by the server
    BN_CTX *bn_ctx = BN_CTX_new();
    BIGNUM *x_bn = BN_new();
    BIGNUM *v_bn = BN_new();
    BIGNUM *g_bn = BN_new();
    BIGNUM *N_bn = BN_new();

    // Set g and N (same as constructor values)
    BN_hex2bn(&g_bn, "2");
    BN_hex2bn(&N_bn, "EEAF0AB9ADB38DD69C33F80AFA8FC5E86072618775FF3C0B9EA2314C"
                     "9C256576D674DF7496EA81D3383B4813D692C6E0E0D5D8E250B98BE4"
                     "8E495C1D6089DAD15DC7D7B46154D6B6CE8EF4AD69B15D4982559B29"
                     "7BCF1885C529F566660E57EC68EDBC3C05726CC02FD4CBF4976EAA9A"
                     "FD5138FE8376435B9FC61D2FC0EB06E3");

    // Convert x hash to BIGNUM
    BN_bin2bn(hash_x, SHA256_DIGEST_LENGTH, x_bn);

    // Compute v = g^x % N
    BN_mod_exp(v_bn, g_bn, x_bn, N_bn, bn_ctx);

    // Convert verifier to hex string
    char *v_hex = BN_bn2hex(v_bn);
    std::string result(v_hex);

    // Clean up OpenSSL resources
    OPENSSL_free(v_hex);
    BN_free(x_bn);
    BN_free(v_bn);
    BN_free(g_bn);
    BN_free(N_bn);
    BN_CTX_free(bn_ctx);

    return result;
}


/**
 * @brief Initializes the client side of the SRP authentication protocol.
 * 
 * This function performs the first step of the SRP (Secure Remote Password) protocol
 * from the client side. It:
 * 1. Stores the username
 * 2. Generates a random private key 'a' (256 bits)
 * 3. Computes a hash of username:password for later use in deriving x
 * 4. Computes the client's public key A = g^a % N
 * 
 * @param username The user identifier for authentication
 * @param password The user's secret password
 * @return true on successful initialization
 * 
 * @note The computed public key A will be sent to the server during the authentication process.
 * @note The function uses SHA-256 to hash the identity information.
 */
bool SRP::clientInit(const std::string &username, const std::string &password)
{
    // Store the username for later use
    username_ = username;

    // Generate a random private key 'a' (256 bits)
    a = BN_new();
    BN_rand(a, 256, -1, 0);

    // Compute SHA256(username | ":" | password) and store as hex
    // This is used later to derive x
    SHA256_CTX sha_ctx;
    unsigned char hash_up[SHA256_DIGEST_LENGTH];
    SHA256_Init(&sha_ctx);
    SHA256_Update(&sha_ctx, username.c_str(), username.length());
    SHA256_Update(&sha_ctx, ":", 1);
    SHA256_Update(&sha_ctx, password.c_str(), password.length());
    SHA256_Final(hash_up, &sha_ctx);
    identity_hash_ = bytes_to_hex(std::vector<uint8_t>(hash_up, hash_up + SHA256_DIGEST_LENGTH));

    // Compute A = g^a % N
    // A is the client's public key, sent to the server
    A = BN_new();
    BN_CTX *bn_ctx = BN_CTX_new();
    BN_mod_exp(A, g, a, N, bn_ctx);
    BN_CTX_free(bn_ctx);

    return true;
}

// Client Step 1: Returns the client's public key A as a hex string
std::string SRP::clientStep1()
{
    // Convert A to hex for transmission to the server
    return BN_to_hex(A);
}

// Client Step 2: Processes the server's response (salt and public key B)
// Computes the shared session key and client proof
/**
 * @brief Performs the second step of the client-side SRP-6a protocol.
 *
 * This function processes the server's response (salt and public ephemeral value B),
 * computes the scrambling parameter 'u', the private key 'x', the session key 'S',
 * the final shared key 'K', and the client proof 'M1'.
 *
 * @param salt_and_B A string containing the salt and the server's public ephemeral value B,
 *                   formatted as "salt_hex:B_hex".
 * @return true if the step was completed successfully and the client proof M1 was generated,
 *         false otherwise (e.g., invalid input format, B is invalid, memory allocation failure).
 *
 * @details
 * The function performs the following calculations:
 * 1. Parses salt and B from the input string.
 * 2. Converts B from hex to BIGNUM and validates it (B % N != 0).
 * 3. Computes u = H(A | B), where H is SHA256 and A, B are padded to the same length.
 * 4. Computes x = H(salt | H(username | ":" | password)). (Uses precomputed identity_hash_ for H(username | ":" | password)).
 * 5. Computes the client's session key S = (B - k * g^x) ^ (a + u * x) % N.
 * 6. Computes the final shared key K = H(S).
 * 7. Computes the client proof M1 = H(H(N) xor H(g) | H(username) | salt | A | B | K).
 *
 * It sets the member variables salt_hex_, B, u, x, S, K, and M1_.
 * Requires N, g, k, a, A, username_, and identity_hash_ to be previously set.
 */
bool SRP::clientStep2(const std::string &salt_and_B)
{
    // Parse the server's response: salt_hex:B_hex
    size_t sep = salt_and_B.find(':');
    if (sep == std::string::npos || sep == 0 || sep == salt_and_B.length() - 1)
    {
        std::cerr << "Invalid salt_and_B format\n";
        return false;
    }

    salt_hex_ = salt_and_B.substr(0, sep);
    std::string B_hex = salt_and_B.substr(sep + 1);

    // Convert server's public key B from hex to BIGNUM
    B = hex_to_BN(B_hex);
    if (!B)
    {
        std::cerr << "Failed to convert B_hex to BIGNUM\n";
        return false;
    }

    BN_CTX *bn_ctx = BN_CTX_new();
    if (!bn_ctx)
    {
        BN_free(B);
        B = nullptr;
        std::cerr << "Failed to create BN_CTX\n";
        return false;
    }

    // Verify B != 0 (mod N) to prevent invalid server keys
    BIGNUM *zero = BN_new();
    BN_zero(zero);
    BIGNUM *tmp = BN_new();
    BN_mod(tmp, B, N, bn_ctx);
    if (BN_cmp(tmp, zero) == 0)
    {
        BN_free(zero);
        BN_free(tmp);
        BN_free(B);
        B = nullptr;
        BN_CTX_free(bn_ctx);
        std::cerr << "B is zero modulo N\n";
        return false;
    }
    BN_free(zero);
    BN_free(tmp);

    // Compute u = SHA256(A | B)
    // u is a random scrambling parameter to prevent replay attacks
    u = BN_new();
    if (!u)
    {
        BN_free(B);
        B = nullptr;
        BN_CTX_free(bn_ctx);
        std::cerr << "Failed to allocate u\n";
        return false;
    }

    std::vector<uint8_t> A_bytes(BN_num_bytes(A));
    BN_bn2bin(A, A_bytes.data());
    std::vector<uint8_t> B_bytes(BN_num_bytes(B));
    BN_bn2bin(B, B_bytes.data());

    // Pad A and B to the same length for consistent hashing
    size_t max_len = std::max(A_bytes.size(), B_bytes.size());
    std::vector<uint8_t> padded_A_bytes(max_len, 0);
    std::vector<uint8_t> padded_B_bytes(max_len, 0);
    std::copy(A_bytes.begin(), A_bytes.end(), padded_A_bytes.end() - A_bytes.size());
    std::copy(B_bytes.begin(), B_bytes.end(), padded_B_bytes.end() - B_bytes.size());

    // Compute SHA256(A | B)
    SHA256_CTX sha_ctx;
    unsigned char u_hash[SHA256_DIGEST_LENGTH];
    SHA256_Init(&sha_ctx);
    SHA256_Update(&sha_ctx, padded_A_bytes.data(), padded_A_bytes.size());
    SHA256_Update(&sha_ctx, padded_B_bytes.data(), padded_B_bytes.size());
    SHA256_Final(u_hash, &sha_ctx);
    BN_bin2bn(u_hash, SHA256_DIGEST_LENGTH, u);

    // Compute x = SHA256(salt | SHA256(username | ":" | password))
    std::vector<uint8_t> salt = hex_to_bytes(salt_hex_);
    if (salt.empty())
    {
        BN_free(u);
        u = nullptr;
        BN_free(B);
        B = nullptr;
        BN_CTX_free(bn_ctx);
        std::cerr << "Invalid salt\n";
        return false;
    }
    std::vector<uint8_t> identity_bytes = hex_to_bytes(identity_hash_);
    if (identity_bytes.empty())
    {
        BN_free(u);
        u = nullptr;
        BN_free(B);
        B = nullptr;
        BN_CTX_free(bn_ctx);
        std::cerr << "Invalid identity hash\n";
        return false;
    }

    SHA256_CTX x_ctx;
    unsigned char x_hash[SHA256_DIGEST_LENGTH];
    SHA256_Init(&x_ctx);
    SHA256_Update(&x_ctx, salt.data(), salt.size());
    SHA256_Update(&x_ctx, identity_bytes.data(), identity_bytes.size());
    SHA256_Final(x_hash, &x_ctx);

    x = BN_new();
    if (!x)
    {
        BN_free(u);
        u = nullptr;
        BN_free(B);
        B = nullptr;
        BN_CTX_free(bn_ctx);
        std::cerr << "Failed to allocate x\n";
        return false;
    }
    BN_bin2bn(x_hash, SHA256_DIGEST_LENGTH, x);

    // Compute S = (B - k * g^x)^(a + u * x) % N
    // S is the shared session key
    S = BN_new();
    if (!S)
    {
        BN_free(x);
        x = nullptr;
        BN_free(u);
        u = nullptr;
        BN_free(B);
        B = nullptr;
        BN_CTX_free(bn_ctx);
        std::cerr << "Failed to allocate S\n";
        return false;
    }

    BIGNUM *gx = BN_new();
    BIGNUM *kgx = BN_new();
    BIGNUM *B_kgx = BN_new();
    BIGNUM *ux = BN_new();
    BIGNUM *a_ux = BN_new();

    if (!gx || !kgx || !B_kgx || !ux || !a_ux)
    {
        BN_free(gx);
        BN_free(kgx);
        BN_free(B_kgx);
        BN_free(ux);
        BN_free(a_ux);
        BN_free(S);
        S = nullptr;
        BN_free(x);
        x = nullptr;
        BN_free(u);
        u = nullptr;
        BN_free(B);
        B = nullptr;
        BN_CTX_free(bn_ctx);
        std::cerr << "Failed to allocate temporary BIGNUMs\n";
        return false;
    }

    // S = (B - k * g^x)^(a + u * x) % N
    BN_mod_exp(gx, g, x, N, bn_ctx);
    BN_mod_mul(kgx, k, gx, N, bn_ctx);
    BN_mod_sub(B_kgx, B, kgx, N, bn_ctx);
    BN_mod_mul(ux, u, x, N, bn_ctx);
    BN_mod_add(a_ux, a, ux, N, bn_ctx);
    BN_mod_exp(S, B_kgx, a_ux, N, bn_ctx);

    BN_free(gx);
    BN_free(kgx);
    BN_free(B_kgx);
    BN_free(ux);
    BN_free(a_ux);

    // Compute K = SHA256(S) (shared session key)
    K = calculateK();
    
    // Compute M1 (client proof) to send to the server
    M1_ = calculateM1(username_, salt_hex_, A, B, K);

    BN_CTX_free(bn_ctx);
    return true;
}


// Returns the client's proof (M1) to be sent to the server
std::string SRP::clientGetProof()
{
    return M1_;
}

// Client Step 3: Verifies the server's proof (M2)
/**
 * @brief Verifies the server's proof message (M2) received from the server.
 *
 * This function is called by the client after receiving the server's proof M2.
 * It calculates the expected M2 based on the client's current state (A, M1, K)
 * and compares it with the M2 received from the server.
 *
 * @param M2_hex A string containing the server's proof message (M2) in hexadecimal format.
 * @return true if the server's proof M2 is valid and matches the expected value, false otherwise.
 *         Returns false also if the client state (A, M1, or K) is not properly initialized before calling this function.
 * @note This function assumes that the client has already computed its public ephemeral value A,
 *       calculated its own proof M1, and derived the session key K.
 *       It prints error messages to std::cerr if the state is incomplete or verification fails,
 *       and a success message to std::cout if verification succeeds.
 */
bool SRP::clientVerifyServerProof(const std::string &M2_hex)
{
    if (!A || M1_.empty() || K.empty())
    {
        std::cerr << "Client state not ready for M2 verification (A, M1, or K missing)\n";
        return false;
    }
    // Calculate the expected M2 based on the current state
    std::string expected_M2 = calculateM2(A, M1_, K);

    // Compare the received M2 with the expected M2
    if (M2_hex != expected_M2)
    {
        std::cerr << "Server proof (M2) verification failed.\n";
        return false;
    }

    std::cout << "Server proof (M2) verified successfully.\n";
    return true;
}

// Initializes the server side of the SRP protocol
// Sets up the server with the user's verifier and salt
/**
 * @brief Initializes the server-side SRP protocol state.
 *
 * This function sets up the server's context for an SRP authentication attempt.
 * It stores the username and salt, converts the provided hex verifier into a BIGNUM,
 * generates a random private key 'b' for the server, and computes the server's
 * public key 'B' using the formula B = (k*v + g^b) % N.
 *
 * @param username The username of the client attempting to authenticate.
 * @param verifier_hex The client's verifier stored on the server, represented as a hexadecimal string.
 * @param salt_hex The salt associated with the client's verifier, represented as a hexadecimal string.
 * @return Always returns true upon completion. Note: Error handling for BIGNUM conversions or operations is not explicitly shown but might occur within the BIGNUM functions.
 */
bool SRP::serverInit(const std::string &username, const std::string &verifier_hex, const std::string &salt_hex)
{
    username_ = username;
    salt_hex_ = salt_hex;

    // Convert the stored verifier from hex to BIGNUM. Instead of storing the password
    v = hex_to_BN(verifier_hex);

    // Generate a random private key 'b' (256 bits)
    b = BN_new();
    BN_rand(b, 256, -1, 0);

    // Compute B = (k*v + g^b) % N
    // B is the server's public key
    B = BN_new();
    BN_CTX *ctx = BN_CTX_new();

    BIGNUM *kv = BN_new();
    BIGNUM *gb = BN_new();

    BN_mod_mul(kv, k, v, N, ctx);
    BN_mod_exp(gb, g, b, N, ctx);
    BN_mod_add(B, kv, gb, N, ctx);

    BN_free(kv);
    BN_free(gb);
    BN_CTX_free(ctx);

    return true;
}

// Server Step 1: Processes the client's public key A
// Returns salt and server public key B
/**
 * @brief Performs the server's first step in the SRP-6a protocol.
 *
 * This function receives the client's public ephemeral value A (as a hex string),
 * validates it (A mod N != 0), computes the scrambling parameter u = H(PAD(A) | PAD(B)),
 * calculates the server's session key S = (A * v^u)^b mod N, and derives the
 * shared secret key K = H(S). The padding ensures that A and B are the same length
 * before hashing.
 *
 * @param A_hex The client's public ephemeral value A, encoded as a hexadecimal string.
 * @return A string containing the server's salt (hex encoded) and public ephemeral
 *         value B (hex encoded), concatenated with a colon (":") in the format
 *         "salt_hex:B_hex". Returns an empty string if the client's public value A
 *         is invalid (A mod N == 0).
 */
std::string SRP::serverStep1(const std::string &A_hex)
{
    // Convert client's public key A from hex to BIGNUM
    A = hex_to_BN(A_hex);

    // Verify A != 0 (mod N) to prevent invalid client keys
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *zero = BN_new();
    BN_zero(zero);

    BIGNUM *tmp = BN_new();
    BN_mod(tmp, A, N, ctx);
    if (BN_cmp(tmp, zero) == 0)
    {
        BN_free(zero);
        BN_free(tmp);
        BN_CTX_free(ctx);
        return ""; // Invalid A
    }

    BN_free(zero);
    BN_free(tmp);

    // Compute u = SHA256(A | B)
    u = BN_new();
    std::vector<uint8_t> A_bytes(BN_num_bytes(A));
    BN_bn2bin(A, A_bytes.data());

    std::vector<uint8_t> B_bytes(BN_num_bytes(B));
    BN_bn2bin(B, B_bytes.data());

    size_t max_len = std::max(A_bytes.size(), B_bytes.size());
    std::vector<uint8_t> padded_A_bytes(max_len, 0);
    std::vector<uint8_t> padded_B_bytes(max_len, 0);

    std::copy(A_bytes.begin(), A_bytes.end(), padded_A_bytes.end() - A_bytes.size());
    std::copy(B_bytes.begin(), B_bytes.end(), padded_B_bytes.end() - B_bytes.size());

    SHA256_CTX sha_ctx;
    unsigned char u_hash[SHA256_DIGEST_LENGTH];

    SHA256_Init(&sha_ctx);
    SHA256_Update(&sha_ctx, padded_A_bytes.data(), padded_A_bytes.size());
    SHA256_Update(&sha_ctx, padded_B_bytes.data(), padded_B_bytes.size());
    SHA256_Final(u_hash, &sha_ctx);

    BN_bin2bn(u_hash, SHA256_DIGEST_LENGTH, u);

    // Compute S = (A * v^u)^b % N
    S = BN_new();
    BIGNUM *vu = BN_new();
    BIGNUM *Avu = BN_new();

    BN_mod_exp(vu, v, u, N, ctx);
    BN_mod_mul(Avu, A, vu, N, ctx);
    BN_mod_exp(S, Avu, b, N, ctx);

    BN_free(vu);
    BN_free(Avu);
    BN_CTX_free(ctx);

    // Compute K = SHA256(S)
    K = calculateK();

    // Return salt and B as "salt_hex:B_hex"
    return salt_hex_ + ":" + BN_to_hex(B);
}

// Server Step 2: Verifies the client's proof (M1)
// Computes the server's proof (M2)
/**
 * @brief Verifies the client's proof (M1) and computes the server's proof (M2).
 *
 * This function performs the second step of the SRP protocol on the server side.
 * It takes the M1 value received from the client, computes the expected M1 based
 * on the session's parameters (username, salt, A, B, K), and compares them.
 * If the received M1 matches the expected M1, it proceeds to compute the
 * server's proof M2 = SHA256(A | M1 | K) and stores it internally.
 *
 * @param M1_hex The client's proof M1, received as a hexadecimal string.
 * @return True if the client's M1 is valid and authentication can proceed,
 *         false otherwise (indicating an authentication failure).
 */
bool SRP::serverStep2(const std::string &M1_hex)
{
    // Compute the expected M1 for verification
    std::string expected_M1 = calculateM1(username_, salt_hex_, A, B, K);

    // Compare received M1 with expected M1
    if (M1_hex != expected_M1)
    {
        return false; // Authentication failed
    }

    // Compute M2 = SHA256(A | M1 | K)
    M2_ = calculateM2(A, M1_hex, K);

    return true;
}

// Returns the server's proof (M2) to be sent to the client
std::string SRP::serverGetProof()
{
    return M2_;
}

// Computes the shared session key K = SHA256(S)
/**
 * @brief Calculates the session key K.
 *
 * This function computes the session key K by taking the SHA256 hash of the shared secret S.
 * The shared secret S (a BIGNUM) is first converted into a byte vector.
 * Then, the SHA256 hash of this byte vector is calculated.
 *
 * @return std::vector<uint8_t> The calculated session key K as a byte vector (SHA256 hash of S).
 */
std::vector<uint8_t> SRP::calculateK()
{
    std::vector<uint8_t> S_bytes(BN_num_bytes(S));
    BN_bn2bin(S, S_bytes.data());

    SHA256_CTX sha_ctx;
    std::vector<uint8_t> K_bytes(SHA256_DIGEST_LENGTH);

    SHA256_Init(&sha_ctx);
    SHA256_Update(&sha_ctx, S_bytes.data(), S_bytes.size());
    SHA256_Final(K_bytes.data(), &sha_ctx);

    return K_bytes;
}

// Computes the client proof M1
// M1 = SHA256(SHA256(N) XOR SHA256(g) | SHA256(username) | salt | A | B | K)
/**
 * @brief Calculates the client's proof of the session key (M1) for SRP-6a.
 *
 * This function computes M1 according to the SRP-6a specification:
 * M1 = H(H(N) XOR H(g) | H(username) | salt | A | B | K)
 * where H is the SHA256 hash function, N and g are the SRP group parameters,
 * username is the user's identifier, salt is the user's salt, A is the client's
 * public ephemeral value, B is the server's public ephemeral value, and K is
 * the computed session key.
 *
 * @param username The user's identifier string.
 * @param salt_hex The user's salt value, provided as a hexadecimal string.
 * @param A A pointer to the BIGNUM representing the client's public ephemeral value.
 * @param B A pointer to the BIGNUM representing the server's public ephemeral value.
 * @param K A vector of bytes representing the session key computed by the client.
 * @return std::string The calculated M1 value, represented as a hexadecimal string.
 */
std::string SRP::calculateM1(const std::string &username, const std::string &salt_hex,
                             const BIGNUM *A, const BIGNUM *B, const std::vector<uint8_t> &K)
{
    SHA256_CTX sha_ctx;

    // Compute SHA256(N)
    unsigned char hash_N[SHA256_DIGEST_LENGTH];
    std::vector<uint8_t> N_bytes(BN_num_bytes(N));
    BN_bn2bin(N, N_bytes.data());

    SHA256_Init(&sha_ctx);
    SHA256_Update(&sha_ctx, N_bytes.data(), N_bytes.size());
    SHA256_Final(hash_N, &sha_ctx);

    // Compute SHA256(g)
    unsigned char hash_g[SHA256_DIGEST_LENGTH];
    std::vector<uint8_t> g_bytes(BN_num_bytes(g));
    BN_bn2bin(g, g_bytes.data());

    SHA256_Init(&sha_ctx);
    SHA256_Update(&sha_ctx, g_bytes.data(), g_bytes.size());
    SHA256_Final(hash_g, &sha_ctx);

    // Compute SHA256(N) XOR SHA256(g)
    unsigned char hash_Ng[SHA256_DIGEST_LENGTH];
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        hash_Ng[i] = hash_N[i] ^ hash_g[i];
    }

    // Compute SHA256(username)
    unsigned char hash_user[SHA256_DIGEST_LENGTH];
    SHA256_Init(&sha_ctx);
    SHA256_Update(&sha_ctx, username.c_str(), username.length());
    SHA256_Final(hash_user, &sha_ctx);

    // Convert salt to bytes
    std::vector<uint8_t> salt = hex_to_bytes(salt_hex);

    // Convert A and B to bytes
    std::vector<uint8_t> A_bytes(BN_num_bytes(A));
    BN_bn2bin(A, A_bytes.data());

    std::vector<uint8_t> B_bytes(BN_num_bytes(B));
    BN_bn2bin(B, B_bytes.data());

    // Compute M1
    unsigned char M1_hash[SHA256_DIGEST_LENGTH];
    SHA256_Init(&sha_ctx);
    SHA256_Update(&sha_ctx, hash_Ng, SHA256_DIGEST_LENGTH);
    SHA256_Update(&sha_ctx, hash_user, SHA256_DIGEST_LENGTH);
    SHA256_Update(&sha_ctx, salt.data(), salt.size());
    SHA256_Update(&sha_ctx, A_bytes.data(), A_bytes.size());
    SHA256_Update(&sha_ctx, B_bytes.data(), B_bytes.size());
    SHA256_Update(&sha_ctx, K.data(), K.size());
    SHA256_Final(M1_hash, &sha_ctx);

    return bytes_to_hex(std::vector<uint8_t>(M1_hash, M1_hash + SHA256_DIGEST_LENGTH));
}

// Computes the server proof M2
// M2 = SHA256(A | M1 | K)
/**
 * @brief Calculates the server's proof M2 in the SRP protocol.
 *
 * M2 is calculated as H(A | M1 | K), where H is the SHA256 hash function,
 * A is the client's public ephemeral value, M1 is the client's proof,
 * and K is the session key.
 *
 * @param A A pointer to a BIGNUM representing the client's public ephemeral value.
 * @param M1 A hexadecimal string representing the client's proof M1.
 * @param K A vector of bytes representing the session key K.
 * @return A hexadecimal string representing the server's proof M2.
 */
std::string SRP::calculateM2(const BIGNUM *A, const std::string &M1, const std::vector<uint8_t> &K)
{
    std::vector<uint8_t> A_bytes(BN_num_bytes(A));
    BN_bn2bin(A, A_bytes.data());

    std::vector<uint8_t> M1_bytes = hex_to_bytes(M1);

    SHA256_CTX sha_ctx;
    unsigned char M2_hash[SHA256_DIGEST_LENGTH];

    SHA256_Init(&sha_ctx);
    SHA256_Update(&sha_ctx, A_bytes.data(), A_bytes.size());
    SHA256_Update(&sha_ctx, M1_bytes.data(), M1_bytes.size());
    SHA256_Update(&sha_ctx, K.data(), K.size());
    SHA256_Final(M2_hash, &sha_ctx);

    return bytes_to_hex(std::vector<uint8_t>(M2_hash, M2_hash + SHA256_DIGEST_LENGTH));
}

// Utility functions for converting between BIGNUM and hex strings
std::string SRP::BN_to_hex(const BIGNUM *bn)
{
    char *hex = BN_bn2hex(bn);
    std::string result(hex);
    OPENSSL_free(hex);
    return result;
}

BIGNUM *SRP::hex_to_BN(const std::string &hex)
{
    BIGNUM *bn = nullptr;
    BN_hex2bn(&bn, hex.c_str());
    return bn;
}

std::vector<uint8_t> SRP::hex_to_bytes(const std::string &hex)
{
    std::vector<uint8_t> bytes;
    for (size_t i = 0; i < hex.length(); i += 2)
    {
        std::string byte_str = hex.substr(i, 2);
        uint8_t byte = static_cast<uint8_t>(std::stoi(byte_str, nullptr, 16));
        bytes.push_back(byte);
    }
    return bytes;
}

std::string SRP::bytes_to_hex(const std::vector<uint8_t> &bytes)
{
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (unsigned char byte : bytes)
    {
        ss << std::setw(2) << static_cast<int>(byte);
    }
    return ss.str();
}