// srp.hpp - Secure Remote Password Protocol implementation

#ifndef SRP_HPP
#define SRP_HPP

#include <string>
#include <vector>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <cstdint>

// SRP-6a implementation
class SRP {
public:
    SRP();
    ~SRP();

    // Client functions
    bool clientInit(const std::string& username, const std::string& password);
    std::string clientStep1(); // Returns A as hex string
    bool clientStep2(const std::string& salt_and_B); // Returns true if authentication succeeded
    std::string clientGetProof(); // Returns M1 proof value

    // Server functions
    bool serverInit(const std::string& username, const std::string& verifier_hex, const std::string& salt_hex);
    std::string serverStep1(const std::string& A_hex); // Returns salt + B as hex string
    bool serverStep2(const std::string& M1_hex); // Verifies client proof, returns true if valid
    std::string serverGetProof(); // Returns M2 proof value
    bool clientVerifyServerProof(const std::string &M2_hex);


    // Utility functions for registration
    static std::string generateSalt();
    static std::string generateVerifier(const std::string& username, const std::string& password, const std::string& salt);
    std::string calculateM2(const BIGNUM* A, const std::string& M1, const std::vector<uint8_t>& K);

private:
    // Constants
    static const int SALT_LENGTH = 16;  // Salt length in bytes
    static const int KEY_LENGTH = 32;   // Session key length in bytes

    // Variables for both client and server
    BIGNUM* N; // Safe prime
    BIGNUM* g; // Generator
    BIGNUM* k; // Multiplier parameter
    
    // Client variables
    BIGNUM* a; // Client private key
    BIGNUM* A; // Client public key
    BIGNUM* B; // Server public key
    BIGNUM* u; // Random scrambling parameter
    BIGNUM* x; // Private key derived from password and salt
    BIGNUM* S; // Session key
    
    // Server variables
    BIGNUM* b; // Server private key
    BIGNUM* v; // Password verifier
    
    // Common data
    std::string username_;
    std::string salt_hex_;
    std::vector<uint8_t> K; // Shared session key
    std::string M1_; // Client proof
    std::string M2_; // Server proof
    
    // Utility methods
    std::vector<uint8_t> calculateK();
    std::string calculateM1(const std::string& username, const std::string& salt_hex, 
                          const BIGNUM* A, const BIGNUM* B, const std::vector<uint8_t>& K);
                          
    std::string identity_hash_; // Hashed username:password
    // Conversion helpers
    static std::string BN_to_hex(const BIGNUM* bn);
    static BIGNUM* hex_to_BN(const std::string& hex);
    static std::vector<uint8_t> hex_to_bytes(const std::string& hex);
    static std::string bytes_to_hex(const std::vector<uint8_t>& bytes);
};

#endif // SRP_HPP