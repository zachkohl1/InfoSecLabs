/**********************************************
 * Filename: SZH.cpp
 * Description: Simple Zach's Hash (SZH) implementation
 * Author: [Your Name]
 * Date: Spring 2025
 * Note: g++ -o SZH SZH.cpp
 *       ./SZH
 * Course: CPE-4800 Information Security
 * Lab: 5 - My Hash
 ***********************************************/
#include <iostream>     // For input/output operations
#include <iomanip>      // For formatting output (hexadecimal)
#include <cstring>      // For memcpy and string operations
#include <vector>       // For dynamic array storage of message and hash
using namespace std;

// Algorithm Constants
const int BLOCK_SIZE_BYTES = 64;          // 512 bits = 64 bytes
const int HASH_SIZE_BYTES = 32;           // 256 bits = 32 bytes
const int NUM_ROUNDS = 16;                // Number of rounds per block
const int WORD_SIZE_BYTES = 4;            // 32 bits = 4 bytes
const int WORDS_PER_BLOCK = 16;           // 512 bits / 32 bits = 16 words
const int LENGTH_SIZE_BITS = 64;          // Size of length field in bits
const int LENGTH_SIZE_BYTES = 8;          // 64 bits = 8 bytes
const int PADDED_MODULO_BITS = 512;       // Block size in bits
const int PADDED_TARGET_BITS = 448;       // Target length mod 512 before length
const int ROT_E = 3;                      // Rotation amount for e variable
const int ROT_A = 7;                      // Rotation amount for a variable
const uint8_t ONE_BIT = 0x80;             // Single '1' bit for padding

// Round constants: first 16 prime numbers as 32-bit values
static const uint32_t ROUND_CONSTANTS[NUM_ROUNDS] = {
    0x02, 0x03, 0x05, 0x07, 0x0B, 0x0D, 0x11, 0x13,
    0x17, 0x1D, 0x1F, 0x25, 0x29, 0x2B, 0x2F, 0x35
};

// Initial hash values: first 8 prime numbers as 32-bit values
// These form the initial 256-bit state
static const uint32_t H0[8] = {
    0x02, 0x03, 0x05, 0x07, 0x0B, 0x0D, 0x11, 0x13
};

/**
 * SZH Algorithm Description:
 * - Input: Variable length message
 * - Output: 256-bit (32-byte) hash
 * - Process:
 *   1. Pad message to multiple of 512 bits
 *   2. Split into 512-bit blocks
 *   3. Initialize 8 32-bit working variables (256 bits total)
 *   4. For each block:
 *      - Create 16-word message schedule
 *      - Perform 16 rounds of mixing with XOR and rotations
 *      - Update hash values
 *   5. Output final hash from working variables
 * 
 * Differences from SHA-256:
 * - Simpler bit alteration: Uses basic XOR and single rotations instead of 
 *   sigma functions and multiple operations
 * - Fewer rounds: 16 vs SHA-256's 64
 * - Simplified message schedule: Direct use of 16 words vs SHA-256's 64-word expansion
 * - Basic constants: First primes vs SHA-256's cube root-derived constants
 * - Less computational complexity: Fewer operations per round
 */

/**
 * @brief Performs a right rotation on a 32-bit value
 * @param x The value to rotate
 * @param n Number of bits to rotate right
 * @return Rotated value
 * Rotates bits right, wrapping around to the left side
 */
uint32_t rotr(uint32_t x, int n) {
    return (x >> n) | (x << (32 - n));
}

/**
 * @brief Computes the SZH hash of a message
 * @param message Input message as a string
 * @return Vector containing the 256-bit (32-byte) hash
 * Main hash function implementing the SZH algorithm
 */
vector<uint8_t> szh_hash(const string& message) {
    // Step 1: Padding the message
    uint64_t msg_len_bits = message.length() * 8;               // Original length in bits. Get the size.
    vector<uint8_t> padded_msg(message.begin(), message.end()); // Copy message
    
    // Append single '1' bit
    padded_msg.push_back(ONE_BIT);
    
    // Calculate total size including length field
    size_t unpadded_size_bits = (padded_msg.size() * 8); // Current size in bits
    size_t total_size_bits = unpadded_size_bits + LENGTH_SIZE_BITS; // Add length field
    
    // Pad with zeros until length is a multiple of 512 bits
    while (total_size_bits % PADDED_MODULO_BITS != 0) {
        padded_msg.push_back(0x00);
        total_size_bits += 8; // Each byte adds 8 bits
    }
    
    // If we overshot (went beyond next 512-bit boundary), add another block
    while ((padded_msg.size() * 8 - LENGTH_SIZE_BITS) % PADDED_MODULO_BITS != PADDED_TARGET_BITS) {
        padded_msg.push_back(0x00);
    }
    
    // Append original message length as 64-bit big-endian integer
    for (int i = LENGTH_SIZE_BYTES - 1; i >= 0; i--) {
        padded_msg.push_back((msg_len_bits >> (i * 8)) & 0xFF);
    }

    // Step 2: Initialize hash working variables with initial values
    uint32_t h[8]; // Declares the hash state array.
    memcpy(h, H0, sizeof(H0)); // Copy initial values to working array. Initializes the eight 32-bit variables with prime numbers (2, 3, 5, 7, 11, 13, 17, 19)

    // Step 3: Process message in 512-bit blocks
    // Loops over the padded message in 512-bit (64-byte) chunks
    for (size_t block = 0; block < padded_msg.size(); block += BLOCK_SIZE_BYTES) {
        uint32_t w[WORDS_PER_BLOCK]; // Message schedule array. Declares the 16-word schedule array.
        
        // Prepare the message schedule
        // Convert each 4 bytes into a 32-bit word (big-endian)
        for (int t = 0; t < WORDS_PER_BLOCK; t++) {
            size_t offset = block + t * WORD_SIZE_BYTES;
            w[t] = (padded_msg[offset] << 24) |
                   (padded_msg[offset + 1] << 16) |
                   (padded_msg[offset + 2] << 8) |
                   (padded_msg[offset + 3]);
        }

        // Initialize working variables for this block
        // Copies the current hash state into working variables (a, b, c, d, e, f, g, h) for this block.
        // Temp variables for the mixing rounds
        uint32_t a = h[0], b = h[1], c = h[2], d = h[3],
                 e = h[4], f = h[5], g = h[6], hh = h[7];

        // Step 4: Perform rounds of mixing
        for (int t = 0; t < NUM_ROUNDS; t++) {
            // Simple bit alteration operations
            // temp1: XOR of h with rotated e, plus message word and constant
            uint32_t temp1 = hh ^ rotr(e, ROT_E) + w[t] + ROUND_CONSTANTS[t];
            // temp2: XOR of rotated a with b
            uint32_t temp2 = rotr(a, ROT_A) ^ b;
            
            // Rotate working variables
            hh = g;
            g = f;
            f = e;
            e = d + temp1;  // Add temp1 to e
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;  // Combine temp values for new a
        }

        // Step 5: Update hash values by adding working variables
        h[0] += a; h[1] += b; h[2] += c; h[3] += d;
        h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
    }

    // Step 6: Produce final 256-bit hash
    vector<uint8_t> hash;
    for (int i = 0; i < 8; i++) {
        // Convert each 32-bit word to 4 bytes (big-endian)
        hash.push_back((h[i] >> 24) & 0xFF);
        hash.push_back((h[i] >> 16) & 0xFF);
        hash.push_back((h[i] >> 8) & 0xFF);
        hash.push_back(h[i] & 0xFF);
    }
    return hash;
}

/**
 * @brief Prints a hash value in hexadecimal format
 * @param hash Vector containing the hash bytes
 * Formats the 32-byte hash as 64 hexadecimal digits
 */
void print_hash(const vector<uint8_t>& hash) {
    cout << hex << setfill('0');  // Set output to hex with leading zeros
    for (uint8_t byte : hash) {
        cout << setw(2) << static_cast<int>(byte);
    }
    cout << dec << endl;  // Reset to decimal output
}

/**
 * @brief Main function to demonstrate SZH hash
 * Tests with predefined messages and provides interactive mode
 */
int main() {
    // Test messages of varying lengths
    vector<string> test_messages = {
        "Hello, CPE-4800!",                    // Medium length (128 bits)
        "This is a test message for SZH hash", // Longer message (280 bits)
        "This message is intentionally long to test multiple blocks in the SZH hash function" // Multi-block (680 bits)
    };

    // Print demonstration header
    cout << "SZH Hash Demonstration\n";
    cout << "=====================\n";

    // Process and display hashes for test messages
    for (const string& msg : test_messages) {
        cout << "Message: \"" << msg << "\"\n";
        cout << "Length: " << msg.length() * 8 << " bits\n";
        cout << "Hash: ";
        vector<uint8_t> hash = szh_hash(msg);
        print_hash(hash);
        cout << endl;
    }

    // Interactive mode for user input
    string input;
    cout << "Enter a message to hash (or 'quit' to exit): ";
    getline(cin, input);
    while (input != "quit") {
        cout << "Hash: ";
        vector<uint8_t> hash = szh_hash(input);
        print_hash(hash);
        cout << "\nEnter a message to hash (or 'quit' to exit): ";
        getline(cin, input);
    }

    return 0;
}