#ifndef MYDES_HPP
#define MYDES_HPP
#include <iostream>
#include <string>
#include <bitset>
#include <vector>
#include <cstring>
/*
 * Key differences from standard DES:
 * 1. Uses 64-bit key (standard DES uses 56-bit key with 8 parity bits)
 * 2. Implements 8 rounds (standard DES uses 16 rounds)
 * 3. Simplified key schedule
 * 4. No S-boxes (substitution boxes) - uses rotations instead
 * 5. Simplified permutation tables
 *
 * 
 * */

// Using 64-bit blocks for messages and key, same as standard DES block size
#define BLOCK_SIZE 64
#define KEY_SIZE 64
using Block = std::bitset<BLOCK_SIZE>;

class SimplifiedDES
{
private:
    // Number of rounds in the Feistel network
    // Standard DES uses 16 rounds, we use 8 for simplification while maintaining security
    static const int NUM_ROUNDS = 8;

    // Store round keys for encryption/decryption
    std::vector<Block> roundKeys;

    /*
     * DES Permutation table taken from standard DES
     */
    const int IP[KEY_SIZE] = {
        58, 50, 42, 34, 26, 18, 10, 2, // Row 1
        60, 52, 44, 36, 28, 20, 12, 4, // Row 2
        62, 54, 46, 38, 30, 22, 14, 6, // Row 3
        64, 56, 48, 40, 32, 24, 16, 8, // Row 4
        57, 49, 41, 33, 25, 17, 9, 1,  // Row 5
        59, 51, 43, 35, 27, 19, 11, 3, // Row 6
        61, 53, 45, 37, 29, 21, 13, 5, // Row 7
        63, 55, 47, 39, 31, 23, 15, 7  // Row 8
    };

    /*
     * DES Inverse Permutation table taken from standard DES
     */
    const int IP_INV[KEY_SIZE] = {
        40, 8, 48, 16, 56, 24, 64, 32, // Row 1
        39, 7, 47, 15, 55, 23, 63, 31, // Row 2
        38, 6, 46, 14, 54, 22, 62, 30, // Row 3
        37, 5, 45, 13, 53, 21, 61, 29, // Row 4
        36, 4, 44, 12, 52, 20, 60, 28, // Row 5
        35, 3, 43, 11, 51, 19, 59, 27, // Row 6
        34, 2, 42, 10, 50, 18, 58, 26, // Row 7
        33, 1, 41, 9, 49, 17, 57, 25   // Row 8
    };

    /*
     * Permutation function
     * Applies a permutation table to a block of bits
     * @param input: The input block to permute
     * @param table: The permutation table to use
     * @param size: Size of the permutation table
     * @return: Permuted block
     */
    Block permute(const Block &input, const int *table, int size)
    {
        Block result;
        for (int i = 0; i < size; i++)
        {
            // Subtract 1 from table value because table uses 1-based indexing
            result[i] = input[table[i] - 1];
        }
        return result;
    }

    /*
     * Round Key Generation
     * Creates unique key for each round through rotation
     *
     * @param masterKey: The original 64-bit key
     * @param round: Current round number (1-based)
     * @return: Generated round key
     */
    Block generateRoundKey(const Block &masterKey, int round)
    {
        Block roundKey = masterKey;
        // Rotate left by different amounts for each round
        // Using multiplication by 7 to ensure good bit mixing
        int shift = (round * 7) % 64;

        // Perform circular left shift
        Block temp = roundKey << shift;                     // left shift
        Block temp2 = roundKey >> (KEY_SIZE - shift);       // right shift

        // This effectively wraps around the bits that were shifted out.
        // Combine the two shifted parts
        return temp | temp2;
    }

    /*
     * f fucntion block
     * XOR and rotations for confusion and diffusion
     *
     * @param right: Right half of the block
     * @param roundKey: Key for current round
     * @return: Processed block
     */
    Block feistelFunction(Block right, Block roundKey)
    {
        // Step 1: XOR with round key (similar to standard DES)
        Block result = right ^ roundKey;

        // Step 2: Add confusion through bit manipulation
        // This replaces DES's S-boxes with simpler operations
        int shift1 = 3; // First rotation amount
        int shift2 = 5; // Second rotation amount
        Block temp1 = result << shift1;
        Block temp2 = result >> shift2;

        // Final mixing step
        result = temp1 ^ temp2 ^ roundKey;

        return result;
    }

public:
    /*
     * Key Schedule Generation
     * Generates all round keys from the master key
     * @param masterKey: The original 64-bit key
     */
    void generateKeys(const Block &masterKey)
    {
        roundKeys.clear();
        for (int i = 0; i < NUM_ROUNDS; i++)
        {
            roundKeys.push_back(generateRoundKey(masterKey, i + 1));
        }
    }

    /*
     * Encryption Function
     * Follows the basic DES structure:
     * 1. Initial permutation
     * 2. Multiple rounds of Feistel network
     * 3. Final permutation
     *
     * @param plaintext: 64-bit block to encrypt
     * @return: Encrypted 64-bit block
     */
    Block encrypt(Block plaintext)
    {
        // Step 1: Initial permutation
        Block state = permute(plaintext, IP, 64);

        // Step 2: Split into left and right halves (32 bits each)
        uint32_t left = (state >> 32).to_ulong();
        uint32_t right = (state & Block(0xFFFFFFFF)).to_ulong();

        // Step 3: Feistel rounds
        for (int i = 0; i < NUM_ROUNDS; i++)
        {
            uint32_t temp = right;
            // Apply Feistel function and XOR with left half
            Block f_result = feistelFunction(Block(right), roundKeys[i]);
            right = left ^ f_result.to_ulong();
            left = temp;
        }

        // Step 4: Combine the halves (with final swap)
        Block result(((uint64_t)right << 32) | left);

        // Step 5: Final permutation
        return permute(result, IP_INV, 64);
    }

    /*
     * Decryption Function
     * - Exact reverse of encryption process
     * - Uses the same structure but with round keys in reverse order
     *
     * @param ciphertext: 64-bit block to decrypt
     * @return: Decrypted 64-bit block
     */
    Block decrypt(Block ciphertext)
    {
        // Step 1: Initial permutation
        Block state = permute(ciphertext, IP, 64);

        // Step 2: Split into left and right halves
        uint32_t left = (state >> 32).to_ulong();
        uint32_t right = (state & Block(0xFFFFFFFF)).to_ulong();

        // Step 3: Feistel rounds in reverse order
        for (int i = NUM_ROUNDS - 1; i >= 0; i--)
        {
            uint32_t temp = right;
            Block f_result = feistelFunction(Block(right), roundKeys[i]);
            right = left ^ f_result.to_ulong();
            left = temp;
        }

        // Step 4: Combine the halves
        Block result(((uint64_t)right << 32) | (uint64_t)left);

        // Step 5: Final permutation
        return permute(result, IP_INV, 64);
    }
};

#endif