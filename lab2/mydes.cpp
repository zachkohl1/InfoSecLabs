// The program implements a simplified DES encryption/decryption tool that:
// - Takes a 64-bit key (16 hex characters)
// - Processes messages in 64-bit blocks
// - Can encrypt ASCII text to hex
// - Can decrypt hex back to ASCII text

#include <sstream>
#include <iomanip>
#include <limits>
#include <vector>
#include "mydes.hpp"
using namespace std;

#define BLOCK_SIZE_HEX 16 // 16 hex characters = 64 bits

static void print_usage(void);
static bool validate_hex(const std::string &str);
static std::string ascii_to_hex(const std::string &ascii);
static std::string hex_to_ascii(const std::string &hex);
static std::string process_blocks(SimplifiedDES &des, const std::string &input_hex, bool is_encrypt);

static void print_usage(void)
{
    std::cout << "Usage:\n"
              << " ./sdes [-e|-d] [-k key] [-m message]\n"
              << "Options:\n"
              << " -e Encryption mode\n"
              << " -d Decryption mode\n"
              << " -k 64-bit key in hexadecimal (16 characters)\n"
              << " -m Message (ASCII text for encryption, hex characters for decryption)\n"
              << "If no options are provided, program will run in interactive mode.\n";
}

// Checks if string contains only valid hex characters (0-9, A-F, a-f)
// Returns false if empty or contains invalid characters
static bool validate_hex(const std::string &str)
{
    if (str.empty())
        return false;
    return str.find_first_not_of("0123456789ABCDEFabcdef") == std::string::npos;
}

// Converts each ASCII character to its 2-digit hex representation
// Example: "ABC" -> "414243"
static std::string ascii_to_hex(const std::string &ascii)
{
    std::stringstream hex_stream;
    hex_stream << std::hex << std::uppercase << std::setfill('0');

    for (char c : ascii)
    {
        hex_stream << std::setw(2) << static_cast<int>(static_cast<unsigned char>(c));
    }

    return hex_stream.str();
}

// Converts pairs of hex digits back to ASCII characters
// Example: "414243" -> "ABC"
// Throws exception if hex string is invalid or odd length
static std::string hex_to_ascii(const std::string &hex)
{
    std::string ascii;
    if (hex.length() % 2 != 0)
    {
        throw std::invalid_argument("Hex string must have even length");
    }

    for (size_t i = 0; i < hex.length(); i += 2)
    {
        std::string byte = hex.substr(i, 2);
        try
        {
            unsigned char chr = static_cast<unsigned char>(std::stoul(byte, nullptr, BLOCK_SIZE_HEX));
            ascii += chr;
        }
        catch (const std::exception &e)
        {
            throw std::invalid_argument("Invalid hex characters: " + byte);
        }
    }
    return ascii;
}

// Processes data in 64-bit blocks (16 hex characters)
// For encryption:
//   - Pads incomplete blocks with zeros
//   - Converts each block to binary
//   - Encrypts using DES algorithm
// For decryption:
//   - Requires exact 64-bit blocks
//   - Decrypts using DES algorithm
//   - Converts back to hex
static std::string process_blocks(SimplifiedDES &des, const std::string &input_hex, bool is_encrypt)
{
    std::stringstream output;

    // Validate input length for decryption
    if (!is_encrypt && input_hex.length() % BLOCK_SIZE_HEX != 0)
    {
        throw std::invalid_argument("Ciphertext length must be a multiple of 16 hex characters (64 bits)");
    }

    // Process each block
    for (size_t i = 0; i < input_hex.length(); i += BLOCK_SIZE_HEX)
    {
        // Extract block (pad with zeros if necessary for encryption only)
        std::string block = input_hex.substr(i, BLOCK_SIZE_HEX);
        if (is_encrypt && block.length() < BLOCK_SIZE_HEX)
        {
            block.append(BLOCK_SIZE_HEX - block.length(), '0');
        }

        try
        {
            // Convert hex string to binary block
            Block input(std::stoull(block, nullptr, BLOCK_SIZE_HEX));

            // Perform encryption or decryption
            Block processed = is_encrypt ? des.encrypt(input) : des.decrypt(input);

            // Convert output to hex string with leading zeros
            std::stringstream ss;
            ss << std::hex << std::uppercase << std::setfill('0')
               << std::setw(BLOCK_SIZE_HEX) << processed.to_ullong();
            output << ss.str();
        }
        catch (const std::exception &e)
        {
            throw std::runtime_error("Error processing block starting at position " +
                                     std::to_string(i) + ": " + e.what());
        }
    }

    return output.str();
}

// 1. User selects encryption or decryption mode
// 2. User enters 16-character hex key
// 3. For encryption:
//    - User enters ASCII text
//    - Text is converted to hex
//    - Each 64-bit block is encrypted
//    - Output is displayed in hex
// 4. For decryption:
//    - User enters hex ciphertext
//    - Each 64-bit block is decrypted
//    - Output is displayed in both hex and ASCII
int main(void)
{
    SimplifiedDES des;
    std::string key;
    std::string message;
    bool is_encrypt = true;
    bool command_line_mode = false;

    std::cout << "SimplifiedDES Encryption/Decryption Tool\n"
              << "----------------------------------------\n"
              << "Select mode:\n"
              << "1. Encryption\n"
              << "2. Decryption\n"
              << "Enter choice (1/2): ";

    int choice;
    std::cin >> choice;
    is_encrypt = (choice == 1);
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

    std::cout << "Enter key (16 hex characters): ";
    std::getline(std::cin, key);
    if (!validate_hex(key) || key.length() != BLOCK_SIZE_HEX)
    {
        std::cerr << "Error: Key must be 16 hexadecimal characters.\n";
        return 1;
    }

    std::cout << "Enter " << (is_encrypt ? "plaintext (ASCII)" : "ciphertext (hex characters)")
              << ": ";
    std::getline(std::cin, message);

    // Validate key
    if (!validate_hex(key) || key.length() != BLOCK_SIZE_HEX)
    {
        std::cerr << "Error: Key must be 16 hexadecimal characters.\n";
        return 1;
    }

    try
    {
        // Convert message to hex if in encryption mode
        std::string hex_message = is_encrypt ? ascii_to_hex(message) : message;

        // Validate hex message in decryption mode
        if (!is_encrypt)
        {
            if (!validate_hex(hex_message))
            {
                std::cerr << "Error: Ciphertext must be hexadecimal characters.\n";
                return 1;
            }
            if (hex_message.length() % BLOCK_SIZE_HEX != 0)
            {
                std::cerr << "Error: Ciphertext length must be a multiple of 16 hex characters (64 bits).\n";
                return 1;
            }
        }

        // Convert key to binary block and generate round keys
        Block masterKey(std::stoull(key, nullptr, BLOCK_SIZE_HEX));
        des.generateKeys(masterKey);

        // Process the message in blocks
        std::string output_hex = process_blocks(des, hex_message, is_encrypt);

        // Output results
        if (is_encrypt)
        {
            std::cout << "\nInput (plaintext): " << message << "\n";
            std::cout << "Input (hex): " << hex_message << "\n";
            std::cout << "Output (ciphertext) hex: " << output_hex << "\n";
            std::cout << "\nNote: When decrypting, use the entire ciphertext hex string.\n";
        }
        else
        {
            std::cout << "\nInput (ciphertext) hex: " << hex_message << "\n";
            std::cout << "Output (plaintext) hex: " << output_hex << "\n";
            std::cout << "Output (ASCII): " << hex_to_ascii(output_hex) << "\n";
        }
    }
    catch (const std::exception &e)
    {
        std::cerr << "Error processing data: " << e.what() << "\n";
        return 1;
    }
    return 0;
}