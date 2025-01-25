#include <openssl/sha.h>
#include <iostream>
#include <fstream>
#include <string>
#include <stdint.h>
#include <sstream>
#include <iomanip>
#include <random>
#include <chrono>
#include <regex>
#include <string.h>
using namespace std;

// Function prototypes
bool isValidPassword(const string& password);
static string sha256(const string& str);
static bool searchUser(const string& username, const string& encrypted_password);
static int generateRandomNumber(void);
static void encryptPasswordFile(void);
static void addUser(const string& username, const string& password, const string& encrypted_password);
static bool changePassword(const string& username, const string& old_password, const string& old_encrypted_password, const string& new_password, const string& new_encrypted_password);
/**
 * Requirements
 * 1. Your program will prompt the user for username and password. You will need to make a password.txt file to 
 *    login the first time with a known username and password.
 * 2. The program will check the username and password with a password file containing pairs of usernames and
 *    SHA256 encrypted passwords. 
 * 3. If a correct username and password is found then program prompts for a 6 digit code.
 *    If a correct username and password is not found the program exits.
 * 4. The program will produce a 6 digit code and display on the screen and ask the user to type in the code. 
 *    If successful, the application will be entered. If the 6 digit code is not successful the program exits.
 * 5. The application shall support 3 command line features; newuser, changepass, logout.
 * 6. The newuser feature shall allow any username and passwords that follow the rules of 8+, A, a, %, characters.
 * 7. The changepass feature shall change the password of the current user and follow the rules of 8+, A, a, %,
 *    characters.
 * 8. The logout feature shall end the program.

 */
#define PASSWORD_FILE "password.txt"
#define PASSWORD_ENCRYPTED_FILE "password_encrypted.txt"
#define RANDOM_NUMBER_LOWER_BOUND 100000
#define RANDOM_NUMBER_UPPER_BOUND 999999
#define DELIMITERS " "

int main(int argc, char* argv[])
{
    string username;
    string password;
    string encrypted_password;
    string command;
    int code;
    int user_code;
    bool user_found = false;
    // map<string, string> users;    // key = encrypted password, value = username

    // Encrypt the password file
    encryptPasswordFile();

    // Get username from user
    cout << "Enter username: ";
    cin >> username;

    // Get password from user
    cout << "Enter password: ";
    cin >> password;

    // Let's first encrypt the password with SHA256
    encrypted_password = sha256(password);

    // Search for the user in the encrypted password file
    user_found = searchUser(username, encrypted_password);

    // If a correct username and password is not found the program exits
    if(!user_found)
    {
        cout << "User not found." << endl;
        exit(EXIT_SUCCESS);
    }

    // If a correct username and password is found then program prompts for a 6 digit code. 
    code = generateRandomNumber();
    cout << "Your 6-digit code is: " << code << endl;

     // Prompt for user to type in  6 digit code
    cout << "Enter your 6-digit code: ";
    cin >> user_code;

    // If successful, the application will be entered. If the 6 digit code is not successful the program exits.
    if(user_code != code)
    {
        cout << "Invalid code." << endl;
        exit(EXIT_SUCCESS);
    }

    /*
    The newuser feature shall allow any username and passwords that follow the rules of 8+, A, a, %, characters.
    * 7. The changepass feature shall change the password of the current user and follow the rules of 8+, A, a, %,
    *    characters.
    * 8. The logout feature shall end the program.
    * 
    */

    for(;;)
    {
        cout << "Type 'newuser' to add a new user, 'changepass' to change your password, or 'logout' to exit: ";
        cin >> command;

        if(!command.compare("newuser"))
        {
            string new_username;
            string new_password;
            string new_encrypted_password;

            cout << "Enter new username: ";
            cin >> new_username;

            cout << "Enter new password: ";
            cin >> new_password;

            while(!isValidPassword(new_password))
            {
                cout << "Password must be at least 8 characters long with at least 1 uppercase letter, 1 lowercase letter, and 1 special character" << endl;
                cout << "Enter new password: ";
                cin >> new_password;
            }

            new_encrypted_password = sha256(new_password);

            addUser(new_username, new_password, new_encrypted_password);
            cout << "User added successfully." << endl;
        } 
        else if(!command.compare("changepass"))
        {
            string new_username;
            string new_password;
            string new_encrypted_password;

            cout << "Enter new password: ";
            cin >> new_password;

            while(!isValidPassword(new_password))
            {
                cout << "Password must be at least 8 characters long with at least 1 uppercase letter, 1 lowercase letter, and 1 special character" << endl;
                cout << "Enter new password: ";
                cin >> new_password;
            }
            new_encrypted_password = sha256(new_password);

            cout << "Password changed successfully." << endl;
            changePassword(username, password, encrypted_password, new_password, new_encrypted_password);
        } 
        else if(!command.compare("logout"))
        {
            cout << "Exiting program..." << endl;
            exit(EXIT_SUCCESS);
        }
    }
}


static bool searchUser(const string& username, const string& encrypted_password)
{
    ifstream password_encrypted_file(PASSWORD_ENCRYPTED_FILE);
    if(!password_encrypted_file.is_open())
    {
        cerr << "Error: Unable to open file " << PASSWORD_ENCRYPTED_FILE << endl;
        exit(EXIT_FAILURE);
    }

    string line;
    while(getline(password_encrypted_file, line))
    {
        // Split the line into username and encrypted password
        size_t delimiter_pos = line.find(DELIMITERS);
        if(delimiter_pos == string::npos) continue;

        string stored_username = line.substr(0, delimiter_pos);
        string stored_encrypted_password = line.substr(delimiter_pos + 1);

        // Check if username and encrypted password match
        if(stored_username == username && stored_encrypted_password == encrypted_password)
        {
            password_encrypted_file.close();

            return true;
        }
    }

    password_encrypted_file.close();
    return false;
}


static int generateRandomNumber(void)
{
    // Generate random 6-digit code
    random_device rd;
    mt19937 gen(rd());

    // Define the range for 6-digit numbers
    uniform_int_distribution<int> dist(RANDOM_NUMBER_LOWER_BOUND, RANDOM_NUMBER_UPPER_BOUND);

    // Generate the random number
    return(dist(gen));
}

static void encryptPasswordFile(void)
{
    ifstream password_file(PASSWORD_FILE);
    ofstream password_encrypted_file(PASSWORD_ENCRYPTED_FILE);
    string encrypted_password;

    if(!password_file.is_open())
    {
        cerr << "Error: Unable to open file " << PASSWORD_FILE << endl;
        exit(EXIT_FAILURE);
    }

    if(!password_encrypted_file.is_open())
    {
        cerr << "Error: Unable to open file " << PASSWORD_ENCRYPTED_FILE << endl;
        exit(EXIT_FAILURE);
    }

    string line;
    while(getline(password_file, line))
    {
        size_t pos = line.find(DELIMITERS);                     // find the delimiter
        string usr = line.substr(0, pos);                       // username is before the delimiter
        string password = line.substr(pos + 1);                 // password is after the delimiter

        // Encrypt the password with SHA256
        encrypted_password = sha256(password);

        // Write the encrypted password to the encrypted password file
        password_encrypted_file << usr << DELIMITERS << encrypted_password << endl;
    }

    password_file.close();
    password_encrypted_file.close();

}


static void addUser(const string& username, const string& password, const string& encrypted_password)
{
    ofstream password_file(PASSWORD_FILE, ios::app);
    ofstream password_encrypted_file(PASSWORD_ENCRYPTED_FILE, ios::app);

    if (!password_file.is_open())
    {
        cerr << "Error: Unable to open file " << PASSWORD_FILE << endl;
        exit(EXIT_FAILURE);
    }

    if (!password_encrypted_file.is_open())
    {
        cerr << "Error: Unable to open file " << PASSWORD_ENCRYPTED_FILE << endl;
        exit(EXIT_FAILURE);
    }

    // Append the new user to the password file
    password_file << username << DELIMITERS << password << endl;
    password_encrypted_file << username << DELIMITERS << encrypted_password << endl;

    password_file.close();
    password_encrypted_file.close();
}


static bool changePassword(const string& username, const string& old_password, const string& old_encrypted_password, const string& new_password, const string& new_encrypted_password)
{
    ifstream password_file(PASSWORD_FILE);
    ifstream password_encrypted_file(PASSWORD_ENCRYPTED_FILE);
    ofstream temp_password_file("temp_" PASSWORD_FILE);
    ofstream temp_encrypted_file("temp_" PASSWORD_ENCRYPTED_FILE);

    if (!password_file.is_open() || !password_encrypted_file.is_open() || !temp_password_file.is_open() || !temp_encrypted_file.is_open())
    {
        cerr << "Error: Unable to open necessary files." << endl;
        exit(EXIT_FAILURE);
    }

    string line;
    bool password_changed = false;

    // Process plain password file
    while (getline(password_file, line))
    {
        size_t pos = line.find(DELIMITERS);
        string stored_username = line.substr(0, pos);
        string stored_password = line.substr(pos + 1);

        if (stored_username == username && stored_password == old_password)
        {
            temp_password_file << username << DELIMITERS << new_password << endl;
            password_changed = true;
        }
        else
        {
            temp_password_file << line << endl;
        }
    }

    // Process encrypted password file
    while (getline(password_encrypted_file, line))
    {
        size_t pos = line.find(DELIMITERS);
        string stored_username = line.substr(0, pos);
        string stored_encrypted_password = line.substr(pos + 1);

        if (stored_username == username && stored_encrypted_password == old_encrypted_password)
        {
            temp_encrypted_file << username << DELIMITERS << new_encrypted_password << endl;
        }
        else
        {
            temp_encrypted_file << line << endl;
        }
    }

    password_file.close();
    password_encrypted_file.close();
    temp_password_file.close();
    temp_encrypted_file.close();

    // Replace old files with new files
    remove(PASSWORD_FILE);
    rename("temp_" PASSWORD_FILE, PASSWORD_FILE);
    remove(PASSWORD_ENCRYPTED_FILE);
    rename("temp_" PASSWORD_ENCRYPTED_FILE, PASSWORD_ENCRYPTED_FILE);

    return password_changed;
}
/**
 * @brief Computes the SHA-256 hash of a given string.
 *
 * This function takes an input string and computes its SHA-256 hash.
 * The resulting hash is returned as a string of characters.
 *
 * @param str The input string to be hashed.
 * @return A string representing the SHA-256 hash of the input string.
 */
static string sha256(const string &str) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, str.c_str(), str.size());
    SHA256_Final(hash, &sha256);

    // Convert binary hash to hex string
    std::stringstream hex_stream;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        hex_stream << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return hex_stream.str();
}

/**
 * @brief Checks if the given password is valid based on predefined criteria.
 *
 * This function validates the password by checking if it meets the following criteria:
 * - The password must be at least 8 characters long.
 *
 * @param password The password string to be validated.
 * @return true if the password is valid (i.e., meets the criteria), false otherwise.
 */
bool isValidPassword(const string &password) {
    regex pattern("^(?=.*[A-Z])(?=.*[a-z])(?=.*[^a-zA-Z0-9]).{8,}$");
    // Explanation:
    // ^               : Start of string
    // (?=.*[A-Z])      : Ensure at least one uppercase letter
    // (?=.*[a-z])      : Ensure at least one lowercase letter
    // (?=.*[^a-zA-Z0-9]): Ensure at least one special character (non-alphanumeric)
    // .{8,}            : Ensure at least 8 characters in total
    // $                : End of string

    return regex_match(password, pattern);
}