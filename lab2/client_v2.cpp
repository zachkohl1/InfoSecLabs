#include "client.hpp"

int main(void)
{
    try {
        Client client(DEFAULT_SERVER_IP, 8082, "2.0.0");
        client.initialize();
        client.run();
    } catch (const std::exception &e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }
    return 0;
}