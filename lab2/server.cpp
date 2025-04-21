#include "server.hpp"

int main(void)
{
    // Ensure active directory exists
    try
    {
        Server server(DEFAULT_SERVER_PORT, DEFAULT_VERSION);
        server.initialize();
        server.run();
    }
    catch (const std::exception &e)
    {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }
    return 0;
}