#include "server.hpp"

int main() {
    try {
        Server server(8082, "2.0.0");
        server.initialize();
        server.run();
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }
    return 0;
}
