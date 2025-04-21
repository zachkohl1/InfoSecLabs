# Makefile for Client/Server/LoadBalancer Example (POSIX/Linux)
CXX = g++
# CXXFLAGS: -std=c++11 or later, -Wall/-Wextra for warnings, -pthread for std::thread linking, -g for debug symbols
CXXFLAGS = -std=c++11 -Wall -Wextra -pthread -g
LDFLAGS = # Typically empty unless linking other specific libraries

# Target executables (no .exe extension)
TARGETS = client server loadbalancer

# Default target
all: $(TARGETS)

# Rule to build client
client: client.cpp common.h
	$(CXX) $(CXXFLAGS) client.cpp -o $@ $(LDFLAGS)

# Rule to build server
server: server.cpp common.h
	$(CXX) $(CXXFLAGS) server.cpp -o $@ $(LDFLAGS)

# Rule to build loadbalancer
loadbalancer: loadbalancer.cpp common.h
	$(CXX) $(CXXFLAGS) loadbalancer.cpp -o $@ $(LDFLAGS)

# Clean target
clean:
	rm -f $(TARGETS) *.o

# Phony targets (targets that aren't files)
.PHONY: all clean