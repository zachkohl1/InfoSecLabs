# Compiler and flags
CXX = g++
CXXFLAGS = -Wall -Wextra -std=c++17
LIBS = -lssl -lcrypto

# Directories
SRC = .
ACTIVE = ./active
UPDATES = ./updates

# Source files
SERVER_V1_SRC = $(SRC)/server.cpp $(SRC)/aes.cpp $(SRC)/srp.cpp
SERVER_V2_SRC = $(SRC)/server_v2.cpp $(SRC)/aes.cpp $(SRC)/srp.cpp
CLIENT_V1_SRC = $(SRC)/client.cpp $(SRC)/aes.cpp $(SRC)/srp.cpp
CLIENT_V2_SRC = $(SRC)/client_v2.cpp $(SRC)/aes.cpp $(SRC)/srp.cpp

# Targets
all: active/client active/server updates/client_v2 updates/server_v2

# Version 1
active/server: $(SERVER_V1_SRC)
	mkdir -p $(ACTIVE)
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LIBS)

active/client: $(CLIENT_V1_SRC)
	mkdir -p $(ACTIVE)
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LIBS)

# Version 2
updates/server_v2: $(SERVER_V2_SRC)
	mkdir -p $(UPDATES)
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LIBS)

updates/client_v2: $(CLIENT_V2_SRC)
	mkdir -p $(UPDATES)
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LIBS)

# Clean
clean:
	# Remove everything in updates except .log files
	find $(UPDATES) -type f ! -name '*.log' -delete

	# Remove all .o, .sig, and top-level .log files (but not ones in active)
	rm -f *.o *.sig ./*.log

	# Remove binaries from active, but NOT transactions.log
	find $(ACTIVE) -type f ! -name 'transactions.log' -delete

.PHONY: all clean