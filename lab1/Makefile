CC=g++
CFLAGS=-c -Wall -g
LDFLAGS=-lssl -lcrypto
SOURCES=pswd.cpp
OBJECTS=$(SOURCES:.cpp=.o)
EXECUTABLE=login

all: $(SOURCES) $(EXECUTABLE) 

# pull in dependency info for *existing* .o files
-include $(OBJECTS:.o=.d)

$(EXECUTABLE): $(OBJECTS)
	$(CC) $(OBJECTS) $(LDFLAGS) -o $@

.cpp.o: 
	$(CC) $(CFLAGS) $< -o $@
	$(CC) -MM $< > $*.d

clean:
	rm -rf $(OBJECTS) $(EXECUTABLE) *.d
