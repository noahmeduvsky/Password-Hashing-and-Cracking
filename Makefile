# Makefile for building C password hash cracking implementations

CC = gcc
CFLAGS = -Wall -Wextra -O2 -fPIC
LDFLAGS = -shared -lssl -lcrypto
TARGET_SERIAL = libhash_cracker_serial.so
TARGET_MULTITHREADED = libhash_cracker_multithreaded.so
OBJ_SERIAL = hash_cracker_serial.o
OBJ_MULTITHREADED = hash_cracker_multithreaded.o

# Default target - build both
all: serial multithreaded

# Build single-threaded shared library
serial: $(OBJ_SERIAL)
	$(CC) $(OBJ_SERIAL) -o $(TARGET_SERIAL) $(LDFLAGS)

# Build object file for serial implementation
$(OBJ_SERIAL): hash_cracker_serial.c hash_cracker_serial.h
	$(CC) $(CFLAGS) -c hash_cracker_serial.c -o $(OBJ_SERIAL)

# Build multi-threaded shared library
multithreaded: hash_cracker_serial.o $(OBJ_MULTITHREADED)
	$(CC) hash_cracker_serial.o hash_cracker_multithreaded.o -o $(TARGET_MULTITHREADED) $(LDFLAGS) -lpthread

# Build object file for multithreaded implementation (depends on serial)
hash_cracker_multithreaded.o: hash_cracker_multithreaded.c hash_cracker_multithreaded.h hash_cracker_serial.h
	$(CC) $(CFLAGS) -c hash_cracker_multithreaded.c -o hash_cracker_multithreaded.o -pthread

# Clean build artifacts
clean:
	rm -f $(OBJ_SERIAL) hash_cracker_serial.o hash_cracker_multithreaded.o $(TARGET_SERIAL) $(TARGET_MULTITHREADED)

# Windows-specific targets
windows-serial:
	$(CC) $(CFLAGS) -shared hash_cracker_serial.c -o hash_cracker_serial.dll -lssl -lcrypto

.PHONY: all serial multithreaded clean windows-serial

