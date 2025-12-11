// Header file for single-threaded C password hash cracking implementation

#ifndef HASH_CRACKER_SERIAL_H
#define HASH_CRACKER_SERIAL_H

#include <stdint.h>

// Hash a password with optional salt using SHA-256
int hash_password(const char* password, const char* salt, char* output);

// Check if a password matches the target hash
int check_password(const char* password, const char* target_hash, const char* salt);

// Brute-force crack a password hash
int brute_force_crack(
    const char* target_hash,
    const char* character_set,
    int max_length,
    uint64_t max_attempts,
    const char* salt,
    char* found_password,
    uint64_t* attempts
);

// Dictionary attack on a password hash
int dictionary_attack(
    const char* target_hash,
    const char** wordlist,
    int wordlist_size,
    const char* salt,
    char* found_password,
    uint64_t* attempts
);

#endif /* HASH_CRACKER_SERIAL_H */

