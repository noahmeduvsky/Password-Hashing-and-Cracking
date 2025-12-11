// Header file for multi-threaded C password hash cracking implementation

#ifndef HASH_CRACKER_MULTITHREADED_H
#define HASH_CRACKER_MULTITHREADED_H

#include <stdint.h>

// Multi-threaded brute-force crack a password hash
int brute_force_crack_multithreaded(
    const char* target_hash,
    const char* character_set,
    int max_length,
    uint64_t max_attempts,
    const char* salt,
    int num_threads,
    char* found_password,
    uint64_t* attempts
);

// Multi-threaded dictionary attack on a password hash
int dictionary_attack_multithreaded(
    const char* target_hash,
    const char** wordlist,
    int wordlist_size,
    const char* salt,
    int num_threads,
    char* found_password,
    uint64_t* attempts
);

#endif /* HASH_CRACKER_MULTITHREADED_H */

