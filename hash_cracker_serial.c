// Single-threaded C implementation for password hash cracking
// Baseline CPU implementation

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include <stdint.h>

#define MAX_PASSWORD_LENGTH 32
#define SHA256_HEX_LENGTH 64

// Hash a password with optional salt using SHA-256
int hash_password(const char* password, const char* salt, char* output) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    char combined[MAX_PASSWORD_LENGTH * 2];
    
    // Combine salt and password if salt is provided
    if (salt && strlen(salt) > 0) {
        snprintf(combined, sizeof(combined), "%s%s", salt, password);
    } else {
        strncpy(combined, password, sizeof(combined) - 1);
        combined[sizeof(combined) - 1] = '\0';
    }
    
    // Compute SHA-256 hash
    if (!SHA256_Init(&sha256)) {
        return -1;
    }
    if (!SHA256_Update(&sha256, combined, strlen(combined))) {
        return -1;
    }
    if (!SHA256_Final(hash, &sha256)) {
        return -1;
    }
    
    // Convert to hex string
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(output + (i * 2), "%02x", hash[i]);
    }
    output[SHA256_HEX_LENGTH] = '\0';
    
    return 0;
}

// Check if a password matches the target hash
int check_password(const char* password, const char* target_hash, const char* salt) {
    char computed_hash[SHA256_HEX_LENGTH + 1];
    
    if (hash_password(password, salt, computed_hash) != 0) {
        return -1;
    }
    
    return (strcmp(computed_hash, target_hash) == 0) ? 1 : 0;
}

// Recursive function to generate passwords and check them
static int generate_and_check_recursive(
    char* prefix,
    int prefix_len,
    int target_len,
    const char* character_set,
    int char_set_len,
    const char* target_hash,
    const char* salt,
    uint64_t* attempts,
    uint64_t max_attempts,
    char* result
) {
    if (prefix_len == target_len) {
        // Try this password
        (*attempts)++;
        
        // Check max attempts
        if (max_attempts > 0 && *attempts > max_attempts) {
            return -2;  // Max attempts exceeded
        }
        
        // Check if this password matches
        int match = check_password(prefix, target_hash, salt);
        if (match == 1) {
            strncpy(result, prefix, target_len + 1);
            return 1;  // Found!
        }
        
        return 0;  // Not found, continue
    }
    
    // Recursively generate next character
    for (int i = 0; i < char_set_len; i++) {
        prefix[prefix_len] = character_set[i];
        prefix[prefix_len + 1] = '\0';
        
        int status = generate_and_check_recursive(
            prefix, prefix_len + 1, target_len,
            character_set, char_set_len,
            target_hash, salt,
            attempts, max_attempts,
            result
        );
        
        if (status == 1) {
            return 1;  // Found!
        }
        if (status == -2) {
            return -2;  // Max attempts exceeded
        }
        if (status == -1) {
            return -1;  // Error
        }
    }
    
    return 0;  // Not found in this branch
}

// Brute-force crack a password hash
int brute_force_crack(
    const char* target_hash,
    const char* character_set,
    int max_length,
    uint64_t max_attempts,
    const char* salt,
    char* found_password,
    uint64_t* attempts
) {
    if (!target_hash || !character_set || !found_password || !attempts) {
        return -1;
    }
    
    *attempts = 0;
    found_password[0] = '\0';
    
    int char_set_len = strlen(character_set);
    if (char_set_len == 0) {
        return -1;
    }
    
    char prefix[MAX_PASSWORD_LENGTH + 1];
    
    // Try each length from 1 to max_length
    for (int length = 1; length <= max_length; length++) {
        prefix[0] = '\0';
        
        int result = generate_and_check_recursive(
            prefix, 0, length,
            character_set, char_set_len,
            target_hash, salt,
            attempts, max_attempts,
            found_password
        );
        
        if (result == 1) {
            return 1;  // Found!
        }
        if (result == -2) {
            return 0;  // Max attempts exceeded, not found
        }
        if (result == -1) {
            return -1;  // Error
        }
    }
    
    return 0;  // Not found
}

// Dictionary attack on a password hash
int dictionary_attack(
    const char* target_hash,
    const char** wordlist,
    int wordlist_size,
    const char* salt,
    char* found_password,
    uint64_t* attempts
) {
    if (!target_hash || !wordlist || !found_password || !attempts) {
        return -1;
    }
    
    *attempts = 0;
    found_password[0] = '\0';
    
    for (int i = 0; i < wordlist_size; i++) {
        if (!wordlist[i]) {
            continue;
        }
        
        (*attempts)++;
        
        int match = check_password(wordlist[i], target_hash, salt);
        if (match == 1) {
            strncpy(found_password, wordlist[i], MAX_PASSWORD_LENGTH);
            found_password[MAX_PASSWORD_LENGTH] = '\0';
            return 1;  // Found!
        }
        if (match == -1) {
            return -1;  // Error
        }
    }
    
    return 0;  // Not found
}

