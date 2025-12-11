// Multi-threaded C implementation for password hash cracking
// Uses pthreads for parallel CPU execution

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <openssl/sha.h>
#include <stdint.h>
#include <stdbool.h>

#include "hash_cracker_serial.h"  // Reuse serial implementation for hashing

#define MAX_PASSWORD_LENGTH 32
#define SHA256_HEX_LENGTH 64
#define MAX_THREADS 256

// Thread data structure
typedef struct {
    const char* target_hash;
    const char* character_set;
    int char_set_len;
    int start_length;
    int end_length;
    uint64_t max_attempts;
    const char* salt;
    char* found_password;
    bool* found;
    uint64_t* attempts;
    pthread_mutex_t* attempt_mutex;
    pthread_mutex_t* found_mutex;
} ThreadData;

// Hash a password with optional salt (from serial implementation)
static int hash_password_local(const char* password, const char* salt, char* output) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    char combined[MAX_PASSWORD_LENGTH * 2];
    
    if (salt && strlen(salt) > 0) {
        snprintf(combined, sizeof(combined), "%s%s", salt, password);
    } else {
        strncpy(combined, password, sizeof(combined) - 1);
        combined[sizeof(combined) - 1] = '\0';
    }
    
    if (!SHA256_Init(&sha256)) return -1;
    if (!SHA256_Update(&sha256, combined, strlen(combined))) return -1;
    if (!SHA256_Final(hash, &sha256)) return -1;
    
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(output + (i * 2), "%02x", hash[i]);
    }
    output[SHA256_HEX_LENGTH] = '\0';
    
    return 0;
}

// Thread-safe password check function
static int check_password_safe(
    const char* password,
    const char* target_hash,
    const char* salt,
    pthread_mutex_t* mutex,
    uint64_t* attempts
) {
    char computed_hash[SHA256_HEX_LENGTH + 1];
    
    if (hash_password_local(password, salt, computed_hash) != 0) {
        return -1;
    }
    
    // Increment attempts atomically
    pthread_mutex_lock(mutex);
    (*attempts)++;
    uint64_t current_attempts = *attempts;
    pthread_mutex_unlock(mutex);
    
    if (strcmp(computed_hash, target_hash) == 0) {
        return 1;
    }
    
    return 0;
}

// Thread-safe recursive password generation and checking
static int generate_and_check_recursive_threaded(
    char* prefix,
    int prefix_len,
    int target_len,
    const char* character_set,
    int char_set_len,
    const char* target_hash,
    const char* salt,
    uint64_t* attempts,
    uint64_t max_attempts,
    pthread_mutex_t* attempt_mutex,
    bool* found,
    pthread_mutex_t* found_mutex,
    char* result
) {
    // Check if another thread found it
    pthread_mutex_lock(found_mutex);
    if (*found) {
        pthread_mutex_unlock(found_mutex);
        return 2;  // Found by another thread
    }
    pthread_mutex_unlock(found_mutex);
    
    if (prefix_len == target_len) {
        // Check max attempts
        pthread_mutex_lock(attempt_mutex);
        if (max_attempts > 0 && *attempts >= max_attempts) {
            pthread_mutex_unlock(attempt_mutex);
            return -2;  // Max attempts exceeded
        }
        pthread_mutex_unlock(attempt_mutex);
        
        // Try this password
        int match = check_password_safe(prefix, target_hash, salt, attempt_mutex, attempts);
        
        if (match == 1) {
            // Found it!
            pthread_mutex_lock(found_mutex);
            if (!*found) {
                *found = true;
                strncpy(result, prefix, target_len + 1);
            }
            pthread_mutex_unlock(found_mutex);
            return 1;  // Found!
        }
        if (match == -1) {
            return -1;  // Error
        }
        
        return 0;  // Not found, continue
    }
    
    // Recursively generate next character
    for (int i = 0; i < char_set_len; i++) {
        // Early exit if found
        pthread_mutex_lock(found_mutex);
        bool should_continue = !(*found);
        pthread_mutex_unlock(found_mutex);
        
        if (!should_continue) {
            return 2;  // Found by another thread
        }
        
        prefix[prefix_len] = character_set[i];
        prefix[prefix_len + 1] = '\0';
        
        int status = generate_and_check_recursive_threaded(
            prefix, prefix_len + 1, target_len,
            character_set, char_set_len,
            target_hash, salt,
            attempts, max_attempts,
            attempt_mutex, found, found_mutex, result
        );
        
        if (status == 1 || status == 2) {
            return status;  // Found!
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

// Worker thread function for brute-force cracking
void* brute_force_worker(void* arg) {
    ThreadData* data = (ThreadData*)arg;
    char prefix[MAX_PASSWORD_LENGTH + 1];
    
    // Try each length in this thread's range
    for (int length = data->start_length; length <= data->end_length; length++) {
        // Check if found by another thread
        pthread_mutex_lock(data->found_mutex);
        if (*data->found) {
            pthread_mutex_unlock(data->found_mutex);
            return NULL;
        }
        pthread_mutex_unlock(data->found_mutex);
        
        prefix[0] = '\0';
        
        int result = generate_and_check_recursive_threaded(
            prefix, 0, length,
            data->character_set, data->char_set_len,
            data->target_hash, data->salt,
            data->attempts, data->max_attempts,
            data->attempt_mutex, data->found, data->found_mutex,
            data->found_password
        );
        
        if (result == 1 || result == 2) {
            // Found!
            return NULL;
        }
        if (result == -2) {
            // Max attempts exceeded
            return NULL;
        }
    }
    
    return NULL;
}

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
) {
    if (!target_hash || !character_set || !found_password || !attempts) {
        return -1;
    }
    
    if (num_threads < 1 || num_threads > MAX_THREADS) {
        return -1;
    }
    
    *attempts = 0;
    found_password[0] = '\0';
    
    int char_set_len = strlen(character_set);
    if (char_set_len == 0) {
        return -1;
    }
    
    // Shared state
    bool found = false;
    uint64_t total_attempts = 0;
    pthread_mutex_t attempt_mutex = PTHREAD_MUTEX_INITIALIZER;
    pthread_mutex_t found_mutex = PTHREAD_MUTEX_INITIALIZER;
    
    // Create threads
    pthread_t threads[MAX_THREADS];
    ThreadData thread_data[MAX_THREADS];
    
    // Distribute lengths across threads
    // Simple strategy: divide length range among threads
    int lengths_per_thread = (max_length + num_threads - 1) / num_threads;
    
    for (int i = 0; i < num_threads; i++) {
        thread_data[i].target_hash = target_hash;
        thread_data[i].character_set = character_set;
        thread_data[i].char_set_len = char_set_len;
        thread_data[i].max_attempts = max_attempts;
        thread_data[i].salt = salt;
        thread_data[i].found_password = found_password;
        thread_data[i].found = &found;
        thread_data[i].attempts = &total_attempts;
        thread_data[i].attempt_mutex = &attempt_mutex;
        thread_data[i].found_mutex = &found_mutex;
        
        // Assign length range to this thread
        thread_data[i].start_length = i * lengths_per_thread + 1;
        thread_data[i].end_length = (i + 1) * lengths_per_thread;
        
        // Make sure we don't exceed max_length
        if (thread_data[i].start_length > max_length) {
            thread_data[i].start_length = max_length + 1;  // No work for this thread
            thread_data[i].end_length = max_length;
        }
        if (thread_data[i].end_length > max_length) {
            thread_data[i].end_length = max_length;
        }
        
        if (pthread_create(&threads[i], NULL, brute_force_worker, &thread_data[i]) != 0) {
            // Cleanup on error
            for (int j = 0; j < i; j++) {
                pthread_join(threads[j], NULL);
            }
            pthread_mutex_destroy(&attempt_mutex);
            pthread_mutex_destroy(&found_mutex);
            return -1;
        }
    }
    
    // Wait for all threads to complete
    for (int i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
    }
    
    // Cleanup mutexes
    pthread_mutex_destroy(&attempt_mutex);
    pthread_mutex_destroy(&found_mutex);
    
    // Set output values
    *attempts = total_attempts;
    
    if (found) {
        return 1;  // Found!
    }
    
    return 0;  // Not found
}

// Worker thread function for dictionary attack
void* dictionary_worker(void* arg) {
    ThreadData* data = (ThreadData*)arg;
    
    // Get thread-specific wordlist range from start_length and end_length
    // In this case, we use these fields to store wordlist indices
    int start_idx = data->start_length;
    int end_idx = data->end_length;
    const char** wordlist = (const char**)(data->character_set);  // Reuse pointer
    
    for (int i = start_idx; i < end_idx; i++) {
        // Check if found by another thread
        pthread_mutex_lock(data->found_mutex);
        if (*data->found) {
            pthread_mutex_unlock(data->found_mutex);
            return NULL;
        }
        pthread_mutex_unlock(data->found_mutex);
        
        if (!wordlist[i]) {
            continue;
        }
        
        // Check password
        int match = check_password_safe(
            wordlist[i],
            data->target_hash,
            data->salt,
            data->attempt_mutex,
            data->attempts
        );
        
        if (match == 1) {
            // Found it!
            pthread_mutex_lock(data->found_mutex);
            if (!*data->found) {
                *data->found = true;
                strncpy(data->found_password, wordlist[i], MAX_PASSWORD_LENGTH);
                data->found_password[MAX_PASSWORD_LENGTH] = '\0';
            }
            pthread_mutex_unlock(data->found_mutex);
            return NULL;
        }
        if (match == -1) {
            return NULL;  // Error
        }
    }
    
    return NULL;
}

// Multi-threaded dictionary attack on a password hash
int dictionary_attack_multithreaded(
    const char* target_hash,
    const char** wordlist,
    int wordlist_size,
    const char* salt,
    int num_threads,
    char* found_password,
    uint64_t* attempts
) {
    if (!target_hash || !wordlist || !found_password || !attempts) {
        return -1;
    }
    
    if (num_threads < 1 || num_threads > MAX_THREADS) {
        return -1;
    }
    
    *attempts = 0;
    found_password[0] = '\0';
    
    // Shared state
    bool found = false;
    uint64_t total_attempts = 0;
    pthread_mutex_t attempt_mutex = PTHREAD_MUTEX_INITIALIZER;
    pthread_mutex_t found_mutex = PTHREAD_MUTEX_INITIALIZER;
    
    // Create threads
    pthread_t threads[MAX_THREADS];
    ThreadData thread_data[MAX_THREADS];
    
    // Distribute wordlist across threads
    int words_per_thread = (wordlist_size + num_threads - 1) / num_threads;
    
    for (int i = 0; i < num_threads; i++) {
        thread_data[i].target_hash = target_hash;
        thread_data[i].character_set = (const char*)wordlist;  // Reuse for wordlist pointer
        thread_data[i].salt = salt;
        thread_data[i].found_password = found_password;
        thread_data[i].found = &found;
        thread_data[i].attempts = &total_attempts;
        thread_data[i].attempt_mutex = &attempt_mutex;
        thread_data[i].found_mutex = &found_mutex;
        
        // Assign wordlist range
        thread_data[i].start_length = i * words_per_thread;
        thread_data[i].end_length = (i + 1) * words_per_thread;
        
        // Make sure we don't exceed wordlist_size
        if (thread_data[i].end_length > wordlist_size) {
            thread_data[i].end_length = wordlist_size;
        }
        
        if (pthread_create(&threads[i], NULL, dictionary_worker, &thread_data[i]) != 0) {
            // Cleanup on error
            for (int j = 0; j < i; j++) {
                pthread_join(threads[j], NULL);
            }
            pthread_mutex_destroy(&attempt_mutex);
            pthread_mutex_destroy(&found_mutex);
            return -1;
        }
    }
    
    // Wait for all threads to complete
    for (int i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
    }
    
    // Cleanup mutexes
    pthread_mutex_destroy(&attempt_mutex);
    pthread_mutex_destroy(&found_mutex);
    
    // Set output values
    *attempts = total_attempts;
    
    if (found) {
        return 1;  // Found!
    }
    
    return 0;  // Not found
}

