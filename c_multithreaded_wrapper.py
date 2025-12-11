# Python wrapper for multi-threaded C backend
# Uses ctypes to load the C library and call multi-threaded C functions

import ctypes
import os
import sys
from typing import Optional, List, Tuple
from pathlib import Path


class CMultithreadedBackend:
    # Wrapper for the multi-threaded C backend
    
    def __init__(self, library_path: Optional[str] = None, num_threads: int = 4):
        # Load the C library and set up function signatures
        self.lib = None
        self.default_num_threads = num_threads
        self._load_library(library_path)
        self._setup_function_signatures()
    
    def _load_library(self, library_path: Optional[str]):
        # Try to find and load the C library
        if library_path is None:
            # Try to find the library in common locations
            possible_names = [
                'libhash_cracker_multithreaded.so',  # Linux
                'hash_cracker_multithreaded.dll',    # Windows
                'libhash_cracker_multithreaded.dylib'  # macOS
            ]
            
            # Check current directory first
            for name in possible_names:
                if os.path.exists(name):
                    library_path = name
                    break
            
            # Check directory where wrapper file is located (project root)
            # This handles the case when running from Scripts/ subdirectory
            if library_path is None:
                wrapper_dir = os.path.dirname(os.path.abspath(__file__))
                for name in possible_names:
                    potential = os.path.join(wrapper_dir, name)
                    if os.path.exists(potential):
                        library_path = potential
                        break
            
            # If not found, check if we have a build directory
            if library_path is None:
                build_dir = Path('build') / 'lib'
                if build_dir.exists():
                    for name in possible_names:
                        potential = build_dir / name
                        if potential.exists():
                            library_path = str(potential)
                            break
        
        if library_path is None or not os.path.exists(library_path):
            raise FileNotFoundError(
                f"Could not find multi-threaded C library. Please build it first using 'make multithreaded' "
                f"or compile manually. Expected one of: {possible_names}"
            )
        
        # Load the library
        try:
            if sys.platform == 'win32':
                # Use absolute path and add OpenSSL DLLs to PATH if needed
                abs_path = os.path.abspath(library_path)
                self.lib = ctypes.CDLL(abs_path)
            else:
                self.lib = ctypes.CDLL(library_path, ctypes.RTLD_GLOBAL)
        except OSError as e:
            raise RuntimeError(f"Failed to load C library from {library_path}: {e}")
    
    def _setup_function_signatures(self):
        # Tell ctypes what the C function signatures are
        # brute_force_crack_multithreaded
        self.lib.brute_force_crack_multithreaded.argtypes = [
            ctypes.c_char_p,      # target_hash
            ctypes.c_char_p,      # character_set
            ctypes.c_int,         # max_length
            ctypes.c_uint64,      # max_attempts
            ctypes.c_char_p,      # salt (can be None)
            ctypes.c_int,         # num_threads
            ctypes.c_char_p,      # found_password buffer
            ctypes.POINTER(ctypes.c_uint64)  # attempts pointer
        ]
        self.lib.brute_force_crack_multithreaded.restype = ctypes.c_int
        
        # dictionary_attack_multithreaded
        self.lib.dictionary_attack_multithreaded.argtypes = [
            ctypes.c_char_p,                          # target_hash
            ctypes.POINTER(ctypes.c_char_p),          # wordlist array
            ctypes.c_int,                             # wordlist_size
            ctypes.c_char_p,                          # salt (can be None)
            ctypes.c_int,                             # num_threads
            ctypes.c_char_p,                          # found_password buffer
            ctypes.POINTER(ctypes.c_uint64)           # attempts pointer
        ]
        self.lib.dictionary_attack_multithreaded.restype = ctypes.c_int
    
    def get_num_threads(self) -> int:
        # Get default number of threads
        return self.default_num_threads
    
    def set_num_threads(self, num_threads: int):
        # Set default number of threads
        if num_threads < 1:
            raise ValueError("Number of threads must be at least 1")
        self.default_num_threads = num_threads
    
    def crack_brute_force(
        self,
        target_hash: str,
        character_set: str,
        max_length: int,
        max_attempts: Optional[int] = None,
        salt: Optional[str] = None,
        num_threads: Optional[int] = None
    ) -> Tuple[Optional[str], int]:
        # Run multi-threaded brute-force attack using C backend
        if num_threads is None:
            num_threads = self.default_num_threads
        
        found_password_buffer = ctypes.create_string_buffer(33)  # Max 32 chars + null
        attempts = ctypes.c_uint64(0)
        
        max_attempts_val = max_attempts if max_attempts is not None else 0
        
        hash_bytes = target_hash.encode('utf-8')
        char_set_bytes = character_set.encode('utf-8')
        salt_bytes = salt.encode('utf-8') if salt else None
        
        result = self.lib.brute_force_crack_multithreaded(
            hash_bytes,
            char_set_bytes,
            max_length,
            max_attempts_val,
            salt_bytes,
            num_threads,
            found_password_buffer,
            ctypes.byref(attempts)
        )
        
        attempts_count = attempts.value
        
        if result == -1:
            raise RuntimeError("Multi-threaded brute-force cracking failed")
        elif result == 1:
            cracked = found_password_buffer.value.decode('utf-8')
            return cracked, attempts_count
        else:
            return None, attempts_count
    
    def crack_dictionary(
        self,
        target_hash: str,
        wordlist: List[str],
        salt: Optional[str] = None,
        num_threads: Optional[int] = None
    ) -> Tuple[Optional[str], int]:
        # Run multi-threaded dictionary attack using C backend
        if num_threads is None:
            num_threads = self.default_num_threads
        
        found_password_buffer = ctypes.create_string_buffer(33)
        attempts = ctypes.c_uint64(0)
        
        # Convert wordlist to C string array
        wordlist_size = len(wordlist)
        wordlist_array = (ctypes.c_char_p * wordlist_size)()
        
        for i, word in enumerate(wordlist):
            wordlist_array[i] = word.encode('utf-8')
        
        hash_bytes = target_hash.encode('utf-8')
        salt_bytes = salt.encode('utf-8') if salt else None
        
        result = self.lib.dictionary_attack_multithreaded(
            hash_bytes,
            wordlist_array,
            wordlist_size,
            salt_bytes,
            num_threads,
            found_password_buffer,
            ctypes.byref(attempts)
        )
        
        attempts_count = attempts.value
        
        if result == -1:
            raise RuntimeError("Multi-threaded dictionary attack failed")
        elif result == 1:
            cracked = found_password_buffer.value.decode('utf-8')
            return cracked, attempts_count
        else:
            return None, attempts_count


# Helper function to get a multi-threaded C backend instance
def get_c_multithreaded_backend(
    library_path: Optional[str] = None,
    num_threads: int = 4
) -> CMultithreadedBackend:
    return CMultithreadedBackend(library_path, num_threads)

