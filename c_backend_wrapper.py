# Python wrapper for C serial backend
# Uses ctypes to load the C library and call C functions from Python

import ctypes
import os
import sys
from typing import Optional, List, Tuple
from pathlib import Path


class CSerialBackend:
    # Wrapper for the single-threaded C backend
    
    def __init__(self, library_path: Optional[str] = None):
        # Load the C shared library and set up function signatures
        self.lib = None
        self._load_library(library_path)
        self._setup_function_signatures()
    
    def _load_library(self, library_path: Optional[str]):
        # Try to find and load the C library
        if library_path is None:
            # Different library names for different OS
            possible_names = [
                'libhash_cracker_serial.so',  # Linux
                'hash_cracker_serial.dll',    # Windows
                'libhash_cracker_serial.dylib'  # macOS
            ]
            
            # Check current directory
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
            
            # Check build directory if not found
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
                f"Could not find C library. Please build it first using 'make serial' "
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
        # hash_password
        self.lib.hash_password.argtypes = [
            ctypes.c_char_p,
            ctypes.c_char_p,
            ctypes.c_char_p
        ]
        self.lib.hash_password.restype = ctypes.c_int
        
        # check_password
        self.lib.check_password.argtypes = [
            ctypes.c_char_p,
            ctypes.c_char_p,
            ctypes.c_char_p
        ]
        self.lib.check_password.restype = ctypes.c_int
        
        # brute_force_crack
        self.lib.brute_force_crack.argtypes = [
            ctypes.c_char_p,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_uint64,
            ctypes.c_char_p,
            ctypes.c_char_p,
            ctypes.POINTER(ctypes.c_uint64)
        ]
        self.lib.brute_force_crack.restype = ctypes.c_int
        
        # dictionary_attack
        self.lib.dictionary_attack.argtypes = [
            ctypes.c_char_p,
            ctypes.POINTER(ctypes.c_char_p),
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_char_p,
            ctypes.POINTER(ctypes.c_uint64)
        ]
        self.lib.dictionary_attack.restype = ctypes.c_int
    
    def hash_password(self, password: str, salt: Optional[str] = None) -> str:
        # Hash a password using the C backend
        output_buffer = ctypes.create_string_buffer(65)
        
        password_bytes = password.encode('utf-8')
        salt_bytes = salt.encode('utf-8') if salt else None
        
        result = self.lib.hash_password(
            password_bytes,
            salt_bytes,
            output_buffer
        )
        
        if result != 0:
            raise RuntimeError("Hash computation failed")
        
        return output_buffer.value.decode('utf-8')
    
    def check_password(self, password: str, target_hash: str, salt: Optional[str] = None) -> bool:
        # Check if password matches hash
        password_bytes = password.encode('utf-8')
        hash_bytes = target_hash.encode('utf-8')
        salt_bytes = salt.encode('utf-8') if salt else None
        
        result = self.lib.check_password(password_bytes, hash_bytes, salt_bytes)
        
        if result == -1:
            raise RuntimeError("Password check failed")
        
        return result == 1
    
    def crack_brute_force(
        self,
        target_hash: str,
        character_set: str,
        max_length: int,
        max_attempts: Optional[int] = None,
        salt: Optional[str] = None
    ) -> Tuple[Optional[str], int]:
        # Run brute-force attack using C backend
        found_password_buffer = ctypes.create_string_buffer(33)
        attempts = ctypes.c_uint64(0)
        
        max_attempts_val = max_attempts if max_attempts is not None else 0
        
        hash_bytes = target_hash.encode('utf-8')
        char_set_bytes = character_set.encode('utf-8')
        salt_bytes = salt.encode('utf-8') if salt else None
        
        result = self.lib.brute_force_crack(
            hash_bytes,
            char_set_bytes,
            max_length,
            max_attempts_val,
            salt_bytes,
            found_password_buffer,
            ctypes.byref(attempts)
        )
        
        attempts_count = attempts.value
        
        if result == -1:
            raise RuntimeError("Brute-force cracking failed")
        elif result == 1:
            cracked = found_password_buffer.value.decode('utf-8')
            return cracked, attempts_count
        else:
            return None, attempts_count
    
    def crack_dictionary(
        self,
        target_hash: str,
        wordlist: List[str],
        salt: Optional[str] = None
    ) -> Tuple[Optional[str], int]:
        # Run dictionary attack using C backend
        found_password_buffer = ctypes.create_string_buffer(33)
        attempts = ctypes.c_uint64(0)
        
        # Convert wordlist to C array
        wordlist_size = len(wordlist)
        wordlist_array = (ctypes.c_char_p * wordlist_size)()
        
        for i, word in enumerate(wordlist):
            wordlist_array[i] = word.encode('utf-8')
        
        hash_bytes = target_hash.encode('utf-8')
        salt_bytes = salt.encode('utf-8') if salt else None
        
        result = self.lib.dictionary_attack(
            hash_bytes,
            wordlist_array,
            wordlist_size,
            salt_bytes,
            found_password_buffer,
            ctypes.byref(attempts)
        )
        
        attempts_count = attempts.value
        
        if result == -1:
            raise RuntimeError("Dictionary attack failed")
        elif result == 1:
            cracked = found_password_buffer.value.decode('utf-8')
            return cracked, attempts_count
        else:
            return None, attempts_count


def get_c_serial_backend(library_path: Optional[str] = None) -> CSerialBackend:
    # Helper function to get a C backend instance
    return CSerialBackend(library_path)
