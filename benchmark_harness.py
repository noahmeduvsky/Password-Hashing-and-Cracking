# Benchmarking harness for password hash cracking
# Compares different implementations (Python serial, C serial, C multi-threaded)

import time
import hashlib
from typing import List, Tuple, Optional, Callable, Dict
from dataclasses import dataclass
from enum import Enum
import sys
import os

# Try to load C backends if available
try:
    from c_backend_wrapper import CSerialBackend
    C_BACKEND_AVAILABLE = True
except ImportError:
    C_BACKEND_AVAILABLE = False

try:
    from c_multithreaded_wrapper import CMultithreadedBackend
    C_MULTITHREADED_BACKEND_AVAILABLE = True
except ImportError:
    C_MULTITHREADED_BACKEND_AVAILABLE = False


# Different backend types we can test
class BackendType(Enum):
    PYTHON_SERIAL = "python_serial"
    C_SERIAL = "c_serial"
    C_MULTITHREADED = "c_multithreaded"
    C_MULTITHREADED_2 = "c_multithreaded_2"
    C_MULTITHREADED_4 = "c_multithreaded_4"
    C_MULTITHREADED_8 = "c_multithreaded_8"
    GPU = "gpu"


# Stores benchmark results
@dataclass
class BenchmarkResult:
    backend: str
    target_hash: str
    cracked_password: Optional[str]
    attempts: int
    runtime_seconds: float
    hashes_per_second: float
    success: bool


# Represents a test workload
@dataclass
class Workload:
    target_hash: str
    target_salt: Optional[str]
    character_set: str
    max_length: int
    dictionary: Optional[List[str]] = None


# Python baseline implementation (single-threaded)
class PythonSerialBackend:
    
    @staticmethod
    def hash_password(password: str, salt: Optional[str] = None) -> str:
        # Hash password with optional salt
        if salt:
            return hashlib.sha256((salt + password).encode()).hexdigest()
        return hashlib.sha256(password.encode()).hexdigest()
    
    @staticmethod
    def crack_brute_force(
        target_hash: str,
        character_set: str,
        max_length: int,
        max_attempts: Optional[int] = None,
        salt: Optional[str] = None
    ) -> Tuple[Optional[str], int]:
        # Try all password combinations up to max_length
        attempts = 0
        
        def generate_passwords_of_length(length: int, chars: str):
            # Recursively generate all passwords of given length
            if length == 1:
                for char in chars:
                    yield char
            else:
                for prefix in generate_passwords_of_length(length - 1, chars):
                    for char in chars:
                        yield prefix + char
        
        for length in range(1, max_length + 1):
            for password in generate_passwords_of_length(length, character_set):
                attempts += 1
                
                # Stop if we hit max attempts
                if max_attempts and attempts > max_attempts:
                    return None, attempts
                
                # Hash and check if it matches
                hashed = PythonSerialBackend.hash_password(password, salt)
                if hashed == target_hash:
                    return password, attempts
        
        return None, attempts
    
    @staticmethod
    def crack_dictionary(
        target_hash: str,
        wordlist: List[str],
        salt: Optional[str] = None
    ) -> Tuple[Optional[str], int]:
        # Try each word in the dictionary
        attempts = 0
        
        for password in wordlist:
            attempts += 1
            hashed = PythonSerialBackend.hash_password(password, salt)
            if hashed == target_hash:
                return password, attempts
        
        return None, attempts


# Main benchmark harness class
class BenchmarkHarness:
    
    def __init__(self):
        self.backends: Dict[str, Callable] = {}
        self.register_backend(BackendType.PYTHON_SERIAL.value, PythonSerialBackend)
        
        # Try loading C backends if they're available
        if C_BACKEND_AVAILABLE:
            try:
                c_backend = CSerialBackend()
                self.register_backend(BackendType.C_SERIAL.value, c_backend)
            except (FileNotFoundError, RuntimeError) as e:
                print(f"Warning: C serial backend not available: {e}", file=sys.stderr)
        
        # Try loading multi-threaded C backend
        if C_MULTITHREADED_BACKEND_AVAILABLE:
            try:
                # Register different thread count versions
                c_mt_2 = CMultithreadedBackend(num_threads=2)
                self.register_backend(BackendType.C_MULTITHREADED_2.value, c_mt_2)
                
                c_mt_4 = CMultithreadedBackend(num_threads=4)
                self.register_backend(BackendType.C_MULTITHREADED_4.value, c_mt_4)
                
                c_mt_8 = CMultithreadedBackend(num_threads=8)
                self.register_backend(BackendType.C_MULTITHREADED_8.value, c_mt_8)
                
                # Default version
                c_mt_default = CMultithreadedBackend(num_threads=4)
                self.register_backend(BackendType.C_MULTITHREADED.value, c_mt_default)
            except (FileNotFoundError, RuntimeError) as e:
                print(f"Warning: C multi-threaded backend not available: {e}", file=sys.stderr)
    
    def register_backend(self, name: str, backend_instance):
        # Add a backend to the list of available backends
        self.backends[name] = backend_instance
    
    def generate_test_hashes(
        self,
        passwords: List[str],
        use_salt: bool = False
    ) -> List[Tuple[str, str, Optional[str]]]:
        # Generate hashes for test passwords
        import os
        results = []
        
        for password in passwords:
            if use_salt:
                salt = os.urandom(16).hex()
                hash_value = PythonSerialBackend.hash_password(password, salt)
            else:
                salt = None
                hash_value = PythonSerialBackend.hash_password(password)
            results.append((password, hash_value, salt))
        
        return results
    
    def benchmark_brute_force(
        self,
        backend_name: str,
        workload: Workload,
        max_attempts: Optional[int] = None
    ) -> BenchmarkResult:
        # Run a brute-force benchmark with the specified backend
        if backend_name not in self.backends:
            raise ValueError(f"Unknown backend: {backend_name}")
        
        backend = self.backends[backend_name]
        
        # Time the cracking attempt
        start_time = time.perf_counter()
        
        # Run the actual crack
        if backend_name == BackendType.PYTHON_SERIAL.value:
            cracked, attempts = backend.crack_brute_force(
                workload.target_hash,
                workload.character_set,
                workload.max_length,
                max_attempts,
                workload.target_salt
            )
        elif backend_name == BackendType.C_SERIAL.value:
            cracked, attempts = backend.crack_brute_force(
                workload.target_hash,
                workload.character_set,
                workload.max_length,
                max_attempts,
                workload.target_salt
            )
        elif backend_name.startswith("c_multithreaded"):
            cracked, attempts = backend.crack_brute_force(
                workload.target_hash,
                workload.character_set,
                workload.max_length,
                max_attempts,
                workload.target_salt,
                num_threads=None
            )
        else:
            raise NotImplementedError(f"Backend {backend_name} not yet implemented")
        
        # Calculate timing and metrics
        end_time = time.perf_counter()
        runtime = end_time - start_time
        hashes_per_second = attempts / runtime if runtime > 0 else 0
        success = cracked is not None
        
        return BenchmarkResult(
            backend=backend_name,
            target_hash=workload.target_hash,
            cracked_password=cracked,
            attempts=attempts,
            runtime_seconds=runtime,
            hashes_per_second=hashes_per_second,
            success=success
        )
    
    def benchmark_dictionary(
        self,
        backend_name: str,
        workload: Workload
    ) -> BenchmarkResult:
        # Run a dictionary attack benchmark
        if workload.dictionary is None:
            raise ValueError("Dictionary workload must have a wordlist")
        
        if backend_name not in self.backends:
            raise ValueError(f"Unknown backend: {backend_name}")
        
        backend = self.backends[backend_name]
        
        start_time = time.perf_counter()
        
        # Run the dictionary attack
        if backend_name == BackendType.PYTHON_SERIAL.value:
            cracked, attempts = backend.crack_dictionary(
                workload.target_hash,
                workload.dictionary,
                workload.target_salt
            )
        elif backend_name == BackendType.C_SERIAL.value:
            cracked, attempts = backend.crack_dictionary(
                workload.target_hash,
                workload.dictionary,
                workload.target_salt
            )
        elif backend_name.startswith("c_multithreaded"):
            cracked, attempts = backend.crack_dictionary(
                workload.target_hash,
                workload.dictionary,
                workload.target_salt,
                num_threads=None
            )
        else:
            raise NotImplementedError(f"Backend {backend_name} not yet implemented")
        
        # Calculate results
        end_time = time.perf_counter()
        runtime = end_time - start_time
        hashes_per_second = attempts / runtime if runtime > 0 else 0
        success = cracked is not None
        
        return BenchmarkResult(
            backend=backend_name,
            target_hash=workload.target_hash,
            cracked_password=cracked,
            attempts=attempts,
            runtime_seconds=runtime,
            hashes_per_second=hashes_per_second,
            success=success
        )
    
    def compare_backends(
        self,
        workload: Workload,
        backend_names: List[str],
        max_attempts: Optional[int] = None
    ) -> List[BenchmarkResult]:
        # Run the same workload on multiple backends and compare
        results = []
        
        for backend_name in backend_names:
            if workload.dictionary:
                result = self.benchmark_dictionary(backend_name, workload)
            else:
                result = self.benchmark_brute_force(backend_name, workload, max_attempts)
            results.append(result)
        
        return results
    
    def calculate_speedup(
        self,
        baseline_result: BenchmarkResult,
        comparison_result: BenchmarkResult
    ) -> float:
        # Calculate how much faster one result is compared to baseline
        if baseline_result.runtime_seconds == 0:
            return 0.0
        return baseline_result.runtime_seconds / comparison_result.runtime_seconds


def print_results(results: List[BenchmarkResult], baseline_idx: int = 0):
    # Print benchmark results in a readable format
    if not results:
        return
    
    baseline = results[baseline_idx]
    
    print("\n" + "="*80)
    print("BENCHMARK RESULTS")
    print("="*80)
    
    for i, result in enumerate(results):
        speedup = 1.0
        if i != baseline_idx:
            speedup = baseline.runtime_seconds / result.runtime_seconds if result.runtime_seconds > 0 else 0
        
        print(f"\nBackend: {result.backend}")
        print(f"  Success: {result.success}")
        if result.success:
            print(f"  Cracked Password: {result.cracked_password}")
        print(f"  Attempts: {result.attempts:,}")
        print(f"  Runtime: {result.runtime_seconds:.4f} seconds")
        print(f"  Hashes/Second: {result.hashes_per_second:,.2f}")
        if i != baseline_idx:
            print(f"  Speedup: {speedup:.2f}x")
    
    print("\n" + "="*80)


if __name__ == "__main__":
    # Simple test example
    harness = BenchmarkHarness()
    
    test_password = "test123"
    test_hash, _, _ = harness.generate_test_hashes([test_password])[0]
    
    workload = Workload(
        target_hash=test_hash,
        target_salt=None,
        character_set="abcdefghijklmnopqrstuvwxyz0123456789",
        max_length=7,
        dictionary=None
    )
    
    print(f"Testing brute-force attack on hash: {test_hash}")
    print(f"Target password: {test_password}")
    
    result = harness.benchmark_brute_force(
        BackendType.PYTHON_SERIAL.value,
        workload,
        max_attempts=None
    )
    
    print_results([result])


