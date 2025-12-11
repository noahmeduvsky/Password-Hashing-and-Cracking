# Password-Hashing-and-Cracking

Parallelizing Password-Hash Search for Security Testing: A Comparative Study of CPU, Multi-thread, and GPU Approaches

## Project Status

**Week 1, Week 2, and Week 3 Complete!**

All required objectives from the proposal have been implemented:
- Python benchmarking harness with timing infrastructure
- Single-threaded C/C++ backend
- Multi-threaded C/C++ backend with thread pool
- Scaling benchmarks with varying thread counts
- Workload generation (brute-force and dictionary attacks)

## Quick Start

### 1. Build C Backends

**Linux/macOS:**
```bash
# Install OpenSSL development libraries first:
# Ubuntu/Debian: sudo apt-get install libssl-dev
# Fedora/RHEL: sudo yum install openssl-devel

# Build both serial and multi-threaded backends
make all
```

**Windows:**
```powershell
# First, install MinGW-w64 (see BUILD_WINDOWS.md)
# Then run the build script:
.\build_windows.ps1
```

### 2. Run Benchmarks

**Simple Test (Python only - no compilation needed):**
```bash
python run_benchmark.py --test
```

**Scaling Benchmark (requires compilation):**
```bash
python scaling_benchmark.py --brute-force --threads 1,2,4,8
```

## Project Structure

### Core Framework
- `benchmark_harness.py` - Main benchmarking framework
- `run_benchmark.py` - Standard benchmark runner
- `scaling_benchmark.py` - Scaling benchmark with varying thread counts
- `workload_generator.py` - Workload generation utilities

### C Implementations
- `hash_cracker_serial.c/h` - Single-threaded C implementation
- `hash_cracker_multithreaded.c/h` - Multi-threaded C implementation
- `Makefile` - Build system

### Python Wrappers
- `c_backend_wrapper.py` - Serial C backend wrapper
- `c_multithreaded_wrapper.py` - Multi-threaded C backend wrapper

### Documentation
- `README_BENCHMARK.md` - Detailed usage documentation
- `BUILD_INSTRUCTIONS.md` - Build instructions for C backends

## Ethics Statement

**Important:** All password hashes used in this project are synthetic or generated with explicit consent. No real user passwords or compromised systems were used. This project is intended for educational purposes and security testing of password policies only.

## Features

### Available Backends
- **Python Serial**: Pure Python baseline (works immediately)
- **C Serial**: Single-threaded C implementation (~10x faster)
- **C Multi-threaded**: Multi-threaded C with configurable threads

### Attack Types
- **Brute-Force**: Try all character combinations up to max length
- **Dictionary**: Try passwords from a wordlist

### Metrics Collected
- Runtime (high-precision seconds)
- Hashes per second
- Total attempts
- Success/failure
- Speedup relative to baseline

## Usage Examples

### Standard Benchmark
```bash
# Brute-force attack
python run_benchmark.py --brute-force --num-targets 5 --max-length 6

# Dictionary attack
python run_benchmark.py --dictionary --num-targets 3 --wordlist-size 1000
```

### Scaling Benchmark
```bash
# Test different thread counts
python scaling_benchmark.py --brute-force --threads 1,2,4,8 --max-attempts 1000000

# Dictionary scaling
python scaling_benchmark.py --dictionary --threads 1,2,4,8 --wordlist-size 10000
```

### Programmatic Usage
```python
from benchmark_harness import BenchmarkHarness
from workload_generator import WorkloadGenerator

harness = BenchmarkHarness()
generator = WorkloadGenerator()

# Create workload
workload = generator.create_simple_test_workload()

# Run benchmark
result = harness.benchmark_brute_force(
    "python_serial",
    workload,
    max_attempts=None
)

print(f"Runtime: {result.runtime_seconds:.4f}s")
print(f"Hashes/Second: {result.hashes_per_second:,.2f}")
```

## Requirements

### Python
- Python 3.x
- Standard library only (no external dependencies)

### C Compilation
- GCC compiler
- OpenSSL development libraries
- pthread (included in standard libraries)

## From Proposal

This project extends the Security and Privacy in Computing project to compare:
1. Single-threaded CPU baseline (Python and C)
2. Multi-threaded CPU implementation (C with pthreads)
3. Optional GPU kernel (stretch goal)

Timeline:
- Week 1: Serial CPU baseline, timing, cleanup (complete)
- Week 2: Multi-threaded backend, scaling runs (complete)
- Week 3: Final benchmarks, report, optional GPU

## Important Notes

- All test data is synthetic or consented - no real passwords are used
- The framework demonstrates parallelization benefits
- Focus is on simplicity and reproducibility
- Windows support requires Visual Studio or MinGW setup

## License

See original repository for license information.
