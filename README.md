# Password Hash Cracking Benchmark

Benchmarking tool to compare different approaches for password hash cracking - Python serial, C serial, and C multi-threaded implementations.

## Quick Start

You can run the Python backend immediately without any setup:

```bash
python run_benchmark.py --test
```

This runs a simple test with the Python backend. No compilation needed.

## Building C Backends (Optional)

The C backends are faster but need to be compiled first.

**Linux/macOS:**
```bash
# Install OpenSSL dev libraries
sudo apt-get install libssl-dev  # Ubuntu/Debian
# or
sudo yum install openssl-devel  # Fedora/RHEL

# Build
make all
```

**Windows:**
```powershell
.\build_windows.ps1
```

You'll need MinGW-w64 and OpenSSL installed. The Python backend works fine without this.

## Running Benchmarks

**Basic test:**
```bash
python run_benchmark.py --test
```

**Brute-force attack:**
```bash
python run_benchmark.py --brute-force --num-targets 5 --max-length 6
```

**Dictionary attack:**
```bash
python run_benchmark.py --dictionary --num-targets 3 --wordlist-size 1000
```

**Scaling test (compare thread counts):**
```bash
python scaling_benchmark.py --brute-force --threads 1,2,4,8
```

## What It Does

- Tests password hash cracking with different backends
- Compares Python vs C implementations
- Tests multi-threading performance with different thread counts
- Supports brute-force and dictionary attacks
- Outputs results to CSV files in `benchmark_results/`

## Requirements

- Python 3.6+
- For C backends: GCC, OpenSSL dev libraries, pthread

## Important

All password hashes used here are synthetic or generated for testing. No real passwords or compromised systems. This is for educational purposes and security testing only.

## Files

- `benchmark_harness.py` - Main framework
- `run_benchmark.py` - Run standard benchmarks
- `scaling_benchmark.py` - Test different thread counts
- `workload_generator.py` - Generate test workloads
- `hash_cracker_serial.c` - Single-threaded C backend
- `hash_cracker_multithreaded.c` - Multi-threaded C backend

## Using in Code

```python
from benchmark_harness import BenchmarkHarness
from workload_generator import WorkloadGenerator

harness = BenchmarkHarness()
generator = WorkloadGenerator()

workload = generator.create_simple_test_workload()
result = harness.benchmark_brute_force("python_serial", workload)

print(f"Runtime: {result.runtime_seconds:.4f}s")
print(f"Hashes/Second: {result.hashes_per_second:,.2f}")
```
