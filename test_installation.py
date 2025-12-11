# Simple test script to verify the project is set up correctly
# Run this to check if everything works

import sys

print("=" * 60)
print("Testing Project Installation")
print("=" * 60)

# Test 1: Check Python version
print("\n1. Checking Python version...")
print(f"   Python version: {sys.version}")
if sys.version_info < (3, 6):
    print("   Python 3.6+ recommended")
else:
    print("   OK")

# Test 2: Check if benchmark harness can be imported
print("\n2. Testing benchmark harness import...")
try:
    from benchmark_harness import BenchmarkHarness
    print("   OK - benchmark_harness imported successfully")
except ImportError as e:
    print(f"   ERROR: {e}")
    sys.exit(1)

# Test 3: Check if workload generator can be imported
print("\n3. Testing workload generator import...")
try:
    from workload_generator import WorkloadGenerator
    print("   OK - workload_generator imported successfully")
except ImportError as e:
    print(f"   ERROR: {e}")
    sys.exit(1)

# Test 4: Create a harness instance
print("\n4. Testing harness initialization...")
try:
    harness = BenchmarkHarness()
    print(f"   OK - Harness created with {len(harness.backends)} backends")
    print(f"   Available backends: {list(harness.backends.keys())}")
except Exception as e:
    print(f"   ERROR: {e}")
    sys.exit(1)

# Test 5: Test workload generation
print("\n5. Testing workload generation...")
try:
    generator = WorkloadGenerator()
    workload = generator.create_simple_test_workload()
    print(f"   OK - Test workload created")
    print(f"   Target hash: {workload.target_hash[:32]}...")
except Exception as e:
    print(f"   ERROR: {e}")
    sys.exit(1)

# Test 6: Try to run a simple benchmark (Python only)
print("\n6. Testing simple benchmark (Python backend only)...")
try:
    result = harness.benchmark_brute_force(
        "python_serial",
        workload,
        max_attempts=1000  # Quick test
    )
    print(f"   OK - Benchmark completed")
    print(f"   Attempts: {result.attempts}")
    print(f"   Runtime: {result.runtime_seconds:.4f} seconds")
    print(f"   Hashes/second: {result.hashes_per_second:,.0f}")
except Exception as e:
    print(f"   ERROR: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

# Test 7: Check for C backends (optional)
print("\n7. Checking for C backends (optional)...")
try:
    from c_backend_wrapper import CSerialBackend
    print("   OK - C serial wrapper available")
    try:
        c_backend = CSerialBackend()
        print("   OK - C serial backend loaded successfully")
    except (FileNotFoundError, RuntimeError) as e:
        print(f"   INFO - C serial backend not built yet: {e}")
        print("   This is OK if you haven't compiled the C code yet")
except ImportError:
    print("   INFO - C backend wrapper not found (this is OK if C backends not needed)")

try:
    from c_multithreaded_wrapper import CMultithreadedBackend
    print("   OK - C multithreaded wrapper available")
    try:
        c_mt_backend = CMultithreadedBackend()
        print("   OK - C multithreaded backend loaded successfully")
    except (FileNotFoundError, RuntimeError) as e:
        print(f"   INFO - C multithreaded backend not built yet: {e}")
        print("   This is OK if you haven't compiled the C code yet")
except ImportError:
    print("   INFO - C multithreaded wrapper not found (this is OK)")

print("\n" + "=" * 60)
print("Installation Test Complete!")
print("=" * 60)
print("\nEverything looks good. The benchmark framework is ready to use.")
print("\nNext steps:")
print("  1. To build C backends (Linux/macOS): make all")
print("  2. To run benchmarks: python run_benchmark.py --test")
print("  3. To run scaling tests: python scaling_benchmark.py --brute-force")
print("\nFor full documentation, see README.md")

