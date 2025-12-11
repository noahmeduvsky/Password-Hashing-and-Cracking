# Main script to run password hash cracking benchmarks
# Compares different backends (Python serial, C serial, etc.)

import sys
import argparse
from benchmark_harness import (
    BenchmarkHarness,
    BenchmarkResult,
    BackendType,
    print_results
)
from workload_generator import (
    WorkloadGenerator,
    BruteForceWorkloadConfig,
    DictionaryWorkloadConfig
)
from results_exporter import export_results_to_csv, create_summary_report


def run_simple_benchmark():
    # Simple benchmark test
    print("="*80)
    print("SIMPLE BENCHMARK TEST")
    print("="*80)
    
    harness = BenchmarkHarness()
    generator = WorkloadGenerator()
    
    # Create a simple workload
    workload = generator.create_simple_test_workload()
    print(f"\nTarget hash: {workload.target_hash}")
    print(f"Character set: {workload.character_set}")
    print(f"Max length: {workload.max_length}")
    print(f"Expected password: test123")
    
    # Get available backends
    available_backends = list(harness.backends.keys())
    print(f"\nAvailable backends: {available_backends}")
    print("Multi-threaded backends are registered separately (e.g., c_multithreaded_2, c_multithreaded_4)")
    
    # Run benchmarks on each backend
    results = []
    for backend_name in available_backends:
        print(f"\nRunning {backend_name}...")
        try:
            result = harness.benchmark_brute_force(
                backend_name,
                workload,
                max_attempts=None
            )
            results.append(result)
        except Exception as e:
            print(f"Error running {backend_name}: {e}")
    
    # Print results
    if results:
        print_results(results, baseline_idx=0)
        
        # Calculate speedups
        if len(results) > 1:
            baseline = results[0]
            print("\nSpeedup Analysis:")
            for i, result in enumerate(results[1:], 1):
                speedup = harness.calculate_speedup(baseline, result)
                print(f"  {result.backend} vs {baseline.backend}: {speedup:.2f}x")


def run_brute_force_benchmark(num_targets: int = 3, max_length: int = 6):
    # Run brute-force benchmarks
    print("="*80)
    print("BRUTE-FORCE BENCHMARK")
    print("="*80)
    
    harness = BenchmarkHarness()
    generator = WorkloadGenerator()
    
    # Generate workloads
    config = BruteForceWorkloadConfig(
        character_set="abcdefghijklmnopqrstuvwxyz0123456789",
        min_length=4,
        max_length=max_length,
        num_targets=num_targets,
        use_salt=False
    )
    
    workloads = generator.generate_brute_force_workloads(config)
    print(f"Generated {len(workloads)} workloads\n")
    
    # Get available backends
    available_backends = list(harness.backends.keys())
    
    # Run benchmarks
    all_results = []
    for i, workload in enumerate(workloads, 1):
        print(f"\nWorkload {i}/{len(workloads)}")
        print(f"  Target hash: {workload.target_hash[:16]}...")
        
        for backend_name in available_backends:
            print(f"  Running {backend_name}...", end=' ', flush=True)
            try:
                result = harness.benchmark_brute_force(
                    backend_name,
                    workload,
                    max_attempts=1000000  # Limit attempts for testing
                )
                all_results.append(result)
                print(f"OK ({result.runtime_seconds:.2f}s)")
            except Exception as e:
                print(f"ERROR: {e}")
    
    # Aggregate and print results
    if all_results:
        # Export results to CSV
        try:
            csv_file = export_results_to_csv(all_results, "bruteforce_results.csv")
            print(f"\nResults exported to: {csv_file}")
        except Exception as e:
            print(f"\nWarning: Could not export results: {e}")
        
        print("\n" + "="*80)
        print("AGGREGATE RESULTS")
        print("="*80)
        
        # Group by backend
        by_backend = {}
        for result in all_results:
            if result.backend not in by_backend:
                by_backend[result.backend] = []
            by_backend[result.backend].append(result)
        
        for backend_name, results in by_backend.items():
            avg_runtime = sum(r.runtime_seconds for r in results) / len(results)
            avg_hps = sum(r.hashes_per_second for r in results) / len(results)
            success_rate = sum(1 for r in results if r.success) / len(results)
            
            print(f"\n{backend_name}:")
            print(f"  Average Runtime: {avg_runtime:.4f} seconds")
            print(f"  Average Hashes/Second: {avg_hps:,.2f}")
            print(f"  Success Rate: {success_rate*100:.1f}%")


def run_dictionary_benchmark(num_targets: int = 3, wordlist_size: int = 1000):
    # Run dictionary attack benchmarks
    print("="*80)
    print("DICTIONARY ATTACK BENCHMARK")
    print("="*80)
    
    harness = BenchmarkHarness()
    generator = WorkloadGenerator()
    
    # Generate workloads
    config = DictionaryWorkloadConfig(
        wordlist_size=wordlist_size,
        min_word_length=4,
        max_word_length=10,
        num_targets=num_targets,
        use_salt=False
    )
    
    workload_data = generator.generate_dictionary_workloads(config)
    print(f"Generated {len(workload_data)} workloads\n")
    
    # Get available backends
    available_backends = list(harness.backends.keys())
    
    # Run benchmarks
    all_results = []
    for i, (workload, target_password) in enumerate(workload_data, 1):
        print(f"\nWorkload {i}/{len(workload_data)}")
        print(f"  Target hash: {workload.target_hash[:16]}...")
        print(f"  Target password: {target_password}")
        print(f"  Wordlist size: {len(workload.dictionary)}")
        
        for backend_name in available_backends:
            print(f"  Running {backend_name}...", end=' ', flush=True)
            try:
                result = harness.benchmark_dictionary(backend_name, workload)
                all_results.append(result)
                status = "OK" if result.success else "FAIL"
                print(f"{status} ({result.runtime_seconds:.4f}s)")
            except Exception as e:
                print(f"ERROR: {e}")
    
    # Aggregate and print results
    if all_results:
        # Export results to CSV
        try:
            csv_file = export_results_to_csv(all_results, "dictionary_results.csv")
            print(f"\nResults exported to: {csv_file}")
        except Exception as e:
            print(f"\nWarning: Could not export results: {e}")
        
        print("\n" + "="*80)
        print("AGGREGATE RESULTS")
        print("="*80)
        
        by_backend = {}
        for result in all_results:
            if result.backend not in by_backend:
                by_backend[result.backend] = []
            by_backend[result.backend].append(result)
        
        for backend_name, results in by_backend.items():
            avg_runtime = sum(r.runtime_seconds for r in results) / len(results)
            avg_hps = sum(r.hashes_per_second for r in results) / len(results)
            success_rate = sum(1 for r in results if r.success) / len(results)
            
            print(f"\n{backend_name}:")
            print(f"  Average Runtime: {avg_runtime:.4f} seconds")
            print(f"  Average Hashes/Second: {avg_hps:,.2f}")
            print(f"  Success Rate: {success_rate*100:.1f}%")


def main():
    # Main entry point
    parser = argparse.ArgumentParser(
        description="Run password hash cracking benchmarks"
    )
    parser.add_argument(
        "--test",
        action="store_true",
        help="Run simple test benchmark"
    )
    parser.add_argument(
        "--brute-force",
        action="store_true",
        help="Run brute-force benchmarks"
    )
    parser.add_argument(
        "--dictionary",
        action="store_true",
        help="Run dictionary attack benchmarks"
    )
    parser.add_argument(
        "--num-targets",
        type=int,
        default=3,
        help="Number of target hashes to test (default: 3)"
    )
    parser.add_argument(
        "--max-length",
        type=int,
        default=6,
        help="Maximum password length for brute-force (default: 6)"
    )
    parser.add_argument(
        "--wordlist-size",
        type=int,
        default=1000,
        help="Wordlist size for dictionary attacks (default: 1000)"
    )
    
    args = parser.parse_args()
    
    # If no specific test is specified, run simple test
    if not any([args.test, args.brute_force, args.dictionary]):
        args.test = True
    
    try:
        if args.test:
            run_simple_benchmark()
        
        if args.brute_force:
            run_brute_force_benchmark(
                num_targets=args.num_targets,
                max_length=args.max_length
            )
        
        if args.dictionary:
            run_dictionary_benchmark(
                num_targets=args.num_targets,
                wordlist_size=args.wordlist_size
            )
    except KeyboardInterrupt:
        print("\n\nBenchmark interrupted by user.")
        sys.exit(1)
    except Exception as e:
        print(f"\n\nError: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()

