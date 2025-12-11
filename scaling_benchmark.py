# Scaling benchmark script
# Tests performance with different thread counts and compares backends

import sys
import argparse
import time
from typing import List
from benchmark_harness import (
    BenchmarkHarness,
    BenchmarkResult,
    BackendType,
    print_results
)
from results_exporter import export_scaling_results_to_csv, create_summary_report
from workload_generator import (
    WorkloadGenerator,
    BruteForceWorkloadConfig,
    DictionaryWorkloadConfig
)

try:
    from c_multithreaded_wrapper import CMultithreadedBackend
    C_MULTITHREADED_AVAILABLE = True
except ImportError:
    C_MULTITHREADED_AVAILABLE = False


def run_scaling_benchmark(
    harness: BenchmarkHarness,
    workload,
    thread_counts: List[int],
    max_attempts: int = 1000000
):
    # Run scaling benchmarks with different thread counts
    print("\n" + "="*80)
    print("SCALING BENCHMARK")
    print("="*80)
    print(f"Workload: Hash {workload.target_hash[:16]}...")
    if workload.dictionary:
        print(f"  Type: Dictionary ({len(workload.dictionary)} words)")
    else:
        print(f"  Type: Brute-force (max length: {workload.max_length})")
    print(f"  Thread counts to test: {thread_counts}")
    print()
    
    results = []
    
    # First, get baseline (Python serial)
    if BackendType.PYTHON_SERIAL.value in harness.backends:
        print("Running Python serial baseline...")
        try:
            if workload.dictionary:
                result = harness.benchmark_dictionary(
                    BackendType.PYTHON_SERIAL.value,
                    workload
                )
            else:
                result = harness.benchmark_brute_force(
                    BackendType.PYTHON_SERIAL.value,
                    workload,
                    max_attempts
                )
            results.append(result)
            print(f"  OK {result.runtime_seconds:.4f}s ({result.hashes_per_second:,.2f} H/s)")
        except Exception as e:
            print(f"  ERROR: {e}")
    
    # Test C serial if available
    if BackendType.C_SERIAL.value in harness.backends:
        print("Running C serial...")
        try:
            if workload.dictionary:
                result = harness.benchmark_dictionary(
                    BackendType.C_SERIAL.value,
                    workload
                )
            else:
                result = harness.benchmark_brute_force(
                    BackendType.C_SERIAL.value,
                    workload,
                    max_attempts
                )
            results.append(result)
            print(f"  OK {result.runtime_seconds:.4f}s ({result.hashes_per_second:,.2f} H/s)")
        except Exception as e:
            print(f"  ERROR: {e}")
    
    # Test multi-threaded with different thread counts
    if C_MULTITHREADED_AVAILABLE:
        baseline = results[0] if results else None
        
        for num_threads in thread_counts:
            print(f"Running C multi-threaded ({num_threads} threads)...")
            try:
                # Create backend with specific thread count
                c_mt_backend = CMultithreadedBackend(num_threads=num_threads)
                
                # Time it ourselves
                start_time = time.perf_counter()
                if workload.dictionary:
                    cracked, attempts_count = c_mt_backend.crack_dictionary(
                        workload.target_hash,
                        workload.dictionary,
                        workload.target_salt,
                        num_threads=num_threads
                    )
                else:
                    cracked, attempts_count = c_mt_backend.crack_brute_force(
                        workload.target_hash,
                        workload.character_set,
                        workload.max_length,
                        max_attempts,
                        workload.target_salt,
                        num_threads=num_threads
                    )
                end_time = time.perf_counter()
                
                runtime = end_time - start_time
                hps = attempts_count / runtime if runtime > 0 else 0
                
                result = BenchmarkResult(
                    backend=f"c_multithreaded_{num_threads}",
                    target_hash=workload.target_hash,
                    cracked_password=cracked,
                    attempts=attempts_count,
                    runtime_seconds=runtime,
                    hashes_per_second=hps,
                    success=(cracked is not None)
                )
                
                results.append(result)
                
                # Calculate speedup
                speedup = ""
                if baseline:
                    speedup = f" (speedup: {baseline.runtime_seconds / runtime:.2f}x)"
                
                print(f"  OK {result.runtime_seconds:.4f}s ({result.hashes_per_second:,.2f} H/s){speedup}")
                
            except Exception as e:
                print(f"  ERROR: {e}")
                import traceback
                traceback.print_exc()
    
    # Print summary
    if results:
        print("\n" + "="*80)
        print("SCALING RESULTS SUMMARY")
        print("="*80)
        
        baseline = results[0]
        for result in results:
            speedup = 1.0
            if result != baseline:
                speedup = baseline.runtime_seconds / result.runtime_seconds if result.runtime_seconds > 0 else 0
            
            print(f"\n{result.backend}:")
            print(f"  Runtime: {result.runtime_seconds:.4f} seconds")
            print(f"  Hashes/Second: {result.hashes_per_second:,.2f}")
            print(f"  Attempts: {result.attempts:,}")
            if result != baseline:
                print(f"  Speedup vs baseline: {speedup:.2f}x")
            if result.success:
                print(f"  SUCCESS: {result.cracked_password}")
        
        # Find best performance
        fastest = min(results, key=lambda r: r.runtime_seconds)
        print(f"\nFastest: {fastest.backend} ({fastest.runtime_seconds:.4f}s)")
        
        if len(results) > 2:  # Have multi-threaded results
            mt_results = [r for r in results if 'multithreaded' in r.backend]
            if mt_results:
                best_threads = min(mt_results, key=lambda r: r.runtime_seconds)
                speedup_over_baseline = baseline.runtime_seconds / best_threads.runtime_seconds
                print(f"Best thread count: {best_threads.backend}")
                print(f"Total speedup over baseline: {speedup_over_baseline:.2f}x")
        
        # Export results
        try:
            csv_file = export_scaling_results_to_csv(results, "scaling_results.csv")
            print(f"\nResults exported to: {csv_file}")
        except Exception as e:
            print(f"\nWarning: Could not export results: {e}")


def main():
    # Main entry point
    parser = argparse.ArgumentParser(
        description="Run scaling benchmarks with varying thread counts"
    )
    parser.add_argument(
        "--brute-force",
        action="store_true",
        help="Run brute-force scaling benchmarks"
    )
    parser.add_argument(
        "--dictionary",
        action="store_true",
        help="Run dictionary attack scaling benchmarks"
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
        default=10000,
        help="Wordlist size for dictionary attacks (default: 10000)"
    )
    parser.add_argument(
        "--threads",
        type=str,
        default="1,2,4,8",
        help="Comma-separated list of thread counts (default: 1,2,4,8)"
    )
    parser.add_argument(
        "--max-attempts",
        type=int,
        default=1000000,
        help="Maximum attempts for brute-force (default: 1000000)"
    )
    
    args = parser.parse_args()
    
    # Parse thread counts
    thread_counts = [int(x.strip()) for x in args.threads.split(',')]
    
    # If no specific test is specified, run both
    if not args.brute_force and not args.dictionary:
        args.brute_force = True
    
    harness = BenchmarkHarness()
    generator = WorkloadGenerator()
    
    try:
        if args.brute_force:
            print("="*80)
            print("BRUTE-FORCE SCALING BENCHMARK")
            print("="*80)
            
            # Create a simple workload
            workload = generator.create_simple_test_workload()
            workload.max_length = args.max_length
            
            print(f"Generated workload:")
            print(f"  Target hash: {workload.target_hash}")
            print(f"  Character set: {workload.character_set}")
            print(f"  Max length: {workload.max_length}")
            
            run_scaling_benchmark(
                harness,
                workload,
                thread_counts,
                max_attempts=args.max_attempts
            )
        
        if args.dictionary:
            print("\n" + "="*80)
            print("DICTIONARY ATTACK SCALING BENCHMARK")
            print("="*80)
            
            # Generate dictionary workload
            config = DictionaryWorkloadConfig(
                wordlist_size=args.wordlist_size,
                min_word_length=4,
                max_word_length=10,
                num_targets=1,
                use_salt=False
            )
            
            workload_data = generator.generate_dictionary_workloads(config)
            workload, target_password = workload_data[0]
            
            print(f"Generated workload:")
            print(f"  Target hash: {workload.target_hash[:16]}...")
            print(f"  Target password: {target_password}")
            print(f"  Wordlist size: {len(workload.dictionary)}")
            
            run_scaling_benchmark(
                harness,
                workload,
                thread_counts,
                max_attempts=None  # Not used for dictionary
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

