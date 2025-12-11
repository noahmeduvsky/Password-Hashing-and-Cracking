# Results exporter for benchmark data
# Exports results to CSV/JSON for analysis and report generation

import csv
import json
from typing import List, Dict, Any
from dataclasses import asdict
from benchmark_harness import BenchmarkResult
from pathlib import Path
import os


def export_results_to_csv(
    results: List[BenchmarkResult],
    output_file: str = "benchmark_results.csv"
) -> str:
    # Export benchmark results to CSV file
    if not results:
        raise ValueError("No results to export")
    
    # Prepare CSV rows
    rows = []
    for result in results:
        row = {
            'backend': result.backend,
            'target_hash': result.target_hash,
            'cracked_password': result.cracked_password if result.cracked_password else '',
            'attempts': result.attempts,
            'runtime_seconds': result.runtime_seconds,
            'hashes_per_second': result.hashes_per_second,
            'success': result.success
        }
        rows.append(row)
    
    # Write CSV file
    with open(output_file, 'w', newline='') as csvfile:
        fieldnames = [
            'backend', 'target_hash', 'cracked_password', 'attempts',
            'runtime_seconds', 'hashes_per_second', 'success'
        ]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        
        writer.writeheader()
        for row in rows:
            writer.writerow(row)
    
    return os.path.abspath(output_file)


def export_results_to_json(
    results: List[BenchmarkResult],
    output_file: str = "benchmark_results.json"
) -> str:
    # Export benchmark results to JSON file
    if not results:
        raise ValueError("No results to export")
    
    # Convert results to dictionaries
    data = {
        'results': [asdict(result) for result in results],
        'summary': {
            'total_runs': len(results),
            'successful': sum(1 for r in results if r.success),
            'failed': sum(1 for r in results if not r.success)
        }
    }
    
    # Write JSON file
    with open(output_file, 'w') as jsonfile:
        json.dump(data, jsonfile, indent=2)
    
    return os.path.abspath(output_file)


def export_scaling_results_to_csv(
    results: List[BenchmarkResult],
    output_file: str = "scaling_results.csv",
    include_speedup: bool = True
) -> str:
    # Export scaling benchmark results to CSV with speedup calculations
    if not results:
        raise ValueError("No results to export")
    
    # Find baseline (usually first result or Python serial)
    baseline = results[0]
    for result in results:
        if 'python_serial' in result.backend.lower():
            baseline = result
            break
    
    # Prepare CSV rows with speedup
    rows = []
    for result in results:
        row = {
            'backend': result.backend,
            'target_hash': result.target_hash[:16] + '...',  # Truncate hash
            'cracked_password': result.cracked_password if result.cracked_password else '',
            'attempts': result.attempts,
            'runtime_seconds': result.runtime_seconds,
            'hashes_per_second': result.hashes_per_second,
            'success': result.success
        }
        
        # Calculate speedup relative to baseline
        if include_speedup:
            if result == baseline:
                speedup = 1.0
            else:
                speedup = baseline.runtime_seconds / result.runtime_seconds if result.runtime_seconds > 0 else 0
            row['speedup'] = speedup
        
        # Extract thread count if multi-threaded
        if 'multithreaded' in result.backend.lower():
            # Try to extract thread count from backend name
            parts = result.backend.split('_')
            for part in parts:
                if part.isdigit():
                    row['num_threads'] = int(part)
                    break
            else:
                row['num_threads'] = 'unknown'
        else:
            row['num_threads'] = 1
        
        rows.append(row)
    
    # Write CSV file
    with open(output_file, 'w', newline='') as csvfile:
        fieldnames = [
            'backend', 'num_threads', 'target_hash', 'cracked_password',
            'attempts', 'runtime_seconds', 'hashes_per_second', 'success'
        ]
        if include_speedup:
            fieldnames.append('speedup')
        
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)
    
    return os.path.abspath(output_file)


def create_summary_report(
    results: List[BenchmarkResult],
    output_file: str = "benchmark_summary.txt"
) -> str:
    # Create a summary report from benchmark results
    if not results:
        raise ValueError("No results to summarize")
    
    # Find baseline
    baseline = results[0]
    for result in results:
        if 'python_serial' in result.backend.lower():
            baseline = result
            break
    
    # Generate report
    lines = []
    lines.append("=" * 80)
    lines.append("BENCHMARK SUMMARY REPORT")
    lines.append("=" * 80)
    lines.append("")
    lines.append(f"Total Runs: {len(results)}")
    lines.append(f"Successful: {sum(1 for r in results if r.success)}")
    lines.append(f"Failed: {sum(1 for r in results if not r.success)}")
    lines.append("")
    lines.append("-" * 80)
    lines.append("RESULTS BY BACKEND")
    lines.append("-" * 80)
    lines.append("")
    
    # Group by backend
    by_backend = {}
    for result in results:
        if result.backend not in by_backend:
            by_backend[result.backend] = []
        by_backend[result.backend].append(result)
    
    for backend_name, backend_results in sorted(by_backend.items()):
        lines.append(f"Backend: {backend_name}")
        lines.append(f"  Runs: {len(backend_results)}")
        
        if backend_results:
            avg_runtime = sum(r.runtime_seconds for r in backend_results) / len(backend_results)
            avg_hps = sum(r.hashes_per_second for r in backend_results) / len(backend_results)
            success_rate = sum(1 for r in backend_results if r.success) / len(backend_results)
            
            lines.append(f"  Average Runtime: {avg_runtime:.4f} seconds")
            lines.append(f"  Average Hashes/Second: {avg_hps:,.2f}")
            lines.append(f"  Success Rate: {success_rate*100:.1f}%")
            
            # Calculate speedup if not baseline
            if backend_name != baseline.backend:
                speedup = baseline.runtime_seconds / avg_runtime if avg_runtime > 0 else 0
                lines.append(f"  Speedup vs Baseline: {speedup:.2f}x")
        
        lines.append("")
    
    # Find fastest
    fastest = min(results, key=lambda r: r.runtime_seconds)
    lines.append("-" * 80)
    lines.append(f"Fastest: {fastest.backend} ({fastest.runtime_seconds:.4f}s)")
    
    if fastest != baseline:
        speedup = baseline.runtime_seconds / fastest.runtime_seconds
        lines.append(f"Total Speedup: {speedup:.2f}x")
    
    lines.append("=" * 80)
    
    # Write report
    with open(output_file, 'w') as f:
        f.write('\n'.join(lines))
    
    return os.path.abspath(output_file)


if __name__ == "__main__":
    # Example usage
    from benchmark_harness import BenchmarkHarness
    from workload_generator import WorkloadGenerator
    
    print("Running example benchmark and exporting results...")
    
    harness = BenchmarkHarness()
    generator = WorkloadGenerator()
    
    workload = generator.create_simple_test_workload()
    
    results = []
    for backend_name in list(harness.backends.keys())[:2]:  # Test first 2 backends
        try:
            result = harness.benchmark_brute_force(
                backend_name,
                workload,
                max_attempts=100000
            )
            results.append(result)
        except Exception as e:
            print(f"Error with {backend_name}: {e}")
    
    if results:
        # Export to CSV
        csv_file = export_results_to_csv(results, "example_results.csv")
        print(f"Exported to CSV: {csv_file}")
        
        # Export to JSON
        json_file = export_results_to_json(results, "example_results.json")
        print(f"Exported to JSON: {json_file}")
        
        # Create summary
        summary_file = create_summary_report(results, "example_summary.txt")
        print(f"Created summary: {summary_file}")


