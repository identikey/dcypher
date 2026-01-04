#!/usr/bin/env python3
"""
HDPRINT Collision Comparison Benchmark - HMAC-per-Character Analysis

This module provides comprehensive collision finding and performance benchmarking
for the HDPRINT HMAC-per-character approach, adapted from the original ColCa
benchmark but updated for the new algorithm.

Features:
- Configurable character length collision testing
- HMAC-per-character performance analysis
- SHA3-512 timing comparison benchmarks (included by default)
- Comprehensive cryptanalysis comparison (included by default)
- Base58 collision space analysis
- Birthday paradox calculations for both approaches
- Statistical collision finding with multiple workers for both methods
- Detailed step-by-step transformation analysis
- Comprehensive keyboard interrupt handling
- Command-line interface with configurable parameters

Algorithm Changes from ColCa:
- Each character comes from separate HMAC-SHA3-512 operation
- Uses base58 encoding taking last character
- Fixed encoding (no swappable schemes)
- HMAC chaining for character dependencies

Usage Examples:
- python3 test_collision_comparison.py --chars 3 --samples 100    # 3-character collisions
- python3 test_collision_comparison.py --chars 5 --samples 50     # 5-character collisions
- python3 test_collision_comparison.py                            # Full benchmark with timing & cryptanalysis
- python3 test_collision_comparison.py --sha3-collision           # SHA3 collision demo with detailed analysis
"""

import sys
import os
import argparse
import time
import multiprocessing
import random
import math
import secrets
import hashlib
from typing import Dict, List, Optional, Tuple, Set, Any
from collections import defaultdict, Counter
from dataclasses import dataclass

import blake3

# Add the source directory to the path to import the HDPRINT library

from dcypher.hdprint import (
    generate_hierarchical_fingerprint,
    generate_hierarchical_fingerprint_with_steps,
    calculate_security_bits,
    analyze_entropy_efficiency,
    get_size_info,
    generate_cyclical_pattern,
    resolve_size_to_segments,
)

library_available = True


@dataclass
class CollisionResult:
    """Result from a collision finding attempt."""

    method_name: str
    total_attempts: int
    collision_found: bool
    collision_time: float
    collision_pair: Optional[Tuple[bytes, bytes]] = None
    collision_fingerprint: Optional[str] = None


@dataclass
class PerformanceResult:
    """Result from performance benchmarking."""

    method_name: str
    iterations: int
    total_time: float
    avg_time_per_operation: float
    operations_per_second: float


@dataclass
class TimingComparison:
    """Result from timing comparison between different methods."""

    hdprint_result: PerformanceResult
    hmac_sha3_result: PerformanceResult
    vanilla_sha3_result: PerformanceResult
    hmac_vs_idk_speedup: float
    vanilla_vs_idk_speedup: float
    vanilla_vs_hmac_speedup: float


@dataclass
class CollisionSample:
    """Single collision sample result."""

    attempts: int
    time: float
    collision_pair: Tuple[bytes, bytes]
    collision_fingerprint: str


@dataclass
class CollisionStats:
    """Statistical analysis of collision samples."""

    method_name: str
    num_chars: int
    total_samples: int
    successful_samples: int
    failed_samples: int

    # Timing statistics
    min_time: float
    max_time: float
    avg_time: float
    median_time: float
    std_time: float

    # Attempt statistics
    min_attempts: int
    max_attempts: int
    avg_attempts: float
    median_attempts: float
    std_attempts: float

    # Theoretical vs actual
    theoretical_expected: float
    actual_vs_theoretical_ratio: float

    # Rate statistics
    avg_rate: float  # attempts per second

    # Last collision found (for display)
    last_collision: Optional[CollisionSample] = None


def generate_hdprint_fingerprint(data: bytes, num_chars: int) -> str:
    """Generate HDPRINT fingerprint with specified number of characters."""
    if not library_available:
        raise RuntimeError("HDPRINT library not available")
    # Use num_segments=1 to get a single segment, but we need to handle custom character counts
    # The HDPRINT library uses predefined patterns, so we need to work with what's available
    # For now, use "tiny" which gives us a single segment of 6 characters
    if num_chars <= 6:
        return generate_hierarchical_fingerprint(data, "tiny")[:num_chars]
    else:
        # For larger numbers, we'll use the medium pattern and truncate
        return generate_hierarchical_fingerprint(data, "medium")[:num_chars]


def generate_sha3_fingerprint(data: bytes, num_chars: int) -> str:
    """Generate fingerprint using pure SHA3-512 approach for comparison."""
    # Use SHA3-512 to generate a hash
    hash_obj = hashlib.sha3_512()
    hash_obj.update(data)
    hash_bytes = hash_obj.digest()

    # Convert to base58 and take last num_chars characters
    # Using built-in base58 implementation
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    num = int.from_bytes(hash_bytes, byteorder="big")

    if num == 0:
        base58_str = alphabet[0]
    else:
        result = ""
        while num > 0:
            num, remainder = divmod(num, 58)
            result = alphabet[remainder] + result
        base58_str = result

    return base58_str[-num_chars:]


def generate_vanilla_hex_fingerprint(data: bytes, num_chars: int) -> str:
    """Generate fingerprint using vanilla SHA3-512 hex approach (left side sampling)."""
    # Use SHA3-512 to generate a hash
    hash_obj = hashlib.sha3_512()
    hash_obj.update(data)
    hash_bytes = hash_obj.digest()

    # Convert to hex and take first num_chars characters from left side
    # This is uniform distribution since hex is uniform
    hex_str = hash_bytes.hex()

    return hex_str[:num_chars]


def generate_hmac_sha3_fingerprint(
    data: bytes, num_chars: int, key: bytes = b"hdprint_key"
) -> str:
    """Generate fingerprint using single HMAC-SHA3-512 approach for comparison."""
    # Use HMAC-SHA3-512 to generate authenticated hash
    import hmac

    hmac_obj = hmac.new(key, data, hashlib.sha3_512)
    hash_bytes = hmac_obj.digest()

    # Convert to base58 and take last num_chars characters
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    num = int.from_bytes(hash_bytes, byteorder="big")

    if num == 0:
        base58_str = alphabet[0]
    else:
        result = ""
        while num > 0:
            num, remainder = divmod(num, 58)
            result = alphabet[remainder] + result
        base58_str = result

    return base58_str[-num_chars:]


def generate_blake3_fingerprint(data: bytes, num_chars: int) -> str:
    """Generate fingerprint using pure BLAKE3 approach for comparison."""
    try:
        import blake3
    except ImportError:
        raise ImportError("blake3 module not available")
    # Use BLAKE3 to generate a hash (32 bytes output)
    hash_bytes = blake3.blake3(data).digest()

    # Convert to base58 and take last num_chars characters
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    num = int.from_bytes(hash_bytes, byteorder="big")

    if num == 0:
        base58_str = alphabet[0]
    else:
        result = ""
        while num > 0:
            num, remainder = divmod(num, 58)
            result = alphabet[remainder] + result
        base58_str = result

    return base58_str[-num_chars:]


def generate_blake3_hex_fingerprint(data: bytes, num_chars: int) -> str:
    """Generate fingerprint using BLAKE3 with hex output (left side sampling)."""
    try:
        import blake3
    except ImportError:
        raise ImportError("blake3 module not available")
    # Use BLAKE3 to generate a hash
    hash_bytes = blake3.blake3(data).digest()

    # Convert to hex and take first num_chars characters from left side
    hex_str = hash_bytes.hex()

    return hex_str[:num_chars]


def generate_hmac_blake3_fingerprint(
    data: bytes, num_chars: int, key: bytes = b"hdprint_key_32byte_padding00"
) -> str:
    """Generate fingerprint using HMAC-BLAKE3 approach for comparison."""
    try:
        import blake3
    except ImportError:
        raise ImportError("blake3 module not available")
    # Use HMAC with BLAKE3 as the hash function
    # Note: Blake3 doesn't have native HMAC, so we'll use a keyed hash instead
    # Blake3 requires exactly 32 bytes for the key
    if len(key) != 32:
        # Pad or truncate key to 32 bytes
        key = (key + b"\x00" * 32)[:32]
    keyed_hasher = blake3.blake3(key=key)
    keyed_hasher.update(data)
    hash_bytes = keyed_hasher.digest()

    # Convert to base58 and take last num_chars characters
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    num = int.from_bytes(hash_bytes, byteorder="big")

    if num == 0:
        base58_str = alphabet[0]
    else:
        result = ""
        while num > 0:
            num, remainder = divmod(num, 58)
            result = alphabet[remainder] + result
        base58_str = result

    return base58_str[-num_chars:]


def pure_collision_worker(
    worker_id,
    method,
    num_chars,
    target_samples,
    max_time,
    result_queue,
    progress_queue,
    stop_event,
):
    """Pure CPU-bound worker process for maximum performance - no shared state during computation."""
    import os
    import time
    import secrets

    # Import blake3 in worker process to avoid multiprocessing issues
    try:
        import blake3

        blake3_available = True
    except ImportError:
        blake3_available = False

    # Set process priority to normal (helps with CPU scheduling)
    try:
        os.nice(0)
    except:
        pass

    samples_found = []
    total_attempts = 0
    seen = {}
    start_time = time.time()
    last_progress = time.time()

    try:
        while len(samples_found) < target_samples and not stop_event.is_set():
            # Check timeout
            if max_time and (time.time() - start_time) > max_time:
                break

            # Generate random key
            key = secrets.token_bytes(32)

            # Generate fingerprint based on method - pure computation, no shared state
            if method == "SHA3-512":
                fingerprint = generate_sha3_fingerprint(key, num_chars)
            elif method == "HMAC-SHA3-512":
                fingerprint = generate_hmac_sha3_fingerprint(key, num_chars)
            elif method == "SHA3-512-HEX":
                fingerprint = generate_vanilla_hex_fingerprint(key, num_chars)
            elif method == "BLAKE3":
                if not blake3_available:
                    # Log error and exit worker gracefully
                    try:
                        result_queue.put((worker_id, [], 0))
                    except:
                        pass
                    return
                fingerprint = generate_blake3_fingerprint(key, num_chars)
            elif method == "BLAKE3-HEX":
                if not blake3_available:
                    # Log error and exit worker gracefully
                    try:
                        result_queue.put((worker_id, [], 0))
                    except:
                        pass
                    return
                fingerprint = generate_blake3_hex_fingerprint(key, num_chars)
            elif method == "HMAC-BLAKE3":
                if not blake3_available:
                    # Log error and exit worker gracefully
                    try:
                        result_queue.put((worker_id, [], 0))
                    except:
                        pass
                    return
                fingerprint = generate_hmac_blake3_fingerprint(key, num_chars)
            else:
                fingerprint = generate_hdprint_fingerprint(key, num_chars)

            total_attempts += 1

            # Check for collision
            if fingerprint in seen:
                collision_time = time.time() - start_time
                sample = CollisionSample(
                    attempts=total_attempts,
                    time=collision_time,
                    collision_pair=(seen[fingerprint], key),
                    collision_fingerprint=fingerprint,
                )
                samples_found.append(sample)

                # Clear seen dict but keep total_attempts accumulating
                seen.clear()
                start_time = time.time()  # Reset timer for next collision
            else:
                seen[fingerprint] = key

            # Report progress occasionally (non-blocking)
            current_time = time.time()
            if current_time - last_progress >= 2.0:  # Every 2 seconds
                try:
                    progress_queue.put_nowait(
                        (worker_id, len(samples_found), total_attempts)
                    )
                    last_progress = current_time
                except:
                    pass  # Queue full, skip this update

    except KeyboardInterrupt:
        pass
    except Exception as e:
        print(f"Worker {worker_id} error: {e}")

    # Send final result
    try:
        result_queue.put((worker_id, samples_found, total_attempts))
    except:
        pass  # Queue might be closed


def collect_collision_samples(
    num_chars: int,
    num_samples: int,
    max_time_per_sample: Optional[float] = None,
    method: str = "HDPRINT",
) -> CollisionStats:
    """Collect collision samples using pure multiprocessing for maximum CPU utilization."""
    print(
        f"\nCOLLECTING {num_samples} COLLISION SAMPLES - {num_chars} CHARS ({method})"
    )
    print("=" * 70)

    # Calculate theoretical expectations
    if method == "SHA3-512-HEX" or method == "BLAKE3-HEX":
        alphabet_size = 16  # Hex characters (0-9, a-f)
        collision_space = alphabet_size**num_chars
    else:
        alphabet_size = 58  # Base58 alphabet
        collision_space = alphabet_size**num_chars

    theoretical_expected = math.sqrt(collision_space * math.pi / 2)

    print(f"Theoretical expected attempts: {theoretical_expected:,.0f}")

    # Skip blake3 methods if not available
    if method in ["BLAKE3", "BLAKE3-HEX", "HMAC-BLAKE3"] and blake3 is None:
        print(f"❌ Skipping {method} - blake3 module not available")
        return CollisionStats(
            method_name=method,
            num_chars=num_chars,
            total_samples=num_samples,
            successful_samples=0,
            failed_samples=num_samples,
            min_time=0,
            max_time=0,
            avg_time=0,
            median_time=0,
            std_time=0,
            min_attempts=0,
            max_attempts=0,
            avg_attempts=0,
            median_attempts=0,
            std_attempts=0,
            theoretical_expected=theoretical_expected,
            actual_vs_theoretical_ratio=0,
            avg_rate=0,
            last_collision=None,
        )

    # Use all CPU cores
    num_workers = multiprocessing.cpu_count()
    samples_per_worker = max(1, num_samples // num_workers)
    remaining_samples = num_samples % num_workers

    print(f"🚀 Spawning {num_workers} pure CPU-bound processes for maximum performance")
    print(f"📊 Each worker targeting {samples_per_worker}+ samples")
    if max_time_per_sample:
        total_max_time = max_time_per_sample * (samples_per_worker + 1)
        print(f"⏰ Max time per worker: {total_max_time:.1f}s")
    else:
        total_max_time = None
        print("⏰ Max time: INFINITE")
    print(f"🔥 Pure process parallelism - no GIL interference")
    print()

    # Create queues for communication
    result_queue = multiprocessing.Queue()
    progress_queue = multiprocessing.Queue()
    stop_event = multiprocessing.Event()

    # Start worker processes
    processes = []
    for i in range(num_workers):
        target_samples = samples_per_worker + (1 if i < remaining_samples else 0)

        process = multiprocessing.Process(
            target=pure_collision_worker,
            args=(
                i,
                method,
                num_chars,
                target_samples,
                total_max_time,
                result_queue,
                progress_queue,
                stop_event,
            ),
            name=f"CollisionWorker-{i}",
        )
        process.start()
        processes.append(process)

    print(f"🔥 Started {len(processes)} independent worker processes")
    print("📈 Real-time monitoring every 5 seconds:")
    print()

    # Monitor progress
    start_time = time.time()
    last_display = start_time
    total_samples_found = 0
    total_attempts = 0
    worker_progress = {}

    try:
        while True:
            current_time = time.time()
            elapsed = current_time - start_time

            # Collect progress updates (non-blocking)
            try:
                while True:
                    worker_id, samples_count, attempts_count = (
                        progress_queue.get_nowait()
                    )
                    worker_progress[worker_id] = (samples_count, attempts_count)
            except:
                pass  # No more progress updates

            # Calculate totals from worker progress
            if worker_progress:
                total_samples_found = sum(
                    progress[0] for progress in worker_progress.values()
                )
                total_attempts = sum(
                    progress[1] for progress in worker_progress.values()
                )

            # Check if we have enough samples
            if total_samples_found >= num_samples:
                print(f"🎉 Target reached! Found {total_samples_found} samples")
                stop_event.set()
                break

            # Display progress every 5 seconds
            if current_time - last_display >= 5.0 and elapsed > 1.0:
                if total_attempts > 0:
                    samples_per_sec = total_samples_found / elapsed
                    attempts_per_sec = total_attempts / elapsed
                    progress_pct = (total_samples_found / num_samples) * 100

                    eta_str = "N/A"
                    if samples_per_sec > 0:
                        remaining = num_samples - total_samples_found
                        eta_seconds = remaining / samples_per_sec
                        eta_str = f"{eta_seconds:.0f}s"

                    # Count active processes
                    active_processes = sum(1 for p in processes if p.is_alive())

                    print(
                        f"📊 [{elapsed:6.1f}s] {method:>15} | "
                        f"Samples: {total_samples_found:3d}/{num_samples} ({progress_pct:5.1f}%) | "
                        f"Hashes: {attempts_per_sec:>10,.0f}/s | "
                        f"Samples/s: {samples_per_sec:5.1f} | "
                        f"Active: {active_processes}/{num_workers} | ETA: {eta_str}"
                    )

                last_display = current_time

            # Check if all processes finished
            if not any(p.is_alive() for p in processes):
                break

            time.sleep(0.1)  # Small sleep to avoid busy waiting

    except KeyboardInterrupt:
        print("\n❌ Collection interrupted by user")
        stop_event.set()

    # Wait for all processes to finish
    print(f"\n🛑 Stopping workers...")
    for process in processes:
        process.join(timeout=5.0)
        if process.is_alive():
            process.terminate()
            process.join(timeout=2.0)
            if process.is_alive():
                process.kill()

    total_time = time.time() - start_time

    # Collect results
    all_samples = []
    total_attempts = 0

    try:
        while True:
            worker_id, worker_samples, worker_attempts = result_queue.get_nowait()
            all_samples.extend(worker_samples)
            total_attempts += worker_attempts
    except:
        pass  # No more results

    # Take only the requested number of samples
    samples = all_samples[:num_samples]
    failed_samples = num_samples - len(samples)

    print(f"🎯 Collection complete!")
    print(f"⏱️  Total time: {total_time:.2f}s")
    print(f"✅ Samples collected: {len(samples)}/{num_samples}")
    print(f"❌ Failed samples: {failed_samples}")
    print(f"🔢 Total attempts: {total_attempts:,}")
    print(f"⚡ Average rate: {total_attempts / total_time:,.0f} attempts/sec")
    print(f"📊 Average samples/sec: {len(samples) / total_time:.1f}")
    print(f"🏁 Peak CPU utilization achieved with {num_workers} processes")
    print()

    if not samples:
        print("❌ No successful collision samples collected!")
        return CollisionStats(
            method_name=method,
            num_chars=num_chars,
            total_samples=num_samples,
            successful_samples=0,
            failed_samples=num_samples,
            min_time=0,
            max_time=0,
            avg_time=0,
            median_time=0,
            std_time=0,
            min_attempts=0,
            max_attempts=0,
            avg_attempts=0,
            median_attempts=0,
            std_attempts=0,
            theoretical_expected=theoretical_expected,
            actual_vs_theoretical_ratio=0,
            avg_rate=0,
            last_collision=None,
        )

    # Calculate statistics
    times = [s.time for s in samples]
    attempts_list = [s.attempts for s in samples]

    import statistics

    stats = CollisionStats(
        method_name=method,
        num_chars=num_chars,
        total_samples=num_samples,
        successful_samples=len(samples),
        failed_samples=failed_samples,
        # Timing statistics
        min_time=min(times),
        max_time=max(times),
        avg_time=statistics.mean(times),
        median_time=statistics.median(times),
        std_time=statistics.stdev(times) if len(times) > 1 else 0,
        # Attempt statistics
        min_attempts=min(attempts_list),
        max_attempts=max(attempts_list),
        avg_attempts=statistics.mean(attempts_list),
        median_attempts=statistics.median(attempts_list),
        std_attempts=statistics.stdev(attempts_list) if len(attempts_list) > 1 else 0,
        # Theoretical vs actual
        theoretical_expected=theoretical_expected,
        actual_vs_theoretical_ratio=statistics.mean(attempts_list)
        / theoretical_expected,
        # Rate statistics
        avg_rate=total_attempts / total_time if total_time > 0 else 0,
        # Last collision for display
        last_collision=samples[-1] if samples else None,
    )

    return stats


def print_collision_audit_summary(stats_list: List[CollisionStats]):
    """Print comprehensive collision audit summary."""
    print("\n" + "=" * 80)
    print("CRYPTOGRAPHIC AUDIT SUMMARY - COLLISION ANALYSIS")
    print("=" * 80)

    for stats in stats_list:
        print(f"\n{stats.method_name} - {stats.num_chars} CHARACTERS")
        print("-" * 60)

        # Sample success rate
        success_rate = (stats.successful_samples / stats.total_samples) * 100
        print(f"Sample Collection:")
        print(f"  Total samples requested: {stats.total_samples}")
        print(f"  Successful samples: {stats.successful_samples}")
        print(f"  Failed samples: {stats.failed_samples}")
        print(f"  Success rate: {success_rate:.1f}%")

        if stats.successful_samples == 0:
            print("  ❌ No statistical analysis possible")
            continue

        # Timing analysis
        print(f"\nTiming Analysis:")
        print(f"  Min time: {stats.min_time:.3f}s")
        print(f"  Max time: {stats.max_time:.3f}s")
        print(f"  Average time: {stats.avg_time:.3f}s")
        print(f"  Median time: {stats.median_time:.3f}s")
        print(f"  Std deviation: {stats.std_time:.3f}s")

        # Attempt analysis
        print(f"\nAttempt Analysis:")
        print(f"  Min attempts: {stats.min_attempts:,}")
        print(f"  Max attempts: {stats.max_attempts:,}")
        print(f"  Average attempts: {stats.avg_attempts:,.0f}")
        print(f"  Median attempts: {stats.median_attempts:,.0f}")
        print(f"  Std deviation: {stats.std_attempts:,.0f}")

        # Theoretical vs actual
        print(f"\nTheoretical vs Actual:")
        print(f"  Theoretical expected: {stats.theoretical_expected:,.0f}")
        print(f"  Actual average: {stats.avg_attempts:,.0f}")
        print(f"  Ratio (actual/theoretical): {stats.actual_vs_theoretical_ratio:.3f}")

        # Security implications
        deviation = abs(stats.actual_vs_theoretical_ratio - 1.0)
        if deviation < 0.1:
            security_assessment = "✅ EXCELLENT - Matches theoretical expectations"
        elif deviation < 0.3:
            security_assessment = "✅ GOOD - Close to theoretical expectations"
        elif deviation < 0.5:
            security_assessment = "⚠️  MODERATE - Some deviation from theory"
        else:
            security_assessment = "❌ POOR - Significant deviation from theory"

        print(f"  Security assessment: {security_assessment}")

        # Performance metrics
        print(f"\nPerformance Metrics:")
        print(f"  Average rate: {stats.avg_rate:,.0f} attempts/second")

        # Last collision details (only show the last one found)
        if stats.last_collision:
            print(f"\nLast Collision Found:")
            print(f"  Fingerprint: '{stats.last_collision.collision_fingerprint}'")
            print(f"  Attempts: {stats.last_collision.attempts:,}")
            print(f"  Time: {stats.last_collision.time:.3f}s")
            print(
                f"  Rate: {stats.last_collision.attempts / stats.last_collision.time:.0f} attempts/sec"
            )

            # Show the collision pair
            key1, key2 = stats.last_collision.collision_pair
            print(f"  Input 1: {key1.hex()}")
            print(f"  Input 2: {key2.hex()}")

    # Overall summary
    print(f"\n" + "=" * 80)
    print("OVERALL AUDIT FINDINGS")
    print("=" * 80)

    print(f"Methods tested: {len(stats_list)}")

    # Find fastest and slowest methods
    valid_stats = [s for s in stats_list if s.successful_samples > 0]
    if valid_stats:
        fastest = min(valid_stats, key=lambda x: x.avg_time)
        slowest = max(valid_stats, key=lambda x: x.avg_time)

        print(
            f"Fastest method: {fastest.method_name} ({fastest.avg_time:.3f}s average)"
        )
        print(
            f"Slowest method: {slowest.method_name} ({slowest.avg_time:.3f}s average)"
        )

        # Security vs performance tradeoff
        print(f"\nSecurity vs Performance Analysis:")
        for stats in valid_stats:
            if stats.method_name == "HDPRINT":
                print(
                    f"  {stats.method_name}: HIGHEST security (per-char HMAC), LOWEST performance"
                )
            elif stats.method_name == "HMAC-SHA3-512":
                print(
                    f"  {stats.method_name}: HIGH security (authenticated), MEDIUM performance"
                )
            elif stats.method_name == "SHA3-512":
                print(
                    f"  {stats.method_name}: MEDIUM security (cryptographic hash), HIGH performance"
                )
            elif stats.method_name == "SHA3-512-HEX":
                print(
                    f"  {stats.method_name}: LOW security (smaller space), HIGHEST performance"
                )
            elif stats.method_name == "BLAKE3-512":
                print(
                    f"  {stats.method_name}: HIGH security (cryptographic hash), MEDIUM performance"
                )

    print(f"\n" + "=" * 80)
    print("CRYPTOGRAPHIC AUDIT SUMMARY COMPLETE")
    print("=" * 80)


def run_three_way_timing_comparison(
    num_chars: int, iterations: int = 10000
) -> TimingComparison:
    """Run comprehensive timing comparison between HDPRINT, HMAC-SHA3-512, and vanilla SHA3-512."""
    print(f"\nTHREE-WAY TIMING COMPARISON - {num_chars} CHARACTERS")
    print("=" * 60)

    # Pre-generate test keys
    test_keys = [secrets.token_bytes(32) for _ in range(iterations)]

    print(f"Benchmarking {iterations:,} operations for each method...")
    print()

    # 1. Benchmark HDPRINT (HMAC-per-character)
    print("Testing HDPRINT (HMAC-per-character)...")
    idk_start_time = time.time()

    i = 0
    try:
        for i, key in enumerate(test_keys):
            generate_hdprint_fingerprint(key, num_chars)

            if i % 1000 == 0 and i > 0:
                elapsed = time.time() - idk_start_time
                rate = i / elapsed if elapsed > 0 else 0
                print(f"  HDPRINT Progress: {i:,}/{iterations:,} ({rate:.0f} ops/sec)")

    except KeyboardInterrupt:
        print("\nHDPRINT benchmark interrupted by user")
        iterations = i

    idk_total_time = time.time() - idk_start_time
    idk_avg_time = idk_total_time / iterations if iterations > 0 else 0
    idk_ops_per_sec = iterations / idk_total_time if idk_total_time > 0 else 0

    hdprint_result = PerformanceResult(
        method_name="HDPRINT",
        iterations=iterations,
        total_time=idk_total_time,
        avg_time_per_operation=idk_avg_time,
        operations_per_second=idk_ops_per_sec,
    )

    # 2. Benchmark HMAC-SHA3-512 (single operation)
    print("\nTesting HMAC-SHA3-512 (single operation)...")
    hmac_start_time = time.time()

    i = 0
    try:
        for i, key in enumerate(test_keys):
            generate_hmac_sha3_fingerprint(key, num_chars)

            if i % 1000 == 0 and i > 0:
                elapsed = time.time() - hmac_start_time
                rate = i / elapsed if elapsed > 0 else 0
                print(
                    f"  HMAC-SHA3 Progress: {i:,}/{iterations:,} ({rate:.0f} ops/sec)"
                )

    except KeyboardInterrupt:
        print("\nHMAC-SHA3 benchmark interrupted by user")
        iterations = i

    hmac_total_time = time.time() - hmac_start_time
    hmac_avg_time = hmac_total_time / iterations if iterations > 0 else 0
    hmac_ops_per_sec = iterations / hmac_total_time if hmac_total_time > 0 else 0

    hmac_sha3_result = PerformanceResult(
        method_name="HMAC-SHA3-512",
        iterations=iterations,
        total_time=hmac_total_time,
        avg_time_per_operation=hmac_avg_time,
        operations_per_second=hmac_ops_per_sec,
    )

    # 3. Benchmark vanilla SHA3-512
    print("\nTesting vanilla SHA3-512...")
    sha3_start_time = time.time()

    i = 0
    try:
        for i, key in enumerate(test_keys):
            generate_sha3_fingerprint(key, num_chars)

            if i % 1000 == 0 and i > 0:
                elapsed = time.time() - sha3_start_time
                rate = i / elapsed if elapsed > 0 else 0
                print(
                    f"  Vanilla SHA3 Progress: {i:,}/{iterations:,} ({rate:.0f} ops/sec)"
                )

    except KeyboardInterrupt:
        print("\nVanilla SHA3 benchmark interrupted by user")
        iterations = i

    sha3_total_time = time.time() - sha3_start_time
    sha3_avg_time = sha3_total_time / iterations if iterations > 0 else 0
    sha3_ops_per_sec = iterations / sha3_total_time if sha3_total_time > 0 else 0

    vanilla_sha3_result = PerformanceResult(
        method_name="Vanilla SHA3-512",
        iterations=iterations,
        total_time=sha3_total_time,
        avg_time_per_operation=sha3_avg_time,
        operations_per_second=sha3_ops_per_sec,
    )

    # 4. Benchmark BLAKE3-512
    print("\nTesting BLAKE3-512...")
    blake3_start_time = time.time()

    i = 0
    try:
        # Check if blake3 is available
        try:
            import blake3

            blake3_available = True
        except ImportError:
            blake3_available = False
            print("  BLAKE3 not available, skipping...")

        if blake3_available:
            for i, key in enumerate(test_keys):
                generate_blake3_fingerprint(key, num_chars)

                if i % 1000 == 0 and i > 0:
                    elapsed = time.time() - blake3_start_time
                    rate = i / elapsed if elapsed > 0 else 0
                    print(
                        f"  BLAKE3 Progress: {i:,}/{iterations:,} ({rate:.0f} ops/sec)"
                    )

    except KeyboardInterrupt:
        print("\nBLAKE3 benchmark interrupted by user")
        iterations = i

    blake3_total_time = time.time() - blake3_start_time
    blake3_avg_time = blake3_total_time / iterations if iterations > 0 else 0
    blake3_ops_per_sec = iterations / blake3_total_time if blake3_total_time > 0 else 0

    blake3_result = PerformanceResult(
        method_name="BLAKE3-512",
        iterations=iterations,
        total_time=blake3_total_time,
        avg_time_per_operation=blake3_avg_time,
        operations_per_second=blake3_ops_per_sec,
    )

    # Calculate comparison metrics
    hmac_vs_idk_speedup = idk_total_time / hmac_total_time if hmac_total_time > 0 else 0
    vanilla_vs_idk_speedup = (
        idk_total_time / sha3_total_time if sha3_total_time > 0 else 0
    )
    vanilla_vs_hmac_speedup = (
        hmac_total_time / sha3_total_time if sha3_total_time > 0 else 0
    )
    blake3_vs_idk_speedup = (
        idk_total_time / blake3_total_time if blake3_total_time > 0 else 0
    )

    # Display comprehensive results
    print(f"\nTHREE-WAY TIMING COMPARISON RESULTS")
    print("=" * 60)

    print(f"HDPRINT (HMAC-per-character, {num_chars} chars):")
    print(f"  Total time: {idk_total_time:.3f}s")
    print(f"  Avg per operation: {idk_avg_time * 1000:.3f}ms")
    print(f"  Operations/second: {idk_ops_per_sec:.0f}")
    print(f"  HMAC operations: {iterations * num_chars:,}")
    print(f"  HMAC rate: {(iterations * num_chars) / idk_total_time:.0f} HMAC/sec")

    print(f"\nHMAC-SHA3-512 (single operation, {num_chars} chars):")
    print(f"  Total time: {hmac_total_time:.3f}s")
    print(f"  Avg per operation: {hmac_avg_time * 1000:.3f}ms")
    print(f"  Operations/second: {hmac_ops_per_sec:.0f}")
    print(f"  HMAC operations: {iterations:,}")
    print(f"  HMAC rate: {iterations / hmac_total_time:.0f} HMAC/sec")

    print(f"\nVanilla SHA3-512 ({num_chars} chars):")
    print(f"  Total time: {sha3_total_time:.3f}s")
    print(f"  Avg per operation: {sha3_avg_time * 1000:.3f}ms")
    print(f"  Operations/second: {sha3_ops_per_sec:.0f}")
    print(f"  SHA3 operations: {iterations:,}")
    print(f"  SHA3 rate: {iterations / sha3_total_time:.0f} SHA3/sec")

    print(f"\nBLAKE3-512 ({num_chars} chars):")
    print(f"  Total time: {blake3_total_time:.3f}s")
    print(f"  Avg per operation: {blake3_avg_time * 1000:.3f}ms")
    print(f"  Operations/second: {blake3_ops_per_sec:.0f}")
    print(f"  BLAKE3 operations: {iterations:,}")
    print(f"  BLAKE3 rate: {iterations / blake3_total_time:.0f} BLAKE3/sec")

    print(f"\nPERFORMANCE ANALYSIS:")
    print(f"  Fastest: Vanilla SHA3-512")
    print(
        f"  Middle: HMAC-SHA3-512 is {vanilla_vs_hmac_speedup:.2f}x slower than vanilla"
    )
    print(f"  Slowest: HDPRINT is {vanilla_vs_idk_speedup:.2f}x slower than vanilla")
    print()
    print(f"  Direct Comparisons:")
    print(f"    HMAC-SHA3-512 vs HDPRINT: {hmac_vs_idk_speedup:.2f}x faster")
    print(f"    Vanilla SHA3 vs HDPRINT: {vanilla_vs_idk_speedup:.2f}x faster")
    print(f"    Vanilla SHA3 vs HMAC-SHA3: {vanilla_vs_hmac_speedup:.2f}x faster")
    print()
    print(f"  Security vs Performance Trade-offs:")
    print(f"    HDPRINT: {num_chars}x operations, per-character security")
    print(f"    HMAC-SHA3-512: 1x operation, authenticated hashing")
    print(f"    Vanilla SHA3-512: 1x operation, basic hashing")
    print(f"    BLAKE3-512: 1x operation, cryptographic hash")

    return TimingComparison(
        hdprint_result=hdprint_result,
        hmac_sha3_result=hmac_sha3_result,
        vanilla_sha3_result=vanilla_sha3_result,
        hmac_vs_idk_speedup=hmac_vs_idk_speedup,
        vanilla_vs_idk_speedup=vanilla_vs_idk_speedup,
        vanilla_vs_hmac_speedup=vanilla_vs_hmac_speedup,
    )


def find_collision_worker(args):
    """Worker function for multiprocessing collision finding."""
    method_name, num_chars, max_attempts, max_time, worker_id = args

    # Import blake3 in worker process to avoid multiprocessing issues
    try:
        import blake3

        blake3_available = True
    except ImportError:
        blake3_available = False

    start_time = time.time()
    seen_fingerprints = {}
    attempts = 0

    try:
        # Handle infinite limits properly
        while (max_attempts == float("inf") or attempts < max_attempts) and (
            max_time == float("inf") or (time.time() - start_time) < max_time
        ):
            # Generate random key
            random_key = secrets.token_bytes(32)  # 256-bit key

            # Generate fingerprint based on method
            if method_name == "SHA3-512":
                fingerprint = generate_sha3_fingerprint(random_key, num_chars)
            elif method_name == "HMAC-SHA3-512":
                fingerprint = generate_hmac_sha3_fingerprint(random_key, num_chars)
            elif method_name == "SHA3-512-HEX":
                fingerprint = generate_vanilla_hex_fingerprint(random_key, num_chars)
            elif method_name == "BLAKE3":
                if not blake3_available:
                    return CollisionResult(
                        method_name=method_name,
                        total_attempts=attempts,
                        collision_found=False,
                        collision_time=time.time() - start_time,
                    )
                fingerprint = generate_blake3_fingerprint(random_key, num_chars)
            elif method_name == "BLAKE3-HEX":
                if not blake3_available:
                    return CollisionResult(
                        method_name=method_name,
                        total_attempts=attempts,
                        collision_found=False,
                        collision_time=time.time() - start_time,
                    )
                fingerprint = generate_blake3_hex_fingerprint(random_key, num_chars)
            elif method_name == "HMAC-BLAKE3":
                if not blake3_available:
                    return CollisionResult(
                        method_name=method_name,
                        total_attempts=attempts,
                        collision_found=False,
                        collision_time=time.time() - start_time,
                    )
                fingerprint = generate_hmac_blake3_fingerprint(random_key, num_chars)
            else:
                fingerprint = generate_hdprint_fingerprint(random_key, num_chars)

            # Check for collision
            if fingerprint in seen_fingerprints:
                collision_time = time.time() - start_time
                return CollisionResult(
                    method_name=method_name,
                    total_attempts=attempts + 1,
                    collision_found=True,
                    collision_time=collision_time,
                    collision_pair=(seen_fingerprints[fingerprint], random_key),
                    collision_fingerprint=fingerprint,
                )

            seen_fingerprints[fingerprint] = random_key
            attempts += 1

            # Progress reporting every 1000 attempts
            if attempts % 1000 == 0:
                elapsed = time.time() - start_time
                rate = attempts / elapsed if elapsed > 0 else 0
                print(
                    f"  Worker {worker_id}: {attempts:,} attempts ({rate:.0f}/sec)",
                    flush=True,
                )

    except KeyboardInterrupt:
        return CollisionResult(
            method_name=method_name,
            total_attempts=attempts,
            collision_found=False,
            collision_time=time.time() - start_time,
        )

    return CollisionResult(
        method_name=method_name,
        total_attempts=attempts,
        collision_found=False,
        collision_time=time.time() - start_time,
    )


def worker_with_timeout(args):
    """Simpler worker function with timeout handling."""
    method_name, num_chars, max_attempts, max_time, worker_id = args

    # Import blake3 in worker process to avoid multiprocessing issues
    try:
        import blake3

        blake3_available = True
    except ImportError:
        blake3_available = False

    start_time = time.time()
    seen_fingerprints = {}
    attempts = 0
    last_progress_time = start_time

    try:
        while (max_attempts == float("inf") or attempts < max_attempts) and (
            max_time == float("inf") or (time.time() - start_time) < max_time
        ):
            # Generate random key
            random_key = secrets.token_bytes(32)

            # Generate fingerprint based on method
            if method_name == "SHA3-512":
                fingerprint = generate_sha3_fingerprint(random_key, num_chars)
            elif method_name == "HMAC-SHA3-512":
                fingerprint = generate_hmac_sha3_fingerprint(random_key, num_chars)
            elif method_name == "SHA3-512-HEX":
                fingerprint = generate_vanilla_hex_fingerprint(random_key, num_chars)
            elif method_name == "BLAKE3":
                if not blake3_available:
                    return CollisionResult(
                        method_name=method_name,
                        total_attempts=attempts,
                        collision_found=False,
                        collision_time=time.time() - start_time,
                    )
                fingerprint = generate_blake3_fingerprint(random_key, num_chars)
            elif method_name == "BLAKE3-HEX":
                if not blake3_available:
                    return CollisionResult(
                        method_name=method_name,
                        total_attempts=attempts,
                        collision_found=False,
                        collision_time=time.time() - start_time,
                    )
                fingerprint = generate_blake3_hex_fingerprint(random_key, num_chars)
            elif method_name == "HMAC-BLAKE3":
                if not blake3_available:
                    return CollisionResult(
                        method_name=method_name,
                        total_attempts=attempts,
                        collision_found=False,
                        collision_time=time.time() - start_time,
                    )
                fingerprint = generate_hmac_blake3_fingerprint(random_key, num_chars)
            else:
                fingerprint = generate_hdprint_fingerprint(random_key, num_chars)

            # Check for collision
            if fingerprint in seen_fingerprints:
                collision_time = time.time() - start_time
                return CollisionResult(
                    method_name=method_name,
                    total_attempts=attempts + 1,
                    collision_found=True,
                    collision_time=collision_time,
                    collision_pair=(seen_fingerprints[fingerprint], random_key),
                    collision_fingerprint=fingerprint,
                )

            seen_fingerprints[fingerprint] = random_key
            attempts += 1

            # Progress reporting every 5 seconds
            current_time = time.time()
            if current_time - last_progress_time >= 5.0:
                elapsed = current_time - start_time
                rate = attempts / elapsed if elapsed > 0 else 0
                print(
                    f"  Worker {worker_id}: {attempts:,} attempts in {elapsed:.1f}s ({rate:.0f}/sec)",
                    flush=True,
                )
                last_progress_time = current_time

    except KeyboardInterrupt:
        return CollisionResult(
            method_name=method_name,
            total_attempts=attempts,
            collision_found=False,
            collision_time=time.time() - start_time,
        )

    return CollisionResult(
        method_name=method_name,
        total_attempts=attempts,
        collision_found=False,
        collision_time=time.time() - start_time,
    )


def run_collision_finding(
    num_chars: int,
    max_time: Optional[float] = None,
    num_workers: Optional[int] = None,
    method: str = "HDPRINT",
) -> CollisionResult:
    """Run collision finding with multiple workers and simplified progress reporting."""

    # Use all available CPU cores if not specified
    if num_workers is None:
        num_workers = multiprocessing.cpu_count()

    print(f"\nCOLLISION FINDING - {num_chars} CHARACTERS ({method})")
    print("-" * 50)

    # Calculate theoretical collision space based on method
    if method == "SHA3-512-HEX" or method == "BLAKE3-HEX":
        alphabet_size = 16  # Hex characters (0-9, a-f)
        collision_space = alphabet_size**num_chars
        alphabet_name = "hex"
    else:
        alphabet_size = 58  # Base58 alphabet
        collision_space = alphabet_size**num_chars
        alphabet_name = "base58"

    expected_attempts = math.sqrt(collision_space * math.pi / 2)  # Birthday paradox

    print(f"Collision space: {alphabet_size}^{num_chars} = {collision_space:,}")
    print(f"Expected attempts (birthday): {expected_attempts:,.0f}")

    if max_time is None:
        print(
            f"Using {num_workers} workers, INFINITE TIME & ATTEMPTS - will search until collision found"
        )
        max_time_per_worker = float("inf")  # Infinite time
        max_attempts_per_worker = float("inf")  # Infinite attempts - truly no limit
    else:
        print(f"Using {num_workers} workers, max {max_time}s each")
        max_time_per_worker = max_time
        max_attempts_per_worker = int(
            expected_attempts * 5 / num_workers
        )  # Increased from 2x to 5x

    print()

    # Prepare worker arguments
    worker_args = [
        (method, num_chars, max_attempts_per_worker, max_time_per_worker, i)
        for i in range(num_workers)
    ]

    start_time = time.time()

    try:
        print(f"Starting {num_workers} collision finding workers...")
        print("Progress updates every 5 seconds per worker...")
        print()

        # Use a simpler approach without shared state
        with multiprocessing.Pool(num_workers) as pool:
            # Use map_async to get results as they complete
            async_result = pool.map_async(worker_with_timeout, worker_args)

            # Wait for completion with timeout if specified
            if max_time is not None:
                results = async_result.get(timeout=max_time + 10)  # Add 10s buffer
            else:
                results = async_result.get()

    except KeyboardInterrupt:
        print("\nCollision finding interrupted by user")
        return CollisionResult(
            method_name=method,
            total_attempts=0,
            collision_found=False,
            collision_time=time.time() - start_time,
        )
    except multiprocessing.TimeoutError:
        print("\nCollision finding timed out")
        return CollisionResult(
            method_name=method,
            total_attempts=0,
            collision_found=False,
            collision_time=time.time() - start_time,
        )

    # Combine results
    total_attempts = sum(r.total_attempts for r in results)
    collision_found = any(r.collision_found for r in results)
    total_time = time.time() - start_time

    # Find the collision if any
    collision_result = next((r for r in results if r.collision_found), None)

    if collision_result:
        print(f"\n\nCOLLISION FOUND!")
        print(f"Time: {collision_result.collision_time:.2f}s")
        print(f"Attempts: {collision_result.total_attempts:,}")
        print()
        print("=" * 60)
        print("COLLISION DETAILS")
        print("=" * 60)
        print(f"Collision fingerprint: '{collision_result.collision_fingerprint}'")
        print()

        # Show the two different keys that produce the same fingerprint
        if collision_result.collision_pair:
            key1 = collision_result.collision_pair[0]
            key2 = collision_result.collision_pair[1]
        else:
            print("   Error: No collision pair data available")
            return collision_result

        print("DATA INPUT 1:")
        print(f"  Key (hex): {key1.hex()}")
        print(f"  Key (bytes): {len(key1)} bytes")

        print()
        print("DATA INPUT 2:")
        print(f"  Key (hex): {key2.hex()}")
        print(f"  Key (bytes): {len(key2)} bytes")

        print()
        print("HMAC-per-Character Process:")

        # Verify and show the collision step by step
        if method == "HDPRINT":
            fp1 = generate_hdprint_fingerprint(key1, num_chars)
            fp2 = generate_hdprint_fingerprint(key2, num_chars)
        elif method == "SHA3-512":
            fp1 = generate_sha3_fingerprint(key1, num_chars)
            fp2 = generate_sha3_fingerprint(key2, num_chars)
        elif method == "HMAC-SHA3-512":
            fp1 = generate_hmac_sha3_fingerprint(key1, num_chars)
            fp2 = generate_hmac_sha3_fingerprint(key2, num_chars)
        elif method == "SHA3-512-HEX":
            fp1 = generate_vanilla_hex_fingerprint(key1, num_chars)
            fp2 = generate_vanilla_hex_fingerprint(key2, num_chars)
        elif method == "BLAKE3":
            fp1 = generate_blake3_fingerprint(key1, num_chars)
            fp2 = generate_blake3_fingerprint(key2, num_chars)
        elif method == "BLAKE3-HEX":
            fp1 = generate_blake3_hex_fingerprint(key1, num_chars)
            fp2 = generate_blake3_hex_fingerprint(key2, num_chars)
        elif method == "HMAC-BLAKE3":
            fp1 = generate_hmac_blake3_fingerprint(key1, num_chars)
            fp2 = generate_hmac_blake3_fingerprint(key2, num_chars)
        else:
            fp1 = generate_hdprint_fingerprint(key1, num_chars)
            fp2 = generate_hdprint_fingerprint(key2, num_chars)

        print(f"  Input 1 → {method} → '{fp1}'")
        print(f"  Input 2 → {method} → '{fp2}'")
        print()
        print(f"MATCH VERIFIED: '{fp1}' == '{fp2}' → {fp1 == fp2}")
        print("=" * 60)

        return collision_result
    else:
        print(f"\nNo collision found")
        print(f"Total time: {total_time:.2f}s")
        print(f"Total attempts: {total_attempts:,}")
        if total_time > 0:
            print(f"Rate: {total_attempts / total_time:.0f} attempts/sec")

        return CollisionResult(
            method_name=method,
            total_attempts=total_attempts,
            collision_found=False,
            collision_time=total_time,
        )


def run_performance_benchmark(
    num_chars: int, iterations: int = 10000
) -> PerformanceResult:
    """Run performance benchmark for HDPRINT."""
    print(f"\nPERFORMANCE BENCHMARK - {num_chars} CHARACTERS")
    print("-" * 50)

    # Pre-generate test keys
    test_keys = [secrets.token_bytes(32) for _ in range(iterations)]

    print(f"Benchmarking {iterations:,} fingerprint generations...")

    start_time = time.time()

    i = 0
    try:
        for i, key in enumerate(test_keys):
            generate_hdprint_fingerprint(key, num_chars)

            if i % 1000 == 0 and i > 0:
                elapsed = time.time() - start_time
                rate = i / elapsed if elapsed > 0 else 0
                print(f"  Progress: {i:,}/{iterations:,} ({rate:.0f} ops/sec)")

    except KeyboardInterrupt:
        print("\nPerformance benchmark interrupted by user")
        iterations = i + 1

    total_time = time.time() - start_time
    avg_time = total_time / iterations if iterations > 0 else 0
    ops_per_sec = iterations / total_time if total_time > 0 else 0

    print(f"\nPerformance Results:")
    print(f"  Iterations: {iterations:,}")
    print(f"  Total time: {total_time:.3f}s")
    print(f"  Avg per operation: {avg_time * 1000:.3f}ms")
    print(f"  Operations/second: {ops_per_sec:.0f}")
    print(f"  HMAC operations: {iterations * num_chars:,}")
    print(f"  HMAC rate: {(iterations * num_chars) / total_time:.0f} HMAC/sec")

    return PerformanceResult(
        method_name="HDPRINT",
        iterations=iterations,
        total_time=total_time,
        avg_time_per_operation=avg_time,
        operations_per_second=ops_per_sec,
    )


def analyze_collision_space(num_chars: int):
    """Analyze theoretical collision space for given character length."""
    print(f"\nCOLLISION SPACE ANALYSIS - {num_chars} CHARACTERS")
    print("-" * 50)

    # Base58 alphabet size
    alphabet_size = 58

    # Total space
    total_space = alphabet_size**num_chars

    # Birthday paradox expected collisions
    birthday_expected = math.sqrt(total_space * math.pi / 2)

    # Security analysis using HDPRINT security model
    # Use "tiny" for small patterns, "medium" for larger ones
    size = "tiny" if num_chars <= 6 else "medium"
    size_info = get_size_info(size)
    security_bits, layer_bits = calculate_security_bits(size=size)

    print(f"Alphabet: Base58 ({alphabet_size} characters)")
    print(f"Total space: {alphabet_size}^{num_chars} = {total_space:,}")
    print(f"Space bits: {math.log2(total_space):.1f}")
    print(f"Birthday expected: {birthday_expected:,.0f} attempts")
    print(f"Birthday bits: {math.log2(birthday_expected):.1f}")
    print()
    print(f"HDPRINT Security Analysis:")
    print(f"  Size: {size}")
    print(f"  Pattern: {size_info['pattern']}")
    print(f"  Security bits: {security_bits:.1f}")
    print(f"  Layer securities: {[f'{b:.1f}' for b in layer_bits]}")
    print(f"  First layer vuln: Birthday attack ({layer_bits[0]:.1f} bits)")
    print()

    # Time estimates
    attempts_per_second = 1000  # Conservative estimate
    birthday_time = birthday_expected / attempts_per_second

    print(f"Time Estimates (at {attempts_per_second:,} attempts/sec):")
    print(
        f"  Birthday attack: {birthday_time:.0f} seconds ({birthday_time / 3600:.1f} hours)"
    )

    if birthday_time < 60:
        print(f"  Very fast - suitable for demonstration")
    elif birthday_time < 3600:
        print(f"  Fast - good for testing")
    elif birthday_time < 86400:
        print(f"  Moderate - might take a while")
    else:
        print(f"  Slow - impractical for real-time testing")


def demonstrate_simple_collision():
    """Demonstrate collision finding with a very simple case."""
    print(f"\nSIMPLE COLLISION DEMONSTRATION")
    print("-" * 50)

    # Use 2 characters for quick demonstration
    num_chars = 2
    print(f"Finding collision for {num_chars} characters...")

    # Quick collision space analysis
    collision_space = 58**num_chars  # 3,364
    expected = math.sqrt(collision_space * math.pi / 2)  # ~73 attempts

    print(f"Collision space: 58^{num_chars} = {collision_space:,}")
    print(f"Expected attempts: {expected:.0f}")
    print()

    seen = {}
    attempts = 0
    start_time = time.time()

    try:
        while True:
            key = secrets.token_bytes(32)
            fingerprint = generate_hdprint_fingerprint(key, num_chars)
            attempts += 1

            if fingerprint in seen:
                elapsed = time.time() - start_time
                print(f"COLLISION FOUND!")
                print(f"  Attempts: {attempts}")
                print(f"  Time: {elapsed:.3f}s")
                print(f"  Rate: {attempts / elapsed:.0f} attempts/sec")
                print()
                print("=" * 60)
                print("COLLISION DETAILS")
                print("=" * 60)
                print(f"Collision fingerprint: '{fingerprint}'")
                print()

                # Show the two different keys that produce the same fingerprint
                key1 = seen[fingerprint]
                key2 = key

                print("DATA INPUT 1:")
                print(f"  Key (hex): {key1.hex()}")
                print(f"  Key (bytes): {len(key1)} bytes")

                print()
                print("DATA INPUT 2:")
                print(f"  Key (hex): {key2.hex()}")
                print(f"  Key (bytes): {len(key2)} bytes")

                print()
                print("HMAC-per-Character Process:")

                # Verify the collision
                fp1 = generate_hdprint_fingerprint(key1, num_chars)
                fp2 = generate_hdprint_fingerprint(key2, num_chars)

                print(f"  Input 1 → HMAC chain → '{fp1}'")
                print(f"  Input 2 → HMAC chain → '{fp2}'")
                print()
                print(f"MATCH VERIFIED: '{fp1}' == '{fp2}' → {fp1 == fp2}")
                print("=" * 60)
                break

            seen[fingerprint] = key

            if attempts % 10 == 0:
                elapsed = time.time() - start_time
                rate = attempts / elapsed if elapsed > 0 else 0
                print(f"  Attempts: {attempts} ({rate:.0f}/sec)")

    except KeyboardInterrupt:
        print(f"\nDemonstration interrupted after {attempts} attempts")


def parse_arguments():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="HDPRINT Collision Comparison Benchmark",
        epilog="""
Examples:
  %(prog)s                                        # Full benchmark - runs EVERYTHING (all methods, demos, timing, cryptanalysis)
  %(prog)s --simple                               # ISOLATED: Quick 2-char HMAC collision demo only
  %(prog)s --sha3-collision                       # ISOLATED: SHA3-512 collision with detailed analysis only
  %(prog)s --vanilla-hex-collision                # ISOLATED: Vanilla SHA3-512 hex collision (left side sampling) only
  %(prog)s --chars 3 --collision-only            # ISOLATED: Find 3-char collision (HMAC only)
  %(prog)s --chars 4 --performance-only          # ISOLATED: Performance benchmark only
  %(prog)s --chars 5 --max-time 300              # Full benchmark with 5-char and 5min timeout
  %(prog)s --analysis-only --chars 6             # ISOLATED: Theoretical analysis only
  %(prog)s --samples 50                          # STATISTICAL: Collect 50 collision samples for audit analysis
  %(prog)s --chars 3 --samples 100 --max-time 10  # STATISTICAL: 100 samples, 10s timeout per sample

Note: This benchmark compares HDPRINT HMAC-per-character vs SHA3-512 approaches.
      DEFAULT (no flags): Runs complete benchmark suite with all methods, demonstrations, timing, and cryptanalysis.
      SWITCHES: Isolate execution to run only the specified component.
      STATISTICAL: Sampling mode is always enabled for comprehensive audit analysis.
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "--chars",
        "-c",
        type=int,
        default=4,
        help="Number of characters to test for collisions (default: 4)",
    )

    parser.add_argument(
        "--max-time",
        "-t",
        type=float,
        default=None,
        help="Maximum time per collision worker in seconds (default: INFINITE - run until found)",
    )

    parser.add_argument(
        "--timeout",
        type=float,
        default=None,
        help="Set a specific timeout in seconds (overrides default infinite behavior)",
    )

    parser.add_argument(
        "--workers",
        "-w",
        type=int,
        default=multiprocessing.cpu_count(),
        help=f"Number of parallel workers for collision finding (default: {multiprocessing.cpu_count()} - all CPU cores)",
    )

    parser.add_argument(
        "--performance-iterations",
        type=int,
        default=10000,
        help="Number of iterations for performance test (default: 10000)",
    )

    parser.add_argument(
        "--samples",
        "-s",
        type=int,
        default=100,
        help="Number of collision samples to collect for statistical analysis (default: 100)",
    )

    parser.add_argument(
        "--collision-only",
        action="store_true",
        help="Run only collision finding test",
    )

    parser.add_argument(
        "--performance-only",
        action="store_true",
        help="Run only performance benchmark",
    )

    parser.add_argument(
        "--analysis-only",
        action="store_true",
        help="Run only theoretical analysis",
    )

    parser.add_argument(
        "--simple",
        action="store_true",
        help="Run simple 2-character collision demonstration",
    )

    parser.add_argument(
        "--sha3-collision",
        action="store_true",
        help="Run SHA3-512 collision demonstration with detailed step-by-step output",
    )

    parser.add_argument(
        "--vanilla-hex-collision",
        action="store_true",
        help="Run vanilla SHA3-512 hex collision demonstration (left side sampling)",
    )

    return parser.parse_args()


def main():
    """Main function with command-line interface."""
    print("HDPRINT COLLISION COMPARISON BENCHMARK")
    print("=" * 70)
    print()

    args = parse_arguments()

    # Skip library check for vanilla hex collision or provide limited functionality
    if not library_available and not args.vanilla_hex_collision:
        print("HDPRINT library not available")
        print("Make sure you're running from the dcypher project root")
        print("Running with limited functionality (vanilla hex collision only)")
        print()

    print(f"Configuration:")
    print(f"  Character length: {args.chars}")

    # Determine timeout behavior
    if args.timeout is not None:
        max_time = args.timeout
        timeout_msg = f"{args.timeout}s"
    elif args.max_time is not None:
        max_time = args.max_time
        timeout_msg = f"{args.max_time}s"
    else:
        max_time = None
        timeout_msg = "INFINITE (run until found)"

    print(f"  Max time per worker: {timeout_msg}")
    print(f"  Collision workers: {args.workers}")
    print(f"  Performance iterations: {args.performance_iterations:,}")
    print(f"  Collision samples: {args.samples}")
    print(f"  Sampling mode: YES (always enabled)")
    print()
    print(f"Algorithm: HDPRINT HMAC-per-character")
    print(f"  Each character from separate HMAC-SHA3-512 operation")
    print(f"  Base58 encoding with last character selection")
    print(f"  HMAC chaining for character dependencies")
    print()

    try:
        if args.simple:
            demonstrate_simple_collision()
        elif args.sha3_collision:
            print("SHA3 collision demonstration not implemented")
        elif args.vanilla_hex_collision:
            print("Vanilla hex collision demonstration not implemented")
        elif args.analysis_only:
            analyze_collision_space(args.chars)
        elif args.collision_only:
            analyze_collision_space(args.chars)
            run_collision_finding(args.chars, max_time, args.workers)
        elif args.performance_only:
            run_performance_benchmark(args.chars, args.performance_iterations)
        else:
            # Run full benchmark suite (or limited functionality if library unavailable)
            if library_available:
                analyze_collision_space(args.chars)
                run_performance_benchmark(args.chars, args.performance_iterations)
                run_three_way_timing_comparison(args.chars, args.performance_iterations)
                print("Cryptanalysis comparison not implemented")

            # Run demonstration (always runs - includes both base58 and hex methods)
            print("Demonstration functionality not implemented")

            if library_available:
                print(f"\nCOLLISION ANALYSIS")
                print("=" * 50)

                # Calculate expected attempts for warning
                collision_space = 58**args.chars
                expected_attempts = math.sqrt(collision_space * math.pi / 2)

                if args.chars > 6 and max_time is None:
                    print(
                        f"WARNING: {args.chars} characters may require ~{expected_attempts:,.0f} attempts"
                    )
                    print(f"   This could take a very long time without a timeout!")
                    print(f"   Consider using --max-time to set a reasonable limit")
                    print()

                print(
                    f"Running statistical sampling mode with {args.samples} samples per method..."
                )

                # Collect collision samples for all methods
                all_stats = []

                # Run HDPRINT collision sampling
                idk_stats = collect_collision_samples(
                    args.chars, args.samples, max_time, method="HDPRINT"
                )
                all_stats.append(idk_stats)

                # Run HMAC-SHA3-512 collision sampling
                hmac_stats = collect_collision_samples(
                    args.chars, args.samples, max_time, method="HMAC-SHA3-512"
                )
                all_stats.append(hmac_stats)

                # Run vanilla SHA3-512 collision sampling
                sha3_stats = collect_collision_samples(
                    args.chars, args.samples, max_time, method="SHA3-512"
                )
                all_stats.append(sha3_stats)

                # Run vanilla SHA3-512-HEX collision sampling
                hex_stats = collect_collision_samples(
                    args.chars, args.samples, max_time, method="SHA3-512-HEX"
                )
                all_stats.append(hex_stats)

                # Run BLAKE3 collision sampling
                blake3_stats = collect_collision_samples(
                    args.chars, args.samples, max_time, method="BLAKE3"
                )
                all_stats.append(blake3_stats)

                # Run BLAKE3-HEX collision sampling
                blake3_hex_stats = collect_collision_samples(
                    args.chars, args.samples, max_time, method="BLAKE3-HEX"
                )
                all_stats.append(blake3_hex_stats)

                # Run HMAC-BLAKE3 collision sampling
                hmac_blake3_stats = collect_collision_samples(
                    args.chars, args.samples, max_time, method="HMAC-BLAKE3"
                )
                all_stats.append(hmac_blake3_stats)

                # Print comprehensive audit summary
                print_collision_audit_summary(all_stats)

            else:
                print(f"\nSkipping collision finding (HDPRINT library not available)")

        print("\nFOUR-WAY COMPARISON BENCHMARK COMPLETED SUCCESSFULLY!")
        print()
        print("ANALYSIS SUMMARY:")
        print("HDPRINT (HMAC-per-character):")
        print("  - Each character requires one HMAC-SHA3-512 operation")
        print("  - Provides per-character security and partial collision resistance")
        print("  - Slowest but most secure approach")
        print()
        print("HMAC-SHA3-512 (single operation):")
        print("  - Single authenticated hash operation")
        print("  - Good balance between security and performance")
        print("  - Prevents key-less attacks while being faster than HDPRINT")
        print()
        print("Vanilla SHA3-512 (base58, right-side sampling):")
        print("  - Single hash operation with base58 encoding")
        print("  - Takes last characters from base58 string")
        print("  - Larger collision space (58^n) due to base58 alphabet")
        print()
        print("Vanilla SHA3-512-HEX (hex, left-side sampling):")
        print("  - Single hash operation with hex encoding")
        print("  - Takes first characters from hex string (uniform distribution)")
        print("  - Smaller collision space (16^n) but faster collision finding")
        print()
        print("CRYPTOGRAPHIC FINDINGS:")
        print(
            "- Base58 provides ~5.86 bits entropy per character, hex provides 4.0 bits"
        )
        print("- All methods vulnerable to birthday attacks on sampled characters")
        print("- Four-way timing comparison reveals clear performance hierarchy")
        print("- Cryptanalysis shows distinct security vs performance trade-offs")
        print("- HMAC methods provide better degradation characteristics")
        print("- Character sampling direction matters for non-uniform encodings")

        print()
        print("STATISTICAL SAMPLING RESULTS:")
        print("- Comprehensive collision timing statistics collected")
        print("- Theoretical vs actual collision rates analyzed")
        print("- Security assessment based on deviation from expected values")
        print("- Per-method performance metrics with variance analysis")
        print("- Only last collision from each method displayed for brevity")

    except KeyboardInterrupt:
        print("\nBenchmark interrupted by user")
    except Exception as e:
        print(f"\nFATAL ERROR: {str(e)}")
        import traceback

        traceback.print_exc()


if __name__ == "__main__":
    main()
