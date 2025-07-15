#!/usr/bin/env python3
"""
Advanced Collision Finding for IDK_HPRINT

This module provides sophisticated collision finding capabilities for IDK_HPRINT,
including multi-worker collision finding, statistical sampling, and comprehensive
performance analysis. Backported from test_collision_comparison.py.

Features:
- Multi-worker collision finding with progress reporting
- Statistical collision sampling with comprehensive analysis
- Support for multiple hash algorithms (IDK_HPRINT, SHA3-512, BLAKE3, HMAC variants)
- Real-time progress monitoring
- Comprehensive audit summaries
- Performance benchmarking and comparison

Usage:
    from dcypher.idk_hprint.attacks.collision_finding import (
        find_collision_advanced,
        collect_collision_samples,
        CollisionStats,
        CollisionResult
    )

    # Find a single collision
    result = find_collision_advanced(num_chars=3, max_time=60)

    # Collect statistical samples
    stats = collect_collision_samples(num_chars=3, num_samples=50)
"""

import sys
import os
import time
import multiprocessing
import math
import secrets
import hashlib
import statistics
from typing import Dict, List, Optional, Tuple, Any
from collections import defaultdict
from dataclasses import dataclass

# Optional dependencies
try:
    import blake3
except ImportError:
    blake3 = None

# Import IDK_HPRINT library
try:
    from .. import generate_hierarchical_fingerprint

    library_available = True
except ImportError:
    library_available = False

    def generate_hierarchical_fingerprint(*args, **kwargs) -> str:
        raise ImportError("IDK_HPRINT library not available")


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


@dataclass
class PerformanceResult:
    """Result from performance benchmarking."""

    method_name: str
    iterations: int
    total_time: float
    avg_time_per_operation: float
    operations_per_second: float


def generate_idk_hprint_fingerprint(data: bytes, num_chars: int) -> str:
    """Generate IDK_HPRINT fingerprint with specified number of characters."""
    if not library_available:
        raise RuntimeError("IDK_HPRINT library not available")
    pattern = [num_chars]  # Single segment with N characters
    return generate_hierarchical_fingerprint(data, pattern)


def generate_sha3_fingerprint(data: bytes, num_chars: int) -> str:
    """Generate fingerprint using pure SHA3-512 approach for comparison."""
    hash_obj = hashlib.sha3_512()
    hash_obj.update(data)
    hash_bytes = hash_obj.digest()

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


def generate_hmac_sha3_fingerprint(
    data: bytes, num_chars: int, key: bytes = b"idk_hprint_key"
) -> str:
    """Generate fingerprint using single HMAC-SHA3-512 approach for comparison."""
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
    if blake3 is None:
        raise ImportError("blake3 module not available")

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


def collision_worker(
    worker_id: int,
    method: str,
    num_chars: int,
    target_samples: int,
    max_time: Optional[float],
    result_queue: multiprocessing.Queue,
    progress_queue: multiprocessing.Queue,
    stop_event: multiprocessing.Event,
):
    """Worker process for collision finding."""
    import os
    import time
    import secrets

    # Import blake3 in worker process to avoid multiprocessing issues
    blake3_available = blake3 is not None
    if not blake3_available and method.startswith("BLAKE3"):
        # Exit gracefully if blake3 not available
        try:
            result_queue.put((worker_id, [], 0))
        except:
            pass
        return

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

            # Generate fingerprint based on method
            if method == "SHA3-512":
                fingerprint = generate_sha3_fingerprint(key, num_chars)
            elif method == "HMAC-SHA3-512":
                fingerprint = generate_hmac_sha3_fingerprint(key, num_chars)
            elif method == "BLAKE3":
                fingerprint = generate_blake3_fingerprint(key, num_chars)
            else:
                fingerprint = generate_idk_hprint_fingerprint(key, num_chars)

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

            # Report progress occasionally
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
        pass


def collect_collision_samples(
    num_chars: int,
    num_samples: int,
    max_time_per_sample: Optional[float] = None,
    method: str = "IDK_HPRINT",
) -> CollisionStats:
    """Collect collision samples using multiprocessing for maximum performance."""
    print(
        f"\nCOLLECTING {num_samples} COLLISION SAMPLES - {num_chars} CHARS ({method})"
    )
    print("=" * 70)

    # Calculate theoretical expectations
    alphabet_size = 58  # Base58 alphabet
    collision_space = alphabet_size**num_chars
    theoretical_expected = math.sqrt(collision_space * math.pi / 2)

    print(f"Theoretical expected attempts: {theoretical_expected:,.0f}")

    # Skip blake3 methods if not available
    if method.startswith("BLAKE3") and blake3 is None:
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

    print(f"🚀 Spawning {num_workers} worker processes")
    print(f"📊 Each worker targeting {samples_per_worker}+ samples")

    # Create queues for communication
    result_queue = multiprocessing.Queue()
    progress_queue = multiprocessing.Queue()
    stop_event = multiprocessing.Event()

    # Start worker processes
    processes = []
    for i in range(num_workers):
        target_samples = samples_per_worker + (1 if i < remaining_samples else 0)

        process = multiprocessing.Process(
            target=collision_worker,
            args=(
                i,
                method,
                num_chars,
                target_samples,
                max_time_per_sample,
                result_queue,
                progress_queue,
                stop_event,
            ),
        )
        process.start()
        processes.append(process)

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

            # Collect progress updates
            try:
                while True:
                    worker_id, samples_count, attempts_count = (
                        progress_queue.get_nowait()
                    )
                    worker_progress[worker_id] = (samples_count, attempts_count)
            except:
                pass

            # Calculate totals
            if worker_progress:
                total_samples_found = sum(
                    progress[0] for progress in worker_progress.values()
                )
                total_attempts = sum(
                    progress[1] for progress in worker_progress.values()
                )

            # Check if we have enough samples
            if total_samples_found >= num_samples:
                stop_event.set()
                break

            # Display progress every 5 seconds
            if current_time - last_display >= 5.0 and elapsed > 1.0:
                if total_attempts > 0:
                    samples_per_sec = total_samples_found / elapsed
                    attempts_per_sec = total_attempts / elapsed
                    progress_pct = (total_samples_found / num_samples) * 100

                    active_processes = sum(1 for p in processes if p.is_alive())

                    print(
                        f"📊 [{elapsed:6.1f}s] {method:>15} | "
                        f"Samples: {total_samples_found:3d}/{num_samples} ({progress_pct:5.1f}%) | "
                        f"Rate: {attempts_per_sec:>10,.0f}/s | "
                        f"Active: {active_processes}/{num_workers}"
                    )

                last_display = current_time

            # Check if all processes finished
            if not any(p.is_alive() for p in processes):
                break

            time.sleep(0.1)

    except KeyboardInterrupt:
        print("\n❌ Collection interrupted by user")
        stop_event.set()

    # Wait for all processes to finish
    for process in processes:
        process.join(timeout=5.0)
        if process.is_alive():
            process.terminate()
            process.join()

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
        pass

    # Take only the requested number of samples
    samples = all_samples[:num_samples]
    failed_samples = num_samples - len(samples)

    print(f"🎯 Collection complete!")
    print(f"⏱️  Total time: {total_time:.2f}s")
    print(f"✅ Samples collected: {len(samples)}/{num_samples}")
    print(f"❌ Failed samples: {failed_samples}")
    print(f"🔢 Total attempts: {total_attempts:,}")
    print(f"⚡ Average rate: {total_attempts / total_time:,.0f} attempts/sec")

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


def find_collision_advanced(
    num_chars: int,
    max_time: Optional[float] = None,
    num_workers: Optional[int] = None,
    method: str = "IDK_HPRINT",
) -> CollisionResult:
    """Find a single collision using advanced multiprocessing approach."""
    if num_workers is None:
        num_workers = multiprocessing.cpu_count()

    print(f"\nFINDING COLLISION - {num_chars} CHARACTERS ({method})")
    print("-" * 50)

    # Calculate theoretical expectations
    alphabet_size = 58  # Base58 alphabet
    collision_space = alphabet_size**num_chars
    expected_attempts = math.sqrt(collision_space * math.pi / 2)

    print(f"Collision space: {alphabet_size}^{num_chars} = {collision_space:,}")
    print(f"Expected attempts: {expected_attempts:.0f}")
    print(f"Using {num_workers} workers")

    # Use collect_collision_samples with target of 1 sample
    stats = collect_collision_samples(
        num_chars=num_chars,
        num_samples=1,
        max_time_per_sample=max_time,
        method=method,
    )

    if stats.successful_samples > 0 and stats.last_collision:
        collision = stats.last_collision
        return CollisionResult(
            method_name=method,
            total_attempts=collision.attempts,
            collision_found=True,
            collision_time=collision.time,
            collision_pair=collision.collision_pair,
            collision_fingerprint=collision.collision_fingerprint,
        )
    else:
        return CollisionResult(
            method_name=method,
            total_attempts=0,
            collision_found=False,
            collision_time=stats.avg_time if stats.avg_time > 0 else 0,
        )


def print_collision_audit_summary(stats_list: List[CollisionStats]) -> None:
    """Print comprehensive collision audit summary."""
    print("\n" + "=" * 80)
    print("COLLISION AUDIT SUMMARY")
    print("=" * 80)

    for stats in stats_list:
        print(f"\n{stats.method_name} - {stats.num_chars} CHARACTERS")
        print("-" * 60)

        # Sample success rate
        success_rate = (stats.successful_samples / stats.total_samples) * 100
        print(f"Sample Collection:")
        print(f"  Total samples requested: {stats.total_samples}")
        print(f"  Successful samples: {stats.successful_samples}")
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

        # Attempt analysis
        print(f"\nAttempt Analysis:")
        print(f"  Min attempts: {stats.min_attempts:,}")
        print(f"  Max attempts: {stats.max_attempts:,}")
        print(f"  Average attempts: {stats.avg_attempts:,.0f}")
        print(f"  Median attempts: {stats.median_attempts:,.0f}")

        # Theoretical vs actual
        print(f"\nTheoretical vs Actual:")
        print(f"  Theoretical expected: {stats.theoretical_expected:,.0f}")
        print(f"  Actual average: {stats.avg_attempts:,.0f}")
        print(f"  Ratio: {stats.actual_vs_theoretical_ratio:.3f}")

        # Security assessment
        deviation = abs(stats.actual_vs_theoretical_ratio - 1.0)
        if deviation < 0.1:
            assessment = "✅ EXCELLENT - Matches theoretical expectations"
        elif deviation < 0.3:
            assessment = "✅ GOOD - Close to theoretical expectations"
        elif deviation < 0.5:
            assessment = "⚠️  MODERATE - Some deviation from theory"
        else:
            assessment = "❌ POOR - Significant deviation from theory"

        print(f"  Security assessment: {assessment}")

        # Performance metrics
        print(f"\nPerformance:")
        print(f"  Average rate: {stats.avg_rate:,.0f} attempts/second")

        # Last collision details
        if stats.last_collision:
            print(f"\nLast Collision:")
            print(f"  Fingerprint: '{stats.last_collision.collision_fingerprint}'")
            print(f"  Attempts: {stats.last_collision.attempts:,}")
            print(f"  Time: {stats.last_collision.time:.3f}s")

    print(f"\n" + "=" * 80)
    print("COLLISION AUDIT COMPLETE")
    print("=" * 80)


def benchmark_collision_methods(
    num_chars: int,
    num_samples: int = 20,
    max_time_per_sample: Optional[float] = None,
) -> List[CollisionStats]:
    """Benchmark collision finding across multiple methods."""
    print(f"\nBENCHMARKING COLLISION METHODS - {num_chars} CHARACTERS")
    print("=" * 70)

    methods = ["IDK_HPRINT", "HMAC-SHA3-512", "SHA3-512"]
    if blake3 is not None:
        methods.append("BLAKE3")

    all_stats = []

    for method in methods:
        print(f"\n🔍 Testing {method}...")
        stats = collect_collision_samples(
            num_chars=num_chars,
            num_samples=num_samples,
            max_time_per_sample=max_time_per_sample,
            method=method,
        )
        all_stats.append(stats)

    # Print comparative summary
    print_collision_audit_summary(all_stats)

    return all_stats


# Public API
__all__ = [
    "CollisionResult",
    "CollisionSample",
    "CollisionStats",
    "PerformanceResult",
    "find_collision_advanced",
    "collect_collision_samples",
    "print_collision_audit_summary",
    "benchmark_collision_methods",
]
