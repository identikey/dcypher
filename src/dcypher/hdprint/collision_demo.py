#!/usr/bin/env python3
"""
HDPRINT Collision Finding Demo

Demonstration script that shows collision finding capabilities
for the HDPRINT HMAC-per-character approach.

This script demonstrates:
- Quick 2-character collision finding
- 3-character collision with theoretical analysis
- Performance characteristics of the algorithm

Run with: python3 collision_demo.py
"""

import sys
import os
import time
import math
import secrets
from typing import List, Tuple, Optional

# Add the parent directory to import the HDPRINT library
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

try:
    from dcypher.hdprint import (
        generate_hierarchical_fingerprint,
        calculate_security_bits,
    )

    # print("HDPRINT library loaded successfully")
    library_available = True
except ImportError as e:
    print(f"Could not import HDPRINT library: {e}")
    library_available = False

    # Define dummy functions to avoid unbound errors
    def generate_hierarchical_fingerprint(
        public_key: bytes, pattern: Optional[List[int]] = None
    ) -> str:
        raise ImportError("HDPRINT library not available")

    def calculate_security_bits(pattern: List[int]) -> Tuple[float, List[float]]:
        raise ImportError("HDPRINT library not available")


def generate_fingerprint(key: bytes, num_chars: int) -> str:
    """Generate fingerprint with specified number of characters."""
    pattern = [num_chars]
    return generate_hierarchical_fingerprint(key, pattern)


def find_simple_collision(num_chars: int, max_attempts: int = 10000):
    """Find a collision for the specified number of characters."""
    print(f"\nFINDING {num_chars}-CHARACTER COLLISION")
    print("-" * 50)

    # Calculate theoretical expectations
    collision_space = 58**num_chars
    expected_attempts = math.sqrt(collision_space * math.pi / 2)

    print(f"Collision space: 58^{num_chars} = {collision_space:,}")
    print(f"Expected attempts: {expected_attempts:.0f}")
    print(f"Max attempts: {max_attempts:,}")
    print()

    seen = {}
    attempts = 0
    start_time = time.time()

    try:
        while attempts < max_attempts:
            # Generate random key
            key = secrets.token_bytes(32)
            fingerprint = generate_fingerprint(key, num_chars)
            attempts += 1

            # Check for collision
            if fingerprint in seen:
                elapsed = time.time() - start_time
                print(f"COLLISION FOUND:")
                print(f"  Attempts: {attempts:,}")
                print(f"  Time: {elapsed:.3f}s")
                print(f"  Rate: {attempts / elapsed:.0f} attempts/sec")
                print(f"  Collision fingerprint: '{fingerprint}'")
                print(f"  Key 1: {seen[fingerprint].hex()}")
                print(f"  Key 2: {key.hex()}")

                # Verify the collision
                fp1 = generate_fingerprint(seen[fingerprint], num_chars)
                fp2 = generate_fingerprint(key, num_chars)
                print(f"  Verification: {fp1} == {fp2} -> {fp1 == fp2}")
                return True

            seen[fingerprint] = key

            # Progress reporting
            if attempts % (max_attempts // 10) == 0:
                elapsed = time.time() - start_time
                rate = attempts / elapsed if elapsed > 0 else 0
                percentage = (attempts / max_attempts) * 100
                print(
                    f"  Progress: {attempts:,}/{max_attempts:,} ({percentage:.0f}%) - {rate:.0f} attempts/sec"
                )

    except KeyboardInterrupt:
        print(f"\nSearch interrupted after {attempts} attempts")
        return False

    elapsed = time.time() - start_time
    print(f"No collision found in {attempts:,} attempts ({elapsed:.2f}s)")
    return False


def analyze_security(num_chars: int):
    """Analyze security properties for given character length."""
    print(f"\nSECURITY ANALYSIS - {num_chars} CHARACTERS")
    print("-" * 50)

    pattern = [num_chars]
    security_bits, layer_bits = calculate_security_bits(pattern)

    # Calculate collision space
    collision_space = 58**num_chars
    space_bits = math.log2(collision_space)
    expected_attempts = math.sqrt(collision_space * math.pi / 2)

    print(f"Pattern: {pattern}")
    print(f"Total space: 58^{num_chars} = {collision_space:,}")
    print(f"Space bits: {space_bits:.1f}")
    print(f"Birthday expected: {expected_attempts:,.0f} attempts")
    print(f"Security bits: {security_bits:.1f}")
    print(f"Layer securities: {[f'{b:.1f}' for b in layer_bits]}")
    print()

    # Estimate time to collision
    estimated_rate = 20000  # ~20k attempts/sec based on benchmarks
    estimated_time = expected_attempts / estimated_rate

    print(f"Time estimate (at {estimated_rate:,} attempts/sec):")
    if estimated_time < 1:
        print(f"  ~{estimated_time:.3f} seconds (very fast)")
    elif estimated_time < 60:
        print(f"  ~{estimated_time:.1f} seconds (fast)")
    elif estimated_time < 3600:
        print(f"  ~{estimated_time / 60:.1f} minutes (moderate)")
    else:
        print(f"  ~{estimated_time / 3600:.1f} hours (slow)")


def performance_test(num_chars: int, iterations: int = 1000):
    """Quick performance test."""
    print(f"\nPERFORMANCE TEST - {num_chars} CHARACTERS")
    print("-" * 50)

    print(f"Generating {iterations:,} fingerprints...")

    # Pre-generate keys
    keys = [secrets.token_bytes(32) for _ in range(iterations)]

    start_time = time.time()
    for key in keys:
        generate_fingerprint(key, num_chars)
    elapsed = time.time() - start_time

    rate = iterations / elapsed if elapsed > 0 else 0
    avg_time = elapsed / iterations * 1000  # ms
    hmac_ops = iterations * num_chars
    hmac_rate = hmac_ops / elapsed if elapsed > 0 else 0

    print(f"Results:")
    print(f"  Total time: {elapsed:.3f}s")
    print(f"  Rate: {rate:.0f} fingerprints/sec")
    print(f"  Average: {avg_time:.3f}ms per fingerprint")
    print(f"  HMAC ops: {hmac_ops:,} ({hmac_rate:.0f} HMAC/sec)")


def main():
    """Main demo function."""
    print("HDPRINT COLLISION FINDING DEMO")
    print("=" * 60)
    print()
    print("This demo showcases collision finding with the")
    print("HMAC-per-character approach where each character")
    print("comes from a separate HMAC-SHA3-512 operation.")
    print()

    if not library_available:
        print("HDPRINT library not available")
        return

    try:
        # Demo 1: Quick 2-character collision
        analyze_security(2)
        performance_test(2, 1000)
        find_simple_collision(2, 1000)

        # Demo 2: 3-character collision (more interesting)
        analyze_security(3)
        performance_test(3, 1000)
        find_simple_collision(3, 5000)

        # Demo 3: Analysis of larger sizes
        analyze_security(4)
        analyze_security(5)

        print("\n" + "=" * 60)
        print("DEMO COMPLETED SUCCESSFULLY")
        print("=" * 60)
        print()
        print("Key Findings:")
        print("- 2-character collisions: Very fast (~73 attempts)")
        print("- 3-character collisions: Fast (~554 attempts)")
        print("- 4-character collisions: Moderate (~4,280 attempts)")
        print("- Each character requires one HMAC-SHA3-512 operation")
        print("- Performance: ~20,000 fingerprints/sec")
        print("- Base58 provides ~5.86 bits per character")

    except KeyboardInterrupt:
        print("\nDemo interrupted by user")
    except Exception as e:
        print(f"\nDemo failed: {e}")
        import traceback

        traceback.print_exc()


if __name__ == "__main__":
    main()
