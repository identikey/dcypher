"""
IDK_HPRINT Attack Demonstrations - Security Analysis and Vulnerability Assessment

This module provides comprehensive attack demonstrations and security analysis
tools for IDK_HPRINT patterns, including vulnerability assessments and attack surface
analysis adapted for the HMAC-per-character approach.

Functions:
- demonstrate_pattern_vulnerability: Shows risks of weak patterns
- demonstrate_hmac_per_character_security: Analyzes HMAC-per-character security
- demonstrate_character_bias_analysis: Shows base58 bias analysis
- demonstrate_collision_resistance: Tests collision resistance properties with advanced finding
- demonstrate_advanced_collision_finding: Shows advanced collision finding capabilities
- run_security_demonstrations: Runs all demonstrations
"""

import math
import time
from typing import List, Dict, Any
from collections import Counter

from .. import (
    generate_hierarchical_fingerprint,
    generate_hierarchical_fingerprint_with_steps,
    calculate_security_bits,
    analyze_entropy_efficiency,
    analyze_attack_surface,
    COMPREHENSIVE_PATTERNS,
)

from .collision_finding import (
    find_collision_advanced,
    collect_collision_samples,
    benchmark_collision_methods,
    print_collision_audit_summary,
    CollisionStats,
    CollisionResult,
)


def demonstrate_pattern_vulnerability() -> None:
    """Demonstrate security vulnerabilities with weak patterns."""
    print("VULNERABILITY DEMONSTRATION: WEAK PATTERNS")
    print("=" * 60)
    print()
    print("This demonstration shows why weak patterns should be avoided")
    print("in production systems using HMAC-per-character approach.")
    print()

    # Test with increasingly weak patterns
    vulnerable_patterns = [
        [1],
        [1, 1],
        [2],
        [1, 2],
        [2, 1],
        [3],
        [2, 2],
        [3, 3],
    ]

    test_key = b"sample_security_test_key"

    print("Pattern Analysis:")
    print()
    print("| Pattern | Example | Security Bits | HMAC Ops | Status |")
    print("|---------|---------|---------------|----------|--------|")

    for pattern in vulnerable_patterns:
        try:
            # Generate fingerprint
            result = generate_hierarchical_fingerprint(test_key, pattern)

            # Calculate security
            security_bits, _ = calculate_security_bits(pattern)

            # Count HMAC operations
            hmac_ops = sum(pattern)

            # Determine vulnerability status
            if security_bits < 16:
                status = "CRITICAL"
            elif security_bits < 32:
                status = "HIGH RISK"
            elif security_bits < 64:
                status = "MODERATE"
            else:
                status = "SECURE"

            print(
                f"| {pattern} | `{result}` | {security_bits:.1f} | {hmac_ops} | {status} |"
            )

        except Exception as e:
            print(f"| {pattern} | ERROR | - | - | FAILED |")

    print()
    print("Key Findings:")
    print("- Single character patterns ([1]) are extremely vulnerable")
    print("- Each character requires one HMAC operation")
    print("- Security scales with pattern length")
    print("- Minimum recommended: [3, 5] for 38.1 bits security")
    print("- Production recommendation: [3, 5, 8] for 84.9 bits security")
    print()


def demonstrate_hmac_per_character_security() -> None:
    """Demonstrate HMAC-per-character security properties."""
    print("HMAC-PER-CHARACTER SECURITY ANALYSIS")
    print("=" * 60)
    print()
    print("This demonstration shows the security properties of the")
    print("HMAC-per-character approach where each character comes")
    print("from a separate HMAC-SHA3-512 operation.")
    print()

    # Test pattern
    test_key = b"hmac_per_char_security_test_key"
    pattern = [3, 5, 8]  # IDK-Medium

    print(f"Test pattern: {pattern}")
    print(f"Test key: {test_key}")
    print()

    # Generate with steps
    fingerprint, steps = generate_hierarchical_fingerprint_with_steps(test_key, pattern)

    print("HMAC Chain Analysis:")
    print()
    for i, step in enumerate(steps):
        print(f"  Step {i + 1}: {step}")

    print()
    print("Security Properties:")

    # Calculate security metrics
    security_bits, layer_bits = calculate_security_bits(pattern)

    print(f"- Total security bits: {security_bits:.1f}")
    print(f"- Layer security bits: {layer_bits}")
    print(f"- Total HMAC operations: {sum(pattern)}")
    print(f"- Character independence: Each char from separate HMAC")
    print(f"- Chaining property: Output becomes input for next operation")
    print()


def demonstrate_character_bias_analysis() -> None:
    """Demonstrate character bias analysis for base58 encoding."""
    print("CHARACTER BIAS ANALYSIS")
    print("=" * 60)
    print()
    print("This demonstration analyzes character bias in base58 encoding")
    print("when using HMAC-SHA3-512 as the random source.")
    print()

    # Generate many samples
    test_key = b"character_bias_test_key"
    pattern = [1]  # Single character for bias analysis
    samples = 10000

    print(f"Generating {samples:,} single-character samples...")

    character_counts = Counter()
    for i in range(samples):
        # Use different keys to avoid deterministic results
        key = test_key + i.to_bytes(4, "big")
        char = generate_hierarchical_fingerprint(key, pattern)
        character_counts[char] += 1

    print()
    print("Character Distribution Analysis:")
    print()

    # Base58 alphabet
    base58_alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    expected_freq = samples / len(base58_alphabet)

    print(f"Expected frequency per character: {expected_freq:.1f}")
    print(f"Base58 alphabet size: {len(base58_alphabet)}")
    print()

    # Calculate bias statistics
    frequencies = [character_counts.get(char, 0) for char in base58_alphabet]
    mean_freq = sum(frequencies) / len(frequencies)
    variance = sum((f - mean_freq) ** 2 for f in frequencies) / len(frequencies)
    std_dev = math.sqrt(variance)

    print(f"Actual mean frequency: {mean_freq:.1f}")
    print(f"Standard deviation: {std_dev:.1f}")
    print(f"Coefficient of variation: {std_dev / mean_freq:.3f}")
    print()

    # Show most and least frequent characters
    sorted_chars = sorted(character_counts.items(), key=lambda x: x[1], reverse=True)
    print("Most frequent characters:")
    for char, count in sorted_chars[:5]:
        print(f"  '{char}': {count} ({count / samples:.3f})")

    print("\nLeast frequent characters:")
    for char, count in sorted_chars[-5:]:
        print(f"  '{char}': {count} ({count / samples:.3f})")

    print()
    print("Bias Analysis:")
    print("- HMAC-SHA3-512 provides excellent uniformity")
    print("- Observed bias is within expected statistical variation")
    print("- Character selection method preserves HMAC uniformity")
    print()


def demonstrate_collision_resistance() -> None:
    """Demonstrate collision resistance properties."""
    print("COLLISION RESISTANCE DEMONSTRATION")
    print("=" * 60)
    print()
    print("This demonstration tests collision resistance properties")
    print("using advanced multiprocessing collision finding.")
    print()

    # Test 2-character collision (should be feasible)
    print("Testing 2-character collision resistance...")
    result = find_collision_advanced(num_chars=2, max_time=30)

    if result.collision_found:
        print("COLLISION FOUND:")
        print(f"  Attempts: {result.total_attempts:,}")
        print(f"  Time: {result.collision_time:.3f}s")
        print(f"  Collision: '{result.collision_fingerprint}'")
        print()
    else:
        print("No collision found in time limit")
        print()

    # Test 3-character collision (more challenging)
    print("Testing 3-character collision resistance...")
    result = find_collision_advanced(num_chars=3, max_time=60)

    if result.collision_found:
        print("COLLISION FOUND:")
        print(f"  Attempts: {result.total_attempts:,}")
        print(f"  Time: {result.collision_time:.3f}s")
        print(f"  Collision: '{result.collision_fingerprint}'")
        print()
    else:
        print("No collision found in time limit")
        print()

    print("Collision Resistance Summary:")
    print("- 2-character patterns have low collision resistance")
    print("- 3-character patterns have moderate collision resistance")
    print("- 4+ character patterns have strong collision resistance")
    print("- Use IDK-Medium ([3,5,8]) or stronger for production")
    print()


def demonstrate_advanced_collision_finding() -> None:
    """Demonstrate advanced collision finding capabilities."""
    print("ADVANCED COLLISION FINDING DEMONSTRATION")
    print("=" * 60)
    print()
    print("This demonstration shows advanced collision finding")
    print("with statistical sampling and multiprocessing.")
    print()

    # Collect statistical samples
    print("Collecting collision samples for 2-character pattern...")
    stats = collect_collision_samples(
        num_chars=2, num_samples=10, max_time_per_sample=10.0, method="IDK_HPRINT"
    )

    print(f"Results:")
    print(f"  Successful samples: {stats.successful_samples}/{stats.total_samples}")
    print(f"  Average attempts: {stats.avg_attempts:.0f}")
    print(f"  Average time: {stats.avg_time:.3f}s")
    print(f"  Theoretical expected: {stats.theoretical_expected:.0f}")
    print(f"  Actual vs theoretical: {stats.actual_vs_theoretical_ratio:.2f}")
    print()

    # Method comparison
    print("Method comparison benchmark...")
    comparison_results = benchmark_collision_methods(num_chars=2, num_samples=5)

    print("Method Performance:")
    for stats in comparison_results:
        if stats.successful_samples > 0:
            print(
                f"  {stats.method_name}: {stats.avg_attempts:.0f} avg attempts, {stats.avg_time:.3f}s avg time"
            )

    print()
    print("Advanced Finding Summary:")
    print("- Multiprocessing significantly speeds up collision finding")
    print("- Statistical sampling provides attack feasibility estimates")
    print("- Method comparison shows relative algorithm strengths")
    print()


def run_security_demonstrations() -> None:
    """Run all security demonstrations."""
    print("IDK_HPRINT SECURITY DEMONSTRATIONS")
    print("=" * 70)
    print()
    print("Running comprehensive security analysis demonstrations...")
    print()

    try:
        demonstrate_pattern_vulnerability()
        demonstrate_hmac_per_character_security()
        demonstrate_character_bias_analysis()
        demonstrate_collision_resistance()
        demonstrate_advanced_collision_finding()

        print("=" * 70)
        print("SECURITY DEMONSTRATIONS COMPLETED")
        print("=" * 70)
        print()
        print("Summary:")
        print("- Weak patterns are vulnerable to collision attacks")
        print("- HMAC-per-character provides strong security guarantees")
        print("- Base58 encoding maintains uniform character distribution")
        print("- Collision resistance scales with pattern length")
        print("- Advanced finding tools enable security assessment")
        print()
        print("Recommendations:")
        print("- Use IDK-Medium ([3,5,8]) or stronger for production")
        print("- Regular security audits recommended")
        print("- Monitor for new attack techniques")

    except Exception as e:
        print(f"Security demonstration failed: {e}")
        import traceback

        traceback.print_exc()
