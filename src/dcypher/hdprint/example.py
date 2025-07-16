#!/usr/bin/env python3
"""
HDprint Library Usage Example - Productized Size System

This script demonstrates how to use the HDprint library with the new
productized size system: tiny, small, medium, rack, and multiple racks.

Run this script to see the productized HDprint library in action:
    python -m dcypher.hdprint.example
"""

import os
import sys
from typing import List

# Add the parent directory to import the HDprint library
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from dcypher.hdprint import (
    generate_hierarchical_fingerprint,
    generate_hierarchical_fingerprint_with_steps,
    get_size_info,
    get_available_sizes,
    calculate_security_bits,
    analyze_entropy_efficiency,
)


def demonstrate_productized_sizes():
    """Demonstrate the productized size system."""
    print("PRODUCTIZED SIZE SYSTEM DEMONSTRATION")
    print("=" * 50)
    print()
    print("Available sizes:")
    print("- tiny: [6] (1 segment) - minimal security for testing")
    print("- small: [6,8] (2 segments) - basic security for non-critical use")
    print("- medium: [6,8,8] (3 segments) - moderate security for general use")
    print("- rack: [6,8,8,8] (4 segments) - full pattern for standard security")
    print("- Multiple racks: 2 racks = [6,8,8,8,6,8,8,8], etc.")
    print()
    print("Note: Segments are joined with underscores (_) for easy selection")
    print()

    # Show size information
    sizes = get_available_sizes()
    print("Size Details:")
    print()
    for size_name, size_info in sizes.items():
        print(f"{size_name.upper()}:")
        print(f"  Pattern: {size_info['pattern']}")
        print(f"  Characters: {size_info['total_characters']}")
        print(f"  Display length: {size_info['display_length']}")
        print(f"  Description: {size_info['description']}")
        print()


def demonstrate_size_based_fingerprints():
    """Demonstrate fingerprint generation using size names."""
    print("SIZE-BASED FINGERPRINT GENERATION")
    print("=" * 50)
    print()

    # Test data (simulating a public key)
    public_key = b"example_public_key_for_productized_demo"

    print(f"Public key: {public_key}")
    print()
    print("Fingerprints by size (with underscores for easy selection):")
    print()

    # Generate fingerprints for each size
    sizes = ["tiny", "small", "medium", "rack"]

    for size in sizes:
        fingerprint = generate_hierarchical_fingerprint(public_key, size)
        security_bits, _ = calculate_security_bits(size=size)
        size_info = get_size_info(size)

        print(f"{size.upper()}: {fingerprint}")
        print(f"  Pattern: {size_info['pattern']}")
        print(f"  Security: {security_bits:.1f} bits")
        print(f"  Length: {len(fingerprint)} characters")
        print()


def demonstrate_rack_scaling():
    """Demonstrate rack-based scaling for high security."""
    print("RACK SCALING DEMONSTRATION")
    print("=" * 50)
    print()
    print("A 'rack' is the full [6,8,8,8] pattern.")
    print("Multiple racks provide high security by repeating the pattern.")
    print()

    public_key = b"rack_scaling_demo_key"

    print(f"Public key: {public_key}")
    print()
    print("Rack-based fingerprints (with underscores):")
    print()

    # Test different rack counts
    for rack_count in [1, 2, 3, 4]:
        fingerprint = generate_hierarchical_fingerprint(public_key, racks=rack_count)
        security_bits, _ = calculate_security_bits(racks=rack_count)

        # Calculate expected pattern
        expected_pattern = [6, 8, 8, 8] * rack_count

        print(f"{rack_count} RACK{'S' if rack_count > 1 else ''}: {fingerprint}")
        print(f"  Pattern: {expected_pattern}")
        print(f"  Security: {security_bits:.1f} bits")
        print(f"  Length: {len(fingerprint)} characters")
        print()


def demonstrate_hierarchical_nesting():
    """Demonstrate hierarchical nesting with productized sizes."""
    print("HIERARCHICAL NESTING WITH SIZES")
    print("=" * 50)
    print()

    public_key = b"hierarchical_nesting_demo"

    # Generate fingerprints with progressive sizes
    sizes = ["tiny", "small", "medium", "rack"]

    fingerprints = []
    for size in sizes:
        fp = generate_hierarchical_fingerprint(public_key, size)
        fingerprints.append((size, fp))
        print(f"{size.upper()}: {fp}")

    print()
    print("Hierarchical nesting verification:")
    for i in range(len(fingerprints) - 1):
        size1, fp1 = fingerprints[i]
        size2, fp2 = fingerprints[i + 1]
        is_prefix = fp2.startswith(fp1 + "_") or fp2 == fp1
        print(f"  {size1} is prefix of {size2}: {is_prefix}")
    print()


def demonstrate_detailed_algorithm():
    """Demonstrate detailed algorithm execution with size."""
    print("DETAILED ALGORITHM EXECUTION")
    print("=" * 50)
    print()

    public_key = b"detailed_algorithm_demo"
    size = "medium"  # [6,8,8] pattern

    print(f"Public key: {public_key}")
    print(f"Size: {size}")
    print()

    # Generate fingerprint with detailed steps
    fingerprint, steps = generate_hierarchical_fingerprint_with_steps(public_key, size)

    print("Algorithm execution steps:")
    for step in steps:
        print(f"  {step}")

    print()
    print("Key insights:")
    print("- Each character requires a separate HMAC operation")
    print("- Takes the LAST character from base58 encoding")
    print("- HMAC output becomes input for next character")
    print("- Size determines pattern via cyclical [6,8,8,8] sequence")
    print("- Segments joined with underscores for easy selection")
    print()


def demonstrate_security_comparison():
    """Demonstrate security comparison across sizes."""
    print("SECURITY COMPARISON ACROSS SIZES")
    print("=" * 50)
    print()

    # Test all sizes plus some rack configurations
    test_configs = [
        ("tiny", None, None),
        ("small", None, None),
        ("medium", None, None),
        ("rack", None, None),
        (None, None, 2),  # 2 racks
        (None, None, 3),  # 3 racks
        (None, None, 5),  # 5 racks
    ]

    print("Security Analysis:")
    print(f"{'Configuration':<15} {'Pattern':<25} {'Security Bits':<15} {'Level':<10}")
    print("-" * 75)

    for size, num_segments, racks in test_configs:
        # Determine configuration name
        if size:
            config_name = size
        elif racks:
            config_name = f"{racks} racks"
        else:
            config_name = f"{num_segments} segs"

        # Calculate security
        security_bits, layer_bits = calculate_security_bits(
            size=size, num_segments=num_segments, racks=racks
        )

        # Get pattern info
        if size:
            size_info = get_size_info(size)
            pattern = size_info["pattern"]
        elif racks:
            pattern = [6, 8, 8, 8] * racks
        elif num_segments:
            from dcypher.hdprint.algorithms import generate_cyclical_pattern

            pattern = generate_cyclical_pattern(num_segments)
        else:
            pattern = []  # This shouldn't happen with our test configs

        # Determine security level
        if security_bits >= 128:
            level = "HIGH"
        elif security_bits >= 80:
            level = "MODERATE"
        else:
            level = "LOW"

        pattern_str = (
            str(pattern)[:23] + ".." if len(str(pattern)) > 23 else str(pattern)
        )

        print(f"{config_name:<15} {pattern_str:<25} {security_bits:<15.1f} {level:<10}")

    print()
    print("Security Level Guidelines:")
    print("- LOW (< 80 bits): Testing and development only")
    print("- MODERATE (80-127 bits): Non-critical applications")
    print("- HIGH (≥ 128 bits): Production and high-security applications")
    print()


def demonstrate_use_case_recommendations():
    """Demonstrate size recommendations for different use cases."""
    print("USE CASE RECOMMENDATIONS")
    print("=" * 50)
    print()

    use_cases = [
        ("Development/Testing", "tiny", "Quick testing, debugging"),
        ("IoT Device", "small", "Constrained environments"),
        ("Mobile App", "medium", "Balanced security/performance"),
        ("Web Application", "rack", "Standard web security"),
        ("API Authentication", "rack", "Standard API security"),
        ("Financial System", 2, "Enhanced security (2 racks)"),
        ("Government/Military", 3, "High security (3 racks)"),
        ("Ultra-secure", 5, "Maximum security (5 racks)"),
    ]

    print("Recommended configurations by use case:")
    print("(All examples use underscores for easy selection)")
    print()

    for use_case, size_or_racks, description in use_cases:
        # Generate example fingerprint
        example_key = (
            f"example_{use_case.lower().replace('/', '_').replace(' ', '_')}".encode()
        )

        if isinstance(size_or_racks, str):
            fingerprint = generate_hierarchical_fingerprint(example_key, size_or_racks)
            security_bits, _ = calculate_security_bits(size=size_or_racks)
            config = f"Size: {size_or_racks}"
        else:
            fingerprint = generate_hierarchical_fingerprint(
                example_key, racks=size_or_racks
            )
            security_bits, _ = calculate_security_bits(racks=size_or_racks)
            config = f"Racks: {size_or_racks}"

        print(f"{use_case}:")
        print(f"  {config}")
        print(f"  Security: {security_bits:.1f} bits")
        print(f"  Description: {description}")
        print(f"  Example: {fingerprint}")
        print()


def demonstrate_selection_friendliness():
    """Demonstrate the improved selection experience with underscores."""
    print("SELECTION-FRIENDLY UNDERSCORE FORMAT")
    print("=" * 50)
    print()
    print("Underscores make fingerprints easier to select on all platforms:")
    print()

    public_key = b"selection_demo_key"

    # Generate some example fingerprints
    examples = [
        ("Desktop Selection", "rack"),
        ("Mobile Selection", "medium"),
        ("Copy/Paste Friendly", 2),  # 2 racks
    ]

    for description, size_or_racks in examples:
        if isinstance(size_or_racks, str):
            fingerprint = generate_hierarchical_fingerprint(public_key, size_or_racks)
        else:
            fingerprint = generate_hierarchical_fingerprint(
                public_key, racks=size_or_racks
            )

        print(f"{description}:")
        print(f"  {fingerprint}")
        print(f"  ↑ Try selecting this - underscores keep it as one unit")
        print()

    print("Benefits of underscore format:")
    print("- Easier to select entire fingerprint with double-click")
    print("- Better copy/paste experience on mobile devices")
    print("- Consistent selection behavior across platforms")
    print("- More user-friendly for manual entry when needed")
    print()


def main():
    """Main demonstration function."""
    print("HDprint Productized Size System Demonstration")
    print("=" * 70)
    print()
    print("This demonstrates the productized HDprint library with:")
    print("- Size names: tiny, small, medium, rack")
    print("- Rack scaling: 1 rack, 2 racks, 3 racks, etc.")
    print("- HMAC-SHA3-512 chain algorithm")
    print("- HMAC-per-character approach")
    print("- Base58 encoding with last character selection")
    print("- Hierarchical nesting properties")
    print("- Underscore separators for easy selection")
    print("- Security analysis tools")
    print()

    try:
        # Run demonstrations
        demonstrate_productized_sizes()
        demonstrate_size_based_fingerprints()
        demonstrate_rack_scaling()
        demonstrate_hierarchical_nesting()
        demonstrate_detailed_algorithm()
        demonstrate_security_comparison()
        demonstrate_use_case_recommendations()
        demonstrate_selection_friendliness()

        print("=" * 70)
        print("HDprint productized size system demonstration completed successfully")
        print("=" * 70)
        print()
        print("Key features:")
        print("- Intuitive size names: tiny, small, medium, rack")
        print("- Scalable rack system for high security")
        print("- Consistent [6,8,8,8] base pattern")
        print("- HMAC-per-character cryptographic strength")
        print("- Hierarchical nesting for prefix matching")
        print("- Configurable security levels via size selection")
        print("- Underscore separators for easy selection")
        print("- Backward compatibility with num_segments parameter")

    except Exception as e:
        print(f"Demonstration failed: {e}")
        import traceback

        traceback.print_exc()


if __name__ == "__main__":
    main()
