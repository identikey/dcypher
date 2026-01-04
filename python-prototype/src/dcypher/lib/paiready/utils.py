"""
Utility functions for PAIREADY library.
"""

import secrets
import hashlib
from typing import List, Dict, Any

from .core import BASE58L_ALPHABET, BASE58_ALPHABET


def generate_test_fingerprints(count: int = 10, size: str = "tiny") -> List[str]:
    """Generate test fingerprints for analysis"""
    fingerprints = []

    for i in range(count):
        # Generate a simple test fingerprint based on size
        if size == "tiny":
            # 6 character fingerprint
            chars = secrets.choice(BASE58L_ALPHABET)
            fingerprint = "".join(secrets.choice(BASE58L_ALPHABET) for _ in range(6))
        elif size == "small":
            # ~15 character fingerprint with underscore
            part1 = "".join(secrets.choice(BASE58L_ALPHABET) for _ in range(6))
            part2 = "".join(secrets.choice(BASE58L_ALPHABET) for _ in range(8))
            fingerprint = f"{part1}_{part2}"
        elif size == "medium":
            # ~24 character fingerprint with underscores
            part1 = "".join(secrets.choice(BASE58L_ALPHABET) for _ in range(6))
            part2 = "".join(secrets.choice(BASE58L_ALPHABET) for _ in range(8))
            part3 = "".join(secrets.choice(BASE58L_ALPHABET) for _ in range(8))
            fingerprint = f"{part1}_{part2}_{part3}"
        elif size == "rack":
            # ~33 character fingerprint with underscores
            part1 = "".join(secrets.choice(BASE58L_ALPHABET) for _ in range(6))
            part2 = "".join(secrets.choice(BASE58L_ALPHABET) for _ in range(8))
            part3 = "".join(secrets.choice(BASE58L_ALPHABET) for _ in range(8))
            part4 = "".join(secrets.choice(BASE58L_ALPHABET) for _ in range(8))
            fingerprint = f"{part1}_{part2}_{part3}_{part4}"
        else:
            # Default to simple test string
            fingerprint = f"test{i:03d}"

        fingerprints.append(fingerprint)

    return fingerprints


def bytes_to_bits(data: bytes, num_bits: int) -> List[int]:
    """Convert bytes to list of bits."""
    bits = []
    for byte in data:
        for i in range(8):
            bits.append((byte >> (7 - i)) & 1)
    return bits[:num_bits]


def bits_to_bytes(bits: List[int]) -> bytes:
    """Convert list of bits to bytes with proper padding."""
    # Pad bits to byte boundary
    padded_bits = bits + [0] * (8 - len(bits) % 8) if len(bits) % 8 != 0 else bits

    # Pack bits into bytes
    result = bytearray()
    for i in range(0, len(padded_bits), 8):
        byte_val = 0
        for j in range(8):
            if i + j < len(padded_bits):
                byte_val |= padded_bits[i + j] << (7 - j)
        result.append(byte_val)

    return bytes(result)


def encode_bits_to_base58l(bits: List[int], alphabet: str = BASE58L_ALPHABET) -> str:
    """Encode bits to Base58L string."""
    if not bits:
        return alphabet[0]

    # Convert bits to integer
    bit_int = 0
    for bit in bits:
        bit_int = (bit_int << 1) | bit

    # Encode to alphabet
    if bit_int == 0:
        return alphabet[0]

    encoded = []
    while bit_int > 0:
        bit_int, remainder = divmod(bit_int, len(alphabet))
        encoded.append(alphabet[remainder])

    return "".join(reversed(encoded))


def decode_base58l_to_bits(
    checksum: str, num_bits: int, alphabet: str = BASE58L_ALPHABET
) -> List[int]:
    """Decode Base58L string to bits."""
    # Decode to integer
    decoded_int = 0
    for char in checksum:
        if char not in alphabet:
            raise ValueError(f"Invalid character: {char}")
        decoded_int = decoded_int * len(alphabet) + alphabet.index(char)

    # Convert to bits
    bits = []
    for _ in range(num_bits):
        bits.append(decoded_int & 1)
        decoded_int >>= 1

    return list(reversed(bits))


def calculate_checksum_statistics(checksums: List[str]) -> Dict[str, Any]:
    """Calculate statistics for a list of checksums"""
    if not checksums:
        return {
            "count": 0,
            "min_length": 0,
            "max_length": 0,
            "avg_length": 0.0,
            "unique_chars": set(),
        }

    lengths = [len(c) for c in checksums]
    all_chars = set()
    for checksum in checksums:
        all_chars.update(checksum)

    return {
        "count": len(checksums),
        "min_length": min(lengths),
        "max_length": max(lengths),
        "avg_length": sum(lengths) / len(lengths),
        "unique_chars": all_chars,
        "char_distribution": {
            char: sum(1 for c in checksums for ch in c if ch == char)
            for char in all_chars
        },
    }


def validate_checksum_format(
    checksum: str, expected_length: int = 7, alphabet: str = BASE58L_ALPHABET
) -> Dict[str, Any]:
    """Validate checksum format and characters"""
    errors = []
    warnings = []

    # Check length
    if len(checksum) != expected_length:
        errors.append(
            f"Invalid length: expected {expected_length}, got {len(checksum)}"
        )

    # Check characters
    invalid_chars = []
    for i, char in enumerate(checksum):
        if char not in alphabet:
            invalid_chars.append((i, char))

    if invalid_chars:
        errors.append(f"Invalid characters at positions: {invalid_chars}")

    # Check for common mistakes
    if any(char in checksum for char in "0OIl"):
        warnings.append("Contains potentially confusing characters (0, O, I, l)")

    if any(char.isupper() for char in checksum) and alphabet == BASE58L_ALPHABET:
        warnings.append("Contains uppercase characters in Base58L checksum")

    return {
        "valid": len(errors) == 0,
        "errors": errors,
        "warnings": warnings,
        "length": len(checksum),
        "alphabet_compliance": all(char in alphabet for char in checksum),
    }


def analyze_bit_patterns(data_list: List[bytes]) -> Dict[str, Any]:
    """Analyze bit patterns in data for randomness and distribution"""
    if not data_list:
        return {"error": "No data provided"}

    # Combine all data
    all_bits = []
    for data in data_list:
        for byte in data:
            for i in range(8):
                all_bits.append((byte >> (7 - i)) & 1)

    if not all_bits:
        return {"error": "No bits found"}

    # Calculate statistics
    ones = sum(all_bits)
    zeros = len(all_bits) - ones

    # Calculate runs (consecutive same bits)
    runs = []
    if all_bits:
        current_run = 1
        current_bit = all_bits[0]

        for bit in all_bits[1:]:
            if bit == current_bit:
                current_run += 1
            else:
                runs.append(current_run)
                current_run = 1
                current_bit = bit
        runs.append(current_run)

    return {
        "total_bits": len(all_bits),
        "ones": ones,
        "zeros": zeros,
        "ones_ratio": ones / len(all_bits),
        "zeros_ratio": zeros / len(all_bits),
        "runs": {
            "count": len(runs),
            "min": min(runs) if runs else 0,
            "max": max(runs) if runs else 0,
            "avg": sum(runs) / len(runs) if runs else 0,
        },
        "balance_score": 1.0
        - abs(0.5 - (ones / len(all_bits))) * 2,  # 1.0 = perfect balance
    }


def create_error_scenarios(
    original_checksum: str, alphabet: str = BASE58L_ALPHABET
) -> List[Dict[str, Any]]:
    """Create various error scenarios for testing"""
    scenarios = []

    # Single character substitutions
    for pos in range(len(original_checksum)):
        original_char = original_checksum[pos]
        for replacement_char in alphabet:
            if replacement_char != original_char:
                corrupted = list(original_checksum)
                corrupted[pos] = replacement_char
                scenarios.append(
                    {
                        "type": "single_substitution",
                        "position": pos,
                        "original_char": original_char,
                        "replacement_char": replacement_char,
                        "corrupted_checksum": "".join(corrupted),
                        "description": f"Position {pos}: '{original_char}' → '{replacement_char}'",
                    }
                )

                # Only test first few replacements to avoid explosion
                if len(scenarios) >= 10:
                    break
        if len(scenarios) >= 10:
            break

    # Character deletions
    for pos in range(len(original_checksum)):
        corrupted = original_checksum[:pos] + original_checksum[pos + 1 :]
        scenarios.append(
            {
                "type": "deletion",
                "position": pos,
                "original_char": original_checksum[pos],
                "corrupted_checksum": corrupted,
                "description": f"Deleted character at position {pos}: '{original_checksum[pos]}'",
            }
        )

    # Character insertions
    for pos in range(len(original_checksum) + 1):
        for insert_char in alphabet[:3]:  # Test first 3 characters
            corrupted = original_checksum[:pos] + insert_char + original_checksum[pos:]
            scenarios.append(
                {
                    "type": "insertion",
                    "position": pos,
                    "inserted_char": insert_char,
                    "corrupted_checksum": corrupted,
                    "description": f"Inserted '{insert_char}' at position {pos}",
                }
            )

    return scenarios[:50]  # Limit to 50 scenarios to avoid overwhelming output


def format_test_results_table(
    results: List[Dict[str, Any]], title: str = "Test Results"
) -> str:
    """Format test results into a readable table"""
    if not results:
        return f"{title}: No results to display"

    output = [f"\n{title}", "=" * len(title)]

    # Determine columns based on first result
    first_result = results[0]
    columns = list(first_result.keys())

    # Create header
    header = " | ".join(f"{col:<12}" for col in columns)
    output.append(header)
    output.append("-" * len(header))

    # Add rows
    for result in results:
        row = " | ".join(f"{str(result.get(col, 'N/A')):<12}" for col in columns)
        output.append(row)

    return "\n".join(output)


def measure_performance(
    func, *args, iterations: int = 1000, **kwargs
) -> Dict[str, Any]:
    """Measure performance of a function"""
    import time

    times = []
    errors = 0

    for _ in range(iterations):
        start_time = time.time()
        try:
            result = func(*args, **kwargs)
        except Exception:
            errors += 1
            continue
        end_time = time.time()
        times.append(end_time - start_time)

    if not times:
        return {"error": "All iterations failed"}

    return {
        "iterations": iterations,
        "successful": len(times),
        "errors": errors,
        "min_time": min(times),
        "max_time": max(times),
        "avg_time": sum(times) / len(times),
        "total_time": sum(times),
        "ops_per_second": len(times) / sum(times) if sum(times) > 0 else 0,
    }
