"""
Core HDprint Algorithms

This module contains the main HMAC chain algorithm for generating
hierarchical cryptographic fingerprints with base58 encoding using
a cyclical pattern [6,8,8,8] with productized size names.

Size Options:
- tiny: [6] (1 segment)
- small: [6,8] (2 segments)
- medium: [6,8,8] (3 segments)
- rack: [6,8,8,8] (full pattern, 4 segments)
- Multiple racks: 2 racks = [6,8,8,8,6,8,8,8], etc.

Algorithm Overview:
1. Use blake3 hashed public key as HMAC key with SHA3-512
2. Generate pattern based on size name or rack count
3. For each character position in the pattern:
   - Generate HMAC of blake3 hashed current data
   - Base58 encode and take the LAST character
   - Use full HMAC bytes for next iteration
4. Group characters into segments and join with underscores

Each character in the output comes from a separate HMAC operation (HMAC roll).
The HMAC chain approach provides cryptographic strength while maintaining
hierarchical nesting properties for cross-system compatibility.
"""

import hashlib
import hmac
from typing import List, Tuple, Optional, Union, Dict, Any
import based58
import blake3


# Productized size definitions
SIZE_DEFINITIONS = {
    "tiny": 1,  # [6]
    "small": 2,  # [6,8]
    "medium": 3,  # [6,8,8]
    "rack": 4,  # [6,8,8,8] - full pattern
}


def generate_cyclical_pattern(num_segments: int) -> List[int]:
    """
    Generate cyclical pattern [6,8,8,8] repeating for specified number of segments.

    Examples:
        num_segments=1: [6]
        num_segments=2: [6,8]
        num_segments=3: [6,8,8]
        num_segments=4: [6,8,8,8]
        num_segments=5: [6,8,8,8,6]
        num_segments=6: [6,8,8,8,6,8]

    Args:
        num_segments: Number of segments to generate

    Returns:
        List of segment lengths following cyclical pattern
    """
    if num_segments <= 0:
        raise ValueError("Number of segments must be positive")

    base_pattern = [6, 8, 8, 8]
    pattern = []

    for i in range(num_segments):
        pattern.append(base_pattern[i % len(base_pattern)])

    return pattern


def generate_rack_pattern(num_racks: int) -> List[int]:
    """
    Generate pattern for specified number of racks.

    A rack is the full [6,8,8,8] pattern (4 segments).
    Multiple racks repeat this pattern.

    Examples:
        num_racks=1: [6,8,8,8]
        num_racks=2: [6,8,8,8,6,8,8,8]
        num_racks=3: [6,8,8,8,6,8,8,8,6,8,8,8]

    Args:
        num_racks: Number of racks to generate

    Returns:
        List of segment lengths for the specified number of racks
    """
    if num_racks <= 0:
        raise ValueError("Number of racks must be positive")

    rack_pattern = [6, 8, 8, 8]
    pattern = []

    for rack in range(num_racks):
        pattern.extend(rack_pattern)

    return pattern


def resolve_size_to_segments(size: Union[str, int]) -> int:
    """
    Resolve size name or rack count to number of segments.

    Args:
        size: Size name ("tiny", "small", "medium", "rack") or number of racks

    Returns:
        Number of segments

    Raises:
        ValueError: If size is not recognized
    """
    if isinstance(size, str):
        if size in SIZE_DEFINITIONS:
            return SIZE_DEFINITIONS[size]
        else:
            raise ValueError(
                f"Unknown size '{size}'. Valid sizes: {list(SIZE_DEFINITIONS.keys())}"
            )
    elif isinstance(size, int):
        if size <= 0:
            raise ValueError("Rack count must be positive")
        return size * 4  # Each rack is 4 segments
    else:
        raise ValueError("Size must be a string (size name) or int (rack count)")


def hmac_sha3_512(key: bytes, data: bytes) -> bytes:
    """
    Generate HMAC-SHA3-512 hash with blake3 preprocessing.

    Both the key and data are first hashed with blake3 before being used
    in the HMAC-SHA3-512 operation.

    Args:
        key: HMAC key (typically public key) - will be blake3 hashed
        data: Input data to authenticate - will be blake3 hashed

    Returns:
        64-byte HMAC-SHA3-512 digest
    """
    # Hash both key and data with blake3 before HMAC
    blake3_key = blake3.blake3(key).digest()
    blake3_data = blake3.blake3(data).digest()
    return hmac.new(blake3_key, blake3_data, hashlib.sha3_512).digest()


def generate_hierarchical_fingerprint(
    public_key: bytes,
    size: Union[str, int, None] = None,
    num_segments: Optional[int] = None,
    racks: Optional[int] = None,
) -> str:
    """
    Generate hierarchical fingerprint using cyclical pattern [6,8,8,8].

    This is the main algorithm that implements the HMAC-based approach with
    productized size names and rack support.

    Args:
        public_key: Public key bytes used as HMAC key (will be blake3 hashed)
        size: Size name ("tiny", "small", "medium", "rack") or rack count
        num_segments: Direct number of segments (for backward compatibility)
        racks: Number of racks (alternative to size parameter)

    Returns:
        Fingerprint string with segments joined by underscores

    Examples:
        >>> # Using size names
        >>> generate_hierarchical_fingerprint(key, "tiny")      # Ab3DeF
        >>> generate_hierarchical_fingerprint(key, "small")     # Ab3DeF_Xy9ZmP7q
        >>> generate_hierarchical_fingerprint(key, "medium")    # Ab3DeF_Xy9ZmP7q_R2sK1M4V
        >>> generate_hierarchical_fingerprint(key, "rack")      # Ab3DeF_Xy9ZmP7q_R2sK1M4V_N6tL9Bw

        >>> # Using rack count
        >>> generate_hierarchical_fingerprint(key, racks=1)     # Ab3DeF_Xy9ZmP7q_R2sK1M4V_N6tL9Bw
        >>> generate_hierarchical_fingerprint(key, racks=2)     # Ab3DeF_Xy9ZmP7q_R2sK1M4V_N6tL9Bw_Pg8HsX_Kf2Cm9Et_Bv7Qw1Ry_Zj5Mu3Ld

        >>> # Using direct segments (backward compatibility)
        >>> generate_hierarchical_fingerprint(key, num_segments=4)  # Ab3DeF_Xy9ZmP7q_R2sK1M4V_N6tL9Bw
    """
    if not public_key:
        raise ValueError("Public key cannot be empty")

    # Determine number of segments from various parameters
    segments = None

    if size is not None:
        segments = resolve_size_to_segments(size)
    elif racks is not None:
        if racks <= 0:
            raise ValueError("Number of racks must be positive")
        segments = racks * 4  # Each rack is 4 segments
    elif num_segments is not None:
        if num_segments <= 0:
            raise ValueError("Number of segments must be positive")
        segments = num_segments
    else:
        # Default to 1 rack
        segments = 4

    # Generate cyclical pattern
    pattern = generate_cyclical_pattern(segments)

    # Calculate total number of characters needed
    total_chars = sum(pattern)

    # Generate each character from a separate HMAC operation
    characters = []
    current_data = public_key

    for char_index in range(total_chars):
        # Generate HMAC using blake3 hashed public key and current data
        char_hash = hmac_sha3_512(public_key, current_data)

        # Base58 encode and take the LAST character
        char_b58 = based58.b58encode(char_hash).decode("ascii")

        # Take the last character from the base58 encoding
        character = char_b58[-1]
        characters.append(character)

        # Use full hash bytes for next iteration
        current_data = char_hash

    # Group characters into segments according to pattern
    segments_list = []
    char_index = 0

    for segment_length in pattern:
        segment = "".join(characters[char_index : char_index + segment_length])
        segments_list.append(segment)
        char_index += segment_length

    # Join segments with underscores for human readability and easy selection
    return "_".join(segments_list)


def generate_hierarchical_fingerprint_with_steps(
    public_key: bytes,
    size: Union[str, int, None] = None,
    num_segments: Optional[int] = None,
    racks: Optional[int] = None,
) -> Tuple[str, List[str]]:
    """
    Generate hierarchical fingerprint with detailed execution steps.

    Args:
        public_key: Public key bytes used as HMAC key
        size: Size name or rack count
        num_segments: Direct number of segments (backward compatibility)
        racks: Number of racks

    Returns:
        Tuple of (fingerprint_string, execution_steps)
    """
    if not public_key:
        raise ValueError("Public key cannot be empty")

    # Determine number of segments
    segments = None
    size_description = ""

    if size is not None:
        segments = resolve_size_to_segments(size)
        if isinstance(size, str):
            size_description = f"size '{size}'"
        else:
            size_description = f"{size} racks"
    elif racks is not None:
        if racks <= 0:
            raise ValueError("Number of racks must be positive")
        segments = racks * 4
        size_description = f"{racks} racks"
    elif num_segments is not None:
        if num_segments <= 0:
            raise ValueError("Number of segments must be positive")
        segments = num_segments
        size_description = f"{num_segments} segments"
    else:
        segments = 4
        size_description = "1 rack (default)"

    # Generate cyclical pattern
    pattern = generate_cyclical_pattern(segments)

    # Calculate total number of characters needed
    total_chars = sum(pattern)

    # Generate each character from a separate HMAC operation
    characters = []
    steps = []
    current_data = public_key

    steps.append(f"Initial data: {len(current_data)} bytes (public key)")
    steps.append(f"Configuration: {size_description}")
    steps.append(f"Pattern: {pattern} (total {total_chars} characters)")
    steps.append(f"Base pattern [6,8,8,8] cyclical for {segments} segments")

    for char_index in range(total_chars):
        # Generate HMAC using blake3 hashed public key and current data
        char_hash = hmac_sha3_512(public_key, current_data)

        # Base58 encode and take the LAST character
        char_b58 = based58.b58encode(char_hash).decode("ascii")
        character = char_b58[-1]
        characters.append(character)

        steps.append(
            f"Char {char_index + 1}: HMAC({len(current_data)} bytes) -> "
            f"{len(char_hash)} bytes -> base58[...{character}] -> '{character}'"
        )

        # Use full hash bytes for next iteration
        current_data = char_hash

    # Group characters into segments according to pattern
    segments_list = []
    char_index = 0

    for i, segment_length in enumerate(pattern):
        segment = "".join(characters[char_index : char_index + segment_length])
        segments_list.append(segment)

        char_range = f"{char_index + 1}-{char_index + segment_length}"
        steps.append(f"Segment {i + 1}: chars {char_range} -> '{segment}'")

        char_index += segment_length

    # Join segments with underscores for human readability and easy selection
    fingerprint = "_".join(segments_list)
    steps.append(f"Final fingerprint: {fingerprint}")

    return fingerprint, steps


def verify_hierarchical_fingerprint(
    public_key: bytes,
    expected_fingerprint: str,
    size: Union[str, int, None] = None,
    num_segments: Optional[int] = None,
    racks: Optional[int] = None,
) -> bool:
    """
    Verify that public key produces the expected hierarchical fingerprint.

    Args:
        public_key: Public key bytes to verify
        expected_fingerprint: Expected fingerprint string
        size: Size name or rack count
        num_segments: Direct number of segments
        racks: Number of racks

    Returns:
        True if verification succeeds, False otherwise
    """
    try:
        actual_fingerprint = generate_hierarchical_fingerprint(
            public_key, size=size, num_segments=num_segments, racks=racks
        )
        return actual_fingerprint == expected_fingerprint
    except Exception:
        return False


def extract_segments(fingerprint: str) -> List[str]:
    """
    Extract individual segments from a hierarchical fingerprint.

    Args:
        fingerprint: Hierarchical fingerprint string

    Returns:
        List of individual segments
    """
    return fingerprint.split("_")


def get_prefix(fingerprint: str, segments: int = 1) -> str:
    """
    Get prefix of fingerprint consisting of first N segments.

    This is useful for hierarchical matching where shorter patterns
    should be prefixes of longer patterns from the same input.

    Args:
        fingerprint: Hierarchical fingerprint string
        segments: Number of segments to include in prefix

    Returns:
        Prefix string with first N segments
    """
    segment_list = extract_segments(fingerprint)
    if segments <= 0:
        return ""
    return "_".join(segment_list[:segments])


def check_hierarchical_compatibility(
    shorter_fingerprint: str, longer_fingerprint: str
) -> bool:
    """
    Check if shorter fingerprint is a prefix of longer fingerprint.

    This verifies the hierarchical nesting property where shorter patterns
    should be prefixes of longer patterns when generated from the same key.

    Args:
        shorter_fingerprint: Fingerprint with fewer segments
        longer_fingerprint: Fingerprint with more segments

    Returns:
        True if shorter is a prefix of longer, False otherwise
    """
    return (
        longer_fingerprint.startswith(shorter_fingerprint + "_")
        or longer_fingerprint == shorter_fingerprint
    )


def get_size_info(size: Union[str, int]) -> Dict[str, Any]:
    """
    Get information about a size configuration.

    Args:
        size: Size name or rack count

    Returns:
        Dictionary with size information
    """
    segments = resolve_size_to_segments(size)
    pattern = generate_cyclical_pattern(segments)

    # Determine description
    if isinstance(size, str):
        if size == "tiny":
            description = "Tiny - minimal security for testing"
        elif size == "small":
            description = "Small - basic security for non-critical use"
        elif size == "medium":
            description = "Medium - moderate security for general use"
        elif size == "rack":
            description = "Rack - full pattern for standard security"
        else:
            description = f"Size '{size}'"
    else:
        if size == 1:
            description = "1 rack - standard security"
        else:
            description = f"{size} racks - high security"

    return {
        "size": size,
        "segments": segments,
        "pattern": pattern,
        "total_characters": sum(pattern),
        "display_length": sum(pattern) + segments - 1,  # Including underscores
        "base_pattern": [6, 8, 8, 8],
        "description": description,
        "is_rack_multiple": segments % 4 == 0,
        "rack_count": segments // 4 if segments % 4 == 0 else None,
    }


def get_available_sizes() -> Dict[str, Dict[str, Any]]:
    """
    Get information about all available predefined sizes.

    Returns:
        Dictionary mapping size names to size information
    """
    sizes = {}

    for size_name in SIZE_DEFINITIONS.keys():
        sizes[size_name] = get_size_info(size_name)

    return sizes


# Backward compatibility function
def get_pattern_info(num_segments: int) -> Dict[str, Any]:
    """
    Get information about the pattern for given number of segments.

    Args:
        num_segments: Number of segments

    Returns:
        Dictionary with pattern information
    """
    if num_segments <= 0:
        raise ValueError("Number of segments must be positive")

    pattern = generate_cyclical_pattern(num_segments)
    total_chars = sum(pattern)

    return {
        "pattern": pattern,
        "num_segments": num_segments,
        "total_characters": total_chars,
        "display_length": total_chars + num_segments - 1,  # Including underscores
        "base_pattern": [6, 8, 8, 8],
        "description": f"Cyclical pattern [6,8,8,8] for {num_segments} segments",
    }


# ============================================================================
# PAIREADY + HDPRINT INTEGRATION
# ============================================================================
# Functions for generating self-correcting identifiers in {paiready}_{hdprint} format


def generate_self_correcting_identifier(
    public_key: bytes,
    size: Union[str, int] = "medium",
    checksum_chars: int = 7,
    racks: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Generate a self-correcting identifier combining Paiready checksum and HDprint fingerprint.

    Format: {paiready}_{hdprint}
    Example: a3k7x5a_Ab3DeF_Xy9ZmP7q_R2sK1M4V

    Args:
        public_key: The key material to fingerprint
        size: Size name ("tiny", "small", "medium", "rack") or number of segments
        checksum_chars: Target length of the checksum part (default: 7)
        racks: Number of racks for high security (overrides size)

    Returns:
        Dictionary containing:
        - identifier: Complete {paiready}_{hdprint} identifier
        - hdprint: The hierarchical fingerprint part
        - paiready: The self-correcting checksum part
        - format_info: Information about the format
        - error_correction: Error correction capabilities

    Raises:
        ImportError: If Paiready library is not available
        ValueError: If invalid parameters are provided
    """
    try:
        from dcypher.lib.paiready import InterleavedBCHChecksum
    except ImportError:
        raise ImportError(
            "Paiready library not available. Install with: pip install dcypher[paiready]"
        )

    # Generate HDprint hierarchical fingerprint
    if racks is not None:
        hdprint = generate_hierarchical_fingerprint(public_key, racks=racks)
        size_info = get_size_info("rack")  # Use rack pattern info for racks
        size_info["racks"] = racks
    else:
        hdprint = generate_hierarchical_fingerprint(public_key, size)
        size_info = get_size_info(size)

    # Generate Paiready self-correcting checksum
    checksum_system = InterleavedBCHChecksum(target_chars=checksum_chars)
    paiready = checksum_system.generate_checksum(hdprint)

    # Combine into complete identifier
    identifier = f"{paiready}_{hdprint}"

    # Calculate security and format information (avoiding circular import)
    if racks is not None:
        security_bits = 158.2 * racks  # Rough estimation based on rack pattern
    else:
        security_map = {"tiny": 17.6, "small": 64.4, "medium": 111.3, "rack": 158.2}
        if isinstance(size, str):
            security_bits = security_map.get(size, 100.0)
        else:
            # If size is int, estimate based on segments
            security_bits = 50.0 * size

    return {
        "identifier": identifier,
        "hdprint": hdprint,
        "paiready": paiready,
        "format_info": {
            "format": "{paiready}_{hdprint}",
            "checksum_length": len(paiready),
            "hdprint_length": len(hdprint),
            "total_length": len(identifier),
            "hdprint_pattern": size_info["pattern"],
            "security_bits": security_bits,
        },
        "error_correction": {
            "single_char_correction": True,
            "case_restoration": True,
            "bch_algorithm": "5 × BCH(t=1,m=7) interleaved",
            "encoding": "Base58L (lowercase) + Base58 (mixed case)",
        },
    }


def verify_and_correct_identifier(
    user_input: str,
    expected_hdprint: Optional[str] = None,
    checksum_chars: int = 7,
) -> Dict[str, Any]:
    """
    Verify and auto-correct a user-provided {paiready}_{hdprint} identifier.

    Supports:
    - Single character error correction in checksum
    - Case error restoration in HDprint
    - Combined checksum + case error correction
    - Format validation

    Args:
        user_input: User-provided identifier (may contain errors)
        expected_hdprint: Expected HDprint for validation (optional)
        checksum_chars: Expected checksum length (default: 7)

    Returns:
        Dictionary containing:
        - status: "valid", "corrected", "invalid", or "error"
        - corrected_identifier: Corrected identifier (if correction possible)
        - original_input: Original user input
        - corrections_made: List of corrections applied
        - error_details: Error information if correction failed

    Raises:
        ImportError: If Paiready library is not available
    """
    try:
        from dcypher.lib.paiready import InterleavedBCHChecksum
    except ImportError:
        raise ImportError(
            "Paiready library not available. Install with: pip install dcypher[paiready]"
        )

    result: Dict[str, Any] = {
        "status": "error",
        "corrected_identifier": user_input,
        "original_input": user_input,
        "corrections_made": [],
        "error_details": None,
    }
    corrections_made = result["corrections_made"]  # Explicit list reference

    try:
        # Step 1: Parse the identifier format
        parts = user_input.split("_", 1)
        if len(parts) < 2:
            result["status"] = "invalid"
            result["error_details"] = "Invalid format: missing underscore separator"
            return result

        user_checksum = parts[0]
        user_hdprint = "_".join(parts[1:])  # Rejoin in case HDprint has underscores

        # Step 2: Validate checksum length
        if len(user_checksum) != checksum_chars:
            result["status"] = "invalid"
            result["error_details"] = (
                f"Invalid checksum length: expected {checksum_chars}, got {len(user_checksum)}"
            )
            return result

        # Step 3: Attempt checksum correction
        checksum_system = InterleavedBCHChecksum(target_chars=checksum_chars)

        # If we have the expected HDprint, use it for correction
        if expected_hdprint:
            correction_result = checksum_system.self_correct_checksum(
                user_checksum, expected_hdprint
            )

            if correction_result.get("correction_successful", False):
                corrected_checksum = correction_result["self_corrected_checksum"]
                corrected_hdprint = expected_hdprint

                if corrected_checksum != user_checksum:
                    corrections_made.append(
                        f"Checksum: {user_checksum} → {corrected_checksum}"
                    )

                # Check for case corrections in HDprint
                if (
                    user_hdprint.lower() == expected_hdprint.lower()
                    and user_hdprint != expected_hdprint
                ):
                    corrections_made.append(
                        f"HDprint case restored: {user_hdprint} → {expected_hdprint}"
                    )
                    corrected_hdprint = expected_hdprint

                result["corrected_identifier"] = (
                    f"{corrected_checksum}_{corrected_hdprint}"
                )
                result["status"] = (
                    "corrected" if result["corrections_made"] else "valid"
                )

            else:
                result["status"] = "invalid"
                result["error_details"] = (
                    f"Checksum correction failed: {correction_result.get('error', 'Unknown error')}"
                )

        else:
            # Without expected HDprint, we can only verify format and attempt basic correction
            # This is a limited correction mode
            result["status"] = "valid"  # Assume valid if we can't verify
            result["corrected_identifier"] = user_input
            result["error_details"] = (
                "Limited verification: no expected HDprint provided"
            )

        return result

    except Exception as e:
        result["status"] = "error"
        result["error_details"] = f"Processing error: {str(e)}"
        return result


def parse_identifier_format(identifier: str) -> Dict[str, Any]:
    """
    Parse a {paiready}_{hdprint} identifier into its components.

    Args:
        identifier: The identifier to parse

    Returns:
        Dictionary containing:
        - is_valid_format: Whether the format is valid
        - checksum: The checksum part (if valid)
        - hdprint: The HDprint part (if valid)
        - format_analysis: Analysis of the format structure
        - validation_errors: List of validation errors (if any)
    """
    result = {
        "is_valid_format": False,
        "checksum": None,
        "hdprint": None,
        "format_analysis": {},
        "validation_errors": [],
    }

    try:
        # Split on first underscore
        parts = identifier.split("_", 1)

        if len(parts) < 2:
            result["validation_errors"].append("Missing underscore separator")
            return result

        checksum = parts[0]
        hdprint = parts[1]

        # Analyze checksum part
        checksum_analysis = {
            "length": len(checksum),
            "is_lowercase": checksum.islower(),
            "is_base58l_compatible": all(
                c in "123456789abcdefghijkmnpqrstuvwxyz" for c in checksum
            ),
        }

        # Analyze HDprint part
        hdprint_segments = hdprint.split("_")
        hdprint_analysis = {
            "total_length": len(hdprint),
            "num_segments": len(hdprint_segments),
            "segment_lengths": [len(seg) for seg in hdprint_segments],
            "has_mixed_case": any(c.isupper() for c in hdprint)
            and any(c.islower() for c in hdprint),
            "is_base58_compatible": all(
                c in "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
                for c in hdprint.replace("_", "")
            ),
        }

        # Validate format requirements
        if checksum_analysis["length"] < 1:
            result["validation_errors"].append("Empty checksum")

        if not checksum_analysis["is_base58l_compatible"]:
            result["validation_errors"].append(
                "Checksum contains invalid Base58L characters"
            )

        if hdprint_analysis["num_segments"] < 1:
            result["validation_errors"].append("Empty HDprint")

        if not hdprint_analysis["is_base58_compatible"]:
            result["validation_errors"].append(
                "HDprint contains invalid Base58 characters"
            )

        # Check if it matches expected patterns
        expected_patterns = [[6], [6, 8], [6, 8, 8], [6, 8, 8, 8]]
        pattern_matches = hdprint_analysis["segment_lengths"] in expected_patterns

        if not pattern_matches:
            # Check for rack patterns (multiples of [6,8,8,8])
            base_pattern = [6, 8, 8, 8]
            segments = hdprint_analysis["segment_lengths"]

            is_rack_pattern = False
            if len(segments) >= 4 and len(segments) % 4 == 0:
                rack_count = len(segments) // 4
                expected_rack_pattern = base_pattern * rack_count
                is_rack_pattern = segments == expected_rack_pattern

            if not is_rack_pattern:
                result["validation_errors"].append(
                    f"HDprint pattern {hdprint_analysis['segment_lengths']} doesn't match expected patterns"
                )

        # Update result
        result["checksum"] = checksum
        result["hdprint"] = hdprint
        result["format_analysis"] = {
            "checksum": checksum_analysis,
            "hdprint": hdprint_analysis,
        }
        result["is_valid_format"] = len(result["validation_errors"]) == 0

        return result

    except Exception as e:
        result["validation_errors"].append(f"Parse error: {str(e)}")
        return result


def restore_case_in_hdprint(
    lowercase_hdprint: str, case_pattern: Optional[str] = None
) -> str:
    """
    Restore proper case in an HDprint that was typed in lowercase.

    This is a simplified case restoration that follows HDprint patterns.
    For full case restoration, the original HDprint or case pattern should be provided.

    Args:
        lowercase_hdprint: HDprint typed in all lowercase
        case_pattern: Reference pattern for case restoration (optional)

    Returns:
        HDprint with restored case
    """
    if case_pattern:
        # Use the provided case pattern
        if len(lowercase_hdprint) == len(case_pattern):
            restored = ""
            for i, char in enumerate(lowercase_hdprint):
                if case_pattern[i].isupper():
                    restored += char.upper()
                else:
                    restored += char.lower()
            return restored

    # Basic heuristic restoration (simplified)
    # In a real implementation, this would use the embedded case patterns
    # from the BCH encoding or other advanced techniques

    segments = lowercase_hdprint.split("_")
    restored_segments = []

    for segment in segments:
        if len(segment) > 0:
            # Simple pattern: First character uppercase, rest lowercase
            # This is a placeholder - real implementation would be more sophisticated
            restored = segment[0].upper() + segment[1:].lower()
            restored_segments.append(restored)

    return "_".join(restored_segments)
