"""
HDprint Security Analysis

This module provides security analysis tools for hierarchical fingerprinting,
including entropy calculations, collision resistance analysis, and attack
surface evaluation for the HMAC-based algorithm with productized size system.
"""

import math
from typing import List, Dict, Tuple, Any, Union, Optional
from .algorithms import generate_cyclical_pattern, resolve_size_to_segments


def calculate_security_bits(
    size: Union[str, int, None] = None,
    num_segments: Optional[int] = None,
    racks: Optional[int] = None,
) -> Tuple[float, List[float]]:
    """
    Calculate security bits for HDprint cyclical pattern.

    For HMAC-based hierarchical fingerprinting with cyclical pattern [6,8,8,8]:
    - Each segment has base58 encoding (~5.86 bits per character)
    - Layer 1 has birthday attack vulnerability (security / 2)
    - Subsequent layers have full preimage attack resistance
    - Total security is sum of all layer securities (conservative model)

    Args:
        size: Size name ("tiny", "small", "medium", "rack") or rack count
        num_segments: Direct number of segments (backward compatibility)
        racks: Number of racks

    Returns:
        Tuple of (total_security_bits, per_layer_security_bits)

    Security Model:
        Layer 1: min(segment_bits / 2, 256)  # Birthday attack on HMAC output
        Layer N: min(segment_bits, 256)     # Preimage attack on HMAC
        Total: sum(layer_securities)        # Conservative additive model
    """
    # Determine number of segments
    segments = None

    if size is not None:
        segments = resolve_size_to_segments(size)
    elif racks is not None:
        if racks <= 0:
            raise ValueError("Number of racks must be positive")
        segments = racks * 4
    elif num_segments is not None:
        if num_segments <= 0:
            raise ValueError("Number of segments must be positive")
        segments = num_segments
    else:
        raise ValueError("Must specify size, racks, or num_segments")

    # Generate cyclical pattern
    pattern = generate_cyclical_pattern(segments)

    # Base58 encoding: log2(58) ≈ 5.86 bits per character
    bits_per_char = math.log2(58)

    layer_securities = []

    for i, segment_length in enumerate(pattern):
        segment_bits = segment_length * bits_per_char

        if i == 0:
            # First layer: Birthday attack vulnerability on HMAC output
            # Limited by either segment entropy or HMAC strength
            layer_security = min(segment_bits / 2, 256)
        else:
            # Subsequent layers: Full preimage attack resistance
            # Limited by either segment entropy or HMAC strength
            layer_security = min(segment_bits, 256)

        layer_securities.append(layer_security)

    # Conservative model: sum all layer securities
    total_security = sum(layer_securities)

    return total_security, layer_securities


def analyze_entropy_efficiency(
    size: Union[str, int, None] = None,
    num_segments: Optional[int] = None,
    racks: Optional[int] = None,
    target_bits: int = 128,
) -> Dict[str, float]:
    """
    Analyze entropy efficiency for cyclical pattern.

    Args:
        size: Size name or rack count
        num_segments: Direct number of segments (backward compatibility)
        racks: Number of racks
        target_bits: Target security level in bits

    Returns:
        Dictionary with efficiency metrics:
        - total_bits: Total entropy bits available
        - effective_bits: Effective security bits (accounting for attacks)
        - efficiency_percentage: Efficiency as percentage
        - chars_per_bit: Characters required per security bit
        - display_efficiency: Security per display character
    """
    # Determine number of segments
    segments = None

    if size is not None:
        segments = resolve_size_to_segments(size)
    elif racks is not None:
        if racks <= 0:
            raise ValueError("Number of racks must be positive")
        segments = racks * 4
    elif num_segments is not None:
        if num_segments <= 0:
            raise ValueError("Number of segments must be positive")
        segments = num_segments
    else:
        raise ValueError("Must specify size, racks, or num_segments")

    # Generate cyclical pattern
    pattern = generate_cyclical_pattern(segments)

    total_chars = sum(pattern)
    display_length = total_chars + segments - 1  # Include separators

    # Base58 theoretical entropy
    bits_per_char = math.log2(58)
    total_bits = total_chars * bits_per_char

    # Effective security accounting for attack models
    effective_bits, _ = calculate_security_bits(num_segments=segments)

    # Efficiency metrics
    efficiency_percentage = (effective_bits / total_bits) * 100 if total_bits > 0 else 0
    chars_per_bit = total_chars / effective_bits if effective_bits > 0 else float("inf")
    display_efficiency = effective_bits / display_length if display_length > 0 else 0

    return {
        "total_bits": total_bits,
        "effective_bits": effective_bits,
        "efficiency_percentage": efficiency_percentage,
        "chars_per_bit": chars_per_bit,
        "display_efficiency": display_efficiency,
        "target_ratio": effective_bits / target_bits if target_bits > 0 else 0,
    }


def calculate_collision_space(
    size: Union[str, int, None] = None,
    num_segments: Optional[int] = None,
    racks: Optional[int] = None,
) -> Dict[str, float]:
    """
    Calculate collision space for different attack scenarios.

    Args:
        size: Size name or rack count
        num_segments: Direct number of segments (backward compatibility)
        racks: Number of racks

    Returns:
        Dictionary with collision space sizes:
        - total_space: Total fingerprint space size
        - first_segment_space: First segment collision space
        - birthday_space: Birthday attack space on first segment
        - preimage_space: Preimage attack space for full pattern
    """
    # Determine number of segments
    segments = None

    if size is not None:
        segments = resolve_size_to_segments(size)
    elif racks is not None:
        if racks <= 0:
            raise ValueError("Number of racks must be positive")
        segments = racks * 4
    elif num_segments is not None:
        if num_segments <= 0:
            raise ValueError("Number of segments must be positive")
        segments = num_segments
    else:
        raise ValueError("Must specify size, racks, or num_segments")

    # Generate cyclical pattern
    pattern = generate_cyclical_pattern(segments)

    # Base58 alphabet size
    alphabet_size = 58

    # Total fingerprint space
    total_chars = sum(pattern)
    total_space = alphabet_size**total_chars

    # First segment space (most vulnerable)
    first_segment_space = alphabet_size ** pattern[0]

    # Birthday attack space (square root of first segment)
    birthday_space = math.sqrt(first_segment_space)

    # Preimage space (limited by HMAC-SHA3-512 strength)
    preimage_space = min(total_space, 2**512)

    return {
        "total_space": total_space,
        "first_segment_space": first_segment_space,
        "birthday_space": birthday_space,
        "preimage_space": preimage_space,
    }


def analyze_attack_surface(
    size: Union[str, int, None] = None,
    num_segments: Optional[int] = None,
    racks: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Analyze attack surface and vulnerabilities.

    Args:
        size: Size name or rack count
        num_segments: Direct number of segments (backward compatibility)
        racks: Number of racks

    Returns:
        Dictionary with attack analysis:
        - vulnerabilities: List of identified vulnerabilities
        - attack_costs: Estimated attack costs in operations
        - recommendations: Security recommendations
    """
    # Determine number of segments
    segments = None

    if size is not None:
        segments = resolve_size_to_segments(size)
    elif racks is not None:
        if racks <= 0:
            raise ValueError("Number of racks must be positive")
        segments = racks * 4
    elif num_segments is not None:
        if num_segments <= 0:
            raise ValueError("Number of segments must be positive")
        segments = num_segments
    else:
        raise ValueError("Must specify size, racks, or num_segments")

    # Generate cyclical pattern
    pattern = generate_cyclical_pattern(segments)

    vulnerabilities = []
    recommendations = []
    attack_costs = {}

    # Analyze individual segments
    for i, segment_length in enumerate(pattern):
        if segment_length < 3:
            vulnerabilities.append(
                f"Segment {i + 1} too short ({segment_length} chars)"
            )
            recommendations.append(f"Increase segment {i + 1} to at least 3 characters")

        if segment_length > 20:
            vulnerabilities.append(
                f"Segment {i + 1} very long ({segment_length} chars)"
            )
            recommendations.append(f"Consider reducing segment {i + 1} for usability")

    # Calculate attack costs
    security_bits, layer_bits = calculate_security_bits(num_segments=segments)

    # Birthday attack on first segment (most feasible)
    birthday_cost = 2 ** (layer_bits[0] if layer_bits else 0)
    attack_costs["birthday_first_segment"] = birthday_cost

    # Preimage attack on full pattern
    preimage_cost = 2**security_bits
    attack_costs["preimage_full_pattern"] = preimage_cost

    # HMAC collision attack (theoretical)
    hmac_collision_cost = 2**256  # SHA3-512 collision resistance
    attack_costs["hmac_collision"] = hmac_collision_cost

    # Security level assessment
    if security_bits < 80:
        vulnerabilities.append("Low security level (< 80 bits)")
        if isinstance(size, str):
            recommendations.append(
                "Consider using 'medium' or 'rack' size for higher security"
            )
        else:
            recommendations.append("Increase number of segments for higher security")
    elif security_bits < 128:
        vulnerabilities.append("Moderate security level (< 128 bits)")
        if isinstance(size, str):
            recommendations.append(
                "Consider using 'rack' size or multiple racks for future-proofing"
            )
        else:
            recommendations.append("Consider more segments for future-proofing")

    # Size-specific analysis
    if isinstance(size, str):
        if size == "tiny":
            vulnerabilities.append("Tiny size intended for testing only")
            recommendations.append("Use 'small' or larger for production")
        elif size == "small":
            vulnerabilities.append("Small size provides basic security only")
            recommendations.append("Consider 'medium' or 'rack' for production use")

    # Rack-based analysis
    rack_count = segments // 4 if segments % 4 == 0 else None
    if rack_count:
        if rack_count >= 3:
            recommendations.append(f"Excellent security with {rack_count} racks")
        elif rack_count == 2:
            recommendations.append("Good security with 2 racks")
        elif rack_count == 1:
            recommendations.append("Standard security with 1 rack")

    return {
        "vulnerabilities": vulnerabilities,
        "attack_costs": attack_costs,
        "recommendations": recommendations,
        "security_level": "high"
        if security_bits >= 128
        else "moderate"
        if security_bits >= 80
        else "low",
        "pattern": pattern,
        "base_pattern": [6, 8, 8, 8],
        "size_info": {
            "size": size,
            "segments": segments,
            "rack_count": rack_count,
        },
    }
