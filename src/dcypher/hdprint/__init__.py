"""
IdentiKey HDprint Library for dCypher

This library provides hierarchical cryptographic fingerprinting using HMAC chains
with base58 encoding and productized size names for deterministic,
collision-resistant identifiers.

Size Options:
- tiny: [6] (1 segment) - minimal security for testing
- small: [6,8] (2 segments) - basic security for non-critical use
- medium: [6,8,8] (3 segments) - moderate security for general use
- rack: [6,8,8,8] (4 segments) - full pattern for standard security
- Multiple racks: 2 racks = [6,8,8,8,6,8,8,8], etc. - high security

Main Features:
- HMAC-based hierarchical fingerprint generation with blake3 preprocessing
- Productized size names (tiny, small, medium, rack) and rack scaling
- Base58 encoding for human-readable output
- Configurable security levels via size selection
- Security analysis and entropy efficiency tools
- Cipheranalysis and attack demonstration tools

Example Usage:
    from dcypher.hdprint import generate_hierarchical_fingerprint, get_size_info

    # Using size names
    public_key = b"your_public_key_here"

    fingerprint = generate_hierarchical_fingerprint(public_key, "tiny")    # Ab3DeF
    fingerprint = generate_hierarchical_fingerprint(public_key, "small")   # Ab3DeF_Xy9ZmP7q
    fingerprint = generate_hierarchical_fingerprint(public_key, "medium")  # Ab3DeF_Xy9ZmP7q_R2sK1M4V
    fingerprint = generate_hierarchical_fingerprint(public_key, "rack")    # Ab3DeF_Xy9ZmP7q_R2sK1M4V_N6tL9Bw

    # Using rack count for high security
    fingerprint = generate_hierarchical_fingerprint(public_key, racks=2)   # Ab3DeF_Xy9ZmP7q_R2sK1M4V_N6tL9Bw_Pg8HsX_Kf2Cm9Et_Bv7Qw1Ry_Zj5Mu3Ld
    fingerprint = generate_hierarchical_fingerprint(public_key, racks=3)   # 3 full racks

    # Get size information
    size_info = get_size_info("rack")
    print(f"Pattern: {size_info['pattern']}")

    # Run security analysis
    from dcypher.hdprint.attacks import run_idk_analysis
    run_idk_analysis()

Note: This algorithm uses HMAC-SHA3-512 chains with blake3 preprocessing for
cryptographic strength and hierarchical properties. Each character comes from
a separate HMAC operation where both the key and data are blake3 hashed.
The productized size system provides intuitive security scaling. Segments are
joined with underscores for easy selection on desktop and mobile platforms.
"""

# Core algorithm functions
from .algorithms import (
    generate_hierarchical_fingerprint,
    generate_hierarchical_fingerprint_with_steps,
    generate_cyclical_pattern,
    generate_rack_pattern,
    resolve_size_to_segments,
    get_size_info,
    get_available_sizes,
    get_pattern_info,  # Backward compatibility
    hmac_sha3_512,
    verify_hierarchical_fingerprint,
    extract_segments,
    get_prefix,
    check_hierarchical_compatibility,
)

# Security analysis
from .security import (
    calculate_security_bits,
    analyze_entropy_efficiency,
    calculate_collision_space,
    analyze_attack_surface,
)

# Advanced analysis
from .analysis import (
    analyze_entropy_distribution,
    analyze_character_bias,
    generate_entropy_report,
    analyze_security_progression,
)

# Pattern definitions
from .patterns import (
    COMPREHENSIVE_PATTERNS,
)

# Configuration management
from .config import (
    ConfigurationManager,
    benchmark_configurations,
    recommend_configuration,
    generate_configuration_report,
    get_security_levels,
)

# Note: attacks module is available as dcypher.hdprint.attacks
# Example: from dcypher.hdprint.attacks import run_idk_analysis

# Public API
__all__ = [
    # Core functions
    "generate_hierarchical_fingerprint",
    "generate_hierarchical_fingerprint_with_steps",
    "generate_cyclical_pattern",
    "generate_rack_pattern",
    "resolve_size_to_segments",
    "get_size_info",
    "get_available_sizes",
    "get_pattern_info",  # Backward compatibility
    "hmac_sha3_512",
    "verify_hierarchical_fingerprint",
    "extract_segments",
    "get_prefix",
    "check_hierarchical_compatibility",
    # Security analysis
    "calculate_security_bits",
    "analyze_entropy_efficiency",
    "calculate_collision_space",
    "analyze_attack_surface",
    # Advanced analysis
    "analyze_entropy_distribution",
    "analyze_character_bias",
    "generate_entropy_report",
    "analyze_security_progression",
    # Configuration management
    "ConfigurationManager",
    "benchmark_configurations",
    "recommend_configuration",
    "generate_configuration_report",
    "get_security_levels",
    # Pattern definitions
    "COMPREHENSIVE_PATTERNS",
]

__version__ = "0.1.0-alpha"
__author__ = "dcypher team"
__description__ = "IdentiKey HDprint hierarchical cryptographic fingerprinting library with productized size system"
