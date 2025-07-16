"""
PAIREADY - Production-ready AI checksum library for IDK-HPRINT

A comprehensive BCH-based error correction system for Base58L checksums.
Provides single character flip correction with interleaved BCH codes.

Author: Cryptography Team
Version: 1.0
"""

from .core import (
    InterleavedBCHChecksum,
    BCHConfigurationSweeper,
    generate_interleaved_base58l_checksum,
    verify_and_correct_checksum,
    is_bch_available,
    BASE58L_ALPHABET,
    BASE58_ALPHABET,
)

from .analysis import (
    ComprehensiveBCHSweeper,
    OptimalBCHSystem,
    BCHGeneratorRanker,
    find_shortest_base58l_checksum,
    test_bch_generator_mp,
)

from .utils import (
    bytes_to_bits,
    bits_to_bytes,
    encode_bits_to_base58l,
    decode_base58l_to_bits,
    generate_test_fingerprints,
)

__version__ = "1.0.0"
__author__ = "Cryptography Team"

# Main API exports
__all__ = [
    # Core functionality
    "InterleavedBCHChecksum",
    "BCHConfigurationSweeper",
    "generate_interleaved_base58l_checksum",
    "verify_and_correct_checksum",
    "is_bch_available",
    # Analysis tools
    "ComprehensiveBCHSweeper",
    "OptimalBCHSystem",
    "BCHGeneratorRanker",
    "find_shortest_base58l_checksum",
    "test_bch_generator_mp",
    # Utilities
    "bytes_to_bits",
    "bits_to_bytes",
    "encode_bits_to_base58l",
    "decode_base58l_to_bits",
    "generate_test_fingerprints",
    # Constants
    "BASE58L_ALPHABET",
    "BASE58_ALPHABET",
]
