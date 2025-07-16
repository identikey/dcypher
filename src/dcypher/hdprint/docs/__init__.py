"""
HDPRINT Documentation Generation Package

This package contains all the modules for generating comprehensive technical
documentation for the HDPRINT BCH checksum system.

The main readme.checksum.py file imports from this package to generate
the complete technical specification.
"""

from .validation import (
    run_comprehensive_validation,
    assert_mathematical_bch_properties,
    assert_base58l_encoding_properties,
    assert_bit_interleaving_properties,
    assert_case_pattern_encoding,
    assert_multiple_error_handling,
    assert_consistency_properties,
    assert_performance_properties,
)
from .configuration import discover_optimal_configuration, validate_configuration
from .demonstrations import demonstrate_error_correction_scenarios
from .generators import generate_technical_documentation

__all__ = [
    "run_comprehensive_validation",
    "assert_mathematical_bch_properties",
    "assert_base58l_encoding_properties",
    "assert_bit_interleaving_properties",
    "assert_case_pattern_encoding",
    "assert_multiple_error_handling",
    "assert_consistency_properties",
    "assert_performance_properties",
    "discover_optimal_configuration",
    "validate_configuration",
    "demonstrate_error_correction_scenarios",
    "generate_technical_documentation",
]
