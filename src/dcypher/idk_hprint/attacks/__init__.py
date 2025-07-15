"""
IDK_HPRINT Attack Demonstrations and Security Analysis

This module provides comprehensive attack demonstrations and security analysis
tools for IDK_HPRINT patterns, including vulnerability assessments, attack surface
analysis, and security testing utilities for the HMAC-per-character approach.

Main Components:
- demonstrations: General attack demonstrations and vulnerability testing
- idk_analysis: IDK pattern family specific security analysis
- hmac_analysis: HMAC-per-character specific attack analysis
- collision_finding: Advanced collision finding with multiprocessing

Features:
- HMAC-per-character security analysis
- Pattern family vulnerability assessments
- Attack surface analysis for HMAC chains
- Security recommendation generation
- Collision resistance testing adapted for HMAC approach
- Advanced multiprocessing collision finding
- Statistical collision sampling
- Comprehensive audit reports

Example Usage:
    from dcypher.idk_hprint.attacks import (
        demonstrate_hmac_per_character_security,
        analyze_idk_pattern_family,
        demonstrate_pattern_vulnerability,
        find_collision_advanced,
        collect_collision_samples,
        benchmark_collision_methods,
    )

    # Run vulnerability demonstration
    demonstrate_pattern_vulnerability()

    # Analyze IDK pattern family
    analyze_idk_pattern_family()

    # Find collision using advanced multiprocessing
    result = find_collision_advanced(num_chars=3, max_time=60)

    # Collect statistical samples
    stats = collect_collision_samples(num_chars=3, num_samples=50)

Note: All attack demonstrations are for educational and security analysis
purposes only. Use responsibly and only on systems you own or have
permission to test.
"""


# Lazy imports to avoid circular dependencies
def _lazy_import_demonstrations():
    from .demonstrations import (
        demonstrate_pattern_vulnerability,
        demonstrate_hmac_per_character_security,
        demonstrate_character_bias_analysis,
        demonstrate_collision_resistance,
        demonstrate_advanced_collision_finding,
        run_security_demonstrations,
    )

    return {
        "demonstrate_pattern_vulnerability": demonstrate_pattern_vulnerability,
        "demonstrate_hmac_per_character_security": demonstrate_hmac_per_character_security,
        "demonstrate_character_bias_analysis": demonstrate_character_bias_analysis,
        "demonstrate_collision_resistance": demonstrate_collision_resistance,
        "demonstrate_advanced_collision_finding": demonstrate_advanced_collision_finding,
        "run_security_demonstrations": run_security_demonstrations,
    }


def _lazy_import_idk_analysis():
    from .idk_analysis import (
        analyze_idk_pattern_family,
        demonstrate_idk_hmac_benchmarking,
        demonstrate_idk_entropy_analysis,
        demonstrate_idk_attack_surface,
        run_idk_analysis,
    )

    return {
        "analyze_idk_pattern_family": analyze_idk_pattern_family,
        "demonstrate_idk_hmac_benchmarking": demonstrate_idk_hmac_benchmarking,
        "demonstrate_idk_entropy_analysis": demonstrate_idk_entropy_analysis,
        "demonstrate_idk_attack_surface": demonstrate_idk_attack_surface,
        "run_idk_analysis": run_idk_analysis,
    }


def _lazy_import_hmac_analysis():
    from .hmac_analysis import (
        analyze_hmac_chain_security,
        demonstrate_hmac_chain_attacks,
        analyze_character_independence,
        demonstrate_base58_bias_analysis,
        run_hmac_analysis,
    )

    return {
        "analyze_hmac_chain_security": analyze_hmac_chain_security,
        "demonstrate_hmac_chain_attacks": demonstrate_hmac_chain_attacks,
        "analyze_character_independence": analyze_character_independence,
        "demonstrate_base58_bias_analysis": demonstrate_base58_bias_analysis,
        "run_hmac_analysis": run_hmac_analysis,
    }


def _lazy_import_collision_finding():
    from .collision_finding import (
        find_collision_advanced,
        collect_collision_samples,
        benchmark_collision_methods,
        print_collision_audit_summary,
        CollisionResult,
        CollisionSample,
        CollisionStats,
        PerformanceResult,
    )

    return {
        "find_collision_advanced": find_collision_advanced,
        "collect_collision_samples": collect_collision_samples,
        "benchmark_collision_methods": benchmark_collision_methods,
        "print_collision_audit_summary": print_collision_audit_summary,
        "CollisionResult": CollisionResult,
        "CollisionSample": CollisionSample,
        "CollisionStats": CollisionStats,
        "PerformanceResult": PerformanceResult,
    }


# Create lazy getters
def __getattr__(name):
    demonstrations = _lazy_import_demonstrations()
    if name in demonstrations:
        return demonstrations[name]

    idk_analysis = _lazy_import_idk_analysis()
    if name in idk_analysis:
        return idk_analysis[name]

    hmac_analysis = _lazy_import_hmac_analysis()
    if name in hmac_analysis:
        return hmac_analysis[name]

    collision_finding = _lazy_import_collision_finding()
    if name in collision_finding:
        return collision_finding[name]

    raise AttributeError(f"module '{__name__}' has no attribute '{name}'")


# Public API
__all__ = [
    # General demonstrations
    "demonstrate_pattern_vulnerability",
    "demonstrate_hmac_per_character_security",
    "demonstrate_character_bias_analysis",
    "demonstrate_collision_resistance",
    "demonstrate_advanced_collision_finding",
    "run_security_demonstrations",
    # IDK-specific analysis
    "analyze_idk_pattern_family",
    "demonstrate_idk_hmac_benchmarking",
    "demonstrate_idk_entropy_analysis",
    "demonstrate_idk_attack_surface",
    "run_idk_analysis",
    # HMAC-specific analysis
    "analyze_hmac_chain_security",
    "demonstrate_hmac_chain_attacks",
    "analyze_character_independence",
    "demonstrate_base58_bias_analysis",
    "run_hmac_analysis",
    # Advanced collision finding
    "find_collision_advanced",
    "collect_collision_samples",
    "benchmark_collision_methods",
    "print_collision_audit_summary",
    "CollisionResult",
    "CollisionSample",
    "CollisionStats",
    "PerformanceResult",
]
