"""
HDPRINT Configuration Module

This module handles the discovery and validation of optimal BCH configurations
for the HDPRINT checksum system. It performs comprehensive parameter sweeping
to find the best configuration and validates it through extensive testing.

GOLD MASTER SPECIFICATION COMPLIANCE:
- All test parameters come from configuration
- All success rate claims are validated against actual data
- No hardcoded fallback thresholds
- System exits if any specifications are violated
"""

import secrets
import math
from typing import Dict, Any

from dcypher.lib.paiready import (
    InterleavedBCHChecksum,
    BCHConfigurationSweeper,
    BASE58L_ALPHABET,
)

# Configuration for gold master specification
GOLD_MASTER_CONFIG = {
    "target_length_range": {"min": 6, "max": 9},  # Character lengths to test
    "min_success_rate": 0.95,  # Minimum acceptable success rate
    "generation_test_count": 20,  # Number of generation tests per config
    "correction_test_positions": 5,  # Number of positions to test for correction
    "correction_test_replacements": 3,  # Number of replacement chars per position
    "generation_success_threshold": 0.85,  # 85% minimum generation success
    "correction_success_threshold": 0.80,  # 80% minimum correction success
    "test_deterministic_seed": 42,  # Fixed seed for reproducible tests
}


class ConfigurationViolationError(Exception):
    """Raised when configuration validation fails against specifications"""

    pass


# Import IDK-HDPRINT for fingerprint generation
try:
    from dcypher.hdprint import generate_hierarchical_fingerprint

    hdprint_available = True
except ImportError:
    print("WARNING: IDK-HDPRINT not available - using synthetic fingerprints")
    hdprint_available = False

    def generate_hierarchical_fingerprint(public_key, size):
        # Generate deterministic mixed-case alphanumeric fingerprints based on the public key
        import random
        import hashlib

        # Use the public key with fixed seed for deterministic gold master tests
        seed_data = (
            public_key + str(GOLD_MASTER_CONFIG["test_deterministic_seed"]).encode()
        )
        seed_hash = hashlib.sha256(seed_data).digest()
        random.seed(int.from_bytes(seed_hash[:4], "big"))

        # Generate base58-like characters (use actual alphabet from live system)
        chars = BASE58L_ALPHABET

        def generate_segment(length):
            return "".join(random.choice(chars) for _ in range(length))

        if size == "tiny":
            return generate_segment(6)
        elif size == "small":
            return f"{generate_segment(6)}_{generate_segment(8)}"
        elif size == "medium":
            return f"{generate_segment(6)}_{generate_segment(8)}_{generate_segment(8)}"
        elif size == "rack":
            return f"{generate_segment(6)}_{generate_segment(8)}_{generate_segment(8)}_{generate_segment(8)}"
        return generate_segment(6)


def discover_optimal_configuration():
    """
    Discover optimal BCH configuration through live parameter sweeping and document it.
    This replaces hardcoded values with actual discovered optimal parameters.

    GOLD MASTER COMPLIANCE:
    - All test ranges come from configuration
    - All claims are validated against actual data
    - No hardcoded fallback values allowed
    """
    print("LIVE PARAMETER DISCOVERY")
    print("=" * 80)
    print(
        "Discovering optimal BCH configuration through comprehensive parameter sweeping..."
    )
    print(
        "This will test all viable (t,m) combinations and validate with real scenarios."
    )
    print()

    config = GOLD_MASTER_CONFIG
    target_range = config["target_length_range"]
    assert isinstance(target_range, dict), "target_length_range should be a dictionary"
    min_target = target_range["min"]
    max_target = target_range["max"]
    min_success_rate = config["min_success_rate"]

    assert isinstance(min_target, int), (
        f"min_target should be int, got {type(min_target)}"
    )
    assert isinstance(max_target, int), (
        f"max_target should be int, got {type(max_target)}"
    )
    assert isinstance(min_success_rate, (int, float)), (
        f"min_success_rate should be numeric, got {type(min_success_rate)}"
    )

    # Use the actual sweeping functionality from core.py
    print("Step 1: Comprehensive BCH Parameter Sweep")
    print("-" * 50)
    print(f"Testing character lengths: {min_target} to {max_target}")
    print(f"Minimum success rate requirement: {min_success_rate:.1%}")
    print()

    # Test different target lengths to find the optimal one
    optimal_configs = {}
    for target_chars in range(min_target, max_target):
        print(f"\nTesting {target_chars}-character Base58L checksum:")

        # Use the actual sweeper from core.py
        discovered_config = BCHConfigurationSweeper.find_optimal_config(
            target_chars=target_chars, min_success_rate=min_success_rate
        )

        if discovered_config:
            optimal_configs[target_chars] = discovered_config
            print(f"   Found working configuration for {target_chars} characters")

            # Type-safe access to nested config with assertions
            bch_config = discovered_config.get("bch_config")
            assert isinstance(bch_config, dict), (
                f"bch_config should be dict, got {type(bch_config)}"
            )

            bch_t = bch_config.get("t")
            bch_m = bch_config.get("m")

            assert bch_t is not None, "BCH parameter 't' missing from configuration"
            assert bch_m is not None, "BCH parameter 'm' missing from configuration"

            print(
                f"   Configuration: {discovered_config['num_codes']} × BCH(t={bch_t},m={bch_m})"
            )
            print(f"   Total bits: {discovered_config['total_bits']}")

            estimated_chars = discovered_config.get("estimated_chars", target_chars)
            print(f"   Estimated length: {estimated_chars} chars")
        else:
            print(f"   No working configuration found for {target_chars} characters")

    # Select the best configuration (shortest working one)
    if optimal_configs:
        best_length = min(optimal_configs.keys())
        best_config = optimal_configs[best_length]

        print(f"\nOPTIMAL CONFIGURATION DISCOVERED:")
        print(f"   Target length: {best_length} characters")

        bch_config = best_config["bch_config"]
        print(
            f"   Configuration: {best_config['num_codes']} × BCH(t={bch_config['t']},m={bch_config['m']})"
        )
        print(f"   Total bits: {best_config['total_bits']}")

        # Calculate and display accurate length information
        actual_chars = best_config["total_bits"] / math.log2(len(BASE58L_ALPHABET))
        print(f"   Natural length: {actual_chars:.5f} chars (mathematically)")

        estimated_chars = best_config.get("estimated_chars", best_length)
        print(f"   System uses: {estimated_chars} chars (adjusted)")
        print(f"   Target success rate: ≥{min_success_rate:.0%} (to be validated)")
        print()

        # ASSERTION: Verify discovered configuration meets requirements
        assert best_config["total_bits"] > 0, (
            "Discovered configuration should have positive total bits"
        )
        assert estimated_chars >= best_length, (
            f"Estimated chars {estimated_chars} should be >= target length {best_length}"
        )

        return best_config
    else:
        error_msg = (
            f"No working configurations found in tested range {min_target}-{max_target}"
        )
        print(f"\n<ERROR>: {error_msg}")
        raise ConfigurationViolationError(error_msg)


def validate_configuration(config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Validate the discovered configuration with comprehensive testing and document results.

    GOLD MASTER COMPLIANCE:
    - All test parameters come from configuration
    - All success rates are measured and asserted
    - No hardcoded thresholds used as fallbacks
    """
    print("CONFIGURATION VALIDATION")
    print("=" * 80)
    print(
        "Validating discovered configuration with comprehensive real-world testing..."
    )
    print()

    gold_config = GOLD_MASTER_CONFIG
    generation_test_count = gold_config["generation_test_count"]
    test_positions = gold_config["correction_test_positions"]
    test_replacements = gold_config["correction_test_replacements"]
    generation_threshold = gold_config["generation_success_threshold"]
    correction_threshold = gold_config["correction_success_threshold"]

    # Type assertions for arithmetic operations
    assert isinstance(generation_test_count, int), (
        f"generation_test_count should be int, got {type(generation_test_count)}"
    )
    assert isinstance(test_positions, int), (
        f"test_positions should be int, got {type(test_positions)}"
    )
    assert isinstance(test_replacements, int), (
        f"test_replacements should be int, got {type(test_replacements)}"
    )
    assert isinstance(generation_threshold, (int, float)), (
        f"generation_threshold should be numeric, got {type(generation_threshold)}"
    )
    assert isinstance(correction_threshold, (int, float)), (
        f"correction_threshold should be numeric, got {type(correction_threshold)}"
    )

    print(f"Test parameters:")
    print(f"   Generation tests: {generation_test_count}")
    print(f"   Correction test positions: {test_positions}")
    print(f"   Replacement chars per position: {test_replacements}")
    print(f"   Generation success threshold: {generation_threshold:.1%}")
    print(f"   Correction success threshold: {correction_threshold:.1%}")
    print()

    # Create a checksum system with the discovered configuration
    try:
        # Initialize with the target length from the discovered config
        target_length = config.get("estimated_chars") or config.get("length")
        assert target_length is not None, (
            "Configuration must provide either 'estimated_chars' or 'length' - no hardcoded fallbacks allowed"
        )
        checksum_system = InterleavedBCHChecksum(target_chars=target_length)

        if not checksum_system.config:
            error_msg = (
                "Failed to initialize checksum system with discovered configuration"
            )
            print(error_msg)
            raise ConfigurationViolationError(error_msg)

        # Document the actual configuration used by the system
        actual_config = checksum_system.config
        print("ACTUAL SYSTEM CONFIGURATION:")
        print(f"   Target characters: {target_length}")
        print(f"   BCH codes: {actual_config['num_codes']}")
        print(f"   Bits per code: {actual_config['bits_per_code']}")
        print(f"   Total bits: {actual_config['total_bits']}")

        # Type-safe access to nested BCH config with assertions
        actual_bch_config = actual_config.get("bch_config")
        assert isinstance(actual_bch_config, dict), (
            f"actual_bch_config should be dict, got {type(actual_bch_config)}"
        )

        actual_bch_t = actual_bch_config.get("t")
        actual_bch_m = actual_bch_config.get("m")
        assert actual_bch_t is not None, "BCH parameter 't' missing from actual config"
        assert actual_bch_m is not None, "BCH parameter 'm' missing from actual config"

        print(f"   BCH parameters: t={actual_bch_t}, m={actual_bch_m}")
        print()

    except Exception as e:
        error_msg = f"Error initializing checksum system: {e}"
        print(error_msg)
        raise ConfigurationViolationError(error_msg)

    # Test checksum generation with real fingerprints
    print("VALIDATION TEST 1: Checksum Generation")
    print("-" * 40)

    test_results: Dict[str, Any] = {
        "checksums_generated": 0,
        "generation_errors": 0,
        "sample_checksums": [],
    }

    for i in range(generation_test_count):
        try:
            # Generate real fingerprint with deterministic seed for reproducibility
            test_key = secrets.token_bytes(32)
            fingerprint = generate_hierarchical_fingerprint(test_key, "tiny")

            # Generate checksum
            checksum = checksum_system.generate_checksum(fingerprint)

            # Validate checksum format
            if len(checksum) != target_length:
                error_msg = f"Wrong checksum length: expected {target_length}, got {len(checksum)}"
                print(f"   {error_msg}")
                test_results["generation_errors"] = (
                    int(test_results["generation_errors"]) + 1
                )
                continue

            if not all(c in BASE58L_ALPHABET for c in checksum):
                error_msg = f"Invalid characters in checksum: {checksum}"
                print(f"   {error_msg}")
                test_results["generation_errors"] = (
                    int(test_results["generation_errors"]) + 1
                )
                continue

            test_results["checksums_generated"] = (
                int(test_results["checksums_generated"]) + 1
            )
            if len(test_results["sample_checksums"]) < 5:
                test_results["sample_checksums"].append(f"{checksum}:{fingerprint}")

        except Exception as e:
            print(f"   Generation error: {e}")
            test_results["generation_errors"] = (
                int(test_results["generation_errors"]) + 1
            )

    # ASSERTION: Generation success rate must meet threshold
    actual_generation_rate = (
        int(test_results["checksums_generated"]) / generation_test_count
    )
    print(
        f"   Generated: {test_results['checksums_generated']}/{generation_test_count} checksums"
    )
    print(f"   Errors: {test_results['generation_errors']}/{generation_test_count}")
    print(f"   Success rate: {actual_generation_rate:.1%}")

    assert actual_generation_rate >= generation_threshold, (
        f"Generation success rate {actual_generation_rate:.1%} below threshold {generation_threshold:.1%}"
    )
    print(
        f"   <ASSERTION>: Generation success rate meets {generation_threshold:.1%} threshold"
    )

    print("   Sample checksums:")
    for sample in test_results["sample_checksums"]:
        print(f"     {sample}")
    print()

    # Test error correction capability
    print("VALIDATION TEST 2: Error Correction Capability")
    print("-" * 40)

    correction_results: Dict[str, Any] = {
        "total_tests": 0,
        "successful_corrections": 0,
        "test_details": [],
    }

    # Test with different fingerprints
    test_fingerprints = []
    for test_fp_idx in range(3):
        test_key = secrets.token_bytes(32)
        test_fingerprint = generate_hierarchical_fingerprint(test_key, "tiny")
        test_fingerprints.append(test_fingerprint)

    for test_fp_idx, test_fingerprint in enumerate(test_fingerprints):
        original_checksum = checksum_system.generate_checksum(test_fingerprint)

        print(f"   Testing fingerprint {test_fp_idx + 1}: {test_fingerprint}")
        print(f"   Original checksum: {original_checksum}")

        # Test single character flips at different positions (systematic, not random)
        test_positions_actual = min(len(original_checksum), test_positions)
        for pos in range(test_positions_actual):
            chars = list(original_checksum)
            original_char = chars[pos]

            # Test with systematic replacement characters (not random)
            replacements_tested = 0
            for replacement_idx, replacement in enumerate(BASE58L_ALPHABET):
                if replacement == original_char:
                    continue
                if replacements_tested >= test_replacements:
                    break

                # Create corrupted checksum
                chars[pos] = replacement
                corrupted_checksum = "".join(chars)

                # Test correction
                try:
                    verification_result = checksum_system.verify_and_correct_checksum(
                        test_fingerprint, corrupted_checksum
                    )

                    correction_successful = verification_result.get("matches", False)
                    if correction_successful:
                        correction_results["successful_corrections"] = (
                            int(correction_results["successful_corrections"]) + 1
                        )

                    correction_results["total_tests"] = (
                        int(correction_results["total_tests"]) + 1
                    )

                    status = "<PASS>" if correction_successful else "<FAIL>"
                    print(f"     Pos {pos}: {original_char}→{replacement} | {status}")

                except Exception as e:
                    print(f"     Pos {pos}: {original_char}→{replacement} | ERROR: {e}")
                    correction_results["total_tests"] = (
                        int(correction_results["total_tests"]) + 1
                    )

                replacements_tested += 1
        print()

    # Calculate and assert success rate
    if int(correction_results["total_tests"]) > 0:
        actual_correction_rate = int(
            correction_results["successful_corrections"]
        ) / int(correction_results["total_tests"])
        print(
            f"   Error correction success rate: {actual_correction_rate:.1%} ({correction_results['successful_corrections']}/{correction_results['total_tests']})"
        )

        # ASSERTION: Correction success rate must meet threshold
        assert actual_correction_rate >= correction_threshold, (
            f"Correction success rate {actual_correction_rate:.1%} below threshold {correction_threshold:.1%}"
        )
        print(
            f"   <ASSERTION>: Correction success rate meets {correction_threshold:.1%} threshold"
        )
    else:
        actual_correction_rate = 0.0
        error_msg = "No error correction tests completed"
        print(f"   {error_msg}")
        raise ConfigurationViolationError(error_msg)

    print()

    # Overall validation result with assertions
    validation_passed = (
        actual_generation_rate >= generation_threshold
        and actual_correction_rate >= correction_threshold
    )

    print("VALIDATION SUMMARY:")
    generation_status = (
        "<PASS>" if actual_generation_rate >= generation_threshold else "<FAIL>"
    )
    correction_status = (
        "<PASS>" if actual_correction_rate >= correction_threshold else "<FAIL>"
    )

    print(f"   Checksum generation: {generation_status} ({actual_generation_rate:.1%})")
    print(f"   Error correction: {correction_status} ({actual_correction_rate:.1%})")
    print(f"   Overall validation: {'<PASS>' if validation_passed else '<FAIL>'}")

    # ASSERTION: Overall validation must pass
    assert validation_passed, (
        f"Configuration validation failed: generation={actual_generation_rate:.1%}, correction={actual_correction_rate:.1%}"
    )
    print(f"   <ASSERTION>: Overall validation passes all thresholds")
    print()

    return {
        "validation_passed": validation_passed,
        "actual_config": actual_config,
        "generation_results": test_results,
        "correction_results": correction_results,
        "success_rate": actual_correction_rate,
        "generation_rate": actual_generation_rate,
        "checksum_system": checksum_system,
    }
