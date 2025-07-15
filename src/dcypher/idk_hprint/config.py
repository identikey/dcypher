"""
IdkHprint Configuration Management

This module provides configuration management and benchmarking capabilities
for hierarchical fingerprinting with cyclical pattern [6,8,8,8] and analysis.
"""

from typing import List, Dict, Any, Optional
from .algorithms import generate_cyclical_pattern, generate_hierarchical_fingerprint
from .security import calculate_security_bits, analyze_entropy_efficiency
import time


class ConfigurationManager:
    """Manages configuration for IdkHprint fingerprinting with cyclical pattern."""

    def __init__(self):
        self.default_num_segments = 4  # Default [6,8,8,8] pattern

    def get_default_num_segments(self) -> int:
        """Get the default number of segments."""
        return self.default_num_segments

    def set_default_num_segments(self, num_segments: int) -> None:
        """Set the default number of segments."""
        if num_segments <= 0:
            raise ValueError("Number of segments must be positive")
        self.default_num_segments = num_segments

    def get_pattern(self, num_segments: Optional[int] = None) -> List[int]:
        """Get the cyclical pattern for specified number of segments."""
        if num_segments is None:
            num_segments = self.default_num_segments
        return generate_cyclical_pattern(num_segments)


def benchmark_configurations(
    segment_counts: List[int], iterations: int = 1000
) -> Dict[str, Any]:
    """
    Benchmark performance of different segment counts.

    Args:
        segment_counts: List of segment counts to benchmark
        iterations: Number of iterations for timing

    Returns:
        Dictionary with benchmark results
    """
    test_key = b"benchmark_key_for_testing_performance_metrics"
    results = []

    for num_segments in segment_counts:
        # Time the fingerprint generation
        start_time = time.time()
        for _ in range(iterations):
            generate_hierarchical_fingerprint(test_key, num_segments)
        end_time = time.time()

        avg_time = (end_time - start_time) / iterations
        security_bits, _ = calculate_security_bits(num_segments)
        pattern = generate_cyclical_pattern(num_segments)

        result = {
            "num_segments": num_segments,
            "pattern": pattern,
            "avg_time_ms": avg_time * 1000,
            "security_bits": security_bits,
            "performance_ratio": security_bits / (avg_time * 1000)
            if avg_time > 0
            else 0,
        }
        results.append(result)

    return {
        "base_pattern": [6, 8, 8, 8],
        "iterations": iterations,
        "results": results,
        "fastest": min(results, key=lambda x: x["avg_time_ms"]),
        "best_performance_ratio": max(results, key=lambda x: x["performance_ratio"]),
    }


def recommend_configuration(use_case: str) -> Dict[str, Any]:
    """
    Recommend configuration based on use case.

    Args:
        use_case: Description of the use case

    Returns:
        Dictionary with recommended configuration
    """
    use_case_lower = use_case.lower()

    # Simple rule-based recommendations for cyclical pattern
    if "iot" in use_case_lower or "embedded" in use_case_lower:
        recommended_segments = 2  # [6,8] - compact
        rationale = "Compact pattern suitable for IoT devices"
    elif "mobile" in use_case_lower:
        recommended_segments = 3  # [6,8,8] - balanced
        rationale = "Balanced pattern for mobile applications"
    elif "enterprise" in use_case_lower or "api" in use_case_lower:
        recommended_segments = 4  # [6,8,8,8] - standard
        rationale = "Standard full cyclical pattern for enterprise applications"
    elif "secure" in use_case_lower or "crypto" in use_case_lower:
        recommended_segments = 6  # [6,8,8,8,6,8] - enhanced
        rationale = "Enhanced security pattern for cryptographic applications"
    elif "maximum" in use_case_lower or "high" in use_case_lower:
        recommended_segments = 8  # [6,8,8,8,6,8,8,8] - maximum
        rationale = "Maximum security pattern for high-value applications"
    else:
        recommended_segments = 4  # [6,8,8,8] - default
        rationale = "Default balanced pattern"

    security_bits, _ = calculate_security_bits(recommended_segments)
    efficiency = analyze_entropy_efficiency(recommended_segments)
    pattern = generate_cyclical_pattern(recommended_segments)

    return {
        "use_case": use_case,
        "recommended_segments": recommended_segments,
        "pattern": pattern,
        "base_pattern": [6, 8, 8, 8],
        "rationale": rationale,
        "security_bits": security_bits,
        "efficiency_percentage": efficiency["efficiency_percentage"],
    }


def generate_configuration_report(
    segment_counts: Optional[List[int]] = None,
) -> Dict[str, Any]:
    """
    Generate comprehensive configuration report.

    Args:
        segment_counts: List of segment counts to analyze, defaults to common counts

    Returns:
        Dictionary with configuration report
    """
    if segment_counts is None:
        # Use common segment counts for cyclical pattern
        segment_counts = [1, 2, 3, 4, 5, 6, 8, 10, 12]

    results = []

    for num_segments in segment_counts:
        pattern = generate_cyclical_pattern(num_segments)
        security_bits, layer_bits = calculate_security_bits(num_segments)
        efficiency = analyze_entropy_efficiency(num_segments)

        result = {
            "num_segments": num_segments,
            "pattern": pattern,
            "security_bits": security_bits,
            "layer_securities": layer_bits,
            "efficiency_percentage": efficiency["efficiency_percentage"],
            "total_characters": sum(pattern),
            "display_length": sum(pattern) + num_segments - 1,
        }
        results.append(result)

    # Find optimal configurations
    best_security = max(results, key=lambda x: x["security_bits"])
    best_efficiency = max(results, key=lambda x: x["efficiency_percentage"])
    most_compact = min(results, key=lambda x: x["total_characters"])

    # Standard recommendations
    standard_4_segments = next((r for r in results if r["num_segments"] == 4), None)

    report = {
        "analysis_date": time.strftime("%Y-%m-%d %H:%M:%S"),
        "base_pattern": [6, 8, 8, 8],
        "segment_counts_analyzed": len(segment_counts),
        "results": results,
        "optimal_configurations": {
            "best_security": best_security,
            "best_efficiency": best_efficiency,
            "most_compact": most_compact,
            "standard_recommendation": standard_4_segments,
        },
        "general_recommendations": [
            "4 segments ([6,8,8,8]) provides balanced security and usability",
            "Use fewer segments for IoT/embedded applications",
            "Use more segments for high-security applications",
            "Consider display constraints when choosing segment count",
            "Cyclical pattern maintains consistent behavior",
        ],
    }

    return report


def get_security_levels() -> Dict[str, Dict[str, Any]]:
    """
    Get predefined security levels with recommended segment counts.

    Returns:
        Dictionary mapping security level names to configurations
    """
    levels = {
        "minimal": {
            "segments": 1,
            "pattern": [6],
            "description": "Minimal security for testing only",
            "security_bits": 0,
            "use_case": "Development and testing",
        },
        "low": {
            "segments": 2,
            "pattern": [6, 8],
            "description": "Low security for non-critical applications",
            "security_bits": 0,
            "use_case": "IoT devices, cache keys",
        },
        "standard": {
            "segments": 4,
            "pattern": [6, 8, 8, 8],
            "description": "Standard security for general use",
            "security_bits": 0,
            "use_case": "Web applications, API tokens",
        },
        "high": {
            "segments": 6,
            "pattern": [6, 8, 8, 8, 6, 8],
            "description": "High security for sensitive applications",
            "security_bits": 0,
            "use_case": "Financial systems, user authentication",
        },
        "maximum": {
            "segments": 8,
            "pattern": [6, 8, 8, 8, 6, 8, 8, 8],
            "description": "Maximum security for critical applications",
            "security_bits": 0,
            "use_case": "Government, military, high-value transactions",
        },
    }

    # Calculate actual security bits for each level
    for level_name, level_config in levels.items():
        segments = int(level_config["segments"])
        security_bits, _ = calculate_security_bits(segments)
        level_config["security_bits"] = float(security_bits)

    return levels
