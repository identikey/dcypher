"""
HDprint Pattern Definitions and Analysis

This module contains comprehensive pattern definitions for different use cases,
from ultra-compact IoT patterns to high-security enterprise patterns, including
mathematical sequences like Fibonacci and the IDK (IdentiKey) family.

Pattern Categories:
- Ultra-compact: Minimal display requirements (IoT, embedded)
- Compact: Quick reference applications (mobile, cache keys)
- Standard: Balanced security/usability (desktop, API tokens)
- Enhanced: Higher security requirements (enterprise, crypto)
- Maximum: Ultra-secure applications (military, government)
- Mathematical: Research and academic applications
- IDK: IdentiKey family with progressive security levels

Each pattern is characterized by:
- Segment lengths: List of integers defining segment sizes
- Category: Security/usability classification
- Use case: Recommended application scenarios
- Description: Human-readable explanation
"""

from dataclasses import dataclass
from typing import List, Optional, Dict
import math


@dataclass
class PatternDefinition:
    """Comprehensive pattern definition for analysis."""

    pattern: List[int]
    name: str
    category: str
    description: str
    use_case: str


# Comprehensive pattern definitions - single source of truth
COMPREHENSIVE_PATTERNS = [
    # Single segment patterns
    PatternDefinition(
        [2], "IoT-2", "Ultra-compact", "Minimal display", "IoT devices, debug IDs"
    ),
    PatternDefinition(
        [3], "Compact-3", "Ultra-compact", "Tiny reference", "Embedded systems"
    ),
    PatternDefinition(
        [4], "Mobile-4", "Compact", "Quick reference", "Mobile apps, cache keys"
    ),
    PatternDefinition(
        [6], "Desktop-6", "Compact", "Balanced single", "Desktop apps, session IDs"
    ),
    PatternDefinition(
        [8], "Enterprise-8", "Standard", "Standard single", "API keys, tokens"
    ),
    PatternDefinition(
        [10], "Secure-10", "Enhanced", "High security single", "Crypto identifiers"
    ),
    PatternDefinition(
        [12], "Maximum-12", "Maximum", "Ultra-secure single", "High-value applications"
    ),
    # Dual segment patterns
    PatternDefinition(
        [2, 2], "IoT-2x2", "Ultra-compact", "Minimal dual", "IoT verification"
    ),
    PatternDefinition(
        [3, 3], "Compact-3x3", "Compact", "Tiny dual", "Embedded verification"
    ),
    PatternDefinition(
        [4, 4], "Mobile-4x4", "Standard", "Mobile dual", "Mobile verification"
    ),
    PatternDefinition(
        [6, 3], "Desktop-6x3", "Balanced", "Desktop compact", "UI-friendly format"
    ),
    PatternDefinition(
        [6, 6], "Desktop-6x6", "Enhanced", "Desktop dual", "Desktop verification"
    ),
    PatternDefinition(
        [8, 4], "Enterprise-8x4", "Standard", "Enterprise compact", "API verification"
    ),
    PatternDefinition(
        [10, 5], "Secure-10x5", "Enhanced", "High security dual", "Crypto verification"
    ),
    PatternDefinition(
        [10, 10], "Secure-10x10", "Maximum", "Ultra-secure dual", "Maximum security"
    ),
    # Triple segment patterns
    PatternDefinition(
        [3, 4, 4],
        "Mixed-3x4x4",
        "Balanced",
        "Progressive cascade",
        "Tiered verification",
    ),
    PatternDefinition(
        [4, 5, 5], "Mixed-4x5x5", "Enhanced", "Balanced cascade", "Progressive security"
    ),
    PatternDefinition(
        [5, 6, 6], "Mixed-5x6x6", "Enhanced", "Strong cascade", "High-tier verification"
    ),
    PatternDefinition(
        [6, 4, 4],
        "Standard-6x4x4",
        "Standard",
        "Standard cascade",
        "Common verification",
    ),
    PatternDefinition(
        [8, 4, 4],
        "Enterprise-8x4x4",
        "Standard",
        "Enterprise cascade",
        "Business applications",
    ),
    PatternDefinition(
        [8, 5, 4], "Mixed-8x5x4", "Mixed", "Descending cascade", "Flexible architecture"
    ),
    PatternDefinition(
        [10, 5, 5],
        "Secure-10x5x5",
        "Enhanced",
        "High security cascade",
        "Secure applications",
    ),
    PatternDefinition(
        [12, 6, 6],
        "Maximum-12x6x6",
        "Maximum",
        "Ultra-secure cascade",
        "Maximum security",
    ),
    # Quad segment patterns
    PatternDefinition(
        [3, 3, 5],
        "Mixed-3x3x5",
        "Mixed",
        "Escalating triple",
        "Progressive verification",
    ),
    PatternDefinition(
        [6, 6, 6, 6],
        "Distributed-6x6x6x6",
        "Distributed",
        "Equal distribution",
        "Multi-point verification",
    ),
    PatternDefinition(
        [2, 2, 2, 2],
        "IoT-2x2x2x2",
        "Ultra-compact",
        "Minimal distribution",
        "IoT multi-point",
    ),
    PatternDefinition(
        [4, 4, 4, 4],
        "Mobile-4x4x4x4",
        "Standard",
        "Mobile distribution",
        "Mobile multi-point",
    ),
    # Mathematical sequence patterns
    PatternDefinition(
        [3, 5, 8, 13],
        "Fibonacci",
        "Mathematical",
        "Fibonacci sequence",
        "Research applications, mathematical progression",
    ),
    PatternDefinition(
        [2, 3, 5, 8],
        "Fibonacci-Short",
        "Mathematical",
        "Short Fibonacci",
        "Compact mathematical sequence",
    ),
    PatternDefinition(
        [1, 2, 3, 5],
        "Fibonacci-Micro",
        "Mathematical",
        "Micro Fibonacci",
        "Ultra-compact mathematical",
    ),
    PatternDefinition(
        [1, 2, 3, 5, 8],
        "Fibonacci-Extended",
        "Mathematical",
        "Extended Fibonacci",
        "Full 5-segment Fibonacci progression",
    ),
    # IDK (IdentiKey) Pattern Family - Progressive Security Levels
    PatternDefinition(
        [3, 5],
        "IDK-Small",
        "IDK",
        "Compact dual verification",
        "Lightweight applications, quick verification",
    ),
    PatternDefinition(
        [3, 5, 8],
        "IDK-Medium",
        "IDK",
        "Balanced triple verification",
        "Standard applications, moderate security",
    ),
    PatternDefinition(
        [3, 5, 8, 8],
        "IDK-Large",
        "IDK",
        "Strong quad verification",
        "High-security applications, enterprise use",
    ),
    PatternDefinition(
        [3, 5, 8, 8, 8],
        "IDK-XLarge",
        "IDK",
        "Extended penta verification",
        "Very high security, extended verification points",
    ),
    PatternDefinition(
        [88],
        "IDK-Full",
        "IDK",
        "Complete fingerprint",
        "Maximum security, full hash preservation",
    ),
    # Special patterns
    PatternDefinition(
        [20],
        "Monolith-20",
        "Monolithic",
        "Single massive",
        "Maximum single-segment security",
    ),
    PatternDefinition(
        [1, 1, 1, 1, 1],
        "Minimal-1x5",
        "Experimental",
        "Minimal distributed",
        "Extreme compression test",
    ),
]


def get_pattern_by_name(name: str) -> Optional[PatternDefinition]:
    """
    Get pattern definition by name.

    Args:
        name: Pattern name (e.g., "IDK-Medium", "Fibonacci")

    Returns:
        PatternDefinition if found, None otherwise
    """
    for pattern_def in COMPREHENSIVE_PATTERNS:
        if pattern_def.name == name:
            return pattern_def
    return None


def find_patterns_by_category(category: str) -> List[PatternDefinition]:
    """
    Find all patterns in a specific category.

    Args:
        category: Category name (e.g., "IDK", "Mathematical", "Ultra-compact")

    Returns:
        List of PatternDefinition objects in the category
    """
    return [p for p in COMPREHENSIVE_PATTERNS if p.category == category]


def get_available_categories() -> List[str]:
    """
    Get list of all available pattern categories.

    Returns:
        Sorted list of unique category names
    """
    categories = set(p.category for p in COMPREHENSIVE_PATTERNS)
    return sorted(categories)


def generate_nchar_patterns(n: int) -> List[List[int]]:
    """
    Generate all patterns that sum to n characters.

    This generates all integer partitions of n, useful for finding
    patterns with specific total character counts.

    Args:
        n: Total number of characters

    Returns:
        List of patterns (each pattern is a list of integers)

    Example:
        >>> generate_nchar_patterns(4)
        [[4], [3, 1], [2, 2], [2, 1, 1], [1, 1, 1, 1]]
    """

    def generate_partitions(n: int, max_val: Optional[int] = None) -> List[List[int]]:
        """Generate all integer partitions of n."""
        if max_val is None:
            max_val = n

        if n == 0:
            return [[]]

        partitions = []
        for i in range(min(max_val, n), 0, -1):
            for partition in generate_partitions(n - i, i):
                partitions.append([i] + partition)

        return partitions

    return generate_partitions(n)


def analyze_pattern_metrics(pattern: List[int]) -> Dict[str, float]:
    """
    Analyze basic metrics for a pattern.

    Args:
        pattern: List of segment lengths

    Returns:
        Dictionary with pattern metrics:
        - total_chars: Total characters in pattern
        - display_length: Length including separators
        - segment_count: Number of segments
        - avg_segment_length: Average segment length
        - min_segment_length: Minimum segment length
        - max_segment_length: Maximum segment length
    """
    if not pattern:
        return {
            "total_chars": 0,
            "display_length": 0,
            "segment_count": 0,
            "avg_segment_length": 0,
            "min_segment_length": 0,
            "max_segment_length": 0,
        }

    total_chars = sum(pattern)
    display_length = total_chars + len(pattern) - 1  # Add separators
    segment_count = len(pattern)
    avg_segment_length = total_chars / segment_count
    min_segment_length = min(pattern)
    max_segment_length = max(pattern)

    return {
        "total_chars": total_chars,
        "display_length": display_length,
        "segment_count": segment_count,
        "avg_segment_length": avg_segment_length,
        "min_segment_length": min_segment_length,
        "max_segment_length": max_segment_length,
    }
