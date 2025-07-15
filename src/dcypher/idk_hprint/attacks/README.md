# IDK_HPRINT Cipheranalysis Tools

Comprehensive security analysis and attack demonstration tools for the IDK_HPRINT HMAC-per-character approach.

## Overview

This module provides specialized cipheranalysis tools adapted for the new HMAC-per-character algorithm where each character in the fingerprint comes from a separate HMAC-SHA3-512 operation, taking the last character from the base58 encoding.

## Key Changes from ColCa

- **HMAC-per-character**: Each character generated from separate HMAC operation
- **Last character selection**: Takes last character from base58 encoding instead of first N
- **Character independence**: Each character has independent cryptographic strength
- **HMAC chaining**: Provides strong dependencies between characters

## Modules

### 1. `demonstrations.py`

General attack demonstrations and vulnerability assessments.

**Functions:**

- `demonstrate_pattern_vulnerability()`: Shows risks of weak patterns
- `demonstrate_hmac_per_character_security()`: Analyzes HMAC-per-character security
- `demonstrate_character_bias_analysis()`: Shows base58 bias analysis
- `demonstrate_collision_resistance()`: Tests collision resistance properties
- `run_security_demonstrations()`: Runs all general demonstrations

### 2. `idk_analysis.py`

IDK pattern family specific security analysis.

**Functions:**

- `analyze_idk_pattern_family()`: Comprehensive IDK pattern analysis
- `demonstrate_idk_hmac_benchmarking()`: HMAC-per-character performance benchmarking
- `demonstrate_idk_entropy_analysis()`: Entropy efficiency analysis
- `demonstrate_idk_attack_surface()`: Attack surface assessment
- `run_idk_analysis()`: Complete IDK analysis suite

### 3. `hmac_analysis.py`

HMAC-specific security analysis for the chain approach.

**Functions:**

- `analyze_hmac_chain_security()`: Analyze HMAC chain security properties
- `demonstrate_hmac_chain_attacks()`: Demonstrate potential attack vectors
- `analyze_character_independence()`: Test character independence properties
- `demonstrate_base58_bias_analysis()`: Analyze base58 encoding bias
- `run_hmac_analysis()`: Complete HMAC analysis suite

## Usage Examples

### Quick Start

```python
from dcypher.idk_hprint.attacks import run_idk_analysis

# Run comprehensive IDK pattern analysis
run_idk_analysis()
```

### Individual Demonstrations

```python
from dcypher.idk_hprint.attacks import (
    demonstrate_pattern_vulnerability,
    demonstrate_hmac_per_character_security,
    analyze_hmac_chain_security,
)

# Show pattern vulnerabilities
demonstrate_pattern_vulnerability()

# Analyze HMAC-per-character security
demonstrate_hmac_per_character_security()

# Analyze HMAC chain security
analyze_hmac_chain_security()
```

### Complete Analysis Suite

```python
from dcypher.idk_hprint.attacks import (
    run_security_demonstrations,
    run_idk_analysis,
    run_hmac_analysis,
)

# Run all analysis suites
run_security_demonstrations()
run_idk_analysis()
run_hmac_analysis()
```

### Run Demo Script

```bash
# Run the complete demonstration
uv run python3 -m src.dcypher.idk_hprint.attacks.demo
```

## Security Analysis Features

### Pattern Vulnerability Analysis

- Identifies weak patterns with low security bits
- Shows HMAC operation count per pattern
- Provides security level classification

### HMAC Chain Security

- Analyzes cryptographic strength of HMAC chains
- Tests resistance to various attack vectors
- Validates character independence properties

### Performance Benchmarking

- Measures HMAC operation performance
- Calculates security-to-performance ratios
- Shows linear scaling with pattern complexity

### Entropy Analysis

- Analyzes entropy efficiency across patterns
- Tests base58 character distribution
- Validates uniformity of HMAC output

### Attack Surface Assessment

- Identifies potential attack vectors
- Provides risk assessment for each pattern
- Recommends security mitigations

## Key Findings

**HMAC-per-character provides excellent security guarantees**

- Each character has independent cryptographic strength
- SHA3-512 ensures strong collision resistance
- Base58 last-character selection maintains uniformity

**IDK patterns offer progressive security scaling**

- IDK-Small: 38.1 bits (testing only)
- IDK-Medium: 84.9 bits (acceptable)
- IDK-Large: 131.8 bits (production ready)

**Attack vectors are well-understood and mitigated**

- Brute force: Protected by key length
- Birthday attacks: Only affect first characters
- Preimage attacks: Protected by SHA3-512 strength

## Security Recommendations

1. **Use IDK-Medium ([3,5,8]) or stronger for production**
2. **Employ strong random keys (≥256 bits)**
3. **Regular security audits recommended**
4. **Monitor cryptographic research for new attack techniques**
5. **Consider quantum-resistant alternatives for long-term security**

## Educational Purpose

**Important**: All attack demonstrations are for educational and security analysis purposes only. Use responsibly and only on systems you own or have permission to test.

## Dependencies

- `dcypher.idk_hprint`: Core IDK_HPRINT library
- `based58`: Base58 encoding library
- `hashlib`: SHA3-512 hashing
- `hmac`: HMAC operations
- Standard Python libraries: `math`, `time`, `collections`
