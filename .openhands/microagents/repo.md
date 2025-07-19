---
description: DCypher OSS project guidelines, architecture, development workflow, and implementation details for quantum-resistant cryptographic operations
globs: ["**/*"]
alwaysApply: true
---

# Important Instructions

VERY IMPORTANT: Activate your OODA loop to complete the task at hand and verbally summarize your OODA loop contents and intentions out loud in a message before each action you take, this will help you function better and coordinate with your team. This is a complicated project and we need our team coordination to be top-notch. This repo contains cutting edge implementations, and some of the methods might be novel, so make sure to reason thoroughly from first principles, and draw from cross-domain experience. Use your tools when strategizing a plan of action to complete the goal, make small targeted changes, and make sure the tests make sense for the goal and that they pass. We work better as a team if we're summarizing our thoughts and plans out loud in a way that is easy to understand and follow. No emojis allowed in the codebase due to compatibility.

Prompt Analysis: Before coding, analyze user prompt for clarity. If ambiguous, infer intent via chain-of-thought (CoT) reasoning, and use your tools to gather information about the local codebase.
Step-by-Step Planning: Break tasks into steps: (a) Understand requirements, (b) Plan structure/symbols, (c) Generate code, (d) Simulate execution mentally.
Multi-Agent Simulation: Emulate agents: Analyst (review logic/errors), Coder (write code), Tester (check edge cases via pseudocode tests and reasoning).
Self-Debugging: After generation, verify with runtime simulation (e.g., mental trace for syntax/semantics). Fix hallucinations using compiler-like feedback.
Quality Alignment: Prioritize readability, efficiency, standards compliance. Use RLHF-style self-critique: Rate code (1-10) on accuracy/reliability; iterate if it rates below 8.
Error Handling: Include robust checks, comments explaining choices. Avoid specialized domains without context; suggest human review if uncertain.
Output Format: Provide code with explanations, tests, potential fixes. Keep it focused if not simple; focus on executable, correct Python/other as specified.

## DCypher OSS Project Overview

This repository contains the reference docs and specification code for DCypher, a quantum-resistant recryption proxy, PKI, and cryptosystem that enables private, shareable, revocable cloud storage, messaging, etc. using proxy recryption (PRE) and other Fully Homomorphic Encryption (FHE) techniques. It has a Python backend (in the `src/` directory) with FastAPI routers, CLI interface, and cryptographic modules.

## Running DCypher with OpenHands

IMPORTANT: Before making any changes to the codebase, ALWAYS ensure proper code quality by running linting and formatting.

Before pushing any changes, you MUST ensure that any lint errors or simple test errors have been fixed.

* If you've made changes to the backend, you should run `just lint` and `just format` and `just typecheck`
* The linting MUST pass successfully before pushing any changes to the repository. This is a mandatory requirement to maintain code quality and consistency.

If either command fails, it may have automatically fixed some issues. You should fix any issues that weren't automatically fixed,
then re-run the command to ensure it passes. Common issues include:

* Ruff formatting issues
* Trailing whitespace
* Missing newlines at end of files
* Import ordering

## Repository Structure

### DO NOT Modify These Directories

* `vendor/` - Contains git submodules for external cryptography libraries (OpenFHE, liboqs, etc.)
* `build/` - Local build artifacts
* Build cache directories (`.pytest_cache/`, `__pycache__/`, etc.)
* `htmlcov/` - Coverage report output
* `profiling_output/` - Performance profiling data

### Backend

* Located in the `src/` directory

* Main modules:
  * `src/dcypher/` - Core Python package
  * `src/dcypher/cli/` - Command-line interface
  * `src/dcypher/crypto/` - Cryptography modules
  * `src/dcypher/lib/` - Core library code
  * `src/dcypher/routers/` - FastAPI routers
  * `src/dcypher/tui/` - Terminal user interface
* Testing:
  * All tests are in `tests/unit/test_*.py` and `tests/integration/test_*.py`
  * To test new code, run `just pytest tests/unit/test_xxx.py` where `xxx` is the appropriate file for the current functionality
  * Write all tests with pytest
  * There are approximately 544 test functions across 67 test files

### Cryptographic Libraries

* Located in the `vendor/` directory (DO NOT MODIFY)

* `vendor/openfhe-development/` - Fully homomorphic encryption library
* `vendor/liboqs/` - Post-quantum cryptography algorithms
* `vendor/liboqs-python/` - Python bindings for liboqs
* `vendor/openfhe-python/` - Python bindings for OpenFHE

### Development Workflow

#### Running Tests

There are approximately 544 test functions, so you can run them in parallel with `just test`. For more targeted testing, use the `just pytest` command with custom arguments.

```bash
# Parallel test execution (preferred for full test suite)
just test
# or

# Regular test execution
just test-unit

# Integration tests
just test-integration  # Takes a really long time to run

# Run pytest with custom arguments (for specific files, functions, classes, marks, etc.)
just pytest tests/unit/test_hdprint.py                    # Specific test file
just pytest tests/unit/test_api_client.py::TestClass::test_method  # Specific test method
just pytest -k "auth"                                     # Tests matching keyword
just pytest -m "slow"                                     # Tests with specific mark
just pytest --verbose --tb=short                          # Custom pytest options
just pytest -x                                           # Stop on first failure
```

#### Code Quality

```bash
# Lint code
just lint

# Format code
just format

# Type checking (if mypy is configured)
just typecheck
```

### Architecture Notes

1. **Package Management**: Uses `uv` for fast, reliable Python environment management
2. **Task Automation**: Uses `just` (modern Make alternative) for task automation
3. **API Framework**: Built with FastAPI for modern async Python web development
4. **Cryptography**:
   * Uses OpenFHE for fully homomorphic encryption
   * Uses liboqs for post-quantum algorithms (KEMs and digital signatures)
   * Implements proxy recryption (PRE) for secure data sharing
5. **CLI Interface**: Comprehensive command-line interface for all operations
6. **TUI**: Terminal user interface built with textual for interactive usage

### Security Considerations

This project handles cryptographic operations, so please:

* Be careful with key generation and random number usage
* Consider timing attacks and side-channels
* Test cryptographic changes thoroughly
* Understand that OpenFHE operations can be computationally intensive
* Always validate cryptographic parameters and inputs
* Use secure random number generation for all cryptographic operations

### File Organization

```
dcypher/
├── src/                    # Main source code
│   ├── dcypher/           # Core Python package
│   │   ├── cli/           # Command-line interface
│   │   ├── crypto/        # Cryptography modules
│   │   ├── hdprint/       # HDPrint algorithm implementation
│   │   ├── lib/           # Core library code (auth, API client, etc.)
│   │   ├── routers/       # FastAPI routers
│   │   └── tui/           # Terminal user interface
│   ├── ffi/               # Foreign function interface (C++ bindings)
│   └── wrapper/           # OpenFHE wrapper code
├── tests/                 # Test suite
│   ├── unit/              # Unit tests
│   ├── integration/       # Integration tests
│   └── tui/               # TUI tests
├── vendor/                # External dependencies (DO NOT MODIFY)
│   ├── openfhe-development/    # OpenFHE library
│   ├── liboqs/                # Post-quantum crypto library
│   ├── liboqs-python/         # Python bindings for liboqs
│   └── openfhe-python/        # Python bindings for OpenFHE
├── docs/                  # Documentation
├── scripts/               # Utility scripts
├── pyproject.toml         # Python project configuration
├── Justfile              # Task definitions
└── config.toml           # OpenHands configuration
```

### Important Concepts

* **Proxy Recryption (PRE)**: Core cryptographic technique that allows recrypting data for different keys without decryption
* **Quantum Resistance**: Uses lattice-based cryptography that's believed to be secure against quantum computers
* **Homomorphic Encryption**: Allows computation on encrypted data using OpenFHE
* **HDPrint with Paiready**: Hierarchical deterministic cryptographic fingerprinting algorithm using HMAC chains with base58 encoding and error-correcting checksums
* **Post-Quantum KEMs**: Key encapsulation mechanisms resistant to quantum attacks
* **Digital Signatures**: Post-quantum signature schemes from liboqs

### Testing Strategy

* **Unit tests**: Focus on individual components and algorithms
* **Integration tests**: Verify end-to-end workflows including cryptographic operations
* **Cryptographic tests**: Verify correctness of encryption, decryption, and key operations
* **Performance tests**: Ensure reasonable execution times for crypto operations
* **API tests**: Test FastAPI endpoints and request/response handling
* **CLI tests**: Verify command-line interface functionality

### Performance Considerations

* Encryption/decryption operations scale with data size
* Consider parallel processing for bulk operations
* Monitor memory usage during large cryptographic operations

## Implementation Details

These details may or may not be useful for your current task.

### Cryptographic Implementation

#### Key Management

* Keys are managed through the `KeyManager` class in `src/dcypher/lib/key_manager.py`

* Supports both classical and post-quantum key types
* Implements secure key generation, storage, and retrieval

#### HDPrint with Paiready Checksum Algorithm

* Located in `src/dcypher/hdprint/`

* Implements secure hash-based data fingerprinting using HMAC-SHA3-512 chains
* Supports collision detection and analysis
* Configurable algorithm parameters with productized size names (tiny, small, medium, rack)
* Base58 encoding for human-readable output
* **Paiready Checksum Integration**: Error correction capabilities with BCH codes
  * Format: `{paiready}_{hdprint}` (e.g., `myzgemb_5ubrZa_T9w1LJRx_hEGmdyaM`)
  * Automatically corrects single-character typos in checksum portion
  * Case-insensitive input - users can type everything in lowercase
  * 7-character base58 lowercase checksum with BCH(t=1,m=7) error correction

#### Post-Quantum Integration

* liboqs integration for KEMs and signatures
* OpenFHE integration for homomorphic encryption
* Wrapper classes provide Python-friendly interfaces

### API Structure

#### FastAPI Routers

* Account management: `src/dcypher/routers/accounts.py`

* Cryptographic operations: `src/dcypher/routers/crypto.py`
* Storage operations: `src/dcypher/routers/storage.py`
* System operations: `src/dcypher/routers/system.py`
* Recryption operations: `src/dcypher/routers/recryption.py`
* Authentication handling in `src/dcypher/lib/auth.py`

#### CLI Commands

* Account operations: `src/dcypher/cli/accounts.py`

* Cryptographic operations: `src/dcypher/cli/crypto.py`
* File operations: `src/dcypher/cli/files.py`
* Identity management: `src/dcypher/cli/identity.py`
* Sharing operations: `src/dcypher/cli/sharing.py`

#### TUI Interface

* Main application: `src/dcypher/tui/app.py`
* Built with Textual framework for modern terminal interfaces
* Cyberpunk-inspired theme with comprehensive screen navigation
* Full feature parity with CLI commands
* Screens for dashboard, identity, crypto, accounts, files, and sharing

### Adding New Cryptographic Algorithms

To add a new cryptographic algorithm to DCypher:

1. **Algorithm Implementation**:
   * Add implementation to appropriate module (e.g., `src/dcypher/crypto/`)
   * Follow existing patterns for parameter validation and error handling
   * Include comprehensive unit tests

2. **CLI Integration**:
   * Add commands to relevant CLI modules
   * Update help text and documentation
   * Add integration tests for CLI functionality

3. **API Integration**:
   * Add endpoints to appropriate FastAPI routers
   * Update request/response models in `src/dcypher/models.py`
   * Add API integration tests

4. **Key Management**:
   * Update `KeyManager` if new key types are needed
   * Add key generation, validation, and storage support
   * Test key lifecycle operations

Remember: This is a security-critical cryptographic system. Always test thoroughly and consider the security implications of any changes. All cryptographic operations should be reviewed for timing attacks, side-channel vulnerabilities, and correct parameter usage.
