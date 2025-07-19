# OpenHands Testing Strategy

## Overview

We maintain a fork of OpenHands with custom modifications (like the Grok empty response fix). To ensure our fork remains compatible with upstream changes, we've implemented a comprehensive testing strategy.

## Testing Infrastructure

### 1. Test Scripts

#### `scripts/test_openhands_fork.sh`

- Tests only our fork-specific modifications
- Currently includes: Grok empty response fix
- Will expand as we add more custom modifications
- Shows verbose test output directly in terminal
- Run with: `just test-openhands-fork`

#### `scripts/test_openhands_suite.sh`

- Runs the full OpenHands test suite
- Ensures our modifications don't break existing functionality
- Includes all unit tests, runtime tests (if available), and E2E tests (if available)
- Shows all test output with `-svv` for maximum visibility
- Run with: `just test-openhands`

### 2. Just Commands

```bash
# Run tests for our fork modifications only
just test-openhands-fork

# Run the full OpenHands test suite
just test-openhands

# Run ALL tests (DCypher + Fork modifications + Full OpenHands)
just test-all
```

### 3. Test Organization

```
just test-all
├── DCypher Unit Tests (tests/unit/)
├── DCypher Integration Tests (tests/integration/)
├── OpenHands Fork Tests (our modifications)
│   └── Grok Empty Response Fix
└── OpenHands Full Test Suite
    ├── Unit Tests (all)
    ├── Runtime Tests (if environment available)
    └── E2E Tests (if environment available)
```

## Continuous Integration

### GitHub Actions Workflow

The `.github/workflows/test-openhands-compatibility.yml` workflow:

1. **Triggers on:**
   - Changes to `vendor/openhands/**`
   - Changes to test scripts
   - Weekly schedule (catch upstream breaking changes)
   - Manual dispatch

2. **Tests:**
   - Fork-specific tests first
   - Full OpenHands test suite
   - All output shown in GitHub Actions logs

## Maintaining Fork Compatibility

### Regular Testing

1. **Before Rebasing**: Run `just test-openhands` to establish baseline
2. **After Rebasing**: Run `just test-openhands` to catch conflicts
3. **Weekly CI**: Automated tests catch upstream changes

### Adding New Fork Modifications

When adding new modifications to OpenHands:

1. Add specific tests to `vendor/openhands/tests/`
2. Update `scripts/test_openhands_fork.sh` to include new tests
3. Document changes in this file
4. Run `just test-all` before committing

### Debugging Failed Tests

If OpenHands tests fail:

1. Look at the test output directly in your terminal
2. Run specific failed test with Poetry:

   ```bash
   cd vendor/openhands
   poetry run pytest tests/unit/test_name.py::specific_test -xvs
   ```

3. Compare with upstream to identify breaking changes

## Test Coverage

### Fork Tests (`test-openhands-fork`)

Tests specific to our modifications:

1. **Grok Empty Response Fix**
   - Non-Grok models preserve original behavior
   - Grok models skip waiting on empty responses
   - Model name variant handling
   - Regression testing on affected files

### Full Suite Tests (`test-openhands`)

Complete OpenHands test coverage:

1. **Unit Tests** - All unit tests with parallel execution (`-n auto`)
2. **Runtime Tests** - Basic runtime functionality (if environment available)
3. **E2E Tests** - End-to-end scenarios (if environment available)

All tests run with `-svv` flags for verbose output showing:

- Test names as they run
- Full assertion details on failures
- Captured stdout/stderr

## Best Practices

1. **Quick validation**: Use `just test-openhands-fork` for rapid feedback
2. **Full validation**: Use `just test-openhands` before major changes
3. **Complete validation**: Use `just test-all` before pushing
4. **Monitor CI results**: Check GitHub Actions for scheduled runs
5. **Document modifications**: Update test scripts when adding new fork changes

## Troubleshooting

### Poetry Not Found

```bash
curl -sSL https://install.python-poetry.org | python3 -
```

### Tests Pass Locally but Fail in CI

- Check Python version (should be 3.12)
- Verify all dependencies in `pyproject.toml`
- Check for missing system dependencies

### Runtime/E2E Tests Fail

These tests require specific environment setup (Docker, etc.). Failures in these tests may not indicate issues with your fork modifications if unit tests pass.

### Merge Conflicts After Rebase

1. Resolve conflicts in modified files
2. Run `just test-openhands-fork` to verify modifications still work
3. Run `just test-openhands` to ensure compatibility
4. Update tests if APIs changed
