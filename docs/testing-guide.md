# Textual TUI Testing Guide

This guide provides best practices for testing Textual TUI applications, based on official documentation and industry standards.

## Table of Contents

1. [Testing Philosophy](#testing-philosophy)
2. [Test Structure](#test-structure)
3. [Best Practices](#best-practices)
4. [Common Patterns](#common-patterns)
5. [Anti-Patterns to Avoid](#anti-patterns-to-avoid)
6. [Examples](#examples)

## Testing Philosophy

### Core Principles

1. **Tests should be atomic** - Each test should focus on a single concern
2. **Tests should be independent** - No test should depend on another
3. **Tests should be fast** - TUI tests should complete in under 30 seconds
4. **Tests should be reliable** - Aim for 99%+ pass rate
5. **Tests should provide clear feedback** - Failures should be easy to diagnose

### Test Pyramid for TUI Applications

```
    E2E TUI Tests (Few)
         /\
        /  \
   Component Tests (Some)
      /        \
 Unit Tests (Many)
```

## Test Structure

### Recommended Directory Structure

```
tests/
├── conftest.py              # Shared fixtures
├── unit/                    # Unit tests
├── integration/             # Integration tests
├── tui/                     # TUI-specific tests
│   ├── test_app.py         # Main app tests
│   ├── test_screens.py     # Screen tests
│   └── test_widgets.py     # Widget tests
└── __init__.py
```

### Test Class Organization

```python
class TestAppInitialization:
    """Test app startup and configuration"""
    pass

class TestUserInteractions:
    """Test user input and navigation"""
    pass

class TestErrorHandling:
    """Test error scenarios and edge cases"""
    pass
```

## Best Practices

### 1. Use Correct Testing Approach for Your Textual Version

**For Textual 3.5.0 and similar versions:**

```python
async def test_app_loads(self):
    """Test that the app loads correctly"""
    app = MyApp()
    async with app.run_test() as pilot:
        await pilot.pause()  # Wait for app to fully load
        assert pilot.app.is_running
```

**For newer Textual versions (with textual.testing):**

```python
from textual.testing import AppTest

async def test_app_loads(self):
    """Test that the app loads correctly"""
    async with AppTest(MyApp) as pilot:
        await pilot.pause()  # Wait for app to fully load
        assert pilot.app.is_running
```

### 2. Always Use pilot.pause()

Use `await pilot.pause()` to ensure the app has fully processed all events:

```python
async def test_key_press(self):
    app = MyApp()
    async with app.run_test() as pilot:
        await pilot.pause()
        
        await pilot.press("f1")
        await pilot.pause()  # Wait for key processing
        
        # Now check the result
        assert some_condition
```

### 3. Test User Interactions, Not Implementation

Focus on what users do, not how it's implemented:

```python
# Good - tests user behavior
async def test_user_can_navigate_to_settings(self):
    app = MyApp()
    async with app.run_test() as pilot:
        await pilot.pause()
        await pilot.press("f2")  # Settings hotkey
        await pilot.pause()
        
        settings_screen = pilot.app.query_one("#settings")
        assert settings_screen.has_class("active")

# Bad - tests implementation details
async def test_settings_widget_exists(self):
    app = MyApp()
    assert hasattr(app, "_settings_widget")
```

### 4. Use Descriptive Test Names

Test names should clearly describe what is being tested:

```python
# Good
async def test_user_can_encrypt_file_with_quantum_resistant_algorithm(self):
    pass

# Bad
async def test_encryption(self):
    pass
```

### 5. Proper Error Handling Tests

Test both success and failure scenarios:

```python
async def test_app_handles_invalid_identity_file(self):
    """Test app gracefully handles corrupted identity files"""
    app = MyApp(identity_path="/invalid/path.json")
    
    async with app.run_test() as pilot:
        await pilot.pause()
        
        # App should display error but not crash
        assert pilot.app.is_running
        error_display = pilot.app.query_one("#error-message")
        assert "Invalid identity file" in error_display.renderable
```

## Common Patterns

### 1. Screen Navigation Testing

```python
async def test_screen_navigation(self):
    """Test navigating between different screens"""
    app = MyApp()
    async with app.run_test() as pilot:
        await pilot.pause()
        
        # Test each navigation method
        screens_to_test = [
            ("f1", "#dashboard"),
            ("f2", "#identity"), 
            ("f3", "#crypto"),
        ]
        
        for key, screen_id in screens_to_test:
            await pilot.press(key)
            await pilot.pause()
            
            screen = pilot.app.query_one(screen_id)
            assert screen is not None
```

### 2. Input Validation Testing

```python
async def test_password_input_validation(self):
    """Test password field validates input correctly"""
    app = MyApp()
    async with app.run_test() as pilot:
        await pilot.pause()
        
        # Navigate to password input
        password_input = pilot.app.query_one("#password-input")
        
        # Test invalid password
        await pilot.click(password_input)
        await pilot.type("weak")
        await pilot.press("enter")
        await pilot.pause()
        
        error_msg = pilot.app.query_one("#password-error")
        assert "Password too weak" in str(error_msg.renderable)
```

### 3. State Persistence Testing

```python
async def test_app_state_persists_across_navigation(self):
    """Test that app state is maintained when navigating"""
    app = MyApp()
    async with app.run_test() as pilot:
        await pilot.pause()
        
        # Set some state
        pilot.app.current_identity = "/test/identity.json"
        
        # Navigate to different screen
        await pilot.press("f2")
        await pilot.pause()
        
        # Return to original screen
        await pilot.press("f1")
        await pilot.pause()
        
        # State should persist
        assert pilot.app.current_identity == "/test/identity.json"
```

### 4. Performance Testing

```python
async def test_app_loads_within_reasonable_time(self):
    """Test that app loads within acceptable timeframe"""
    import time
    
    start_time = time.time()
    
    app = MyApp()
    async with app.run_test() as pilot:
        await pilot.pause()
        
    load_time = time.time() - start_time
    assert load_time < 2.0, f"App took {load_time:.2f}s to load"
```

## Anti-Patterns to Avoid

### 1. Don't Test Implementation Details

```python
# BAD - testing internal structure
def test_app_has_correct_widgets(self):
    app = MyApp()
    assert len(app._widgets) == 5
    assert isinstance(app._header, Header)

# GOOD - testing user-visible behavior
async def test_app_displays_header(self):
    app = MyApp()
    async with app.run_test() as pilot:
        await pilot.pause()
        header = pilot.app.query_one("Header")
        assert header is not None
```

### 2. Don't Chain Tests Together

```python
# BAD - tests depend on each other
class TestUserWorkflow:
    async def test_01_user_logs_in(self):
        # login logic
        self.user_logged_in = True
    
    async def test_02_user_creates_identity(self):
        assert self.user_logged_in  # Depends on previous test
        # create identity logic

# GOOD - each test is independent
class TestUserWorkflow:
    async def test_user_can_login(self):
        # Complete login test with setup
        pass
    
    async def test_user_can_create_identity(self):
        # Complete identity creation test with setup
        pass
```

### 3. Don't Use Hard-Coded Waits

```python
# BAD - arbitrary waits
async def test_slow_operation(self):
    app = MyApp()
    async with app.run_test() as pilot:
        await pilot.press("f1")
        await asyncio.sleep(5)  # Hard-coded wait
        # check result

# GOOD - use pilot.pause() or proper waiting
async def test_slow_operation(self):
    app = MyApp()
    async with app.run_test() as pilot:
        await pilot.press("f1")
        await pilot.pause()  # Wait for processing
        # check result
```

### 4. Don't Ignore Test Failures

```python
# BAD - masking failures
async def test_unreliable_feature(self):
    try:
        app = MyApp()
        async with app.run_test() as pilot:
            # test logic that sometimes fails
            pass
    except Exception:
        pytest.skip("Test is flaky")  # Don't do this!

# GOOD - fix the root cause or improve the test
async def test_reliable_feature(self):
    app = MyApp()
    async with app.run_test() as pilot:
        await pilot.pause()  # Ensure proper synchronization
        # reliable test logic
```

## Examples

### Complete Test Example

```python
import pytest
from src.tui.app import DCypherTUI


class TestDCypherTUINavigation:
    """Test navigation functionality in the TUI"""
    
    async def test_user_can_access_all_main_screens(self):
        """Test that user can navigate to all main application screens"""
        app = DCypherTUI()
        async with app.run_test() as pilot:
            await pilot.pause()
            
            # Define screen navigation tests
            navigation_tests = [
                {
                    "key": "f1",
                    "screen_id": "#dashboard",
                    "description": "Dashboard screen"
                },
                {
                    "key": "f2", 
                    "screen_id": "#identity",
                    "description": "Identity management screen"
                },
                {
                    "key": "f3",
                    "screen_id": "#crypto", 
                    "description": "Cryptography screen"
                }
            ]
            
            for test_case in navigation_tests:
                await pilot.press(test_case["key"])
                await pilot.pause()
                
                screen = pilot.app.query_one(test_case["screen_id"])
                assert screen is not None, f"Could not find {test_case['description']}"
                
                # Verify screen is active/visible
                assert screen.has_class("active") or screen.display, \
                    f"{test_case['description']} is not active"
    
    async def test_help_screen_displays_correct_keybindings(self):
        """Test that help screen shows all available keybindings"""
        app = DCypherTUI()
        async with app.run_test() as pilot:
            await pilot.pause()
            
            # Open help screen
            await pilot.press("f12")
            await pilot.pause()
            
            help_content = pilot.app.query_one("#help-content")
            help_text = str(help_content.renderable)
            
            # Verify key bindings are displayed
            expected_bindings = ["F1: Dashboard", "F2: Identity", "F12: Help"]
            for binding in expected_bindings:
                assert binding in help_text, f"Missing binding: {binding}"
    
    @pytest.mark.parametrize("invalid_key", ["f13", "ctrl+z", "alt+x"])
    async def test_invalid_keys_dont_crash_app(self, invalid_key):
        """Test that pressing invalid keys doesn't crash the application"""
        app = DCypherTUI()
        async with app.run_test() as pilot:
            await pilot.pause()
            
            # Press invalid key
            await pilot.press(invalid_key)
            await pilot.pause()
            
            # App should still be running
            assert pilot.app.is_running
```

### Mock Data Testing

```python
@pytest.fixture
def mock_identity_data():
    """Provide mock identity data for testing"""
    return {
        "mnemonic": "test word list here",
        "version": "1.0",
        "derivable": True,
        "auth_keys": {
            "classic": {
                "sk_hex": "abcd1234",
                "pk_hex": "efgh5678"
            }
        }
    }

async def test_identity_screen_loads_mock_data(self, mock_identity_data, tmp_path):
    """Test identity screen with mock data"""
    # Create temporary identity file
    identity_file = tmp_path / "test_identity.json"
    identity_file.write_text(json.dumps(mock_identity_data))
    
    # Test with mock data
    app = DCypherTUI(identity_path=str(identity_file))
    async with app.run_test() as pilot:
        await pilot.pause()
        
        # Navigate to identity screen
        await pilot.press("f2")
        await pilot.pause()
        
        # Verify identity is loaded
        identity_display = pilot.app.query_one("#identity-display")
        assert "test word list here" in str(identity_display.renderable)
```

## Configuration

### pytest.ini Configuration

```ini
[tool:pytest]
asyncio_mode = auto
testpaths = tests
python_files = test_*.py
python_classes = Test*
python_functions = test_*
addopts = 
    --strict-markers
    --verbose
    --tb=short
markers =
    slow: marks tests as slow
    integration: marks tests as integration tests
    tui: marks tests as TUI tests
```

### Test Dependencies

Add these to your `requirements-dev.txt`:

```txt
pytest>=7.0.0
pytest-asyncio>=0.21.0
pytest-cov>=4.0.0
pytest-mock>=3.10.0
textual[dev]>=3.5.0
```

## Version-Specific Notes

### Textual 3.5.0 and Earlier

- Use `app.run_test()` directly from app instance
- No separate `textual.testing` module
- Import pilot functionality from `textual.pilot` for type hints

### Textual 4.0+ (Future Versions)

- May include `textual.testing.AppTest` class
- Check official documentation for latest patterns

## Conclusion

Following these practices will help you create reliable, maintainable tests for your Textual TUI applications. Remember:

1. **Keep tests atomic and independent**
2. **Use async/await properly**
3. **Test user behavior, not implementation**
4. **Handle errors gracefully**
5. **Aim for high reliability (99%+ pass rate)**
6. **Use the correct testing approach for your Textual version**

Good tests will save you time in the long run by catching regressions early and providing confidence when refactoring or adding new features.
