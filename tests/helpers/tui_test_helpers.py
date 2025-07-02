"""
TUI Test Helpers

Consolidated helpers for TUI end-to-end testing across the dCypher application.
Combines conditional waiting patterns (inspired by XCUITest/Selenium) with
manual trigger fallbacks for reliable TUI testing.

FUNCTIONALITY:
- Conditional waiting classes for reliable element interaction
- TUI navigation and interaction helpers
- Identity and account creation workflows
- File operation helpers
- Manual trigger fallbacks for TUI event timing issues
- Common test setup and teardown patterns
"""

import asyncio
import json
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, Optional

import pytest

from src.tui.app import DCypherTUI


# =============================================================================
# CONDITIONAL WAITING CLASSES (inspired by XCUITest and Selenium patterns)
# =============================================================================


class WaitCondition:
    """Base class for wait conditions - inspired by XCUITest patterns"""

    def __init__(self, timeout: float = 30.0):
        self.timeout = timeout

    async def check(self, pilot: Any) -> bool:
        """Override in subclasses to implement specific condition check"""
        raise NotImplementedError

    async def wait_until(self, pilot: Any) -> bool:
        """Wait until condition is met or timeout occurs"""
        start_time = time.time()
        while time.time() - start_time < self.timeout:
            try:
                if await self.check(pilot):
                    return True
            except Exception:
                # Continue waiting if check fails
                pass
            await asyncio.sleep(0.1)  # Small delay between checks
        return False


class ElementExists(WaitCondition):
    """Wait for element to exist - like XCUITest waitForExistence"""

    def __init__(self, selector: str, timeout: float = 30.0):
        super().__init__(timeout)
        self.selector = selector

    async def check(self, pilot: Any) -> bool:
        try:
            element = pilot.app.query_one(self.selector)
            return element is not None
        except Exception:
            return False


class ElementHittable(WaitCondition):
    """Wait for element to be interactable - like XCUITest waitForElementToBecomeHittable"""

    def __init__(self, selector: str, timeout: float = 30.0):
        super().__init__(timeout)
        self.selector = selector

    async def check(self, pilot: Any) -> bool:
        try:
            element = pilot.app.query_one(self.selector)
            return element is not None and not element.disabled and element.display
        except Exception:
            return False


class TextPresent(WaitCondition):
    """Wait for specific text to appear in element - like Selenium text_to_be_present_in_element"""

    def __init__(self, selector: str, text: str, timeout: float = 30.0):
        super().__init__(timeout)
        self.selector = selector
        self.text = text

    async def check(self, pilot: Any) -> bool:
        try:
            element = pilot.app.query_one(self.selector)
            element_text = ""

            # Try different ways to get text content
            if hasattr(element, "renderable") and getattr(element, "renderable", None):
                element_text = str(getattr(element, "renderable"))
            elif hasattr(element, "label") and getattr(element, "label", None):
                element_text = str(getattr(element, "label"))
            elif hasattr(element, "value") and getattr(element, "value", None):
                element_text = str(getattr(element, "value"))

            return self.text in element_text
        except Exception:
            return False


# =============================================================================
# TUI INTERACTION HELPERS WITH CONDITIONAL WAITING
# =============================================================================


async def wait_and_click(pilot: Any, selector: str, timeout: float = 30.0) -> bool:
    """
    Wait for element to be clickable, then click it.
    Includes retry logic and alternative click methods.
    """
    condition = ElementHittable(selector, timeout)
    if await condition.wait_until(pilot):
        try:
            # Try to scroll element into view first
            element = pilot.app.query_one(selector)
            if hasattr(element, "scroll_visible"):
                element.scroll_visible()

            await pilot.click(selector)
            return True
        except Exception as e:
            print(f"⚠️  Click failed for {selector}: {e}")
            # Try alternative approach - send key events if it's a button
            try:
                element = pilot.app.query_one(selector)
                if hasattr(element, "focus"):
                    element.focus()
                    await pilot.press("enter")
                    return True
            except Exception as e2:
                print(f"⚠️  Alternative click failed for {selector}: {e2}")
    return False


async def wait_and_fill(
    pilot: Any, selector: str, text: str, timeout: float = 30.0
) -> bool:
    """Wait for input field to be available, then fill it"""
    condition = ElementHittable(selector, timeout)
    if await condition.wait_until(pilot):
        input_field = pilot.app.query_one(selector)
        if hasattr(input_field, "value"):
            setattr(input_field, "value", text)
        return True
    return False


async def navigate_to_tab(pilot: Any, tab_number: int, timeout: float = 30.0) -> bool:
    """Navigate to a specific tab by number (1-6)"""
    tab_id = f"#--content-tab-tab-{tab_number}"
    return await wait_and_click(pilot, tab_id, timeout)


async def manual_trigger_action(
    pilot: Any, screen_selector: str, action_name: str
) -> bool:
    """
    Manual trigger fallback for TUI actions when button clicks fail.
    This addresses TUI event timing issues in test frameworks.
    """
    try:
        screen = pilot.app.query_one(screen_selector)
        if hasattr(screen, action_name):
            action_method = getattr(screen, action_name)
            action_method()
            return True
        else:
            print(f"   ❌ {action_name} method not found on {screen_selector}")
            return False
    except Exception as e:
        print(f"   ❌ Manual trigger failed: {e}")
        return False


class OperationComplete(WaitCondition):
    """Wait for an operation to complete by checking for result indicators"""

    def __init__(self, result_check_fn, timeout: float = 30.0):
        super().__init__(timeout)
        self.result_check_fn = result_check_fn

    async def check(self, pilot: Any) -> bool:
        try:
            return self.result_check_fn()
        except Exception:
            return False


class FileExists(WaitCondition):
    """Wait for a file to exist on the filesystem"""

    def __init__(self, file_path: Path, timeout: float = 30.0):
        super().__init__(timeout)
        self.file_path = file_path

    async def check(self, pilot: Any) -> bool:
        return self.file_path.exists()


# =============================================================================
# IDENTITY AND ACCOUNT WORKFLOW HELPERS
# =============================================================================


async def create_identity_via_tui(
    pilot: Any,
    identity_name: str,
    storage_path: Path,
    api_base_url: str,
    use_manual_fallback: bool = True,
) -> Optional[Path]:
    """
    Create identity through TUI with conditional waiting instead of fixed delays.
    Returns path to created identity file if successful.
    """
    print(f"🆔 Creating identity '{identity_name}' via TUI...")

    # Navigate to Identity tab
    if not await navigate_to_tab(pilot, 2):  # Tab 2 = Identity
        print("   ❌ Failed to navigate to Identity tab")
        return None

    # Fill identity form
    if not await wait_and_fill(pilot, "#new-identity-name", identity_name):
        print("   ❌ Failed to fill identity name")
        return None

    if not await wait_and_fill(pilot, "#new-identity-path", str(storage_path)):
        print("   ❌ Failed to fill storage path")
        return None

    # Try button click first
    expected_file = storage_path / f"{identity_name}.json"
    button_success = await wait_and_click(pilot, "#create-identity-btn")

    if button_success:
        # Wait for file to exist instead of fixed delay
        file_created = FileExists(expected_file, timeout=30.0)
        if await file_created.wait_until(pilot):
            print("   ✅ Identity created successfully via TUI!")
            return expected_file

    if use_manual_fallback:
        print("   🔧 Button click failed, trying manual trigger...")
        manual_success = await manual_trigger_action(
            pilot, "#identity", "action_create_identity"
        )

        if manual_success:
            # Wait for file to exist instead of fixed delay
            file_created = FileExists(expected_file, timeout=30.0)
            if await file_created.wait_until(pilot):
                print("   ✅ Manual trigger worked! Identity created.")
                return expected_file

    print("   ❌ Identity creation failed")
    return None


async def create_account_via_tui(
    pilot: Any, identity_path: Path, api_base_url: str
) -> bool:
    """Create account through TUI with conditional waiting"""
    print("👤 Creating account via TUI...")

    # Navigate to Accounts tab
    if not await navigate_to_tab(pilot, 4):  # Tab 4 = Accounts
        print("   ❌ Failed to navigate to Accounts tab")
        return False

    # Set identity and API URL
    if not await wait_and_fill(pilot, "#identity-path-input", str(identity_path)):
        print("   ❌ Failed to set identity path")
        return False

    if not await wait_and_fill(pilot, "#api-url-input", api_base_url):
        print("   ❌ Failed to set API URL")
        return False

    # Set identity
    if not await wait_and_click(pilot, "#set-identity-btn"):
        print("   ❌ Failed to set identity")
        return False

    # Create account
    if not await wait_and_click(pilot, "#create-account-btn"):
        print("   ❌ Failed to create account")
        return False

    print("   ✅ Account creation initiated")
    return True


async def upload_file_via_tui(
    pilot: Any, file_path: Path, identity_path: Path, api_base_url: str
) -> bool:
    """Upload file through TUI with conditional waiting"""
    print("📤 Uploading file via TUI...")

    # Navigate to Files tab
    if not await navigate_to_tab(pilot, 5):  # Tab 5 = Files
        print("   ❌ Failed to navigate to Files tab")
        return False

    # Set identity and API URL
    if not await wait_and_fill(pilot, "#identity-path-input", str(identity_path)):
        print("   ❌ Failed to set identity path")
        return False

    if not await wait_and_fill(pilot, "#api-url-input", api_base_url):
        print("   ❌ Failed to set API URL")
        return False

    # Set identity
    if not await wait_and_click(pilot, "#set-identity-btn"):
        print("   ❌ Failed to set identity")
        return False

    # Set file path
    if not await wait_and_fill(pilot, "#file-path-input", str(file_path)):
        print("   ❌ Failed to set file path")
        return False

    # Upload file
    if not await wait_and_click(pilot, "#upload-file-btn"):
        print("   ❌ Failed to upload file")
        return False

    print("   ✅ File upload initiated")
    return True


async def wait_for_tui_ready(pilot: Any, timeout: float = 30.0) -> bool:
    """Wait for TUI to be fully loaded and ready"""
    main_ready = ElementExists("#main-container", timeout)
    tabs_ready = ElementExists("#main-tabs", timeout)

    return await main_ready.wait_until(pilot) and await tabs_ready.wait_until(pilot)


async def wait_for_tab_content(
    pilot: Any, tab_number: int, timeout: float = 30.0
) -> bool:
    """Wait for specific tab content to be loaded and visible"""
    tab_content_map = {
        1: "#dashboard",
        2: "#identity",
        3: "#crypto",
        4: "#accounts",
        5: "#files",
        6: "#sharing",
    }

    if tab_number not in tab_content_map:
        return False

    content_selector = tab_content_map[tab_number]
    content_ready = ElementExists(content_selector, timeout)
    return await content_ready.wait_until(pilot)


# =============================================================================
# TEST SETUP AND VALIDATION HELPERS
# =============================================================================


def create_test_file(file_path: Path, content: str) -> None:
    """Create a test file with given content"""
    file_path.write_text(content)


def validate_identity_file(identity_path: Path) -> bool:
    """Validate that an identity file has the correct structure"""
    if not identity_path.exists():
        return False

    try:
        with open(identity_path, "r") as f:
            identity_data = json.load(f)

        required_keys = ["mnemonic", "auth_keys"]
        return all(key in identity_data for key in required_keys)
    except Exception:
        return False


def get_recommended_viewport_size() -> tuple[int, int]:
    """Get recommended viewport size for TUI testing to avoid OutOfBounds errors"""
    return (120, 40)  # Modern terminal size that works well


async def setup_fresh_tui_app(api_base_url: str) -> DCypherTUI:
    """Setup a fresh TUI app instance for testing"""
    return DCypherTUI(api_url=api_base_url)


# =============================================================================
# COMMON TEST PATTERNS
# =============================================================================


async def complete_fresh_user_workflow(
    pilot: Any,
    identity_name: str,
    storage_path: Path,
    api_base_url: str,
    test_file_content: str = "Test file content",
) -> Dict[str, Any]:
    """
    Complete fresh user workflow with conditional waiting instead of fixed delays.
    Returns results dictionary with success status and file paths.
    """
    results: Dict[str, Any] = {
        "identity_created": False,
        "account_created": False,
        "file_uploaded": False,
        "identity_path": None,
        "test_file_path": None,
    }

    # Wait for TUI to be ready first
    if not await wait_for_tui_ready(pilot):
        print("❌ TUI failed to load properly")
        return results

    # Step 1: Create identity
    identity_path = await create_identity_via_tui(
        pilot, identity_name, storage_path, api_base_url
    )
    if identity_path:
        results["identity_created"] = True
        results["identity_path"] = identity_path
    else:
        return results

    # Step 2: Create account
    account_success = await create_account_via_tui(pilot, identity_path, api_base_url)
    results["account_created"] = account_success

    if not account_success:
        return results

    # Step 3: Upload test file
    test_file = storage_path / "test_upload.txt"
    create_test_file(test_file, test_file_content)
    results["test_file_path"] = test_file

    file_success = await upload_file_via_tui(
        pilot, test_file, identity_path, api_base_url
    )
    results["file_uploaded"] = file_success

    return results


# =============================================================================
# PYTEST FIXTURES
# =============================================================================


@pytest.fixture
def tui_viewport_size():
    """Recommended viewport size for TUI testing"""
    return get_recommended_viewport_size()


@pytest.fixture
async def fresh_tui_app(api_base_url: str):
    """Fresh TUI app instance for testing"""
    return setup_fresh_tui_app(api_base_url)


@pytest.fixture
def test_identity_name():
    """Default test identity name"""
    return "test_user_identity"


@pytest.fixture
def test_file_content():
    """Default test file content"""
    return "This is test content for TUI file operations."
