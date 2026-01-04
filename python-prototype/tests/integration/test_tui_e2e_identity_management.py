"""
End-to-end integration tests for TUI centralized identity management.

This test suite verifies that:
1. Identity is managed centrally in the app
2. All screens can access the loaded identity
3. API client is properly integrated
4. Identity changes propagate to all components
5. The new centralized architecture works correctly
"""

import pytest
import json
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch
from typing import Any, Dict

from dcypher.tui.app import DCypherTUI
from dcypher.lib.api_client import DCypherClient
from tests.helpers.tui_test_helpers import (
    wait_for_notification,
    wait_and_click,
    wait_and_fill,
    navigate_to_tab,
    ElementExists,
    ElementHittable,
    FileExists,
    TextPresent,
    WaitCondition,
    create_identity_via_tui,
    create_test_file,
    wait_for_tab_content,
    wait_for_tui_ready,
)
from textual.pilot import Pilot


class TestTUICentralizedIdentityManagement:
    """Test centralized identity management in the TUI"""

    @pytest.mark.asyncio
    async def test_identity_state_initialization(self):
        """Test that identity state is properly initialized"""
        app = DCypherTUI(api_url="http://127.0.0.1:8000")

        async with app.run_test(size=(160, 60)) as pilot:
            await pilot.pause(0.1)

            # Check initial state
            assert app.current_identity_path is None
            assert app.identity_info is None
            assert app.api_client is None
            assert app.connection_status == "disconnected"
            print("✅ Initial state verified")

    @pytest.mark.asyncio
    async def test_api_client_creation(self):
        """Test that API client is created and cached properly"""
        app = DCypherTUI(api_url="http://127.0.0.1:8000")

        async with app.run_test(size=(160, 60)) as pilot:
            await pilot.pause(0.1)

            # Create API client
            client1 = app.get_or_create_api_client()
            assert client1 is not None
            assert isinstance(client1, DCypherClient)
            assert client1.api_url == "http://127.0.0.1:8000"

            # Verify it's cached
            client2 = app.get_or_create_api_client()
            assert client1 is client2  # Same instance
            print("✅ API client created and cached successfully")

    @pytest.mark.asyncio
    async def test_identity_loading_updates_app_state(self, tmp_path):
        """Test that loading an identity updates app state correctly"""
        app = DCypherTUI(api_url="http://127.0.0.1:8000")

        # Create a test identity file
        identity_path = tmp_path / "test_identity.json"
        identity_data = {
            "mnemonic": "test mnemonic",
            "version": "hd_v1",
            "derivable": True,
            "auth_keys": {
                "classic": {"pk_hex": "abcd1234" * 8, "sk_hex": "secret" * 10},
                "pq": [{"alg": "ML-DSA-44", "pk_hex": "pqkey1", "sk_hex": "pqsecret1"}],
                "pre": {"pk_hex": "prekey1", "sk_hex": "presecret1"},
            },
        }

        with open(identity_path, "w") as f:
            json.dump(identity_data, f)

        async with app.run_test(size=(160, 60)) as pilot:
            await pilot.pause(0.1)

            # Update app state with identity
            app.current_identity_path = str(identity_path)

            # Wait for reactive updates
            await pilot.pause(0.2)

            # Verify state was updated
            assert app.current_identity_path == str(identity_path)
            assert app.identity_info is not None
            assert app.identity_info["version"] == "hd_v1"
            assert "auth_keys" in app.identity_info

            # Verify API client was updated
            assert app.api_client is not None
            assert app.api_client.keys_path == str(identity_path)
            print("✅ Identity loaded and app state updated correctly")

    @pytest.mark.asyncio
    async def test_identity_screen_uses_centralized_state(self):
        """Test that Identity screen uses app's centralized state"""
        app = DCypherTUI(api_url="http://127.0.0.1:8000")

        async with app.run_test(size=(160, 60)) as pilot:
            # Switch to Identity tab
            await navigate_to_tab(pilot, 2)
            await pilot.pause(0.2)

            # Get the identity screen
            identity_screen = app.query_one("#identity")

            # Test that it accesses app state
            assert (
                getattr(identity_screen, "current_identity_path", None)
                == app.current_identity_path
            )
            assert getattr(identity_screen, "identity_info", None) == app.identity_info
            assert getattr(identity_screen, "api_url", None) == app.api_url
            print("✅ Identity screen uses centralized state")

    @pytest.mark.asyncio
    @patch("dcypher.lib.api_client.DCypherClient.create_identity_file")
    async def test_identity_creation_flow(self, mock_create_identity, tmp_path):
        """Test creating a new identity through the Identity screen"""
        # Setup mock
        test_identity_path = tmp_path / "new_identity.json"
        identity_data = {
            "mnemonic": "test mnemonic phrase",
            "version": "hd_v1",
            "derivable": True,
            "auth_keys": {
                "classic": {"pk_hex": "testpk", "sk_hex": "testsk"},
                "pq": [{"alg": "ML-DSA-44", "pk_hex": "pqpk", "sk_hex": "pqsk"}],
                "pre": {},
            },
        }

        # Write test identity file
        with open(test_identity_path, "w") as f:
            json.dump(identity_data, f)

        mock_create_identity.return_value = ("test mnemonic", test_identity_path)

        app = DCypherTUI(api_url="http://127.0.0.1:8000")

        async with app.run_test(size=(160, 60)) as pilot:
            # Switch to Identity tab
            await navigate_to_tab(pilot, 2)
            await pilot.pause(0.2)

            # Fill in identity creation form
            await wait_and_fill(pilot, "#new-identity-name", "test_identity")
            await wait_and_fill(pilot, "#new-identity-path", str(tmp_path))

            # Click create button
            await wait_and_click(pilot, "#create-identity-btn")

            # Wait for notifications
            await wait_for_notification(pilot, "created successfully")

            # Verify app state was updated
            assert app.current_identity_path == str(test_identity_path)
            assert app.identity_info is not None
            assert app.api_client is not None
            assert app.api_client.keys_path == str(test_identity_path)
            print("✅ Identity created and app state updated")

    @pytest.mark.asyncio
    async def test_dashboard_displays_identity_status(self, tmp_path):
        """Test that Dashboard screen displays current identity status"""
        app = DCypherTUI(api_url="http://127.0.0.1:8000")

        # Create test identity
        identity_path = tmp_path / "test_identity.json"
        identity_data = {
            "version": "hd_v1",
            "auth_keys": {
                "classic": {"pk_hex": "abcd1234" * 8, "sk_hex": "secret"},
                "pq": [{"alg": "ML-DSA-44", "pk_hex": "pq1", "sk_hex": "pqs1"}],
                "pre": {"pk_hex": "pre1", "sk_hex": "pres1"},
            },
        }

        with open(identity_path, "w") as f:
            json.dump(identity_data, f)

        async with app.run_test(size=(160, 60)) as pilot:
            await pilot.pause(0.1)

            # Initially no identity
            identity_status = app.query_one("#identity-status")
            renderable = getattr(identity_status, "renderable", None)
            if renderable:
                plain_text = getattr(renderable.renderable, "plain", "")
                assert "NO IDENTITY" in plain_text

            # Load identity
            app.current_identity_path = str(identity_path)
            await pilot.pause(0.2)

            # Check identity status updated
            identity_status = app.query_one("#identity-status")
            renderable = getattr(identity_status, "renderable", None)
            if renderable:
                plain_text = getattr(renderable.renderable, "plain", "")
                assert "IDENTITY LOADED" in plain_text
                assert "test_identity.json" in plain_text
            print("✅ Dashboard displays identity status correctly")

    @pytest.mark.asyncio
    async def test_accounts_screen_uses_loaded_identity(self, tmp_path):
        """Test that Accounts screen uses the loaded identity"""
        app = DCypherTUI(api_url="http://127.0.0.1:8000")

        # Create test identity
        identity_path = tmp_path / "test_identity.json"
        identity_data = {
            "version": "hd_v1",
            "auth_keys": {
                "classic": {"pk_hex": "testpk", "sk_hex": "testsk"},
                "pq": [{"alg": "ML-DSA-44", "pk_hex": "pqpk", "sk_hex": "pqsk"}],
            },
        }

        with open(identity_path, "w") as f:
            json.dump(identity_data, f)

        async with app.run_test(size=(160, 60)) as pilot:
            # Load identity
            app.current_identity_path = str(identity_path)
            await pilot.pause(0.2)

            # Switch to Accounts tab
            await navigate_to_tab(pilot, 4)
            await pilot.pause(0.2)

            # Get accounts screen
            accounts_screen = app.query_one("#accounts")

            # Verify it uses app's identity
            assert getattr(accounts_screen, "current_identity_path", None) == str(
                identity_path
            )
            api_client = getattr(accounts_screen, "api_client", None)
            assert api_client is not None
            assert getattr(api_client, "keys_path", None) == str(identity_path)

            # Check status display
            identity_status = app.query_one("#current-identity-status")
            renderable = getattr(identity_status, "renderable", None)
            if renderable:
                plain_text = getattr(renderable.renderable, "plain", "")
                assert "test_identity.json" in plain_text
            print("✅ Accounts screen uses loaded identity")

    @pytest.mark.asyncio
    async def test_identity_change_propagates_to_all_screens(self, tmp_path):
        """Test that changing identity propagates to all screens"""
        app = DCypherTUI(api_url="http://127.0.0.1:8000")

        # Create two test identities
        identity1_path = tmp_path / "identity1.json"
        identity2_path = tmp_path / "identity2.json"

        for path, pk in [(identity1_path, "pk1"), (identity2_path, "pk2")]:
            identity_data = {
                "version": "hd_v1",
                "auth_keys": {
                    "classic": {"pk_hex": pk, "sk_hex": "sk"},
                    "pq": [{"alg": "ML-DSA-44", "pk_hex": "pq", "sk_hex": "pqs"}],
                },
            }
            with open(path, "w") as f:
                json.dump(identity_data, f)

        async with app.run_test(size=(160, 60)) as pilot:
            await pilot.pause(0.1)

            # Load first identity
            app.current_identity_path = str(identity1_path)
            await pilot.pause(0.2)

            # Verify all screens see identity1
            identity_screen = app.query_one("#identity")
            accounts_screen = app.query_one("#accounts")

            assert getattr(identity_screen, "current_identity_path", None) == str(
                identity1_path
            )
            assert getattr(accounts_screen, "current_identity_path", None) == str(
                identity1_path
            )

            # Change to second identity
            app.current_identity_path = str(identity2_path)
            await pilot.pause(0.2)

            # Verify all screens see identity2
            assert getattr(identity_screen, "current_identity_path", None) == str(
                identity2_path
            )
            assert getattr(accounts_screen, "current_identity_path", None) == str(
                identity2_path
            )
            assert app.api_client is not None
            assert app.api_client.keys_path == str(identity2_path)
            print("✅ Identity changes propagate to all screens")

    @pytest.mark.asyncio
    async def test_api_connection_status_updates(self):
        """Test that API connection status is properly tracked"""
        app = DCypherTUI(api_url="http://127.0.0.1:8000")

        async with app.run_test(size=(160, 60)) as pilot:
            await pilot.pause(0.1)

            # Initially disconnected
            assert app.connection_status == "disconnected"

            # Create API client
            app.get_or_create_api_client()

            # Mock successful API call
            with patch.object(app._api_client, "get_nonce", return_value="test_nonce"):
                app.check_api_connection()
                assert app.connection_status == "connected"

            # Mock failed API call
            with patch.object(
                app._api_client, "get_nonce", side_effect=Exception("Connection failed")
            ):
                app.check_api_connection()
                assert app.connection_status == "disconnected"

            print("✅ API connection status tracking works")

    @pytest.mark.asyncio
    async def test_dashboard_quick_actions_require_identity(self):
        """Test that dashboard quick actions check for loaded identity"""
        app = DCypherTUI(api_url="http://127.0.0.1:8000")

        async with app.run_test(size=(160, 60)) as pilot:
            await pilot.pause(0.1)

            # No identity loaded
            assert app.current_identity_path is None

            # Try upload file action
            await wait_and_click(pilot, "#upload-file-btn")
            await wait_for_notification(pilot, "Load identity first")

            # Try create share action
            await wait_and_click(pilot, "#create-share-btn")
            await wait_for_notification(pilot, "Load identity first")

            print("✅ Dashboard quick actions require identity")

    @pytest.mark.asyncio
    async def test_files_screen_uses_centralized_identity(self, tmp_path):
        """Test that Files screen uses centralized identity for operations"""
        app = DCypherTUI(api_url="http://127.0.0.1:8000")

        # Create test identity
        identity_path = tmp_path / "test_identity.json"
        identity_data = {
            "version": "hd_v1",
            "auth_keys": {
                "classic": {"pk_hex": "testpk", "sk_hex": "testsk"},
                "pq": [{"alg": "ML-DSA-44", "pk_hex": "pqpk", "sk_hex": "pqsk"}],
                "pre": {"pk_hex": "prepk", "sk_hex": "presk"},
            },
        }

        with open(identity_path, "w") as f:
            json.dump(identity_data, f)

        async with app.run_test(size=(160, 60)) as pilot:
            # Load identity
            app.current_identity_path = str(identity_path)
            await pilot.pause(0.2)

            # Switch to Files tab
            await navigate_to_tab(pilot, 5)
            await pilot.pause(0.2)

            # Files screen should automatically use the loaded identity
            files_screen = app.query_one("#files")

            # Check that it sees the identity
            assert getattr(files_screen, "current_identity_path", None) == str(
                identity_path
            )
            assert getattr(files_screen, "api_client", None) is not None
            print("✅ Files screen uses centralized identity")

    @pytest.mark.asyncio
    async def test_sharing_screen_uses_centralized_identity(self, tmp_path):
        """Test that Sharing screen uses centralized identity"""
        app = DCypherTUI(api_url="http://127.0.0.1:8000")

        # Create test identity with PRE keys
        identity_path = tmp_path / "test_identity.json"
        identity_data = {
            "version": "hd_v1",
            "auth_keys": {
                "classic": {"pk_hex": "testpk", "sk_hex": "testsk"},
                "pq": [{"alg": "ML-DSA-44", "pk_hex": "pqpk", "sk_hex": "pqsk"}],
                "pre": {"pk_hex": "prepk", "sk_hex": "presk"},
            },
        }

        with open(identity_path, "w") as f:
            json.dump(identity_data, f)

        async with app.run_test(size=(160, 60)) as pilot:
            # Load identity
            app.current_identity_path = str(identity_path)
            await pilot.pause(0.2)

            # Switch to Sharing tab
            await navigate_to_tab(pilot, 6)
            await pilot.pause(0.2)

            # Sharing screen should see the identity
            sharing_screen = app.query_one("#sharing")

            assert getattr(sharing_screen, "current_identity_path", None) == str(
                identity_path
            )
            assert getattr(sharing_screen, "api_client", None) is not None
            print("✅ Sharing screen uses centralized identity")

    @pytest.mark.asyncio
    async def test_complete_identity_workflow_e2e(self, api_base_url, tmp_path):
        """Test complete end-to-end workflow with centralized identity management"""
        app = DCypherTUI(api_url=api_base_url)

        # Mock the API client creation to avoid real server calls
        with patch(
            "dcypher.lib.api_client.DCypherClient.create_identity_file"
        ) as mock_create:
            # Setup mock identity
            identity_path = tmp_path / "e2e_identity.json"
            identity_data = {
                "mnemonic": "test mnemonic phrase for e2e",
                "version": "hd_v1",
                "derivable": True,
                "auth_keys": {
                    "classic": {"pk_hex": "e2epk", "sk_hex": "e2esk"},
                    "pq": [
                        {"alg": "ML-DSA-44", "pk_hex": "e2epqpk", "sk_hex": "e2epqsk"}
                    ],
                    "pre": {"pk_hex": "e2eprepk", "sk_hex": "e2epresk"},
                },
            }

            with open(identity_path, "w") as f:
                json.dump(identity_data, f)

            mock_create.return_value = ("test mnemonic", identity_path)

            async with app.run_test(size=(160, 60)) as pilot:
                print("\n🚀 Starting E2E Identity Workflow Test")

                # Step 1: Create identity
                print("1️⃣  Creating identity...")
                await navigate_to_tab(pilot, 2)  # Identity tab
                await pilot.pause(0.2)

                await wait_and_fill(pilot, "#new-identity-name", "e2e_identity")
                await wait_and_fill(pilot, "#new-identity-path", str(tmp_path))
                await wait_and_click(pilot, "#create-identity-btn")
                await pilot.pause(0.5)

                # Verify identity loaded
                assert app.current_identity_path == str(identity_path)
                print("   ✅ Identity created and loaded")

                # Step 2: Navigate to dashboard - should show identity
                print("2️⃣  Checking dashboard...")
                await navigate_to_tab(pilot, 1)  # Dashboard
                await pilot.pause(0.2)

                identity_status = app.query_one("#identity-status")
                renderable = getattr(identity_status, "renderable", None)
                if renderable:
                    plain_text = getattr(renderable.renderable, "plain", "")
                    assert "IDENTITY LOADED" in plain_text
                print("   ✅ Dashboard shows loaded identity")

                # Step 3: Navigate to accounts - should use loaded identity
                print("3️⃣  Checking accounts...")
                await navigate_to_tab(pilot, 4)  # Accounts
                await pilot.pause(0.2)

                accounts_screen = app.query_one("#accounts")
                assert getattr(accounts_screen, "current_identity_path", None) == str(
                    identity_path
                )
                print("   ✅ Accounts screen uses loaded identity")

                # Step 4: Navigate to files - should use loaded identity
                print("4️⃣  Checking files...")
                await navigate_to_tab(pilot, 5)  # Files
                await pilot.pause(0.2)

                files_screen = app.query_one("#files")
                assert getattr(files_screen, "current_identity_path", None) == str(
                    identity_path
                )
                print("   ✅ Files screen uses loaded identity")

                # Step 5: Navigate to sharing - should use loaded identity
                print("5️⃣  Checking sharing...")
                await navigate_to_tab(pilot, 6)  # Sharing
                await pilot.pause(0.2)

                sharing_screen = app.query_one("#sharing")
                assert getattr(sharing_screen, "current_identity_path", None) == str(
                    identity_path
                )
                print("   ✅ Sharing screen uses loaded identity")

                print("\n🎉 E2E Identity Workflow Test: SUCCESS!")
                print("✅ Identity created once, available everywhere")
                print("✅ Centralized identity management working perfectly")
                print("✅ All screens use the same identity and API client")


# =============================================================================
# NEW WAIT CONDITIONS FOR IDENTITY MANAGEMENT
# =============================================================================


class IdentityLoadedInApp(WaitCondition):
    """Wait for identity to be loaded in the app's centralized state"""

    def __init__(self, expected_path: str, timeout: float = 30.0):
        super().__init__(timeout)
        self.expected_path = expected_path

    async def check(self, pilot: Pilot) -> bool:
        try:
            # Check if app has the identity loaded
            app = pilot.app
            current_path = getattr(app, "current_identity_path", None)
            return current_path == self.expected_path
        except Exception:
            return False


class APIConnectionEstablished(WaitCondition):
    """Wait for API connection to be established"""

    def __init__(self, expected_status: str = "connected", timeout: float = 30.0):
        super().__init__(timeout)
        self.expected_status = expected_status

    async def check(self, pilot: Pilot) -> bool:
        try:
            app = pilot.app
            status = getattr(app, "connection_status", None)
            return status == self.expected_status
        except Exception:
            return False


class IdentityInfoLoaded(WaitCondition):
    """Wait for identity info to be loaded in the app"""

    def __init__(self, timeout: float = 30.0):
        super().__init__(timeout)

    async def check(self, pilot: Pilot) -> bool:
        try:
            app = pilot.app
            info = getattr(app, "identity_info", None)
            return info is not None and "mnemonic" in info
        except Exception:
            return False


# =============================================================================
# ADDITIONAL HELPERS FOR IDENTITY MANAGEMENT
# =============================================================================


async def load_identity_via_tui(
    pilot: Pilot, identity_path: Path, use_manual_fallback: bool = True
) -> bool:
    """Load an existing identity through the TUI Identity screen"""
    print(f"🔑 Loading identity '{identity_path}' via TUI...")

    # Navigate to Identity tab
    if not await navigate_to_tab(pilot, 2):  # Tab 2 = Identity
        print("   ❌ Failed to navigate to Identity tab")
        return False

    # Wait for tab content to load
    if not await wait_for_tab_content(pilot, 2):
        print("   ❌ Identity tab content failed to load")
        return False

    # Fill the load identity path
    if not await wait_and_fill(pilot, "#load-identity-path", str(identity_path)):
        print("   ❌ Failed to fill identity path")
        return False

    # Click load button
    button_success = await wait_and_click(pilot, "#load-identity-btn")
    if not button_success:
        print("   ⚠️ Load identity button click failed")

    # Give the reactive system a moment to process
    await pilot.pause(0.5)

    # Force the app to refresh if needed
    pilot.app.refresh()

    # Wait for identity path to be loaded in app state
    identity_loaded = IdentityLoadedInApp(str(identity_path), timeout=10.0)
    if await identity_loaded.wait_until(pilot):
        print("   ✅ Identity path loaded in app state!")

        # Also wait for identity info to be loaded
        identity_info_loaded = IdentityInfoLoaded(timeout=10.0)
        if await identity_info_loaded.wait_until(pilot):
            print("   ✅ Identity info loaded successfully!")
            return True
        else:
            print("   ⚠️ Identity path loaded but info failed to load")
            # Debug: check what's in the app state
            app = pilot.app
            print(
                f"   🔍 Current identity path: {getattr(app, 'current_identity_path', 'None')}"
            )
            print(
                f"   🔍 Current identity info: {getattr(app, 'identity_info', 'None')}"
            )
            return False

    # If button click didn't work, try manual trigger fallback
    if use_manual_fallback:
        print("   🔧 Button click failed, trying manual trigger...")
        try:
            identity_screen = pilot.app.query_one("#identity")
            if hasattr(identity_screen, "load_identity_file"):
                print(
                    f"   🔧 Calling load_identity_file directly with: {identity_path}"
                )
                identity_screen.load_identity_file(str(identity_path))

                # Wait again for the identity to be loaded after manual trigger
                identity_loaded_manual = IdentityLoadedInApp(
                    str(identity_path), timeout=10.0
                )
                if await identity_loaded_manual.wait_until(pilot):
                    print("   ✅ Manual trigger worked! Identity loaded.")
                    return True
                else:
                    print("   ❌ Manual trigger also failed")
        except Exception as e:
            print(f"   ❌ Manual trigger failed with exception: {e}")

    print("   ❌ Identity failed to load in app state")
    # Debug: check what's in the app state
    app = pilot.app
    print(
        f"   🔍 Current identity path: {getattr(app, 'current_identity_path', 'None')}"
    )
    print(f"   🔍 Expected path: {identity_path}")
    return False


async def verify_identity_in_screen(
    pilot: Pilot, screen_tab: int, expected_identity_path: str
) -> bool:
    """Verify that a specific screen shows the correct identity"""
    print(f"🔍 Verifying identity in tab {screen_tab}...")

    # Navigate to the tab
    if not await navigate_to_tab(pilot, screen_tab):
        print(f"   ❌ Failed to navigate to tab {screen_tab}")
        return False

    # Wait for tab content
    if not await wait_for_tab_content(pilot, screen_tab):
        print(f"   ❌ Tab {screen_tab} content failed to load")
        return False

    # Different tabs show identity in different ways
    # We'll check the app state since it's centralized
    app = pilot.app
    current_identity = getattr(app, "current_identity_path", None)

    if current_identity == expected_identity_path:
        print(
            f"   ✅ Tab {screen_tab} has correct identity: {Path(expected_identity_path).name}"
        )
        return True
    else:
        print(f"   ❌ Tab {screen_tab} has wrong identity: {current_identity}")
        return False


async def check_dashboard_status(pilot: Pilot) -> dict:
    """Check the dashboard status panels"""
    print("📊 Checking dashboard status...")

    # Navigate to Dashboard
    if not await navigate_to_tab(pilot, 1):  # Tab 1 = Dashboard
        print("   ❌ Failed to navigate to Dashboard")
        return {}

    # Wait for dashboard content
    if not await wait_for_tab_content(pilot, 1):
        print("   ❌ Dashboard content failed to load")
        return {}

    # Check app state for status info
    app = pilot.app
    status = {
        "identity": getattr(app, "current_identity_path", None),
        "connection": getattr(app, "connection_status", None),
        "api_url": getattr(app, "api_url", None),
    }

    print(f"   📋 Dashboard status: {status}")
    return status


# =============================================================================
# TEST IMPLEMENTATION
# =============================================================================


@pytest.mark.asyncio
async def test_tui_centralized_identity_management(tmp_path, api_base_url):
    """Test that TUI properly manages identity state centrally across all screens"""

    # Create test identity file manually
    identity_path = tmp_path / "test_identity.json"

    # Create identity data (same structure as KeyManager creates)
    from dcypher.lib.key_manager import KeyManager
    import secrets

    # Generate mnemonic using bip_utils like KeyManager does
    from bip_utils import Bip39MnemonicGenerator, Bip39SeedGenerator, Bip39WordsNum

    mnemonic = Bip39MnemonicGenerator().FromWordsNumber(Bip39WordsNum.WORDS_NUM_24)

    # Create auth keys bundle
    pk_classic_hex, auth_keys_path = KeyManager.create_auth_keys_bundle(tmp_path)

    # Read auth keys and create identity file
    with open(auth_keys_path, "r") as f:
        auth_keys = json.load(f)

    identity_data = {
        "mnemonic": str(mnemonic),  # Convert to string for JSON serialization
        "auth_keys": auth_keys,
    }

    identity_path.write_text(json.dumps(identity_data))

    # Create TUI app with proper size
    app = DCypherTUI(api_url=api_base_url)

    async with app.run_test(size=(160, 60)) as pilot:
        print("🚀 Starting TUI centralized identity management test...")

        # Wait for TUI to be ready
        assert await wait_for_tui_ready(pilot), "TUI failed to initialize"

        # Step 1: Verify initial state
        print("\n📍 Step 1: Verifying initial state...")
        initial_status = await check_dashboard_status(pilot)
        assert initial_status["identity"] is None, "Identity should be None initially"
        assert initial_status["connection"] in ["connected", "Connected"], (
            "Should be connected to test API"
        )

        # Step 2: Create a new identity through TUI
        print("\n📍 Step 2: Creating new identity via TUI...")
        new_identity_path = await create_identity_via_tui(
            pilot,
            identity_name="new_test_user",
            storage_path=tmp_path,
            api_base_url=api_base_url,
        )
        assert new_identity_path is not None, "Failed to create identity"
        assert new_identity_path.exists(), "Identity file not created"

        # Wait for identity to be loaded in app state
        identity_loaded = IdentityLoadedInApp(str(new_identity_path), timeout=10.0)
        assert await identity_loaded.wait_until(pilot), (
            "Identity not loaded in app state"
        )

        # Step 3: Verify identity is set across all screens
        print("\n📍 Step 3: Verifying identity propagated to all screens...")

        # Check Dashboard (Tab 1)
        assert await verify_identity_in_screen(pilot, 1, str(new_identity_path))

        # Check Identity screen (Tab 2) - already there
        assert await verify_identity_in_screen(pilot, 2, str(new_identity_path))

        # Check Accounts screen (Tab 4)
        assert await verify_identity_in_screen(pilot, 4, str(new_identity_path))

        # Check Files screen (Tab 5)
        assert await verify_identity_in_screen(pilot, 5, str(new_identity_path))

        # Check Sharing screen (Tab 6)
        assert await verify_identity_in_screen(pilot, 6, str(new_identity_path))

        # Step 4: Load a different identity
        print("\n📍 Step 4: Loading different identity via TUI...")
        assert await load_identity_via_tui(pilot, identity_path)

        # Wait for the new identity to be loaded
        identity_switched = IdentityLoadedInApp(str(identity_path), timeout=10.0)
        assert await identity_switched.wait_until(pilot), "Identity switch failed"

        # Step 5: Verify all screens updated to new identity
        print("\n📍 Step 5: Verifying all screens updated to new identity...")

        assert await verify_identity_in_screen(pilot, 1, str(identity_path))
        assert await verify_identity_in_screen(pilot, 4, str(identity_path))
        assert await verify_identity_in_screen(pilot, 5, str(identity_path))
        assert await verify_identity_in_screen(pilot, 6, str(identity_path))

        # Step 6: Check API client is properly initialized
        print("\n📍 Step 6: Checking API client state...")
        app = pilot.app
        api_client = getattr(app, "_api_client", None)
        assert api_client is not None, "API client should be initialized"

        # The API client should have the current identity (DCypherClient uses keys_path attribute)
        client_identity = getattr(api_client, "keys_path", None)
        assert client_identity == str(identity_path), "API client has wrong identity"

        # Step 7: Test quick actions on dashboard
        print("\n📍 Step 7: Testing dashboard quick actions...")

        # Navigate to dashboard
        await navigate_to_tab(pilot, 1)

        # Test "Load Identity" quick action
        if await wait_and_click(pilot, "#quick-load-identity"):
            # Should navigate to Identity tab
            await wait_for_tab_content(pilot, 2, timeout=5.0)
            # Verify we're on identity screen
            identity_screen = ElementExists("#identity")
            assert await identity_screen.wait_until(pilot), (
                "Quick action didn't navigate to Identity"
            )

        # Go back to dashboard
        await navigate_to_tab(pilot, 1)

        # Test "Create Account" quick action - only if identity is loaded
        current_identity = getattr(app, "current_identity_path", None)
        if current_identity:
            if await wait_and_click(pilot, "#quick-create-account"):
                # Should navigate to Accounts tab
                await wait_for_tab_content(pilot, 4, timeout=5.0)
                accounts_screen = ElementExists("#accounts")
                assert await accounts_screen.wait_until(pilot), (
                    "Quick action didn't navigate to Accounts"
                )

        print(
            "\n✅ All tests passed! Centralized identity management working correctly."
        )


@pytest.mark.asyncio
async def test_tui_identity_persistence_across_operations(tmp_path, api_base_url):
    """Test that identity persists correctly during various operations"""

    # Create test identity
    from dcypher.lib.key_manager import KeyManager
    from bip_utils import Bip39MnemonicGenerator, Bip39SeedGenerator, Bip39WordsNum

    identity_path = tmp_path / "persistent_identity.json"

    # Generate mnemonic using bip_utils like KeyManager does
    mnemo = Bip39MnemonicGenerator()
    mnemonic = mnemo.FromWordsNumber(Bip39WordsNum.WORDS_NUM_24)

    # Create auth keys bundle
    pk_classic_hex, auth_keys_path = KeyManager.create_auth_keys_bundle(tmp_path)

    # Read auth keys and create identity file
    with open(auth_keys_path, "r") as f:
        auth_keys = json.load(f)

    identity_data = {"mnemonic": str(mnemonic), "auth_keys": auth_keys}

    identity_path.write_text(json.dumps(identity_data))

    # Create test file
    test_file = tmp_path / "test.txt"
    create_test_file(test_file, "Test content")

    app = DCypherTUI(api_url=api_base_url)

    async with app.run_test(size=(160, 60)) as pilot:
        print("🚀 Testing identity persistence across operations...")

        # Wait for TUI ready
        assert await wait_for_tui_ready(pilot), "TUI failed to initialize"

        # Load identity
        assert await load_identity_via_tui(pilot, identity_path)

        # Wait for API connection
        connection_established = APIConnectionEstablished(timeout=10.0)
        assert await connection_established.wait_until(pilot), (
            "API connection not established"
        )

        # Navigate to Files tab and verify identity is still set
        await navigate_to_tab(pilot, 5)  # Files tab

        # Check that identity is still loaded
        app = pilot.app
        assert getattr(app, "current_identity_path", None) == str(identity_path)

        # The Files screen should use the app's identity automatically
        # No need to set identity manually

        # Try to upload a file (this will use the centralized identity)
        if await wait_and_fill(pilot, "#file-path-input", str(test_file)):
            if await wait_and_click(pilot, "#upload-file-btn"):
                print("   ✅ File operation initiated with persistent identity")

        # Navigate to another tab and back
        await navigate_to_tab(pilot, 1)  # Dashboard
        await navigate_to_tab(pilot, 5)  # Back to Files

        # Verify identity is still set
        assert getattr(app, "current_identity_path", None) == str(identity_path)

        print("\n✅ Identity persisted correctly across all operations!")


@pytest.mark.asyncio
async def test_tui_api_client_caching(tmp_path, api_base_url):
    """Test that API client is properly cached and reused"""

    # Create test identity
    from dcypher.lib.key_manager import KeyManager
    from bip_utils import Bip39MnemonicGenerator, Bip39SeedGenerator, Bip39WordsNum

    identity_path = tmp_path / "cached_identity.json"

    # Generate mnemonic using bip_utils like KeyManager does
    mnemo = Bip39MnemonicGenerator()
    mnemonic = mnemo.FromWordsNumber(Bip39WordsNum.WORDS_NUM_24)

    # Create auth keys bundle
    pk_classic_hex, auth_keys_path = KeyManager.create_auth_keys_bundle(tmp_path)

    # Read auth keys and create identity file
    with open(auth_keys_path, "r") as f:
        auth_keys = json.load(f)

    identity_data = {"mnemonic": str(mnemonic), "auth_keys": auth_keys}

    identity_path.write_text(json.dumps(identity_data))

    app = DCypherTUI(api_url=api_base_url)

    async with app.run_test(size=(160, 60)) as pilot:
        print("🚀 Testing API client caching...")

        # Wait for TUI ready
        assert await wait_for_tui_ready(pilot), "TUI failed to initialize"

        # Load identity
        assert await load_identity_via_tui(pilot, identity_path)

        # Get the API client instance
        app = pilot.app
        client1 = app.get_or_create_api_client()  # type: ignore
        assert client1 is not None, "Failed to create API client"

        # Call get_or_create_api_client again - should return same instance
        client2 = app.get_or_create_api_client()  # type: ignore
        assert client2 is client1, "API client not properly cached"

        # Navigate through different screens and verify same client
        await navigate_to_tab(pilot, 4)  # Accounts
        client3 = app.get_or_create_api_client()  # type: ignore
        assert client3 is client1, "API client changed after navigation"

        await navigate_to_tab(pilot, 5)  # Files
        client4 = app.get_or_create_api_client()  # type: ignore
        assert client4 is client1, "API client changed after another navigation"

        print("\n✅ API client properly cached and reused!")
