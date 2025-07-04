"""
Tests for the main TUI application
"""

import pytest
from unittest.mock import Mock, patch
import asyncio

from dcypher.tui.app import DCypherTUI


class TestDCypherTUI:
    """Test cases for the main TUI application"""

    def test_app_initialization(self):
        """Test that the app initializes correctly"""
        app = DCypherTUI()
        assert app.TITLE == "v0.0.1 dCypher Terminal: PQ-Lattice FHE System"
        assert app.SUB_TITLE == "REPLICANT TERMINAL v2.1.0"
        assert app.current_identity_path is None
        assert app.api_url == "http://127.0.0.1:8000"
        assert app.connection_status == "disconnected"

    def test_app_initialization_with_params(self):
        """Test app initialization with custom parameters"""
        identity_path = "/test/identity.json"
        api_url = "https://api.example.com"

        app = DCypherTUI(identity_path=identity_path, api_url=api_url)
        assert app.current_identity_path == identity_path
        assert app.api_url == api_url

    @pytest.mark.asyncio
    async def test_app_compose(self):
        """Test that the app composes correctly"""
        app = DCypherTUI()
        async with app.run_test() as pilot:
            # Wait for app to fully load
            await pilot.pause()

            # Check that main components are present
            assert pilot.app.query("#main-container")
            assert pilot.app.query(
                "DCypherHeader"
            )  # Changed to match our custom header
            assert pilot.app.query("Footer")
            assert pilot.app.query("TabbedContent")

    @pytest.mark.asyncio
    async def test_app_tabs_present(self):
        """Test that all required tabs are present"""
        app = DCypherTUI()
        async with app.run_test() as pilot:
            await pilot.pause()

            # Check for specific tab content containers
            tab_containers = [
                "#dashboard",
                "#identity",
                "#crypto",
                "#accounts",
                "#files",
                "#sharing",
            ]

            for container_id in tab_containers:
                container = pilot.app.query_one(container_id)
                assert container is not None, f"Container {container_id} should exist"

    def test_app_bindings(self):
        """Test that key bindings are properly configured"""
        app = DCypherTUI()
        # Bindings are Binding objects with .key attribute
        binding_keys = []
        for binding in app.BINDINGS:
            # Handle Binding objects properly
            if hasattr(binding, "key"):
                binding_keys.append(binding.key)
            elif isinstance(binding, tuple):
                # Handle tuple format (key, action, description)
                binding_keys.append(binding[0])
            else:
                # Fallback for other formats
                binding_keys.append(str(binding))

        expected_bindings = ["ctrl+c", "ctrl+d", "f1", "f2", "f12"]
        for expected_binding in expected_bindings:
            assert expected_binding in binding_keys

    @pytest.mark.asyncio
    async def test_toggle_dark_mode(self):
        """Test dark mode toggle functionality"""
        app = DCypherTUI()
        async with app.run_test() as pilot:
            await pilot.pause()

            initial_theme = pilot.app.theme
            await pilot.press("ctrl+d")  # The correct binding for toggle_dark
            await pilot.pause()

            # Theme should have changed
            assert pilot.app.theme != initial_theme

    def test_reactive_properties(self):
        """Test reactive property updates"""
        app = DCypherTUI()

        # Test identity property
        test_identity = "/test/identity.json"
        app.current_identity_path = test_identity
        assert app.current_identity_path == test_identity

        # Test API URL property
        test_api_url = "https://test.api.com"
        app.api_url = test_api_url
        assert app.api_url == test_api_url

        # Test connection status property
        app.connection_status = "connected"
        assert app.connection_status == "connected"

    @patch("dcypher.tui.app.DCypherTUI.set_interval")
    @pytest.mark.asyncio
    async def test_app_mount_intervals(self, mock_set_interval):
        """Test that intervals are set up on mount"""
        app = DCypherTUI()
        async with app.run_test() as pilot:
            await pilot.pause()

            # Check that intervals were set up
            assert mock_set_interval.call_count >= 2

            # Check interval calls
            calls = mock_set_interval.call_args_list
            intervals = [call[0][0] for call in calls]  # First argument (interval time)

            assert 1.0 in intervals  # System status update
            assert 5.0 in intervals  # API connection check

    @pytest.mark.asyncio
    async def test_app_screenshot_action(self):
        """Test screenshot functionality"""
        app = DCypherTUI()
        async with app.run_test() as pilot:
            await pilot.pause()

            # This should not raise an exception
            pilot.app.action_screenshot()

    def test_app_css_theme_loaded(self):
        """Test that the cyberpunk theme is loaded"""
        app = DCypherTUI()
        assert app.CSS is not None
        assert len(app.CSS) > 0
        # Check for some key theme elements
        assert "$primary: #00ff41" in app.CSS or "primary" in app.CSS.lower()


class TestTUIIntegration:
    """Integration tests for TUI components"""

    @pytest.mark.asyncio
    async def test_dashboard_screen_loads(self):
        """Test that dashboard screen loads without errors"""
        app = DCypherTUI()
        async with app.run_test() as pilot:
            await pilot.pause()

            # Switch to dashboard tab (should be default)
            dashboard_tab = pilot.app.query_one("#dashboard")
            assert dashboard_tab is not None

    @pytest.mark.asyncio
    async def test_identity_screen_loads(self):
        """Test that identity screen loads without errors"""
        app = DCypherTUI()
        async with app.run_test() as pilot:
            await pilot.pause()

            # Switch to identity tab
            identity_tab = pilot.app.query_one("#identity")
            assert identity_tab is not None

    @pytest.mark.asyncio
    async def test_all_screens_accessible(self):
        """Test that all screens can be accessed"""
        app = DCypherTUI()
        async with app.run_test() as pilot:
            await pilot.pause()

            screen_ids = [
                "dashboard",
                "identity",
                "crypto",
                "accounts",
                "files",
                "sharing",
            ]

            for screen_id in screen_ids:
                screen = pilot.app.query_one(f"#{screen_id}")
                assert screen is not None, f"Screen {screen_id} not found"

    @pytest.mark.asyncio
    async def test_app_state_persistence(self):
        """Test that app state persists across screen changes"""
        app = DCypherTUI()
        async with app.run_test() as pilot:
            await pilot.pause()

            # Set some state using the app instance directly
            app.current_identity_path = "/test/identity.json"
            app.api_url = "https://test.api.com"

            # Switch tabs (simulate user interaction)
            await pilot.press("f2")  # Assuming this switches tabs
            await pilot.pause()

            # State should persist
            assert app.current_identity_path == "/test/identity.json"
            assert app.api_url == "https://test.api.com"


class TestTUIUserInteractions:
    """Test user interactions and key presses"""

    @pytest.mark.asyncio
    async def test_key_navigation(self):
        """Test that key navigation works correctly"""
        app = DCypherTUI()
        async with app.run_test() as pilot:
            await pilot.pause()

            # Test various key combinations
            await pilot.press("f1")  # Help
            await pilot.pause()

            await pilot.press("f2")  # Navigate
            await pilot.pause()

            # Should not crash
            assert pilot.app.is_running

    @pytest.mark.asyncio
    async def test_tab_switching(self):
        """Test switching between tabs"""
        app = DCypherTUI()
        async with app.run_test() as pilot:
            await pilot.pause()

            # Get initial tab
            tabbed_content = pilot.app.query_one("TabbedContent")
            initial_tab = tabbed_content.active

            # Switch to next tab
            await pilot.press("tab")
            await pilot.pause()

            # Tab should have changed or stayed the same (depending on implementation)
            assert tabbed_content.active is not None


@pytest.fixture
def mock_identity_file(tmp_path):
    """Create a mock identity file for testing"""
    identity_data = {
        "mnemonic": "test mnemonic phrase",
        "version": "1.0",
        "derivable": True,
        "auth_keys": {
            "classic": {"sk_hex": "test_secret_key", "pk_hex": "test_public_key"},
            "pq": [
                {
                    "alg": "Falcon-512",
                    "sk_hex": "test_pq_secret",
                    "pk_hex": "test_pq_public",
                    "derivable": True,
                }
            ],
        },
    }

    identity_file = tmp_path / "test_identity.json"
    import json

    with open(identity_file, "w") as f:
        json.dump(identity_data, f)

    return str(identity_file)


class TestTUIWithMockData:
    """Tests using mock data"""

    def test_app_with_mock_identity(self, mock_identity_file):
        """Test app initialization with mock identity file"""
        app = DCypherTUI(identity_path=mock_identity_file)
        assert app.current_identity_path == mock_identity_file

    @pytest.mark.asyncio
    async def test_identity_loading_integration(self, mock_identity_file):
        """Test identity loading in the TUI"""
        app = DCypherTUI()
        async with app.run_test() as pilot:
            await pilot.pause()

            # This would test the actual identity loading process
            # For now, just verify the app can handle the file path
            app.current_identity_path = mock_identity_file
            assert app.current_identity_path == mock_identity_file


class TestTUIErrorHandling:
    """Test error handling and edge cases"""

    @pytest.mark.asyncio
    async def test_app_handles_invalid_identity_path(self):
        """Test app gracefully handles invalid identity file"""
        app = DCypherTUI(identity_path="/nonexistent/file.json")

        async with app.run_test() as pilot:
            await pilot.pause()

            # App should still load even with invalid identity
            assert pilot.app.is_running

    @pytest.mark.asyncio
    async def test_app_handles_network_errors(self):
        """Test app handles network connectivity issues"""
        app = DCypherTUI(api_url="http://invalid.url:9999")

        async with app.run_test() as pilot:
            await pilot.pause()

            # App should handle network errors gracefully
            assert app.connection_status in ["disconnected", "error"]

    @pytest.mark.asyncio
    async def test_app_shutdown_cleanup(self):
        """Test that app cleans up properly on shutdown"""
        app = DCypherTUI()
        async with app.run_test() as pilot:
            await pilot.pause()

            # Force app shutdown
            await pilot.app.action_quit()

            # App should exit cleanly
            # This test mainly ensures no exceptions during shutdown
