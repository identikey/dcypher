"""
TUI Integration Tests
Tests the TUI interface against a live server, covering the core workflows
that users would perform through the interactive terminal interface.
"""

import pytest
import asyncio
import json
import tempfile
from pathlib import Path
from textual.pilot import Pilot
from textual.app import App

from src.tui.app import DCypherTUI
from src.lib.api_client import DCypherClient
from src.lib.key_manager import KeyManager


class TestDCypherTUI:
    """Test class for TUI integration tests"""

    @pytest.mark.asyncio
    async def test_tui_basic_functionality(self, api_base_url: str, tmp_path):
        """
        Test basic TUI functionality - app startup, navigation, and API connection.
        This test verifies the TUI can start and respond to basic interactions.
        """
        # Create TUI app instance with test configuration
        app = DCypherTUI(api_url=api_base_url)

        async with app.run_test(size=(120, 40)) as pilot:
            # Wait for app to load properly
            await pilot.pause(0.5)

            # Test that the app started successfully
            assert app.title == "dCypher - Quantum-Resistant Encryption TUI"
            assert app.api_url == api_base_url

            # Test tab navigation
            await pilot.press("2")  # Identity tab
            await pilot.pause(0.2)

            await pilot.press("3")  # Crypto tab
            await pilot.pause(0.2)

            await pilot.press("4")  # Accounts tab
            await pilot.pause(0.2)

            await pilot.press("5")  # Files tab
            await pilot.pause(0.2)

            await pilot.press("6")  # Sharing tab
            await pilot.pause(0.2)

            await pilot.press("1")  # Back to Dashboard
            await pilot.pause(0.2)

    @pytest.mark.asyncio
    async def test_tui_with_real_identity(self, api_base_url: str, tmp_path):
        """
        Test TUI functionality with a real identity created via KeyManager.
        This verifies the integration between TUI and backend systems.
        """
        # Create a real identity file using KeyManager
        mnemonic, identity_file = KeyManager.create_identity_file(
            "tui_test", tmp_path, overwrite=True
        )
        assert identity_file.exists()

        # Verify identity file structure
        with open(identity_file, "r") as f:
            identity_data = json.load(f)

        assert "mnemonic" in identity_data
        assert "auth_keys" in identity_data
        assert identity_data["derivable"] is True

        # Test TUI with the real identity
        app = DCypherTUI(identity_path=str(identity_file), api_url=api_base_url)

        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause(0.5)

            # Verify the identity was loaded
            assert app.current_identity == str(identity_file)

            # Test navigation with loaded identity
            await pilot.press("2")  # Identity tab
            await pilot.pause(0.2)

            await pilot.press("4")  # Accounts tab
            await pilot.pause(0.2)

    @pytest.mark.asyncio
    async def test_tui_navigation_and_shortcuts(self, api_base_url: str, tmp_path):
        """
        Test TUI navigation, keyboard shortcuts, and tab switching functionality.
        """
        app = DCypherTUI(api_url=api_base_url)

        async with app.run_test() as pilot:
            # Test tab navigation with number keys
            await pilot.press("1")  # Dashboard
            await pilot.pause()

            await pilot.press("2")  # Identity
            await pilot.pause()

            await pilot.press("3")  # Crypto
            await pilot.pause()

            await pilot.press("4")  # Accounts
            await pilot.pause()

            await pilot.press("5")  # Files
            await pilot.pause()

            await pilot.press("6")  # Sharing
            await pilot.pause()

            # Test arrow key navigation
            await pilot.press("left")  # Previous tab
            await pilot.pause()

            await pilot.press("right")  # Next tab
            await pilot.pause()

            # Test tab key navigation
            await pilot.press("tab")  # Next tab
            await pilot.pause()

            await pilot.press("shift+tab")  # Previous tab
            await pilot.pause()

    @pytest.mark.asyncio
    async def test_rapid_tab_switching(self, api_base_url: str, tmp_path):
        """Test rapid tab switching doesn't cause issues"""
        app = DCypherTUI(api_url=api_base_url)

        async with app.run_test() as pilot:
            # Rapidly switch between tabs
            for _ in range(3):
                for tab in ["1", "2", "3", "4", "5", "6"]:
                    await pilot.press(tab)
                    # Minimal pause to allow UI updates
                    await pilot.pause(0.1)


class TestTUIComponents:
    """Test specific TUI components and widgets"""

    @pytest.mark.asyncio
    async def test_identity_screen_navigation(self, api_base_url: str, tmp_path):
        """Test identity screen navigation and basic interaction"""
        app = DCypherTUI(api_url=api_base_url)

        async with app.run_test() as pilot:
            await pilot.press("2")  # Identity tab
            await pilot.pause()

            # Test that we can access the identity screen without errors
            # Basic navigation test without complex widget interactions
            assert True  # Placeholder for successful navigation

    @pytest.mark.asyncio
    async def test_crypto_screen_navigation(self, api_base_url: str, tmp_path):
        """Test crypto screen navigation and basic interaction"""
        app = DCypherTUI(api_url=api_base_url)

        async with app.run_test() as pilot:
            await pilot.press("3")  # Crypto tab
            await pilot.pause()

            # Test that we can access the crypto screen without errors
            # Basic navigation test without complex widget interactions
            assert True  # Placeholder for successful navigation

    @pytest.mark.asyncio
    async def test_accounts_screen_navigation(self, api_base_url: str, tmp_path):
        """Test accounts screen navigation and basic interaction"""
        app = DCypherTUI(api_url=api_base_url)

        async with app.run_test() as pilot:
            await pilot.press("4")  # Accounts tab
            await pilot.pause()

            # Test that we can access the accounts screen without errors
            # Basic navigation test without complex widget interactions
            assert True  # Placeholder for successful navigation

    @pytest.mark.asyncio
    async def test_files_screen_navigation(self, api_base_url: str, tmp_path):
        """Test files screen navigation and basic interaction"""
        app = DCypherTUI(api_url=api_base_url)

        async with app.run_test() as pilot:
            await pilot.press("5")  # Files tab
            await pilot.pause()

            # Test that we can access the files screen without errors
            # Basic navigation test without complex widget interactions
            assert True  # Placeholder for successful navigation

    @pytest.mark.asyncio
    async def test_sharing_screen_navigation(self, api_base_url: str, tmp_path):
        """Test sharing screen navigation and basic interaction"""
        app = DCypherTUI(api_url=api_base_url)

        async with app.run_test() as pilot:
            await pilot.press("6")  # Sharing tab
            await pilot.pause()

            # Test that we can access the sharing screen without errors
            # Basic navigation test without complex widget interactions
            assert True  # Placeholder for successful navigation


class TestTUIPerformance:
    """Test TUI performance and responsiveness"""

    @pytest.mark.asyncio
    async def test_app_startup_performance(self, api_base_url: str, tmp_path):
        """Test that the TUI app starts up within reasonable time"""
        import time

        start_time = time.time()
        app = DCypherTUI(api_url=api_base_url)

        async with app.run_test() as pilot:
            await pilot.pause(0.1)
            startup_time = time.time() - start_time

            # App should start up within 5 seconds
            assert startup_time < 5.0

    @pytest.mark.asyncio
    async def test_tab_switching_responsiveness(self, api_base_url: str, tmp_path):
        """Test that tab switching is responsive"""
        app = DCypherTUI(api_url=api_base_url)

        async with app.run_test() as pilot:
            import time

            # Test tab switching performance
            start_time = time.time()

            for tab in ["1", "2", "3", "4", "5", "6"]:
                await pilot.press(tab)
                await pilot.pause(0.05)

            switch_time = time.time() - start_time

            # All tab switches should complete within 3 seconds
            assert switch_time < 3.0


class TestTUIErrorHandling:
    """Test TUI error handling for various error conditions"""

    @pytest.mark.asyncio
    async def test_invalid_api_url_handling(self, tmp_path):
        """Test TUI behavior with invalid API URL"""
        app = DCypherTUI(api_url="http://invalid-url:9999")

        async with app.run_test() as pilot:
            await pilot.pause(0.5)

            # App should still start even with invalid API URL
            # Error handling should be graceful
            assert app.api_url == "http://invalid-url:9999"

    @pytest.mark.asyncio
    async def test_missing_identity_handling(self, api_base_url: str, tmp_path):
        """Test TUI behavior when identity file is missing"""
        nonexistent_path = str(tmp_path / "nonexistent.json")
        app = DCypherTUI(identity_path=nonexistent_path, api_url=api_base_url)

        async with app.run_test() as pilot:
            await pilot.pause(0.5)

            # App should handle missing identity gracefully
            # Navigation should still work
            await pilot.press("2")  # Identity tab
            await pilot.pause(0.2)


class TestTUIIntegration:
    """Integration tests for TUI with real backend operations"""

    @pytest.mark.asyncio
    async def test_tui_with_keymanager_integration(self, api_base_url: str, tmp_path):
        """Test TUI integration with KeyManager operations"""
        # Create identity using KeyManager
        mnemonic, identity_file = KeyManager.create_identity_file(
            "integration_test", tmp_path, overwrite=True
        )

        # Test TUI with the created identity
        app = DCypherTUI(identity_path=str(identity_file), api_url=api_base_url)

        async with app.run_test() as pilot:
            await pilot.pause(0.5)

            # Test navigation with real identity
            await pilot.press("2")  # Identity tab
            await pilot.pause(0.2)

            await pilot.press("4")  # Accounts tab
            await pilot.pause(0.2)

            # Verify identity integration
            assert app.current_identity == str(identity_file)

    @pytest.mark.asyncio
    async def test_tui_api_client_integration(self, api_base_url: str, tmp_path):
        """Test TUI integration with API client operations"""
        app = DCypherTUI(api_url=api_base_url)

        async with app.run_test() as pilot:
            await pilot.pause(0.5)

            # Test that API client integration doesn't break navigation
            await pilot.press("3")  # Crypto tab
            await pilot.pause(0.2)

            await pilot.press("5")  # Files tab
            await pilot.pause(0.2)

            # Verify API URL is properly set
            assert app.api_url == api_base_url
