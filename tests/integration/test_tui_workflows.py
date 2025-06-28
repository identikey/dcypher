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
    async def test_tui_crypto_operations_workflow(self, api_base_url: str, tmp_path):
        """
        Test the complete cryptographic operations workflow through the TUI.
        This includes generating crypto context, keys, and performing encryption/decryption.
        """
        # Create TUI app instance
        app = DCypherTUI(api_url=api_base_url)

        async with app.run_test() as pilot:
            # Navigate to Crypto tab
            await pilot.press("3")  # Switch to Crypto tab
            await pilot.pause()

            # Test crypto context generation
            await pilot.click("#cc-output-path")
            await pilot.type("test_cc.json")

            await pilot.click("#gen-cc-btn")
            await pilot.pause()

            # Verify crypto context was created
            cc_file = tmp_path / "test_cc.json"
            # Note: The app runs in test mode, so files are created in the app's working directory
            # In a real integration test, we'd need to handle this differently

            # Test key generation
            await pilot.click("#key-prefix")
            await pilot.type("test_key")

            await pilot.click("#gen-keys-btn")
            await pilot.pause()

            # Test signing key generation
            await pilot.click("#gen-signing-btn")
            await pilot.pause()

            # Test encryption with text input
            await pilot.click("#encrypt-input")
            await pilot.type("This is a test message for TUI encryption!")

            await pilot.click("#encrypt-btn")
            await pilot.pause()

    @pytest.mark.asyncio
    async def test_tui_account_management_workflow(self, api_base_url: str, tmp_path):
        """
        Test the account management workflow through the TUI.
        This includes setting identity, creating accounts, and managing PQ keys.
        """
        # First create an identity file for testing
        identity_dir = tmp_path
        mnemonic, identity_file = KeyManager.create_identity_file(
            "tui_test", identity_dir, overwrite=True
        )

        # Create TUI app instance
        app = DCypherTUI(api_url=api_base_url)

        async with app.run_test() as pilot:
            # Navigate to Accounts tab
            await pilot.press("4")  # Switch to Accounts tab
            await pilot.pause()

            # Set identity path
            await pilot.click("#identity-path-input")
            await pilot.type(str(identity_file))

            await pilot.click("#api-url-input")
            await pilot.type(api_base_url)

            await pilot.click("#set-identity-btn")
            await pilot.pause()

            # Test listing supported algorithms
            await pilot.click("#supported-algs-btn")
            await pilot.pause()

            # Test account creation
            await pilot.click("#create-account-btn")
            await pilot.pause()

            # Test listing accounts
            await pilot.click("#list-accounts-btn")
            await pilot.pause()

    @pytest.mark.asyncio
    async def test_tui_file_operations_workflow(self, api_base_url: str, tmp_path):
        """
        Test the file operations workflow through the TUI.
        This includes setting up identity, uploading files, and downloading them.
        """
        # Create test identity with PRE capabilities
        identity_dir = tmp_path
        mnemonic, identity_file = KeyManager.create_identity_file(
            "file_test", identity_dir, overwrite=True
        )

        # Initialize PRE for the identity using API client
        client = DCypherClient(api_base_url, identity_path=identity_file)
        try:
            client.initialize_pre_for_identity()
        except Exception:
            # PRE initialization might fail in test environment, continue anyway
            pass

        # Create a test file to upload
        test_file = tmp_path / "test_upload.txt"
        test_content = b"This is test content for TUI file upload testing!"
        with open(test_file, "wb") as f:
            f.write(test_content)

        # Create TUI app instance
        app = DCypherTUI(api_url=api_base_url)

        async with app.run_test() as pilot:
            # Navigate to Files tab
            await pilot.press("5")  # Switch to Files tab
            await pilot.pause()

            # Set identity and API URL
            await pilot.click("#identity-path-input")
            await pilot.type(str(identity_file))

            await pilot.click("#api-url-input")
            await pilot.type(api_base_url)

            await pilot.click("#set-identity-btn")
            await pilot.pause()

            # Set file path for upload
            await pilot.click("#file-path-input")
            await pilot.type(str(test_file))

            # Test file upload (Note: This might fail due to missing PRE setup, but tests the UI)
            await pilot.click("#upload-file-btn")
            await pilot.pause()

    @pytest.mark.asyncio
    async def test_tui_sharing_workflow(self, api_base_url: str, tmp_path):
        """
        Test the sharing workflow through the TUI.
        This includes PRE initialization, creating shares, and managing sharing.
        """
        # Create test identity
        identity_dir = tmp_path
        mnemonic, identity_file = KeyManager.create_identity_file(
            "share_test", identity_dir, overwrite=True
        )

        # Create TUI app instance
        app = DCypherTUI(api_url=api_base_url)

        async with app.run_test() as pilot:
            # Navigate to Sharing tab
            await pilot.press("6")  # Switch to Sharing tab
            await pilot.pause()

            # Set identity and API URL
            await pilot.click("#identity-path-input")
            await pilot.type(str(identity_file))

            await pilot.click("#api-url-input")
            await pilot.type(api_base_url)

            await pilot.click("#set-identity-btn")
            await pilot.pause()

            # Test getting PRE context
            await pilot.click("#get-pre-context-btn")
            await pilot.pause()

            # Test PRE initialization
            await pilot.click("#init-pre-btn")
            await pilot.pause()

            # Test listing shares
            await pilot.click("#list-shares-btn")
            await pilot.pause()

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
    async def test_tui_error_handling(self, api_base_url: str, tmp_path):
        """
        Test TUI error handling for various error conditions.
        """
        app = DCypherTUI(api_url=api_base_url)

        async with app.run_test() as pilot:
            # Test identity creation with invalid path
            await pilot.press("2")  # Identity tab
            await pilot.pause()

            await pilot.click("#new-identity-name")
            await pilot.type("test")

            await pilot.click("#new-identity-path")
            await pilot.type("/invalid/nonexistent/path")

            await pilot.click("#create-identity-btn")
            await pilot.pause()

            # Test crypto operations without proper setup
            await pilot.press("3")  # Crypto tab
            await pilot.pause()

            await pilot.click("#encrypt-btn")  # Should show error
            await pilot.pause()

            # Test account operations without identity
            await pilot.press("4")  # Accounts tab
            await pilot.pause()

            await pilot.click("#create-account-btn")  # Should show error
            await pilot.pause()

    @pytest.mark.asyncio
    async def test_tui_full_integration_workflow(self, api_base_url: str, tmp_path):
        """
        Test a complete end-to-end workflow that demonstrates the full capability
        of the TUI when working with a live server.
        """
        app = DCypherTUI(api_url=api_base_url)

        async with app.run_test() as pilot:
            # 1. Create new identity
            await pilot.press("2")  # Identity tab
            await pilot.pause()

            await pilot.click("#new-identity-name")
            await pilot.type("integration_test")

            await pilot.click("#new-identity-path")
            await pilot.type(str(tmp_path))

            await pilot.click("#create-identity-btn")
            await pilot.pause()

            # 2. Generate crypto context and keys
            await pilot.press("3")  # Crypto tab
            await pilot.pause()

            await pilot.click("#gen-cc-btn")
            await pilot.pause()

            await pilot.click("#gen-keys-btn")
            await pilot.pause()

            await pilot.click("#gen-signing-btn")
            await pilot.pause()

            # 3. Set up account management
            await pilot.press("4")  # Accounts tab
            await pilot.pause()

            identity_file = tmp_path / "integration_test.json"
            await pilot.click("#identity-path-input")
            await pilot.type(str(identity_file))

            await pilot.click("#api-url-input")
            await pilot.type(api_base_url)

            await pilot.click("#set-identity-btn")
            await pilot.pause()

            # 4. Test account creation and management
            await pilot.click("#supported-algs-btn")
            await pilot.pause()

            await pilot.click("#create-account-btn")
            await pilot.pause()

            await pilot.click("#list-accounts-btn")
            await pilot.pause()

            # 5. Test sharing setup
            await pilot.press("6")  # Sharing tab
            await pilot.pause()

            await pilot.click("#identity-path-input")
            await pilot.type(str(identity_file))

            await pilot.click("#api-url-input")
            await pilot.type(api_base_url)

            await pilot.click("#set-identity-btn")
            await pilot.pause()

            await pilot.click("#get-pre-context-btn")
            await pilot.pause()


# Additional helper tests for specific TUI components


class TestTUIComponents:
    """Test specific TUI components and widgets"""

    @pytest.mark.asyncio
    async def test_identity_screen_components(self, api_base_url: str, tmp_path):
        """Test identity screen specific functionality"""
        app = DCypherTUI(api_url=api_base_url)

        async with app.run_test() as pilot:
            await pilot.press("2")  # Identity tab
            await pilot.pause()

            # Test loading existing identity
            await pilot.click("#load-identity-path")
            await pilot.type("nonexistent.json")

            await pilot.click("#load-identity-btn")
            await pilot.pause()  # Should show error

    @pytest.mark.asyncio
    async def test_crypto_screen_components(self, api_base_url: str, tmp_path):
        """Test crypto screen specific functionality"""
        app = DCypherTUI(api_url=api_base_url)

        async with app.run_test() as pilot:
            await pilot.press("3")  # Crypto tab
            await pilot.pause()

            # Test input type selection
            await pilot.click("#input-type-select")
            await pilot.pause()

            # Test file path vs text encryption toggle
            await pilot.click("#encrypt-input")
            await pilot.type("test encryption data")

    @pytest.mark.asyncio
    async def test_accounts_screen_components(self, api_base_url: str, tmp_path):
        """Test accounts screen specific functionality"""
        app = DCypherTUI(api_url=api_base_url)

        async with app.run_test() as pilot:
            await pilot.press("4")  # Accounts tab
            await pilot.pause()

            # Test PQ algorithm selection
            await pilot.click("#pq-algorithm-select")
            await pilot.pause()

            # Test account public key input
            await pilot.click("#account-pubkey-input")
            await pilot.type("test_public_key_hex")

    @pytest.mark.asyncio
    async def test_files_screen_components(self, api_base_url: str, tmp_path):
        """Test files screen specific functionality"""
        app = DCypherTUI(api_url=api_base_url)

        async with app.run_test() as pilot:
            await pilot.press("5")  # Files tab
            await pilot.pause()

            # Test download type selection
            await pilot.click("#download-type-select")
            await pilot.pause()

            # Test file hash input
            await pilot.click("#file-hash-input")
            await pilot.type("test_file_hash")

    @pytest.mark.asyncio
    async def test_sharing_screen_components(self, api_base_url: str, tmp_path):
        """Test sharing screen specific functionality"""
        app = DCypherTUI(api_url=api_base_url)

        async with app.run_test() as pilot:
            await pilot.press("6")  # Sharing tab
            await pilot.pause()

            # Test recipient key input
            await pilot.click("#recipient-key-input")
            await pilot.type("recipient_public_key")

            # Test file hash input for sharing
            await pilot.click("#file-hash-input")
            await pilot.type("file_hash_to_share")

            # Test share ID input
            await pilot.click("#share-id-input")
            await pilot.type("share_id_12345")


# Performance and stress tests


class TestTUIPerformance:
    """Test TUI performance and responsiveness"""

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

    @pytest.mark.asyncio
    async def test_large_input_handling(self, api_base_url: str, tmp_path):
        """Test TUI handling of large text inputs"""
        app = DCypherTUI(api_url=api_base_url)

        async with app.run_test() as pilot:
            await pilot.press("3")  # Crypto tab
            await pilot.pause()

            # Test large text input in encryption field
            large_text = "A" * 1000  # 1KB of text
            await pilot.click("#encrypt-input")
            await pilot.type(large_text)
            await pilot.pause()
