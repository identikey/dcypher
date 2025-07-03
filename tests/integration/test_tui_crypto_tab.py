"""
Comprehensive tests for the Crypto tab in the TUI.
Tests all crypto operations including encrypt, decrypt, key generation, and re-encryption.
"""

import pytest
import tempfile
import json
from pathlib import Path
from unittest.mock import patch, MagicMock
from tests.helpers.tui_test_helpers import (
    wait_for_notification,
)
from src.tui.app import DCypherTUI
from src.tui.screens.crypto import CryptoScreen


class TestCryptoTabOperations:
    """Test crypto operations in the TUI"""

    @pytest.mark.asyncio
    async def test_generate_crypto_context(self):
        """Test generating a crypto context through the TUI"""
        with tempfile.TemporaryDirectory() as temp_dir:
            app = DCypherTUI()
            async with app.run_test(size=(160, 60)) as pilot:
                # Navigate to Crypto tab (Tab 3)
                await pilot.press("3")
                await pilot.pause(0.5)

                # Find the crypto screen
                crypto_screen = pilot.app.query_one(CryptoScreen)
                assert crypto_screen is not None

                # Set output path
                cc_output = pilot.app.query_one("#cc-output-path")
                cc_output.value = f"{temp_dir}/test_cc.json"

                # Click generate crypto context button
                gen_cc_btn = pilot.app.query_one("#gen-cc-btn")
                await pilot.click(gen_cc_btn)

                # Wait for success notification
                await wait_for_notification(pilot, "Crypto context generated")

                # Verify file was created
                cc_file = Path(temp_dir) / "test_cc.json"
                assert cc_file.exists()

                # Verify file contents
                with open(cc_file, "r") as f:
                    cc_data = json.load(f)
                    assert "cc" in cc_data
                    assert isinstance(cc_data["cc"], str)  # Base64 encoded

    @pytest.mark.asyncio
    async def test_generate_key_pair(self, tmp_path):
        """Test generating PRE key pairs through the TUI"""
        with tempfile.TemporaryDirectory() as temp_dir:
            app = DCypherTUI()
            async with app.run_test(size=(160, 60)) as pilot:
                # Navigate to Crypto tab
                await pilot.press("3")
                await pilot.pause(0.5)

                # First generate crypto context
                cc_output = pilot.app.query_one("#cc-output-path")
                cc_output.value = f"{temp_dir}/cc.json"

                gen_cc_btn = pilot.app.query_one("#gen-cc-btn")
                await pilot.click(gen_cc_btn)
                await wait_for_notification(pilot, "Crypto context generated")

                # Set key prefix
                key_prefix = pilot.app.query_one("#key-prefix")
                key_prefix.value = f"{temp_dir}/testkey"

                # Generate keys
                gen_keys_btn = pilot.app.query_one("#gen-keys-btn")
                await pilot.click(gen_keys_btn)

                # Wait for success
                await wait_for_notification(pilot, "Key pair generated successfully")

                # Verify files created
                pk_file = Path(temp_dir) / "testkey.pub"
                sk_file = Path(temp_dir) / "testkey.sec"
                assert pk_file.exists()
                assert sk_file.exists()

    @pytest.mark.asyncio
    async def test_generate_signing_keys(self):
        """Test generating ECDSA signing keys through the TUI"""
        with tempfile.TemporaryDirectory() as temp_dir:
            app = DCypherTUI()
            async with app.run_test(size=(160, 60)) as pilot:
                # Navigate to Crypto tab
                await pilot.press("3")
                await pilot.pause(0.5)

                # Generate signing keys
                gen_signing_btn = pilot.app.query_one("#gen-signing-btn")
                await pilot.click(gen_signing_btn)

                # Wait for success
                await wait_for_notification(
                    pilot, "Signing keys generated successfully"
                )

                # Note: Default paths are used, we'd need to update the UI to accept custom paths

    @pytest.mark.asyncio
    async def test_encrypt_decrypt_text_flow(self, tmp_path):
        """Test encrypting and decrypting text data through the TUI"""
        with tempfile.TemporaryDirectory() as temp_dir:
            app = DCypherTUI()
            async with app.run_test(size=(160, 60)) as pilot:
                # Navigate to Crypto tab
                await pilot.press("3")
                await pilot.pause(0.5)

                # Setup: Generate crypto context and keys
                cc_output = pilot.app.query_one("#cc-output-path")
                cc_output.value = f"{temp_dir}/cc.json"

                await pilot.click("#gen-cc-btn")
                await wait_for_notification(pilot, "Crypto context generated")

                key_prefix = pilot.app.query_one("#key-prefix")
                key_prefix.value = f"{temp_dir}/key"

                await pilot.click("#gen-keys-btn")
                await wait_for_notification(pilot, "Key pair generated successfully")

                await pilot.click("#gen-signing-btn")
                await wait_for_notification(
                    pilot, "Signing keys generated successfully"
                )

                # Update file paths
                pk_path = pilot.app.query_one("#pk-path")
                pk_path.value = f"{temp_dir}/key.pub"

                sk_path = pilot.app.query_one("#sk-path")
                sk_path.value = f"{temp_dir}/key.sec"

                # Enter text to encrypt
                encrypt_input = pilot.app.query_one("#encrypt-input")
                test_message = "Hello, homomorphic encryption!"
                encrypt_input.text = test_message

                # Select text input type
                input_type = pilot.app.query_one("#input-type-select")
                input_type.value = "text"

                # Encrypt
                await pilot.click("#encrypt-btn")
                await wait_for_notification(pilot, "Encryption completed successfully")

                # Verify ciphertext file created
                ciphertext_file = Path("ciphertext.idk")
                assert ciphertext_file.exists()

                # Now decrypt
                await pilot.click("#decrypt-btn")
                await wait_for_notification(pilot, "Decryption completed successfully")

                # Verify decrypted output
                decrypted_file = Path("decrypted_output.txt")
                assert decrypted_file.exists()

                with open(decrypted_file, "r") as f:
                    decrypted_text = f.read()
                    assert decrypted_text == test_message

                # Cleanup
                ciphertext_file.unlink(missing_ok=True)
                decrypted_file.unlink(missing_ok=True)

    @pytest.mark.asyncio
    async def test_encrypt_file_input(self, tmp_path):
        """Test encrypting a file through the TUI"""
        # Create test file
        test_file = tmp_path / "test_input.txt"
        test_content = "This is a test file for encryption"
        test_file.write_text(test_content)

        app = DCypherTUI()
        async with app.run_test(size=(160, 60)) as pilot:
            # Navigate to Crypto tab and setup
            await pilot.press("3")
            await pilot.pause(0.5)

            # Quick setup of crypto context and keys
            cc_output = pilot.app.query_one("#cc-output-path")
            cc_output.value = f"{tmp_path}/cc.json"
            await pilot.click("#gen-cc-btn")
            await wait_for_notification(pilot, "Crypto context generated")

            key_prefix = pilot.app.query_one("#key-prefix")
            key_prefix.value = f"{tmp_path}/key"
            await pilot.click("#gen-keys-btn")
            await wait_for_notification(pilot, "Key pair generated successfully")

            await pilot.click("#gen-signing-btn")
            await wait_for_notification(pilot, "Signing keys generated successfully")

            # Update paths
            pk_path = pilot.app.query_one("#pk-path")
            pk_path.value = f"{tmp_path}/key.pub"

            # Enter file path in text area
            encrypt_input = pilot.app.query_one("#encrypt-input")
            encrypt_input.text = str(test_file)

            # Select file input type
            input_type = pilot.app.query_one("#input-type-select")
            input_type.value = "file"

            # Encrypt
            await pilot.click("#encrypt-btn")
            await wait_for_notification(pilot, "Encryption completed successfully")

            # Verify ciphertext created
            assert Path("ciphertext.idk").exists()
            Path("ciphertext.idk").unlink()

    @pytest.mark.asyncio
    async def test_generate_reencryption_key(self, tmp_path):
        """Test generating a re-encryption key through the TUI"""
        with tempfile.TemporaryDirectory() as temp_dir:
            app = DCypherTUI()
            async with app.run_test(size=(160, 60)) as pilot:
                # Navigate to Crypto tab
                await pilot.press("3")
                await pilot.pause(0.5)

                # Generate crypto context
                cc_output = pilot.app.query_one("#cc-output-path")
                cc_output.value = f"{temp_dir}/cc.json"
                await pilot.click("#gen-cc-btn")
                await wait_for_notification(pilot, "Crypto context generated")

                # Generate Alice's keys
                key_prefix = pilot.app.query_one("#key-prefix")
                key_prefix.value = f"{temp_dir}/alice"
                await pilot.click("#gen-keys-btn")
                await wait_for_notification(pilot, "Key pair generated successfully")

                # Generate Bob's keys
                key_prefix.value = f"{temp_dir}/bob"
                await pilot.click("#gen-keys-btn")
                await wait_for_notification(pilot, "Key pair generated successfully")

                # Set paths for re-encryption key generation
                alice_sk = pilot.app.query_one("#alice-sk-path")
                alice_sk.value = f"{temp_dir}/alice.sec"

                bob_pk = pilot.app.query_one("#bob-pk-path")
                bob_pk.value = f"{temp_dir}/bob.pub"

                # Generate re-encryption key
                await pilot.click("#gen-rekey-btn")
                await wait_for_notification(
                    pilot, "Re-encryption key generated successfully"
                )

                # Verify rekey file created
                rekey_file = Path("rekey.json")
                assert rekey_file.exists()

                with open(rekey_file, "r") as f:
                    rekey_data = json.load(f)
                    assert "rekey" in rekey_data

                rekey_file.unlink()

    @pytest.mark.asyncio
    async def test_crypto_files_table_updates(self):
        """Test that the crypto files table updates when files are created"""
        with tempfile.TemporaryDirectory() as temp_dir:
            app = DCypherTUI()
            async with app.run_test(size=(160, 60)) as pilot:
                # Navigate to Crypto tab
                await pilot.press("3")
                await pilot.pause(0.5)

                # Check initial table state
                table = pilot.app.query_one("#crypto-files-table")
                initial_rows = len(table.rows)

                # Generate a crypto context
                cc_output = pilot.app.query_one("#cc-output-path")
                cc_output.value = "cc.json"
                await pilot.click("#gen-cc-btn")
                await wait_for_notification(pilot, "Crypto context generated")

                # Table should have updated
                await pilot.pause(0.5)
                assert len(table.rows) > initial_rows

                # Cleanup
                Path("cc.json").unlink(missing_ok=True)

    @pytest.mark.asyncio
    async def test_crypto_error_handling(self):
        """Test error handling in crypto operations"""
        app = DCypherTUI()
        async with app.run_test(size=(160, 60)) as pilot:
            # Navigate to Crypto tab
            await pilot.press("3")
            await pilot.pause(0.5)

            # Try to generate keys without crypto context
            await pilot.click("#gen-keys-btn")
            await wait_for_notification(
                pilot, "Crypto context file not found", severity="error"
            )

            # Try to encrypt without required files
            await pilot.click("#encrypt-btn")
            await wait_for_notification(
                pilot, "Enter data to encrypt", severity="warning"
            )

            # Enter data but still missing files
            encrypt_input = pilot.app.query_one("#encrypt-input")
            encrypt_input.text = "test data"
            await pilot.click("#encrypt-btn")
            await wait_for_notification(
                pilot, "crypto context file not found", severity="error"
            )

    @pytest.mark.asyncio
    async def test_reencrypt_warning(self):
        """Test that re-encryption shows proper warning about IDK format"""
        app = DCypherTUI()
        async with app.run_test(size=(160, 60)) as pilot:
            # Navigate to Crypto tab
            await pilot.press("3")
            await pilot.pause(0.5)

            # Click re-encrypt button
            await pilot.click("#re-encrypt-btn")

            # Should show warning about IDK format not supported
            await wait_for_notification(
                pilot, "Re-encryption requires JSON format", severity="warning"
            )

            # Check results display
            crypto_screen = pilot.app.query_one(CryptoScreen)
            assert (
                "IDK message re-encryption not yet supported"
                in crypto_screen.operation_results
            )
