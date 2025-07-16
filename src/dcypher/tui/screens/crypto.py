"""
Crypto Operations Screen
Handles encryption, decryption, key generation, and recryption
"""

import json
import base64
from pathlib import Path
from textual.containers import Container, Horizontal, Vertical
from textual.widgets import Static, Button, Input, DataTable, Label, TextArea, Select
from textual.widget import Widget
from textual.reactive import reactive
from rich.panel import Panel
from rich.text import Text

# Import crypto libraries
try:
    from dcypher.lib import pre
    from dcypher.lib.key_manager import KeyManager
    from dcypher.lib import idk_message
    import ecdsa

    crypto_available = True
except ImportError:
    crypto_available = False


class CryptoScreen(Widget):
    """
    Cryptographic operations screen with CLI feature parity
    Supports: gen-cc, gen-keys, encrypt, decrypt, gen-rekey, recrypt
    """

    # Reactive state
    crypto_context_path = reactive("cc.json")
    current_keys = reactive({})
    operation_results = reactive("")

    def compose(self):
        """Compose the crypto operations interface"""
        if not crypto_available:
            yield Static(
                "⚠️ Crypto libraries not available. Please install dependencies.",
                classes="error",
            )
            return

        with Container(id="crypto-container"):
            yield Static("◢ CRYPTOGRAPHIC OPERATIONS ◣", classes="title")

            with Horizontal():
                # Key generation panel
                with Vertical(id="key-gen-panel"):
                    yield Label("Key Generation")
                    yield Input(
                        placeholder="cc.json", id="cc-output-path", value="cc.json"
                    )
                    yield Button(
                        "Generate Crypto Context", id="gen-cc-btn", variant="primary"
                    )

                    yield Input(placeholder="key prefix", id="key-prefix", value="key")
                    yield Button("Generate Key Pair", id="gen-keys-btn")
                    yield Button("Generate Signing Keys", id="gen-signing-btn")

                # Encryption panel
                with Vertical(id="encryption-panel"):
                    yield Label("Encryption Operations")
                    yield Label("Data to encrypt:")
                    yield TextArea(id="encrypt-input")
                    yield Select(
                        [("Text Input", "text"), ("File Path", "file")],
                        id="input-type-select",
                        value="text",
                    )

                    with Horizontal():
                        yield Button("Encrypt", id="encrypt-btn", variant="success")
                        yield Button("Decrypt", id="decrypt-btn", variant="warning")

            # Recryption panel
            with Horizontal():
                with Vertical(id="recrypt-panel"):
                    yield Label("Proxy Recryption")
                    yield Input(placeholder="Alice secret key path", id="alice-sk-path")
                    yield Input(placeholder="Bob public key path", id="bob-pk-path")
                    yield Button("Generate Re-key", id="gen-rekey-btn")
                    yield Button("Recrypt", id="recrypt-btn")

                # File paths panel
                with Vertical(id="file-paths-panel"):
                    yield Label("File Paths")
                    yield Input(
                        placeholder="Public key path", id="pk-path", value="key.pub"
                    )
                    yield Input(
                        placeholder="Secret key path", id="sk-path", value="key.sec"
                    )
                    yield Input(
                        placeholder="Signing key path",
                        id="signing-key-path",
                        value="idk_signing.sec",
                    )
                    yield Input(
                        placeholder="Verifying key path",
                        id="verifying-key-path",
                        value="idk_signing.pub",
                    )

            # Results area
            yield Static(id="crypto-results")
            yield DataTable(id="crypto-files-table")

    def on_mount(self) -> None:
        """Initialize crypto screen"""
        if crypto_available:
            self.setup_crypto_files_table()
            self.update_results_display()

    def setup_crypto_files_table(self) -> None:
        """Setup the crypto files table"""
        table = self.query_one("#crypto-files-table", DataTable)
        table.add_columns("File", "Type", "Path", "Size", "Created")

        # Scan for existing crypto files
        self.refresh_crypto_files()

    def refresh_crypto_files(self) -> None:
        """Refresh the list of crypto files"""
        table = self.query_one("#crypto-files-table", DataTable)
        table.clear()

        # Look for common crypto files
        crypto_files = [
            ("cc.json", "Crypto Context"),
            ("key.pub", "Public Key"),
            ("key.sec", "Secret Key"),
            ("idk_signing.pub", "Signing Public Key"),
            ("idk_signing.sec", "Signing Secret Key"),
            ("rekey.json", "Recryption Key"),
            ("ciphertext.idk", "IDK Message"),
        ]

        for filename, file_type in crypto_files:
            path = Path(filename)
            if path.exists():
                size = path.stat().st_size
                created = path.stat().st_mtime
                table.add_row(
                    filename, file_type, str(path), f"{size} bytes", str(created)
                )

    def update_results_display(self) -> None:
        """Update the results display"""
        results_widget = self.query_one("#crypto-results", Static)

        if self.operation_results:
            content = Panel(
                Text(self.operation_results, style="green"),
                title="[bold]Operation Results[/bold]",
                border_style="green",
            )
        else:
            content = Panel(
                Text("No operations performed yet", style="dim"),
                title="[bold]Results[/bold]",
                border_style="dim",
            )

        results_widget.update(content)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle crypto operation buttons"""
        if not crypto_available:
            self.notify("Crypto libraries not available", severity="error")
            return

        button_id = event.button.id

        if button_id == "gen-cc-btn":
            self.action_generate_crypto_context()
        elif button_id == "gen-keys-btn":
            self.action_generate_keys()
        elif button_id == "gen-signing-btn":
            self.action_generate_signing_keys()
        elif button_id == "encrypt-btn":
            self.action_encrypt()
        elif button_id == "decrypt-btn":
            self.action_decrypt()
        elif button_id == "gen-rekey-btn":
            self.action_generate_rekey()
        elif button_id == "recrypt-btn":
            self.action_re_encrypt()

    def action_generate_crypto_context(self) -> None:
        """Generate crypto context (equivalent to CLI gen-cc)"""
        try:
            output_path = self.query_one("#cc-output-path", Input).value or "cc.json"

            self.notify("Generating crypto context...", severity="information")

            # Generate crypto context using same parameters as CLI
            cc = pre.create_crypto_context(plaintext_modulus=65537, scaling_mod_size=60)
            serialized_cc = pre.serialize(cc)

            # Save to file
            with open(output_path, "w") as f:
                json.dump({"cc": serialized_cc}, f)

            self.operation_results = f"✓ Crypto context saved to {output_path}"
            self.update_results_display()
            self.refresh_crypto_files()
            self.notify(f"Crypto context generated: {output_path}", severity="success")

        except Exception as e:
            self.notify(f"Failed to generate crypto context: {e}", severity="error")

    def action_generate_keys(self) -> None:
        """Generate key pair (equivalent to CLI gen-keys)"""
        try:
            cc_path = self.query_one("#cc-output-path", Input).value or "cc.json"
            key_prefix = self.query_one("#key-prefix", Input).value or "key"

            if not Path(cc_path).exists():
                self.notify(
                    "Crypto context file not found. Generate it first.",
                    severity="error",
                )
                return

            self.notify("Generating key pair...", severity="information")

            # Load crypto context
            with open(cc_path, "r") as f:
                cc_data = json.load(f)
            cc = pre.deserialize_cc(base64.b64decode(cc_data["cc"]))

            # Generate keys
            keys = pre.generate_keys(cc)

            serialized_pk = pre.serialize(keys.publicKey)
            serialized_sk = pre.serialize(keys.secretKey)

            pk_path = f"{key_prefix}.pub"
            sk_path = f"{key_prefix}.sec"

            # Save keys
            with open(pk_path, "w") as f:
                json.dump({"key": serialized_pk}, f)

            with open(sk_path, "w") as f:
                json.dump({"key": serialized_sk}, f)

            self.operation_results = (
                f"✓ Key pair generated:\n  Public: {pk_path}\n  Secret: {sk_path}"
            )
            self.update_results_display()
            self.refresh_crypto_files()
            self.notify("Key pair generated successfully", severity="success")

        except Exception as e:
            self.notify(f"Failed to generate keys: {e}", severity="error")

    def action_generate_signing_keys(self) -> None:
        """Generate ECDSA signing keys (equivalent to CLI gen-signing-keys)"""
        try:
            self.notify("Generating ECDSA signing key pair...", severity="information")

            # Generate classic ECDSA key pair
            sk, pk_hex = KeyManager.generate_classic_keypair()

            pk_path = "idk_signing.pub"
            sk_path = "idk_signing.sec"

            # Save keys
            with open(pk_path, "w") as f:
                f.write(pk_hex)

            with open(sk_path, "w") as f:
                f.write(sk.to_string().hex())

            self.operation_results = f"✓ Signing key pair generated:\n  Public: {pk_path}\n  Secret: {sk_path}"
            self.update_results_display()
            self.refresh_crypto_files()
            self.notify("Signing keys generated successfully", severity="success")

        except Exception as e:
            self.notify(f"Failed to generate signing keys: {e}", severity="error")

    def action_encrypt(self) -> None:
        """Encrypt data (equivalent to CLI encrypt)"""
        try:
            input_area = self.query_one("#encrypt-input", TextArea)
            input_type = self.query_one("#input-type-select", Select).value
            cc_path = self.query_one("#cc-output-path", Input).value or "cc.json"
            pk_path = self.query_one("#pk-path", Input).value or "key.pub"
            signing_key_path = (
                self.query_one("#signing-key-path", Input).value or "idk_signing.sec"
            )

            data_input = input_area.text
            if not data_input:
                self.notify("Enter data to encrypt", severity="warning")
                return

            # Check required files exist
            for path, name in [
                (cc_path, "crypto context"),
                (pk_path, "public key"),
                (signing_key_path, "signing key"),
            ]:
                if not Path(path).exists():
                    self.notify(f"{name} file not found: {path}", severity="error")
                    return

            self.notify("Encrypting data...", severity="information")

            # Load crypto context
            with open(cc_path, "r") as f:
                cc_data = json.load(f)
            cc = pre.deserialize_cc(base64.b64decode(cc_data["cc"]))

            # Load public key
            with open(pk_path, "r") as f:
                pk_data = json.load(f)
            pk = pre.deserialize_public_key(base64.b64decode(pk_data["key"]))

            # Load signing key
            with open(signing_key_path, "r") as f:
                sk_hex = f.read()
                sk_sign = ecdsa.SigningKey.from_string(
                    bytes.fromhex(sk_hex), curve=ecdsa.SECP256k1
                )

            # Prepare data
            if input_type == "file":
                try:
                    with open(data_input, "rb") as f:
                        input_data_bytes = f.read()
                except Exception as e:
                    self.notify(f"Could not read file: {e}", severity="error")
                    return
            else:
                input_data_bytes = data_input.encode("utf-8")

            # Create IDK message
            message_parts = idk_message.create_idk_message_parts(
                data=input_data_bytes,
                cc=cc,
                pk=pk,
                signing_key=sk_sign,
            )

            output_path = "ciphertext.idk"
            with open(output_path, "w") as f:
                f.write("\n".join(message_parts))

            self.operation_results = f"✓ Data encrypted and saved to {output_path}\n  Parts: {len(message_parts)}"
            self.update_results_display()
            self.refresh_crypto_files()
            self.notify("Encryption completed successfully", severity="success")

        except Exception as e:
            self.notify(f"Encryption failed: {e}", severity="error")

    def action_decrypt(self) -> None:
        """Decrypt data (equivalent to CLI decrypt)"""
        try:
            cc_path = self.query_one("#cc-output-path", Input).value or "cc.json"
            sk_path = self.query_one("#sk-path", Input).value or "key.sec"
            verifying_key_path = (
                self.query_one("#verifying-key-path", Input).value or "idk_signing.pub"
            )
            ciphertext_path = "ciphertext.idk"

            # Check required files exist
            for path, name in [
                (cc_path, "crypto context"),
                (sk_path, "secret key"),
                (verifying_key_path, "verifying key"),
                (ciphertext_path, "ciphertext"),
            ]:
                if not Path(path).exists():
                    self.notify(f"{name} file not found: {path}", severity="error")
                    return

            self.notify("Decrypting data...", severity="information")

            # Load crypto context
            with open(cc_path, "r") as f:
                cc_data = json.load(f)
            cc = pre.deserialize_cc(base64.b64decode(cc_data["cc"]))

            # Load secret key
            with open(sk_path, "r") as f:
                sk_data = json.load(f)
            sk = pre.deserialize_secret_key(base64.b64decode(sk_data["key"]))

            # Load IDK message
            with open(ciphertext_path, "r") as f:
                message_content = f.read()

            # Decrypt
            decrypted_data = idk_message.decrypt_idk_message(
                cc=cc, sk=sk, message_str=message_content
            )

            output_path = "decrypted_output.txt"
            Path(output_path).write_bytes(decrypted_data)

            # Show preview of decrypted data
            try:
                preview = decrypted_data.decode("utf-8")[:200] + (
                    "..." if len(decrypted_data) > 200 else ""
                )
            except:
                preview = f"<binary data, {len(decrypted_data)} bytes>"

            self.operation_results = f"✓ Decryption successful!\n  Output: {output_path}\n  Preview: {preview}"
            self.update_results_display()
            self.refresh_crypto_files()
            self.notify("Decryption completed successfully", severity="success")

        except Exception as e:
            self.notify(f"Decryption failed: {e}", severity="error")

    def action_generate_rekey(self) -> None:
        """Generate recryption key (equivalent to CLI gen-rekey)"""
        try:
            alice_sk_path = self.query_one("#alice-sk-path", Input).value
            bob_pk_path = self.query_one("#bob-pk-path", Input).value
            cc_path = self.query_one("#cc-output-path", Input).value or "cc.json"

            if not alice_sk_path or not bob_pk_path:
                self.notify(
                    "Enter Alice secret key and Bob public key paths",
                    severity="warning",
                )
                return

            # Check files exist
            for path, name in [
                (cc_path, "crypto context"),
                (alice_sk_path, "Alice secret key"),
                (bob_pk_path, "Bob public key"),
            ]:
                if not Path(path).exists():
                    self.notify(f"{name} file not found: {path}", severity="error")
                    return

            self.notify("Generating recryption key...", severity="information")

            # Load crypto context
            with open(cc_path, "r") as f:
                cc_data = json.load(f)
            cc = pre.deserialize_cc(base64.b64decode(cc_data["cc"]))

            # Load Alice's secret key
            with open(alice_sk_path, "r") as f:
                sk_data = json.load(f)
            sk_alice = pre.deserialize_secret_key(base64.b64decode(sk_data["key"]))

            # Load Bob's public key
            with open(bob_pk_path, "r") as f:
                pk_data = json.load(f)
            pk_bob = pre.deserialize_public_key(base64.b64decode(pk_data["key"]))

            # Generate recryption key
            rekey = pre.generate_re_encryption_key(cc, sk_alice, pk_bob)
            serialized_rekey = pre.serialize(rekey)

            output_path = "rekey.json"
            with open(output_path, "w") as f:
                json.dump({"rekey": serialized_rekey}, f)

            self.operation_results = f"✓ Recryption key generated: {output_path}"
            self.update_results_display()
            self.refresh_crypto_files()
            self.notify("Recryption key generated successfully", severity="success")

        except Exception as e:
            self.notify(f"Failed to generate recryption key: {e}", severity="error")

    def action_re_encrypt(self) -> None:
        """Recrypt ciphertext (equivalent to CLI recrypt)"""
        try:
            cc_path = self.query_one("#cc-output-path", Input).value or "cc.json"
            rekey_path = "rekey.json"
            ciphertext_path = "ciphertext.json"  # Note: needs JSON format, not IDK

            self.notify("Recrypting ciphertext...", severity="information")
            self.notify(
                "Note: Recryption requires JSON ciphertext format, not IDK messages",
                severity="warning",
            )

            self.operation_results = "⚠️ Recryption requires JSON format ciphertext.\nIDK message recryption not yet supported in TUI."
            self.update_results_display()

        except Exception as e:
            self.notify(f"Recryption failed: {e}", severity="error")

    def watch_operation_results(self, results: str) -> None:
        """Update display when results change"""
        self.update_results_display()
