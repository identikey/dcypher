"""
File Management Screen
Handles file upload, download, and management operations
"""

import json
import gzip
from pathlib import Path
from textual.containers import Container, Horizontal, Vertical
from textual.widgets import (
    Static,
    Button,
    Input,
    DataTable,
    Label,
    ProgressBar,
    Select,
    TextArea,
)
from textual.widget import Widget
from textual.reactive import reactive
from rich.panel import Panel
from rich.text import Text
from typing import Optional

# Import file operation modules
try:
    from src.lib.api_client import DCypherClient, DCypherAPIError
    from src.lib import idk_message
    from src.lib import pre
    import base64
    import ecdsa

    files_available = True
except ImportError:
    files_available = False


class FilesScreen(Widget):
    """
    File management screen with CLI feature parity
    Supports: upload, download, download-chunks
    """

    # Reactive state - removed local identity/api state, now using centralized app state
    files_data = reactive([])
    operation_results = reactive("")
    upload_progress = reactive(0.0)

    @property
    def current_identity_path(self):
        """Get current identity path from app state"""
        return getattr(self.app, "current_identity_path", None)

    @property
    def api_url(self):
        """Get API URL from app state"""
        return getattr(self.app, "api_url", "http://127.0.0.1:8000")

    @property
    def api_client(self):
        """Get API client from app"""
        get_client_method = getattr(self.app, "get_or_create_api_client", None)
        if get_client_method and callable(get_client_method):
            return get_client_method()
        return None

    def compose(self):
        """Compose the file management interface"""
        if not files_available:
            yield Static(
                "⚠️ File operation libraries not available. Please install dependencies.",
                classes="error",
            )
            return

        with Container(id="files-container"):
            yield Static("◢ FILE MANAGEMENT ◣", classes="title")

            # Configuration row
            with Horizontal(id="config-row"):
                with Vertical(id="config-panel"):
                    yield Label("Configuration")
                    yield Input(value="http://127.0.0.1:8000", id="api-url-input")
                    yield Input(id="identity-path-input")
                    yield Button("Set Identity", id="set-identity-btn")

                with Vertical(id="status-panel"):
                    yield Static(id="connection-status")
                    yield Static(id="current-identity-status")

            with Horizontal():
                # File operations
                with Vertical(id="file-ops-panel"):
                    yield Label("File Operations")
                    yield Input(id="file-path-input")
                    yield Button("Browse File", id="browse-file-btn")
                    yield Button("Upload File", id="upload-file-btn", variant="primary")
                    yield ProgressBar(id="file-progress", show_eta=False)

                    yield Label("Download Operations")
                    yield Input(id="file-hash-input")
                    yield Input(id="output-path-input")
                    yield Select(
                        [
                            ("Standard Download", "standard"),
                            ("Compressed Download", "compressed"),
                            ("Download Chunks", "chunks"),
                        ],
                        id="download-type-select",
                        value="standard",
                    )
                    yield Button("Download File", id="download-file-btn")

                # File info panel
                with Vertical(id="file-info-panel"):
                    yield Static(id="file-info-display")

            # Results area
            yield Static(id="file-results")

            # Files table
            yield DataTable(id="files-table")

    def on_mount(self) -> None:
        """Initialize files screen"""
        if files_available:
            self.setup_files_table()
            self.update_status_display()
            self.update_results_display()

    def setup_files_table(self) -> None:
        """Setup the files table"""
        table = self.query_one("#files-table", DataTable)
        table.add_columns("Filename", "Hash", "Size", "Uploaded", "Status")

    def update_status_display(self) -> None:
        """Update connection and identity status"""
        connection_widget = self.query_one("#connection-status", Static)
        identity_widget = self.query_one("#current-identity-status", Static)

        # Connection status
        connection_content = Panel(
            Text(f"API URL: {self.api_url}\nStatus: Not tested", style="yellow"),
            title="[bold]Connection[/bold]",
            border_style="yellow",
        )
        connection_widget.update(connection_content)

        # Identity status
        if self.current_identity_path:
            identity_text = f"Identity: {Path(self.current_identity_path).name}\nPath: {self.current_identity_path}"
            style = "green"
        else:
            identity_text = "No identity loaded\nLoad identity to upload files"
            style = "red"

        identity_content = Panel(
            Text(identity_text, style=style),
            title="[bold]Identity[/bold]",
            border_style=style,
        )
        identity_widget.update(identity_content)

    def update_results_display(self) -> None:
        """Update the results display"""
        results_widget = self.query_one("#file-results", Static)

        if self.operation_results:
            content = Panel(
                Text(self.operation_results, style="green"),
                title="[bold]Operation Results[/bold]",
                border_style="green",
            )
        else:
            content = Panel(
                Text("No file operations performed yet", style="dim"),
                title="[bold]Results[/bold]",
                border_style="dim",
            )

        results_widget.update(content)

    def update_file_info_display(self, file_path: Optional[str] = None) -> None:
        """Update file info display"""
        info_widget = self.query_one("#file-info-display", Static)

        if file_path and Path(file_path).exists():
            path_obj = Path(file_path)
            size = path_obj.stat().st_size

            info_text = f"Selected File:\n"
            info_text += f"  Name: {path_obj.name}\n"
            info_text += f"  Size: {size:,} bytes\n"
            info_text += f"  Path: {file_path}"

            content = Panel(
                Text(info_text, style="cyan"),
                title="[bold]File Info[/bold]",
                border_style="cyan",
            )
        else:
            content = Panel(
                Text("No file selected\nEnter file path or browse", style="dim"),
                title="[bold]File Info[/bold]",
                border_style="dim",
            )

        info_widget.update(content)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle file operation buttons"""
        if not files_available:
            self.notify("File operation libraries not available", severity="error")
            return

        button_id = event.button.id

        if button_id == "set-identity-btn":
            self.action_set_identity()
        elif button_id == "browse-file-btn":
            self.action_browse_file()
        elif button_id == "upload-file-btn":
            self.action_upload_file()
        elif button_id == "download-file-btn":
            self.action_download_file()

    def on_input_changed(self, event: Input.Changed) -> None:
        """Handle input changes"""
        if event.input.id == "file-path-input":
            self.update_file_info_display(event.value)

    def action_set_identity(self) -> None:
        """Set the current identity path"""
        identity_input = self.query_one("#identity-path-input", Input)
        api_input = self.query_one("#api-url-input", Input)

        identity_path = identity_input.value
        api_url = api_input.value

        if not identity_path:
            self.notify("Enter identity file path", severity="warning")
            return

        if not Path(identity_path).exists():
            self.notify(f"Identity file not found: {identity_path}", severity="error")
            return

        # Update app state using setattr for type safety
        setattr(self.app, "current_identity_path", identity_path)
        setattr(self.app, "api_url", api_url)
        self.update_status_display()
        self.notify(f"Identity set: {Path(identity_path).name}", severity="information")

    def action_browse_file(self) -> None:
        """Browse for file (placeholder - file browser not implemented)"""
        self.notify(
            "File browser not yet implemented. Please enter file path manually.",
            severity="information",
        )

    def action_upload_file(self) -> None:
        """Upload file (equivalent to CLI upload)"""
        if not self.current_identity_path:
            self.notify("Load an identity first", severity="warning")
            return

        file_input = self.query_one("#file-path-input", Input)
        file_path = file_input.value

        if not file_path:
            self.notify("Enter file path", severity="warning")
            return

        if not Path(file_path).exists():
            self.notify(f"File not found: {file_path}", severity="error")
            return

        try:
            self.notify("Starting file upload...", severity="information")
            progress = self.query_one("#file-progress", ProgressBar)
            progress.update(progress=0)

            # Initialize API client
            client = DCypherClient(
                self.api_url, identity_path=self.current_identity_path
            )

            # Get server's crypto context
            self.notify("Getting server crypto context...", severity="information")
            progress.update(progress=10)
            cc_bytes = client.get_pre_crypto_context()
            cc = pre.deserialize_cc(cc_bytes)

            # Load identity data to get keys
            self.notify("Loading keys from identity file...", severity="information")
            progress.update(progress=20)
            with open(self.current_identity_path, "r") as f:
                identity_data = json.load(f)

            # Get PRE public key from identity
            if (
                "pre" not in identity_data["auth_keys"]
                or not identity_data["auth_keys"]["pre"]
            ):
                self.notify(
                    "Identity file does not contain PRE keys. Initialize PRE first.",
                    severity="error",
                )
                return

            pre_pk_hex = identity_data["auth_keys"]["pre"]["pk_hex"]
            pre_pk_bytes = bytes.fromhex(pre_pk_hex)
            pk_enc = pre.deserialize_public_key(pre_pk_bytes)

            # Get signing key from identity
            classic_sk_hex = identity_data["auth_keys"]["classic"]["sk_hex"]
            sk_sign_idk = ecdsa.SigningKey.from_string(
                bytes.fromhex(classic_sk_hex), curve=ecdsa.SECP256k1
            )

            # Get classic public key for API operations
            pk_classic_hex = client.get_classic_public_key()

            # Create IDK message parts in memory
            self.notify(
                "Encrypting file and creating IDK message parts...",
                severity="information",
            )
            progress.update(progress=40)
            with open(file_path, "rb") as f:
                file_content_bytes = f.read()

            message_parts = idk_message.create_idk_message_parts(
                data=file_content_bytes,
                cc=cc,
                pk=pk_enc,
                signing_key=sk_sign_idk,
            )
            part_one_content = message_parts[0]
            data_chunks = message_parts[1:]
            total_chunks = len(message_parts)

            # Parse the header to get file hash
            part_one_parsed = idk_message.parse_idk_message_part(part_one_content)
            file_hash = part_one_parsed["headers"]["MerkleRoot"]

            progress.update(progress=60)
            self.notify(f"File hash: {file_hash}", severity="information")

            # Register the file
            self.notify("Registering file with API...", severity="information")
            result = client.register_file(
                pk_classic_hex,
                file_hash,
                part_one_content,
                Path(file_path).name,
                "application/octet-stream",
                len(file_content_bytes),
            )

            progress.update(progress=80)

            # Upload data chunks
            if data_chunks:
                self.notify(
                    f"Uploading {len(data_chunks)} data chunks...",
                    severity="information",
                )
                for i, chunk_content in enumerate(data_chunks):
                    # Compress chunk for upload
                    compressed_chunk = gzip.compress(chunk_content.encode("utf-8"))

                    # Calculate hash of the original chunk content
                    import hashlib

                    chunk_hash = hashlib.blake2b(
                        chunk_content.encode("utf-8")
                    ).hexdigest()

                    result = client.upload_chunk(
                        pk_classic_hex,
                        file_hash,
                        compressed_chunk,
                        chunk_hash,
                        i + 1,  # chunk_index (1-based)
                        len(data_chunks),
                        compressed=True,
                    )

                    # Update progress for each chunk
                    chunk_progress = 80 + (20 * (i + 1) / len(data_chunks))
                    progress.update(progress=chunk_progress)

            progress.update(progress=100)

            self.operation_results = f"✓ Upload completed successfully!\n  File: {Path(file_path).name}\n  Hash: {file_hash}\n  Size: {len(file_content_bytes):,} bytes\n  Chunks: {len(data_chunks)}"
            self.update_results_display()
            self.refresh_files_list()
            self.notify("File uploaded successfully!", severity="information")

        except DCypherAPIError as e:
            self.notify(f"API request failed: {e}", severity="error")
        except Exception as e:
            self.notify(f"Upload failed: {e}", severity="error")
        finally:
            progress.update(progress=0)

    def action_download_file(self) -> None:
        """Download file (equivalent to CLI download/download-chunks)"""
        if not self.current_identity_path:
            self.notify("Load an identity first", severity="warning")
            return

        hash_input = self.query_one("#file-hash-input", Input)
        output_input = self.query_one("#output-path-input", Input)
        download_type_select = self.query_one("#download-type-select", Select)

        file_hash = hash_input.value
        output_path = output_input.value
        download_type = download_type_select.value

        if not file_hash:
            self.notify("Enter file hash", severity="warning")
            return

        if not output_path:
            output_path = f"downloaded_{file_hash[:8]}.dat"
            output_input.value = output_path

        try:
            self.notify(f"Starting {download_type} download...", severity="information")
            progress = self.query_one("#file-progress", ProgressBar)
            progress.update(progress=0)

            # Initialize API client with identity file
            client = DCypherClient(
                self.api_url, identity_path=self.current_identity_path
            )
            pk_classic_hex = client.get_classic_public_key()

            progress.update(progress=30)

            if download_type == "chunks":
                # Download chunks (equivalent to CLI download-chunks)
                self.notify(
                    "Downloading concatenated chunks...", severity="information"
                )
                downloaded_content = client.download_chunks(pk_classic_hex, file_hash)
            else:
                # Standard or compressed download (equivalent to CLI download)
                compressed = download_type == "compressed"
                self.notify(
                    f"Downloading file {'(compressed)' if compressed else ''}...",
                    severity="information",
                )
                downloaded_content = client.download_file(
                    pk_classic_hex, file_hash, compressed
                )

            progress.update(progress=70)

            # Save the downloaded content
            with open(output_path, "wb") as f:
                f.write(downloaded_content)

            progress.update(progress=100)

            # Verify integrity if it's a standard download
            if download_type == "standard":
                try:
                    # Try to verify IDK message integrity
                    content_to_verify = downloaded_content
                    parsed_part = idk_message.parse_idk_message_part(
                        content_to_verify.decode("utf-8")
                    )
                    computed_hash = parsed_part["headers"]["MerkleRoot"]

                    if computed_hash == file_hash:
                        integrity_status = "✓ Integrity verified"
                    else:
                        integrity_status = "⚠️ Integrity check failed"
                except:
                    integrity_status = "⚠️ Could not verify integrity"
            else:
                integrity_status = "No integrity check for this download type"

            self.operation_results = f"✓ Download completed successfully!\n  File Hash: {file_hash}\n  Output: {output_path}\n  Size: {len(downloaded_content):,} bytes\n  Type: {download_type}\n  {integrity_status}"
            self.update_results_display()
            self.notify("File downloaded successfully!", severity="information")

        except DCypherAPIError as e:
            self.notify(f"Download failed: {e}", severity="error")
        except Exception as e:
            self.notify(f"Download error: {e}", severity="error")
        finally:
            progress.update(progress=0)

    def refresh_files_list(self) -> None:
        """Refresh the files list from server"""
        if not self.current_identity_path:
            return

        try:
            client = DCypherClient(
                self.api_url, identity_path=self.current_identity_path
            )
            pk_classic_hex = client.get_classic_public_key()
            files = client.list_files(pk_classic_hex)

            # Update table
            table = self.query_one("#files-table", DataTable)
            table.clear()

            for file_info in files:
                filename = file_info.get("filename", "N/A")
                file_hash = file_info.get("hash", "N/A")
                size = file_info.get("size", "Unknown")
                uploaded = file_info.get("uploaded_at", "Unknown")
                status = "Available"

                table.add_row(
                    filename,
                    file_hash[:16] + "..." if len(file_hash) > 16 else file_hash,
                    str(size),
                    uploaded,
                    status,
                )

        except Exception as e:
            # Don't show error notifications for background refresh
            pass

    def watch_operation_results(self, results: str) -> None:
        """Update display when results change"""
        self.update_results_display()

    def watch_current_identity_path(self, path: str) -> None:
        """Update display when identity changes"""
        self.update_status_display()
        if path:
            self.refresh_files_list()
