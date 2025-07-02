"""
Sharing Management Screen
Handles proxy re-encryption sharing operations
"""

import json
from pathlib import Path
from textual.containers import Container, Horizontal, Vertical
from textual.widgets import Static, Button, Input, DataTable, Label, Select
from textual.widget import Widget
from textual.reactive import reactive
from rich.panel import Panel
from rich.text import Text

# Import sharing operation modules
try:
    from lib.api_client import DCypherClient, DCypherAPIError

    sharing_available = True
except ImportError:
    sharing_available = False

    class DCypherAPIError(Exception):
        pass

    class DCypherClient:
        def __init__(self, *args, **kwargs):
            pass

        def get_account(self, *args, **kwargs):
            raise DCypherAPIError("Sharing libraries not available")

        def generate_re_encryption_key(self, *args, **kwargs):
            raise DCypherAPIError("Sharing libraries not available")

        def create_share(self, *args, **kwargs):
            raise DCypherAPIError("Sharing libraries not available")

        def list_shares(self, *args, **kwargs):
            raise DCypherAPIError("Sharing libraries not available")

        def download_shared_file(self, *args, **kwargs):
            raise DCypherAPIError("Sharing libraries not available")

        def revoke_share(self, *args, **kwargs):
            raise DCypherAPIError("Sharing libraries not available")

        def get_classic_public_key(self, *args, **kwargs):
            raise DCypherAPIError("Sharing libraries not available")

        def get_pre_crypto_context(self, *args, **kwargs):
            raise DCypherAPIError("Sharing libraries not available")

        def initialize_pre_for_identity(self, *args, **kwargs):
            raise DCypherAPIError("Sharing libraries not available")


class SharingScreen(Widget):
    """
    Sharing management screen with CLI feature parity
    Supports: init-pre, create-share, list-shares, download-shared, revoke-share, get-pre-context
    """

    # Reactive state
    shares_data = reactive([])
    operation_results = reactive("")

    @property
    def current_identity_path(self) -> str | None:
        """Get current identity from global app state"""
        return getattr(self.app, "current_identity", None)

    @property
    def api_url(self) -> str:
        """Get API URL from global app state"""
        return getattr(self.app, "api_url", "http://127.0.0.1:8000")

    def compose(self):
        """Compose the sharing management interface"""
        if not sharing_available:
            yield Static(
                "⚠️ Sharing libraries not available. Please install dependencies.",
                classes="error",
            )
            return

        with Container(id="sharing-container"):
            yield Static("◢ PROXY RE-ENCRYPTION SHARING ◣", classes="title")

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
                # PRE operations
                with Vertical(id="pre-ops-panel"):
                    yield Label("PRE Operations")
                    yield Button("Get PRE Context", id="get-pre-context-btn")
                    yield Button("Initialize PRE", id="init-pre-btn", variant="primary")
                    yield Button("List Shares", id="list-shares-btn")

                # Share operations
                with Vertical(id="share-ops-panel"):
                    yield Label("Share Management")
                    yield Input(id="recipient-key-input")
                    yield Input(id="file-hash-input")
                    yield Button("Create Share", id="create-share-btn")

                    yield Label("Download Shared Files")
                    yield Input(id="share-id-input")
                    yield Input(id="download-output-input")
                    yield Button("Download Shared", id="download-shared-btn")
                    yield Button("Revoke Share", id="revoke-share-btn")

            # Results area
            yield Static(id="sharing-results")

            # Shares table
            yield DataTable(id="shares-table")

    def on_mount(self) -> None:
        """Initialize sharing screen"""
        if sharing_available:
            self.setup_shares_table()
            self.update_status_display()
            self.update_results_display()

    def setup_shares_table(self) -> None:
        """Setup the shares table"""
        table = self.query_one("#shares-table", DataTable)
        table.add_columns(
            "Share ID", "File Hash", "Recipient/Sender", "Created", "Status", "Type"
        )

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
            identity_text = "No identity loaded\nLoad identity for sharing operations"
            style = "red"

        identity_content = Panel(
            Text(identity_text, style=style),
            title="[bold]Identity[/bold]",
            border_style=style,
        )
        identity_widget.update(identity_content)

    def update_results_display(self) -> None:
        """Update the results display"""
        results_widget = self.query_one("#sharing-results", Static)

        if self.operation_results:
            content = Panel(
                Text(self.operation_results, style="green"),
                title="[bold]Operation Results[/bold]",
                border_style="green",
            )
        else:
            content = Panel(
                Text("No sharing operations performed yet", style="dim"),
                title="[bold]Results[/bold]",
                border_style="dim",
            )

        results_widget.update(content)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle sharing operation buttons"""
        if not sharing_available:
            self.notify("Sharing libraries not available", severity="error")
            return

        button_id = event.button.id

        if button_id == "set-identity-btn":
            self.action_set_identity()
        elif button_id == "get-pre-context-btn":
            self.action_get_pre_context()
        elif button_id == "init-pre-btn":
            self.action_init_pre()
        elif button_id == "create-share-btn":
            self.action_create_share()
        elif button_id == "list-shares-btn":
            self.action_list_shares()
        elif button_id == "download-shared-btn":
            self.action_download_shared()
        elif button_id == "revoke-share-btn":
            self.action_revoke_share()

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

        # Set identity in global app state
        if hasattr(self.app, "current_identity"):
            self.app.current_identity = identity_path
        if hasattr(self.app, "api_url"):
            self.app.api_url = api_url
        self.update_status_display()
        self.notify(f"Identity set: {Path(identity_path).name}", severity="information")

    def action_get_pre_context(self) -> None:
        """Get PRE context (equivalent to CLI get-pre-context)"""
        try:
            self.notify("Downloading PRE crypto context...", severity="information")

            client = DCypherClient(self.api_url)
            context_bytes = client.get_pre_crypto_context()

            output_path = "pre_context.dat"
            with open(output_path, "wb") as f:
                f.write(context_bytes)

            self.operation_results = f"✓ PRE crypto context saved to {output_path}\n  Size: {len(context_bytes)} bytes"
            self.update_results_display()
            self.notify("PRE context downloaded successfully", severity="information")

        except DCypherAPIError as e:
            self.notify(f"Failed to get PRE crypto context: {e}", severity="error")
        except Exception as e:
            self.notify(f"Error: {e}", severity="error")

    def action_init_pre(self) -> None:
        """Initialize PRE capabilities (equivalent to CLI init-pre)"""
        if not self.current_identity_path:
            self.notify("Load an identity first", severity="warning")
            return

        try:
            self.notify(
                "Initializing PRE capabilities for identity...", severity="information"
            )

            client = DCypherClient(
                self.api_url, identity_path=self.current_identity_path
            )
            client.initialize_pre_for_identity()

            self.operation_results = "✓ PRE keys added to identity file!\n  Your identity now supports proxy re-encryption operations."
            self.update_results_display()
            self.notify(
                "PRE initialization completed successfully", severity="information"
            )

        except DCypherAPIError as e:
            self.notify(f"Failed to initialize PRE: {e}", severity="error")
        except Exception as e:
            self.notify(f"Error: {e}", severity="error")

    def action_create_share(self) -> None:
        """Create a new share (equivalent to CLI create-share)"""
        print(
            f"🔧 SHARE DEBUG: action_create_share called, current_identity_path={self.current_identity_path}"
        )

        if not self.current_identity_path:
            print(f"🔧 SHARE DEBUG: No identity path, exiting early")
            self.notify("Load an identity first", severity="warning")
            return

        recipient_input = self.query_one("#recipient-key-input", Input)
        file_hash_input = self.query_one("#file-hash-input", Input)

        recipient = recipient_input.value
        file_hash = file_hash_input.value
        print(f"🔧 SHARE DEBUG: recipient='{recipient}', file_hash='{file_hash}'")

        if not recipient or not file_hash:
            print(f"🔧 SHARE DEBUG: Missing recipient or file_hash, exiting")
            self.notify("Enter recipient key and file hash", severity="warning")
            return

        try:
            self.notify(
                f"Creating share for file {file_hash[:16]}...", severity="information"
            )

            client = DCypherClient(
                self.api_url, identity_path=self.current_identity_path
            )

            # Get Bob's account info to retrieve his PRE public key
            self.notify(
                "Looking up recipient's PRE public key...", severity="information"
            )
            bob_account = client.get_account(recipient)
            bob_pre_pk_hex = bob_account.get("pre_public_key_hex")

            if not bob_pre_pk_hex:
                self.notify(
                    f"Recipient does not have PRE capabilities enabled. They need to initialize PRE first.",
                    severity="error",
                )
                return

            # Generate re-encryption key using Bob's PRE public key
            self.notify("Generating re-encryption key...", severity="information")
            re_key_hex = client.generate_re_encryption_key(bob_pre_pk_hex)

            # Create the share
            result = client.create_share(recipient, file_hash, re_key_hex)
            share_id = result.get("share_id")

            self.operation_results = f"✓ Share created successfully!\n  Share ID: {share_id}\n  File: {file_hash}\n  Shared with: {recipient[:16]}..."
            self.update_results_display()
            self.refresh_shares_list()
            self.notify("Share created successfully", severity="information")

        except DCypherAPIError as e:
            self.notify(f"Failed to create share: {e}", severity="error")
        except Exception as e:
            self.notify(f"Error: {e}", severity="error")

    def action_list_shares(self) -> None:
        """List all shares (equivalent to CLI list-shares)"""
        if not self.current_identity_path:
            self.notify("Load an identity first", severity="warning")
            return

        try:
            self.notify("Loading shares...", severity="information")

            client = DCypherClient(
                self.api_url, identity_path=self.current_identity_path
            )
            pk_classic_hex = client.get_classic_public_key()
            shares = client.list_shares(pk_classic_hex)

            shares_sent = shares.get("shares_sent", [])
            shares_received = shares.get("shares_received", [])

            # Update table
            table = self.query_one("#shares-table", DataTable)
            table.clear()

            # Add sent shares
            for share in shares_sent:
                table.add_row(
                    share.get("share_id", "N/A")[:16] + "..."
                    if len(share.get("share_id", "")) > 16
                    else share.get("share_id", "N/A"),
                    share.get("file_hash", "N/A")[:16] + "..."
                    if len(share.get("file_hash", "")) > 16
                    else share.get("file_hash", "N/A"),
                    share.get("to", "N/A")[:16] + "..."
                    if len(share.get("to", "")) > 16
                    else share.get("to", "N/A"),
                    share.get("created_at", "Unknown"),
                    "Active",
                    "Sent",
                )

            # Add received shares
            for share in shares_received:
                table.add_row(
                    share.get("share_id", "N/A")[:16] + "..."
                    if len(share.get("share_id", "")) > 16
                    else share.get("share_id", "N/A"),
                    share.get("file_hash", "N/A")[:16] + "..."
                    if len(share.get("file_hash", "")) > 16
                    else share.get("file_hash", "N/A"),
                    share.get("from", "N/A")[:16] + "..."
                    if len(share.get("from", "")) > 16
                    else share.get("from", "N/A"),
                    share.get("created_at", "Unknown"),
                    "Active",
                    "Received",
                )

            results = []
            if shares_sent:
                results.append(f"📤 Shares sent: {len(shares_sent)}")
            if shares_received:
                results.append(f"📥 Shares received: {len(shares_received)}")

            if not shares_sent and not shares_received:
                results.append("No shares found")

            self.operation_results = "✓ Shares loaded:\n" + "\n".join(results)
            self.update_results_display()
            self.notify(
                f"Found {len(shares_sent)} sent and {len(shares_received)} received shares",
                severity="information",
            )

        except DCypherAPIError as e:
            self.notify(f"Failed to list shares: {e}", severity="error")
        except Exception as e:
            self.notify(f"Error: {e}", severity="error")

    def action_download_shared(self) -> None:
        """Download shared file (equivalent to CLI download-shared)"""
        if not self.current_identity_path:
            self.notify("Load an identity first", severity="warning")
            return

        share_id_input = self.query_one("#share-id-input", Input)
        output_input = self.query_one("#download-output-input", Input)

        share_id = share_id_input.value
        output_path = output_input.value

        if not share_id:
            self.notify("Enter share ID", severity="warning")
            return

        if not output_path:
            output_path = f"shared_file_{share_id[:8]}.dat"
            output_input.value = output_path

        try:
            self.notify(
                f"Downloading shared file with share ID: {share_id[:16]}...",
                severity="information",
            )

            client = DCypherClient(
                self.api_url, identity_path=self.current_identity_path
            )
            shared_content = client.download_shared_file(share_id)

            # Save the content
            with open(output_path, "wb") as f:
                f.write(shared_content)

            self.operation_results = f"✓ Shared file downloaded successfully!\n  Output: {output_path}\n  Size: {len(shared_content):,} bytes\n  Note: This is a re-encrypted version"
            self.update_results_display()
            self.notify("Shared file downloaded successfully", severity="information")

        except DCypherAPIError as e:
            self.notify(f"Failed to download shared file: {e}", severity="error")
        except Exception as e:
            self.notify(f"Error: {e}", severity="error")

    def action_revoke_share(self) -> None:
        """Revoke a share (equivalent to CLI revoke-share)"""
        if not self.current_identity_path:
            self.notify("Load an identity first", severity="warning")
            return

        share_id_input = self.query_one("#share-id-input", Input)
        share_id = share_id_input.value

        if not share_id:
            self.notify("Enter share ID to revoke", severity="warning")
            return

        try:
            self.notify(f"Revoking share: {share_id[:16]}...", severity="information")

            client = DCypherClient(
                self.api_url, identity_path=self.current_identity_path
            )
            result = client.revoke_share(share_id)

            self.operation_results = f"✓ Share revoked successfully!\n  Share ID: {share_id}\n  The shared user no longer has access to the file."
            self.update_results_display()
            self.refresh_shares_list()
            self.notify("Share revoked successfully", severity="information")

        except DCypherAPIError as e:
            self.notify(f"Failed to revoke share: {e}", severity="error")
        except Exception as e:
            self.notify(f"Error: {e}", severity="error")

    def refresh_shares_list(self) -> None:
        """Refresh the shares list from server"""
        if not self.current_identity_path:
            return

        try:
            # Call list_shares to refresh the table
            self.action_list_shares()
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
            self.refresh_shares_list()
