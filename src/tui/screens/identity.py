"""
Identity Management Screen
Handles identity creation, loading, rotation, and backup operations
"""

from pathlib import Path
from textual.containers import Container, Horizontal, Vertical
from textual.widgets import Static, Button, Input, DataTable, Label
from textual.widget import Widget
from textual.reactive import reactive
from textual.screen import ModalScreen
from rich.panel import Panel
from rich.text import Text
from rich.table import Table
from typing import Dict, Any

from src.lib.key_manager import KeyManager
from src.lib.api_client import DCypherClient


class IdentityScreen(Widget):
    """
    Identity management screen with full CLI feature parity
    Supports: new, migrate, info, rotate, backup operations
    """

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    @property
    def current_identity_path(self):
        """Get current identity path from app state"""
        return getattr(self.app, "current_identity_path", None)

    @property
    def identity_info(self):
        """Get identity info from app state"""
        return getattr(self.app, "identity_info", None)

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
        """Compose the identity management interface"""
        with Container(id="identity-container"):
            # Header
            yield Static("◢ IDENTITY MANAGEMENT ◣", classes="title")

            # Current identity panel
            with Horizontal(id="current-identity-row"):
                yield Static(id="identity-info-panel")
                yield Static(id="identity-actions-panel")

            # Identity operations
            with Horizontal(id="identity-operations-row"):
                with Vertical(id="create-identity-panel"):
                    yield Label("Create New Identity")
                    yield Input(placeholder="Identity name", id="new-identity-name")
                    yield Input(placeholder="Storage path", id="new-identity-path")
                    yield Button(
                        "Create Identity", id="create-identity-btn", variant="primary"
                    )

                with Vertical(id="load-identity-panel"):
                    yield Label("Load Existing Identity")
                    yield Input(
                        placeholder="Identity file path", id="load-identity-path"
                    )
                    yield Button("Load Identity", id="load-identity-btn")
                    yield Button("Browse...", id="browse-identity-btn")

            # Identity list/history
            yield DataTable(id="identity-history-table")

    def on_mount(self) -> None:
        """Initialize identity screen"""
        self.setup_identity_table()
        self.update_identity_display()

    def setup_identity_table(self) -> None:
        """Setup the identity history table"""
        table = self.query_one("#identity-history-table", DataTable)
        table.add_columns("Name", "Path", "Created", "Last Used", "Status")

        # Add some sample data (in real implementation, load from config)
        table.add_rows(
            [
                (
                    "default",
                    "~/.dcypher/default.json",
                    "2024-01-15",
                    "2024-01-20",
                    "Active",
                ),
                (
                    "backup",
                    "~/.dcypher/backup.json",
                    "2024-01-10",
                    "2024-01-18",
                    "Inactive",
                ),
                (
                    "test",
                    "~/.dcypher/test.json",
                    "2024-01-05",
                    "2024-01-12",
                    "Inactive",
                ),
            ]
        )

    def update_identity_display(self) -> None:
        """Update the current identity display"""
        info_panel = self.query_one("#identity-info-panel", Static)
        actions_panel = self.query_one("#identity-actions-panel", Static)

        if self.current_identity_path and self.identity_info:
            # Show loaded identity info
            info_content = self.create_identity_info_panel()
            actions_content = self.create_identity_actions_panel()
        else:
            # Show no identity loaded
            info_content = self.create_no_identity_panel()
            actions_content = Panel(
                Text("Load an identity to see available actions", style="dim"),
                title="[bold]Actions[/bold]",
                border_style="dim",
            )

        info_panel.update(info_content)
        actions_panel.update(actions_content)

    def create_identity_info_panel(self) -> Panel:
        """Create the identity information panel"""
        if not self.identity_info:
            return self.create_no_identity_panel()

        content = Text()
        content.append("CURRENT IDENTITY\n\n", style="bold green")

        # Basic info
        content.append(f"Path: {self.current_identity_path}\n", style="dim")
        content.append(
            f"Version: {self.identity_info.get('version', 'unknown')}\n", style="dim"
        )
        content.append(
            f"Derivable: {self.identity_info.get('derivable', False)}\n", style="dim"
        )

        # Key information
        auth_keys = self.identity_info.get("auth_keys", {})
        if "classic" in auth_keys:
            pk_hex = auth_keys["classic"]["pk_hex"]
            content.append(f"Classic Key: {pk_hex[:16]}...\n", style="cyan")

        if "pq" in auth_keys:
            content.append(f"PQ Keys: {len(auth_keys['pq'])}\n", style="cyan")
            for i, pq_key in enumerate(auth_keys["pq"][:3]):  # Show first 3
                content.append(f"  {i + 1}. {pq_key['alg']}\n", style="dim")

        # PRE keys if available
        if "pre" in auth_keys:
            content.append("PRE: Enabled\n", style="green")
        else:
            content.append("PRE: Not initialized\n", style="yellow")

        return Panel(
            content, title="[bold green]◢IDENTITY◣[/bold green]", border_style="green"
        )

    def create_no_identity_panel(self) -> Panel:
        """Create panel for when no identity is loaded"""
        content = Text()
        content.append("NO IDENTITY LOADED\n\n", style="bold yellow")
        content.append("Create a new identity or load an existing one\n", style="dim")
        content.append("to begin using dCypher operations.\n\n", style="dim")
        content.append("Quantum-safe cryptography requires\n", style="dim")
        content.append("proper identity management.", style="dim")

        return Panel(
            content,
            title="[bold yellow]◢IDENTITY◣[/bold yellow]",
            border_style="yellow",
        )

    def create_identity_actions_panel(self) -> Panel:
        """Create the identity actions panel"""
        content = Text()
        content.append("AVAILABLE ACTIONS\n\n", style="bold cyan")
        content.append("• Rotate Keys\n", style="white")
        content.append("• Create Backup\n", style="white")
        content.append("• View Details\n", style="white")
        content.append("• Export Keys\n", style="white")
        content.append("• Initialize PRE\n", style="white")

        return Panel(
            content, title="[bold cyan]◢ACTIONS◣[/bold cyan]", border_style="cyan"
        )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button presses"""
        button_id = event.button.id

        if button_id == "create-identity-btn":
            self.action_create_identity()
        elif button_id == "load-identity-btn":
            self.action_load_identity()
        elif button_id == "browse-identity-btn":
            self.action_browse_identity()

    def action_create_identity(self) -> None:
        """Create a new identity"""
        name_input = self.query_one("#new-identity-name", Input)
        path_input = self.query_one("#new-identity-path", Input)

        name = name_input.value or "default"
        path = path_input.value or str(Path.home() / ".dcypher")

        try:
            # Use the centralized API client
            client = self.api_client
            if not client:
                self.notify(
                    "API client not initialized. Cannot create identity.",
                    severity="error",
                )
                return

            # Use DCypherClient to create identity - it handles crypto context internally
            self.notify(
                "Creating identity with server context...", severity="information"
            )

            identity_dir = Path(path)
            # Type checker doesn't know client is DCypherClient, but we checked it's not None
            mnemonic, file_path = client.create_identity_file(  # type: ignore
                name, identity_dir, overwrite=False
            )

            self.notify(
                f"Identity '{name}' created successfully!", severity="information"
            )
            self.notify(
                "Please backup your mnemonic phrase securely!", severity="warning"
            )

            # Update app state with new identity - use direct assignment to trigger reactive watchers
            self.app.current_identity_path = str(file_path)  # type: ignore

            # Clear inputs
            name_input.value = ""
            path_input.value = ""

        except FileExistsError:
            self.notify(f"Identity '{name}' already exists!", severity="error")
        except Exception as e:
            self.notify(f"Failed to create identity: {e}", severity="error")

    def action_load_identity(self) -> None:
        """Load an existing identity"""
        path_input = self.query_one("#load-identity-path", Input)
        identity_path = path_input.value

        if not identity_path:
            self.notify("Please enter an identity file path", severity="warning")
            return

        self.load_identity_file(identity_path)

    def action_browse_identity(self) -> None:
        """Browse for identity file"""
        # TODO: Implement file browser dialog
        self.notify("File browser not yet implemented", severity="information")

    def load_identity_file(self, file_path: str) -> None:
        """Load identity from file"""
        try:
            identity_path = Path(file_path)
            if not identity_path.exists():
                self.notify(f"Identity file not found: {file_path}", severity="error")
                return

            # Update app state with loaded identity - use direct assignment to trigger reactive watchers
            self.app.current_identity_path = str(identity_path)  # type: ignore

            self.notify(
                f"Identity loaded: {identity_path.name}", severity="information"
            )

        except Exception as e:
            self.notify(f"Failed to load identity: {e}", severity="error")

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        """Handle identity table row selection"""
        table = event.data_table
        row_key = event.row_key
        row_data = table.get_row(row_key)

        if row_data:
            identity_path = row_data[1]  # Path column
            self.load_identity_file(identity_path)


class IdentityDetailsModal(ModalScreen[None]):
    """
    Modal screen for showing detailed identity information
    """

    def __init__(self, identity_data: Dict[str, Any], **kwargs):
        super().__init__(**kwargs)
        self.identity_data = identity_data

    def compose(self):
        """Compose the identity details modal"""
        with Container(id="identity-details-modal"):
            yield Static("Identity Details", classes="modal-title")
            yield Static(id="identity-details-content")
            yield Button("Close", id="close-modal-btn")

    def on_mount(self) -> None:
        """Initialize the modal"""
        content_widget = self.query_one("#identity-details-content", Static)

        # Create detailed identity information
        content = Text()
        content.append("IDENTITY DETAILS\n\n", style="bold green")

        # Add all identity information here
        for key, value in self.identity_data.items():
            if key != "mnemonic":  # Don't show mnemonic in details
                content.append(f"{key}: {value}\n", style="white")

        panel = Panel(content, border_style="green")
        content_widget.update(panel)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle modal button presses"""
        if event.button.id == "close-modal-btn":
            self.dismiss()
