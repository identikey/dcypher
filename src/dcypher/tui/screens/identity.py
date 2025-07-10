"""
Identity Management Screen
Handles identity creation, loading, rotation, and backup operations
"""

import os
import json
import shutil
from pathlib import Path
from textual.containers import Container, Horizontal, Vertical, ScrollableContainer
from textual.widgets import Static, Button, Input, DataTable, Label
from textual.widget import Widget
from textual.reactive import reactive
from textual.screen import ModalScreen
from rich.panel import Panel
from rich.text import Text
from rich.table import Table
from typing import Dict, Any, List, Optional

from dcypher.lib.key_manager import KeyManager
from dcypher.lib.api_client import DCypherClient


class IdentityScreen(Widget):
    """
    Identity management screen with full CLI feature parity
    Supports: new, migrate, info, rotate, backup operations
    """

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.selected_file_path: Optional[str] = None

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
            # Expanded identity information panel
            with Container(id="identity-main-section"):
                with ScrollableContainer(id="identity-info-panel"):
                    yield Static(id="identity-info-content")

            # Compact management controls section
            with Container(id="management-controls"):
                # Action buttons (compact single row)
                with Horizontal(id="identity-actions-row"):
                    yield Button(
                        "Unload Identity", id="unload-identity-btn", variant="error"
                    )
                    yield Button("Rotate Keys", id="rotate-keys-btn")
                    yield Button("Create Backup", id="create-backup-btn")
                    yield Button("Export Keys", id="export-keys-btn")
                    yield Button("Initialize PRE", id="init-pre-btn")

                # Directory and creation controls (compact)
                with Horizontal(id="controls-row"):
                    yield Input(
                        value=str(Path.home() / ".dcypher"),
                        placeholder="dCypher directory path",
                        id="dcypher-home-input",
                    )
                    yield Button("LOAD", id="load-selected-btn", variant="success")
                    yield Button("↻ ", id="refresh-files-btn")
                    yield Input(placeholder="Identity name", id="new-identity-name")
                    yield Button("Create", id="create-identity-btn", variant="primary")

                # Identity files (compact) - constrained height
                with Container(id="files-table-container"):
                    yield DataTable(id="identity-files-table")

    def on_mount(self) -> None:
        """Initialize identity screen"""
        # Ensure selected_file_path is properly initialized
        self.selected_file_path = None

        # Set border title for the home directory input and constrain its width
        home_input = self.query_one("#dcypher-home-input", Input)
        home_input.border_title = "Home"
        home_input.styles.width = "35"  # Constrain width to leave room for buttons

        # Constrain the new identity name input too
        name_input = self.query_one("#new-identity-name", Input)
        name_input.styles.width = "20"  # Reasonable width for names
        name_input.border_title = "New"

        # Ensure buttons are visible with minimum sizes
        load_btn = self.query_one("#load-selected-btn")
        load_btn.styles.min_width = "6"  # LOAD button

        refresh_btn = self.query_one("#refresh-files-btn")
        refresh_btn.styles.min_width = "3"  # ↻ button

        create_btn = self.query_one("#create-identity-btn")
        create_btn.styles.min_width = "8"  # Create button

        # Remove excess padding from action buttons
        rotate_btn = self.query_one("#rotate-keys-btn")
        rotate_btn.styles.padding = (0, 0)  # No padding at all

        export_btn = self.query_one("#export-keys-btn")
        export_btn.styles.padding = (0, 0)  # No padding at all

        # Set up main container for proper vertical layout
        main_container = self.query_one("#identity-container")
        main_container.styles.layout = "vertical"

        # Identity section expands to fill remaining space
        identity_section = self.query_one("#identity-main-section")
        identity_section.styles.height = "1fr"  # Fill remaining space after management

        # Make the identity panel expand to fill available height
        info_panel = self.query_one("#identity-info-panel")
        info_panel.styles.height = "100%"  # Expand to full height

        # Management controls sit tight at the very bottom
        management_controls = self.query_one("#management-controls")
        management_controls.styles.height = "auto"  # Size to content with constraints
        management_controls.styles.min_height = "9"  # Tighter minimum height
        management_controls.styles.max_height = "12"  # Tighter maximum height
        management_controls.styles.margin = (0, 0)  # No margins
        management_controls.styles.padding = (0, 0)  # No padding

        # Remove vertical spacing between rows for tighter layout
        actions_row = self.query_one("#identity-actions-row")
        actions_row.styles.margin = (0, 0)  # No margins at all
        actions_row.styles.padding = (0, 0)
        actions_row.styles.height = "3"  # Slightly more height for buttons

        controls_row = self.query_one("#controls-row")
        controls_row.styles.margin = (0, 0)  # No margins at all
        controls_row.styles.padding = (0, 0)
        controls_row.styles.height = "3"  # Slightly more height for inputs/buttons

        # Files table sized for 2-5 items at the very bottom
        table_container = self.query_one("#files-table-container")
        table_container.styles.height = "5"  # Height for 2-4 items + header + borders
        table_container.styles.overflow_y = "auto"  # Enable scrolling
        table_container.styles.margin = (0, 0)  # No margins
        table_container.styles.padding = (0, 0)  # No padding

        self.setup_identity_files_table()
        self.update_identity_display()
        self.refresh_identity_files()

    def setup_identity_files_table(self) -> None:
        """Setup the identity files table"""
        table = self.query_one("#identity-files-table", DataTable)
        table.add_columns("Filename", "Size", "Modified", "Type")
        table.border_title = "Identity Files"

    def get_dcypher_home(self) -> Path:
        """Get the current dcypher home directory from the input field"""
        home_input = self.query_one("#dcypher-home-input", Input)
        return Path(home_input.value or str(Path.home() / ".dcypher"))

    def refresh_identity_files(self) -> None:
        """Refresh the identity files table with files from dcypher home directory"""
        table = self.query_one("#identity-files-table", DataTable)

        # Clear existing rows
        table.clear()

        dcypher_home = self.get_dcypher_home()

        try:
            if not dcypher_home.exists():
                # Directory doesn't exist, show empty table
                self.notify(f"Directory not found: {dcypher_home}", severity="warning")
                return

            if not dcypher_home.is_dir():
                self.notify(
                    f"Path is not a directory: {dcypher_home}", severity="error"
                )
                return

            # Get all files in the directory
            files = []
            for file_path in dcypher_home.iterdir():
                if file_path.is_file():
                    try:
                        stat = file_path.stat()
                        size = self.format_file_size(stat.st_size)
                        modified = self.format_timestamp(stat.st_mtime)

                        # Determine file type based on extension
                        file_type = self.get_file_type(file_path)

                        files.append((file_path.name, size, modified, file_type))
                    except OSError:
                        # Skip files we can't stat
                        continue

            # Sort files by name
            files.sort(key=lambda x: x[0])

            # Add files to table
            if files:
                table.add_rows(files)
            else:
                # Show message if directory is empty
                table.add_row("(no files found)", "", "", "")

        except PermissionError:
            self.notify(
                f"Permission denied accessing: {dcypher_home}", severity="error"
            )
        except Exception as e:
            self.notify(f"Error reading directory: {e}", severity="error")

    def format_file_size(self, size_bytes: int) -> str:
        """Format file size in human readable format"""
        if size_bytes == 0:
            return "0 B"

        size_names = ["B", "KB", "MB", "GB"]
        i = 0
        size = float(size_bytes)

        while size >= 1024.0 and i < len(size_names) - 1:
            size /= 1024.0
            i += 1

        return f"{size:.1f} {size_names[i]}"

    def format_timestamp(self, timestamp: float) -> str:
        """Format timestamp as readable date"""
        import datetime

        dt = datetime.datetime.fromtimestamp(timestamp)
        return dt.strftime("%Y-%m-%d %H:%M")

    def get_file_type(self, file_path: Path) -> str:
        """Determine file type based on extension and content"""
        suffix = file_path.suffix.lower()

        if suffix == ".json":
            return "Identity"
        elif suffix == ".bak":
            return "Backup"
        elif suffix == ".key":
            return "Key"
        elif suffix == ".pem":
            return "Certificate"
        elif suffix == ".txt":
            return "Text"
        else:
            return "Unknown"

    def update_identity_display(self) -> None:
        """Update the current identity display"""
        info_panel = self.query_one("#identity-info-content", Static)

        if self.current_identity_path and self.identity_info:
            # Show loaded identity info
            info_content = self.create_identity_info_panel()
        else:
            # Show no identity loaded
            info_content = self.create_no_identity_panel()

        info_panel.update(info_content)

    def create_identity_info_panel(self) -> Panel:
        """Create the comprehensive identity information panel"""
        if not self.identity_info:
            return self.create_no_identity_panel()

        content = Text()
        content.append("IDENTITY DETAILS\n\n", style="bold green")

        # Basic information
        content.append(f"Path: {self.current_identity_path}\n", style="dim")
        content.append(
            f"Version: {self.identity_info.get('version', 'unknown')}\n", style="white"
        )
        content.append(
            f"Derivable: {self.identity_info.get('derivable', False)}\n", style="white"
        )
        content.append(
            f"Rotation Count: {self.identity_info.get('rotation_count', 0)}\n",
            style="white",
        )

        # Mnemonic information (without showing the actual mnemonic for security)
        if "mnemonic" in self.identity_info:
            mnemonic_words = self.identity_info["mnemonic"].split()
            content.append(
                f"Mnemonic: {len(mnemonic_words)} words (hidden for security)\n",
                style="yellow",
            )

        # Timestamps
        if "created_at" in self.identity_info:
            content.append(
                f"Created: {self.identity_info['created_at']}\n", style="dim"
            )
        if "last_rotation" in self.identity_info:
            import datetime

            last_rotation = datetime.datetime.fromtimestamp(
                self.identity_info["last_rotation"]
            )
            content.append(
                f"Last Rotation: {last_rotation.strftime('%Y-%m-%d %H:%M:%S')}\n",
                style="dim",
            )

        # Rotation reason if available
        if "rotation_reason" in self.identity_info:
            content.append(
                f"Last Rotation Reason: {self.identity_info['rotation_reason']}\n",
                style="dim",
            )

        content.append("\n")

        # Crypto context information
        if "crypto_context" in self.identity_info:
            content.append("CRYPTO CONTEXT:\n", style="bold magenta")
            crypto_ctx = self.identity_info["crypto_context"]
            if "context_source" in crypto_ctx:
                content.append(
                    f"  Source: {crypto_ctx['context_source']}\n", style="white"
                )
            if "context_size" in crypto_ctx:
                size_kb = crypto_ctx["context_size"] / 1024
                content.append(f"  Size: {size_kb:.1f} KB\n", style="white")
            if "context_bytes_hex" in crypto_ctx:
                context_hex = crypto_ctx["context_bytes_hex"]
                content.append(
                    f"  Context Hash: {context_hex[:16]}...{context_hex[-16:]}\n",
                    style="dim",
                )
            content.append("\n")

        # Key information
        auth_keys = self.identity_info.get("auth_keys", {})

        if "classic" in auth_keys:
            content.append("CLASSIC KEYS (ECDSA SECP256K1):\n", style="bold cyan")
            classic_key = auth_keys["classic"]
            pk_hex = classic_key.get("pk_hex", "")
            content.append(
                f"  Public Key: {pk_hex[:32]}{'...' if len(pk_hex) > 32 else ''}\n",
                style="white",
            )
            if "sk_hex" in classic_key:
                content.append("  Private Key: [PROTECTED]\n", style="red")
            content.append("\n")

        if "pq" in auth_keys:
            content.append("POST-QUANTUM KEYS:\n", style="bold cyan")
            for i, pq_key in enumerate(auth_keys["pq"]):
                content.append(
                    f"  {i + 1}. Algorithm: {pq_key.get('alg', 'unknown')}\n",
                    style="white",
                )
                pk_hex = pq_key.get("pk_hex", "")
                content.append(
                    f"     Public Key: {pk_hex[:32]}{'...' if len(pk_hex) > 32 else ''}\n",
                    style="dim",
                )
                if "sk_hex" in pq_key:
                    content.append("     Private Key: [PROTECTED]\n", style="red")
            content.append("\n")

        if "pre" in auth_keys and auth_keys["pre"]:
            content.append("PRE KEYS (PROXY RE-ENCRYPTION):\n", style="bold green")
            pre_key = auth_keys["pre"]
            if "pk_hex" in pre_key and pre_key["pk_hex"]:
                pk_hex = pre_key["pk_hex"]
                content.append(
                    f"  Public Key: {pk_hex[:32]}{'...' if len(pk_hex) > 32 else ''}\n",
                    style="white",
                )
                if "sk_hex" in pre_key:
                    content.append("  Private Key: [PROTECTED]\n", style="red")
            else:
                content.append("  Not initialized\n", style="yellow")
            content.append("\n")
        else:
            content.append("PRE KEYS: Not initialized\n", style="yellow")
            content.append("\n")

        # Derivation paths (if available)
        if "derivation_paths" in self.identity_info:
            content.append("DERIVATION PATHS (HD WALLET):\n", style="bold yellow")
            paths = self.identity_info["derivation_paths"]
            for key_type, path in paths.items():
                content.append(f"  {key_type.title()}: {path}\n", style="dim")
            content.append("\n")

        # Security information
        content.append("SECURITY INFO:\n", style="bold red")
        content.append("  • Private keys are encrypted in identity file\n", style="dim")
        content.append("  • Mnemonic allows full key recovery\n", style="dim")
        content.append("  • Compatible with server crypto context\n", style="dim")
        if self.identity_info.get("derivable", False):
            content.append("  • Keys can be rotated using mnemonic\n", style="dim")

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

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button presses"""
        button_id = event.button.id

        if button_id == "create-identity-btn":
            self.action_create_identity()
        elif button_id == "load-selected-btn":
            self.action_load_selected()
        elif button_id == "refresh-files-btn":
            self.refresh_identity_files()
        elif button_id == "unload-identity-btn":
            self.action_unload_identity()
        elif button_id == "rotate-keys-btn":
            self.action_rotate_keys()
        elif button_id == "create-backup-btn":
            self.action_create_backup()
        elif button_id == "export-keys-btn":
            self.action_export_keys()
        elif button_id == "init-pre-btn":
            self.action_initialize_pre()

    def on_input_changed(self, event: Input.Changed) -> None:
        """Handle input field changes"""
        if event.input.id == "dcypher-home-input":
            # Auto-refresh when directory path changes
            self.refresh_identity_files()

    def action_create_identity(self) -> None:
        """Create a new identity"""
        name_input = self.query_one("#new-identity-name", Input)
        dcypher_home = self.get_dcypher_home()

        name = name_input.value or "default"

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

            # Create the directory if it doesn't exist
            dcypher_home.mkdir(parents=True, exist_ok=True)

            # Type checker doesn't know client is DCypherClient, but we checked it's not None
            mnemonic, file_path = client.create_identity_file(  # type: ignore
                name, dcypher_home, overwrite=False
            )

            self.notify(
                f"Identity '{name}' created successfully!", severity="information"
            )
            self.notify(
                "Please backup your mnemonic phrase securely!", severity="warning"
            )

            # Update app state with new identity - use direct assignment to trigger reactive watchers
            self.app.current_identity_path = str(file_path)  # type: ignore

            # Clear inputs and refresh file list
            name_input.value = ""
            self.refresh_identity_files()

        except FileExistsError:
            self.notify(f"Identity '{name}' already exists!", severity="error")
        except Exception as e:
            self.notify(f"Failed to create identity: {e}", severity="error")

    def action_load_selected(self) -> None:
        """Load the currently selected identity file"""
        # Try to get the currently selected row directly from the table
        try:
            table = self.query_one("#identity-files-table", DataTable)
            self.notify(
                f"DEBUG: Table cursor position: {table.cursor_coordinate}",
                severity="information",
            )

            # Get the selected row data directly
            if table.cursor_coordinate is not None:
                row_key = table.coordinate_to_cell_key(table.cursor_coordinate).row_key
                row_data = table.get_row(row_key)
                self.notify(
                    f"DEBUG: Current row data: {row_data}", severity="information"
                )

                if row_data and row_data[0] != "(no files found)":
                    filename = row_data[0]  # Filename column
                    file_type = row_data[3]  # Type column

                    if file_type == "Identity":
                        dcypher_home = self.get_dcypher_home()
                        identity_path = dcypher_home / filename
                        self.notify(
                            f"Loading identity: {identity_path}", severity="information"
                        )
                        self.load_identity_file(str(identity_path))
                        return
                    else:
                        self.notify(
                            f"Selected file '{filename}' is not an identity file",
                            severity="error",
                        )
                        return

            # Fallback to stored selection if cursor method doesn't work
            self.notify(
                f"DEBUG: Fallback - stored selected_file_path = {self.selected_file_path}",
                severity="information",
            )

            if not self.selected_file_path:
                self.notify(
                    "Please select an identity file from the list first",
                    severity="warning",
                )
                return

            # Check if the selected file is an identity file
            selected_path = Path(self.selected_file_path)
            if selected_path.suffix.lower() != ".json":
                self.notify(
                    "Selected file is not an identity file (must be .json)",
                    severity="error",
                )
                return

            self.load_identity_file(self.selected_file_path)

        except Exception as e:
            self.notify(f"DEBUG: Error in action_load_selected: {e}", severity="error")
            import traceback

            self.notify(f"DEBUG: Traceback: {traceback.format_exc()}", severity="error")

    def load_identity_file(self, file_path: str) -> None:
        """Load identity from file"""
        try:
            identity_path = Path(file_path)
            self.notify(
                f"Attempting to load identity: {identity_path}", severity="information"
            )

            if not identity_path.exists():
                self.notify(f"Identity file not found: {file_path}", severity="error")
                return

            # First, try to validate the identity file format
            try:
                with open(identity_path, "r") as f:
                    identity_data = json.load(f)

                # Basic validation
                if not isinstance(identity_data, dict):
                    self.notify(
                        "Invalid identity file: not a JSON object", severity="error"
                    )
                    return

                if "auth_keys" not in identity_data:
                    self.notify(
                        "Invalid identity file: missing 'auth_keys' section",
                        severity="error",
                    )
                    return

                self.notify("Identity file validation passed", severity="information")

            except json.JSONDecodeError as e:
                self.notify(f"Invalid JSON in identity file: {e}", severity="error")
                return
            except Exception as e:
                self.notify(f"Error reading identity file: {e}", severity="error")
                return

            # Update app state with loaded identity - this will trigger the reactive watcher
            # which will call load_identity_info and update the UI
            old_path = getattr(self.app, "current_identity_path", None)
            self.notify(
                f"Setting identity path from {old_path} to {str(identity_path)}",
                severity="information",
            )

            self.app.current_identity_path = str(identity_path)  # type: ignore

            # Give the reactive system a moment to process
            self.call_later(self.check_identity_loaded, identity_path)

        except Exception as e:
            self.notify(f"Failed to load identity: {e}", severity="error")
            import traceback

            self.notify(f"Full error: {traceback.format_exc()}", severity="error")

    def check_identity_loaded(self, expected_path: Path) -> None:
        """Check if identity was properly loaded after reactive update"""
        current_path = getattr(self.app, "current_identity_path", None)
        identity_info = getattr(self.app, "identity_info", None)

        if current_path == str(expected_path):
            if identity_info:
                self.notify(
                    f"✓ Identity loaded successfully: {expected_path.name}",
                    severity="information",
                )
                self.update_identity_display()
            else:
                self.notify(
                    "⚠ Identity path set but info not loaded", severity="warning"
                )
        else:
            self.notify(
                f"✗ Identity path not updated. Expected: {expected_path}, Got: {current_path}",
                severity="error",
            )

    def action_unload_identity(self) -> None:
        """Unload the current identity"""
        if self.current_identity_path:
            # Clear the identity from app state
            self.app.current_identity_path = None  # type: ignore
            self.notify("Identity unloaded", severity="information")
        else:
            self.notify("No identity loaded", severity="warning")

    def action_rotate_keys(self) -> None:
        """Rotate keys in the current identity"""
        if not self.current_identity_path:
            self.notify("No identity loaded", severity="warning")
            return

        try:
            identity_path = Path(self.current_identity_path)

            # Check if identity is derivable
            if not self.identity_info or not self.identity_info.get("derivable", False):
                self.notify(
                    "Cannot rotate keys in non-derivable identity", severity="error"
                )
                return

            self.notify("Rotating keys...", severity="information")

            # Use KeyManager to rotate keys
            rotation_info = KeyManager.rotate_keys_in_identity(identity_path)

            # Reload the identity info to show updated keys
            self.app.load_identity_info(self.current_identity_path)  # type: ignore

            self.notify(
                f"Keys rotated successfully! Rotation count: {rotation_info.get('rotation_count', 'unknown')}",
                severity="information",
            )

        except Exception as e:
            self.notify(f"Failed to rotate keys: {e}", severity="error")

    def action_create_backup(self) -> None:
        """Create a backup of the current identity"""
        if not self.current_identity_path:
            self.notify("No identity loaded", severity="warning")
            return

        try:
            identity_path = Path(self.current_identity_path)
            backup_name = (
                f"{identity_path.stem}_backup_{int(__import__('time').time())}.json"
            )
            backup_path = identity_path.parent / backup_name

            # Copy the identity file
            shutil.copy2(identity_path, backup_path)

            self.notify(f"Backup created: {backup_path.name}", severity="information")
            self.refresh_identity_files()

        except Exception as e:
            self.notify(f"Failed to create backup: {e}", severity="error")

    def action_export_keys(self) -> None:
        """Export keys from the current identity"""
        if not self.current_identity_path:
            self.notify("No identity loaded", severity="warning")
            return

        try:
            # TODO: Implement key export functionality
            # This could export public keys, signing certificates, etc.
            self.notify("Key export not yet implemented", severity="information")

        except Exception as e:
            self.notify(f"Failed to export keys: {e}", severity="error")

    def action_initialize_pre(self) -> None:
        """Initialize PRE capabilities for the current identity"""
        if not self.current_identity_path:
            self.notify("No identity loaded", severity="warning")
            return

        try:
            client = self.api_client
            if not client:
                self.notify("API client not initialized", severity="error")
                return

            # Check if PRE is already initialized
            if self.identity_info and "pre" in self.identity_info.get("auth_keys", {}):
                self.notify(
                    "PRE already initialized for this identity", severity="warning"
                )
                return

            self.notify("Initializing PRE capabilities...", severity="information")

            # Use the API client to initialize PRE
            initialize_method = getattr(client, "initialize_pre_for_identity", None)
            if initialize_method and callable(initialize_method):
                initialize_method()
            else:
                self.notify(
                    "API client does not support PRE initialization", severity="error"
                )
                return

            # Reload the identity info to show PRE keys
            self.app.load_identity_info(self.current_identity_path)  # type: ignore

            self.notify(
                "PRE capabilities initialized successfully!", severity="information"
            )

        except Exception as e:
            self.notify(f"Failed to initialize PRE: {e}", severity="error")

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        """Handle identity files table row selection"""
        self.notify("DEBUG: on_data_table_row_selected called", severity="information")

        table = event.data_table
        row_key = event.row_key
        row_data = table.get_row(row_key)

        self.notify(
            f"DEBUG: Row selection - row_key: {row_key}, row_data: {row_data}",
            severity="information",
        )

        if row_data and row_data[0] != "(no files found)":
            filename = row_data[0]  # Filename column
            dcypher_home = self.get_dcypher_home()
            identity_path = dcypher_home / filename

            # Track the selected file
            old_path = self.selected_file_path
            self.selected_file_path = str(identity_path)
            self.notify(
                f"DEBUG: Updated selected_file_path from '{old_path}' to '{self.selected_file_path}'",
                severity="information",
            )

            # Show selection feedback
            if row_data[3] == "Identity":  # Type column
                self.notify(
                    f"Selected identity file: {filename} (click LOAD to open)",
                    severity="information",
                )
            else:
                self.notify(
                    f"Selected file: {filename} (not an identity file)",
                    severity="information",
                )
        else:
            self.notify(
                "DEBUG: No valid row data in selection event", severity="information"
            )
