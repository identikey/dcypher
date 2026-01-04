"""
Identity Management Screen
Handles identity creation, loading, rotation, and backup operations
"""

import os
import json
import shutil
from pathlib import Path
from textual.containers import Container, Horizontal, Vertical, ScrollableContainer
from textual.widgets import Static, Button, Input, DataTable, Label, Select
from textual.widget import Widget
from textual.reactive import reactive
from textual.screen import ModalScreen
from rich.panel import Panel
from rich.text import Text
from rich.table import Table
from typing import Dict, Any, List, Optional

from dcypher.lib.key_manager import KeyManager
from dcypher.lib.api_client import DCypherClient

from dcypher.tui.screens.identity_modals import (
    PREKeyDetailsModal,
    CryptoContextDetailsModal,
    PQKeyDetailsModal,
    PQKeySelectionModal,
)


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
            # Identity information panel with integrated buttons - wrap in bordered panel
            with Container(id="identity-main-section"):
                with ScrollableContainer(id="identity-info-panel"):
                    # Basic info section
                    with Container(id="basic-info-section"):
                        yield Static(id="basic-info-content")

                    # Classic keys section
                    with Container(id="classic-keys-section"):
                        yield Static(id="classic-keys-content")
                        with Horizontal(id="classic-keys-buttons"):
                            yield Button(
                                "Rotate Classic",
                                id="rotate-classic-btn",
                                variant="primary",
                                compact=True,
                            )
                            yield Button(
                                "Export Classic",
                                id="export-classic-btn",
                                variant="default",
                                compact=True,
                            )

                    # Post-quantum keys section
                    with Container(id="pq-keys-section"):
                        yield Static(id="pq-keys-content")
                        # Add PQ button at top of section
                        with Horizontal(id="pq-add-button"):
                            yield Button(
                                "Add PQ Key",
                                id="add-pq-btn",
                                variant="success",
                                compact=True,
                            )
                        # Container for individual PQ key entries with their buttons
                        with Container(id="pq-entries-container"):
                            # Dynamic PQ key entries will be created here
                            pass

                    # PRE keys section
                    with Container(id="pre-keys-section"):
                        yield Static(id="pre-keys-content")
                        with Horizontal(id="pre-keys-buttons"):
                            yield Button(
                                "Init PRE",
                                id="init-pre-btn",
                                variant="success",
                                compact=True,
                            )
                            yield Button(
                                "View PRE",
                                id="view-pre-btn",
                                variant="default",
                                compact=True,
                            )
                            yield Button(
                                "Rotate PRE",
                                id="rotate-pre-btn",
                                variant="primary",
                                compact=True,
                            )
                            yield Button(
                                "Export PRE",
                                id="export-pre-btn",
                                variant="default",
                                compact=True,
                            )
                            yield Button(
                                "Remove PRE",
                                id="remove-pre-btn",
                                variant="warning",
                                compact=True,
                            )

                    # Crypto context section
                    with Container(id="crypto-context-section"):
                        yield Static(id="crypto-context-content")
                        with Horizontal(id="crypto-context-buttons"):
                            yield Button(
                                "View Context",
                                id="view-context-btn",
                                variant="default",
                                compact=True,
                            )

                    # Security info section
                    with Container(id="security-info-section"):
                        yield Static(id="security-info-content")

            # Compact management controls section
            with Container(id="management-controls"):
                # Action buttons (compact single row)
                with Horizontal(id="identity-actions-row"):
                    yield Button(
                        "Unload Identity",
                        id="unload-identity-btn",
                        variant="error",
                        compact=True,
                    )
                    yield Button("Rotate All Keys", id="rotate-keys-btn", compact=True)
                    yield Button("Create Backup", id="create-backup-btn", compact=True)
                    yield Button("Export All Keys", id="export-keys-btn", compact=True)

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
                    yield Button("CREATE", id="create-identity-btn", variant="success")

                # Identity files (compact) - constrained height
                with Container(id="files-table-container"):
                    yield DataTable(id="identity-files-table")

    def on_mount(self) -> None:
        """Set up the identity screen after mounting"""
        self.setup_identity_files_table()

        # Set up main container for proper vertical layout
        main_container = self.query_one("#identity-container")
        main_container.styles.layout = "vertical"

        # Identity section expands to fill remaining space and add border panel
        identity_section = self.query_one("#identity-main-section")
        identity_section.styles.height = "1fr"  # Fill remaining space after management
        identity_section.styles.border = ("solid", "cyan")  # Add cyan border
        identity_section.styles.margin = (
            0,
            0,
            0,
            0,
        )  # No margins for seamless connection

        # Make the identity panel expand to fill available height with contained scrolling
        info_panel = self.query_one("#identity-info-panel")
        info_panel.styles.height = (
            "100%"  # Expand to full height within the bordered container
        )
        info_panel.styles.overflow_y = (
            "scroll"  # Enable vertical scrolling within the panel
        )
        info_panel.styles.overflow_x = "hidden"  # Hide horizontal scrollbar

        # Style button containers to be compact
        for button_container_id in [
            "classic-keys-buttons",
            "pq-add-button",
            "pre-keys-buttons",
            "crypto-context-buttons",
        ]:
            try:
                container = self.query_one(f"#{button_container_id}")
                container.styles.height = "auto"  # Let buttons determine height
                container.styles.margin = (0, 0)  # No margin
                container.styles.padding = (0, 0)  # No padding
            except:
                pass

        # Style the section containers to ensure proper layout
        for section_id in [
            "basic-info-section",
            "classic-keys-section",
            "pq-keys-section",
            "pre-keys-section",
            "crypto-context-section",
            "security-info-section",
        ]:
            try:
                section = self.query_one(f"#{section_id}")
                section.styles.layout = "vertical"
                section.styles.height = "auto"
                section.styles.margin = (0, 0)  # Remove all margins for tighter spacing
                section.styles.padding = (0, 0)
            except:
                pass

        # Ensure Static widgets don't take up all the space in their sections
        for static_id in [
            "basic-info-content",
            "classic-keys-content",
            "pq-keys-content",
            "pre-keys-content",
            "crypto-context-content",
            "security-info-content",
        ]:
            try:
                static_widget = self.query_one(f"#{static_id}")
                static_widget.styles.height = "auto"
                static_widget.styles.margin = (0, 0)
                static_widget.styles.padding = (
                    0,
                    0,
                )  # Remove padding for tighter spacing
            except:
                pass

        # Management controls take up minimal space
        mgmt_controls = self.query_one("#management-controls")
        mgmt_controls.styles.height = "auto"  # Only as much as needed
        mgmt_controls.styles.margin = (0, 0)  # No margins
        mgmt_controls.styles.padding = (0, 0)  # No padding

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

        # Remove vertical spacing between rows for tighter layout
        actions_row = self.query_one("#identity-actions-row")
        actions_row.styles.margin = (0, 0)  # No margins at all
        actions_row.styles.padding = (0, 0)
        actions_row.styles.height = "auto"  # Minimal height for compact buttons

        controls_row = self.query_one("#controls-row")
        controls_row.styles.margin = (0, 0)  # No margins at all
        controls_row.styles.padding = (0, 0)
        controls_row.styles.height = (
            "auto"  # Minimal height for compact buttons and inputs
        )

        # Files table sized for 2-5 items at the very bottom
        table_container = self.query_one("#files-table-container")
        table_container.styles.height = "5"  # Height for 2-4 items + header + borders
        table_container.styles.overflow_y = "auto"  # Enable scrolling
        table_container.styles.margin = (0, 0)  # No margins
        table_container.styles.padding = (0, 0)  # No padding

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
        # Update each section
        self.update_basic_info_section()
        self.update_classic_keys_section()
        self.update_pq_keys_section()
        self.update_pre_keys_section()
        self.update_crypto_context_section()
        self.update_security_info_section()

    def update_basic_info_section(self) -> None:
        """Update the basic information section"""
        basic_info = self.query_one("#basic-info-content", Static)

        content = Text()
        content.append("═══ IDENTITY DETAILS ═══\n", style="bold green")

        if self.current_identity_path and self.identity_info:
            content.append(f"Path: {self.current_identity_path}\n", style="dim")
            content.append(
                f"Version: {self.identity_info.get('version', 'unknown')}\n",
                style="white",
            )
            content.append(
                f"Derivable: {self.identity_info.get('derivable', False)}\n",
                style="white",
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
        else:
            content.append("NO IDENTITY LOADED\n", style="yellow")
            content.append(
                "Create a new identity or load an existing one\n", style="dim"
            )
            content.append("to begin using dCypher operations.\n", style="dim")

        basic_info.update(content)

    def update_classic_keys_section(self) -> None:
        """Update the classic keys section"""
        classic_keys = self.query_one("#classic-keys-content", Static)

        content = Text()
        content.append("═══ CLASSIC KEYS (ECDSA SECP256K1) ═══\n", style="bold cyan")

        if (
            self.identity_info
            and "auth_keys" in self.identity_info
            and "classic" in self.identity_info["auth_keys"]
        ):
            classic_key = self.identity_info["auth_keys"]["classic"]
            pk_hex = classic_key.get("pk_hex", "")
            content.append(
                f"Public Key: {pk_hex[:32]}{'...' if len(pk_hex) > 32 else ''}\n",
                style="white",
            )

            # Add ColCa fingerprint display
            try:
                fingerprint = KeyManager.generate_classic_key_fingerprint(
                    pk_hex, "public"
                )
                content.append(f"ColCa Fingerprint: {fingerprint}\n", style="dim cyan")
                # Add security info for ColCa
                from dcypher.lib.key_manager import calculate_colca_security_bits

                security_bits = calculate_colca_security_bits([8, 4, 4])
                content.append(
                    f"Security Level: {security_bits:.0f} bits (quantum-safe)\n",
                    style="dim green",
                )
            except Exception as e:
                content.append(f"Fingerprint: [Error generating: {e}]\n", style="red")

            if "sk_hex" in classic_key:
                sk_hex = classic_key["sk_hex"]
                content.append(
                    "Private Key: [AVAILABLE - Click 'View Details' to display]\n",
                    style="yellow",
                )
                try:
                    sk_fingerprint = KeyManager.generate_classic_key_fingerprint(
                        sk_hex, "private"
                    )
                    content.append(
                        f"Private Key Fingerprint: {sk_fingerprint}\n",
                        style="dim yellow",
                    )
                except Exception as e:
                    content.append(
                        f"Private Key Fingerprint: [Error: {e}]\n", style="red"
                    )
            else:
                content.append("Private Key: [NOT AVAILABLE]\n", style="red")
            content.append("Status: Available\n", style="green")
        else:
            content.append("Status: Not available\n", style="red")
            content.append(
                "Classic keys are required for authentication\n", style="dim"
            )

        classic_keys.update(content)

    def update_pq_keys_section(self) -> None:
        """Update the post-quantum keys section"""
        self.log("update_pq_keys_section called")
        pq_keys = self.query_one("#pq-keys-content", Static)

        content = Text()
        content.append("═══ POST-QUANTUM KEYS ═══\n", style="bold cyan")

        if (
            self.identity_info
            and "auth_keys" in self.identity_info
            and "pq" in self.identity_info["auth_keys"]
        ):
            pq_key_list = self.identity_info["auth_keys"]["pq"]
            if pq_key_list:
                content.append(
                    f"Found {len(pq_key_list)} quantum-safe algorithms:\n",
                    style="green",
                )
            else:
                content.append("No PQ keys available\n", style="red")
                content.append(
                    "Click 'Add PQ Key' above to add quantum-safe algorithms\n",
                    style="dim",
                )
        else:
            content.append("Status: Not available\n", style="red")
            content.append(
                "Post-quantum keys provide quantum-safe security\n", style="dim"
            )

        pq_keys.update(content)

        # Clear and rebuild the PQ entries container with individual buttons
        try:
            entries_container = self.query_one("#pq-entries-container")
            self.log(f"Found entries container: {entries_container}")
            entries_container.remove_children()

            # Style the main entries container for tight spacing
            entries_container.styles.height = "auto"
            entries_container.styles.margin = (0, 0)
            entries_container.styles.padding = (0, 0)

            if (
                self.identity_info
                and "auth_keys" in self.identity_info
                and "pq" in self.identity_info["auth_keys"]
            ):
                pq_key_list = self.identity_info["auth_keys"]["pq"]
                self.log(f"PQ key list: {pq_key_list}")
                if pq_key_list:
                    self.log(f"Creating buttons for {len(pq_key_list)} PQ keys")
                    for i, pq_key in enumerate(pq_key_list):
                        # Create entry container with tight spacing
                        entry_container = Container()

                        # Mount the entry container to the parent FIRST
                        entries_container.mount(entry_container)

                        # Style entry container for tight spacing
                        entry_container.styles.height = "auto"
                        entry_container.styles.margin = (0, 0)
                        entry_container.styles.padding = (0, 0)

                        # Algorithm info
                        alg_info = Text()
                        alg_info.append(
                            f"[{i + 1}] {pq_key.get('alg', 'unknown')}\n",
                            style="white bold",
                        )
                        pk_hex = pq_key.get("pk_hex", "")
                        alg_info.append(
                            f"    Key: {pk_hex[:32]}{'...' if len(pk_hex) > 32 else ''}\n",
                            style="dim",
                        )

                        # Add ColCa fingerprint display for PQ keys
                        try:
                            fingerprint = KeyManager.generate_pq_key_fingerprint(
                                pk_hex, pq_key.get("alg", "unknown"), "public"
                            )
                            alg_info.append(
                                f"    ColCa Fingerprint: {fingerprint}\n",
                                style="dim cyan",
                            )
                            # Add security level info
                            from dcypher.lib.key_manager import (
                                calculate_colca_security_bits,
                            )

                            security_bits = calculate_colca_security_bits([8, 4, 4])
                            alg_info.append(
                                f"    Security Level: {security_bits:.0f} bits\n",
                                style="dim green",
                            )
                        except Exception as e:
                            alg_info.append(
                                f"    Fingerprint: [Error: {e}]\n", style="red"
                            )

                        if "sk_hex" in pq_key:
                            sk_hex = pq_key["sk_hex"]
                            alg_info.append(
                                "    Private Key: [AVAILABLE - Click 'View' to display]\n",
                                style="yellow",
                            )
                            try:
                                sk_fingerprint = KeyManager.generate_pq_key_fingerprint(
                                    sk_hex, pq_key.get("alg", "unknown"), "private"
                                )
                                alg_info.append(
                                    f"    Private Key Fingerprint: {sk_fingerprint}\n",
                                    style="dim yellow",
                                )
                            except Exception as e:
                                alg_info.append(
                                    f"    Private Key Fingerprint: [Error: {e}]\n",
                                    style="red",
                                )
                        else:
                            alg_info.append(
                                "    Private Key: [NOT AVAILABLE]\n", style="red"
                            )

                        info_static = Static(alg_info)
                        entry_container.mount(info_static)

                        # Style info static for tight spacing
                        info_static.styles.height = "auto"
                        info_static.styles.margin = (0, 0)
                        info_static.styles.padding = (0, 0)

                        # Individual buttons for this PQ key
                        buttons_container = Horizontal()

                        # Mount the buttons_container to entry_container FIRST
                        entry_container.mount(buttons_container)

                        # Style buttons container for tight spacing
                        buttons_container.styles.height = "auto"
                        buttons_container.styles.margin = (0, 0)
                        buttons_container.styles.padding = (0, 0)

                        rotate_btn = Button(
                            "Rotate",
                            id=f"rotate-pq-{i}",
                            variant="primary",
                            compact=True,
                        )
                        view_btn = Button(
                            "View", id=f"view-pq-{i}", variant="default", compact=True
                        )
                        export_btn = Button(
                            "Export",
                            id=f"export-pq-{i}",
                            variant="default",
                            compact=True,
                        )
                        remove_btn = Button(
                            "Remove",
                            id=f"remove-pq-{i}",
                            variant="warning",
                            compact=True,
                        )

                        buttons_container.mount(rotate_btn)
                        buttons_container.mount(view_btn)
                        buttons_container.mount(export_btn)
                        buttons_container.mount(remove_btn)

                        self.log(f"Mounted PQ key {i} with buttons")

                    self.log(
                        f"Entries container now has {len(entries_container.children)} children"
                    )
                else:
                    self.log("No PQ keys found in list")
            else:
                self.log("No PQ keys or auth_keys section found")

        except Exception as e:
            # Fallback if dynamic creation fails
            import traceback

            self.log(f"Error creating individual PQ entries: {e}")
            self.log(f"Full error: {traceback.format_exc()}")
            self.notify(
                f"Error creating individual PQ entries: {e}", severity="warning"
            )

    def update_pre_keys_section(self) -> None:
        """Update the PRE keys section"""
        pre_keys = self.query_one("#pre-keys-content", Static)

        content = Text()
        content.append("═══ PRE KEYS (PROXY RECRYPTION) ═══\n", style="bold green")

        if (
            self.identity_info
            and "auth_keys" in self.identity_info
            and "pre" in self.identity_info["auth_keys"]
        ):
            pre_key = self.identity_info["auth_keys"]["pre"]
            if pre_key and "pk_hex" in pre_key and pre_key["pk_hex"]:
                pk_hex = pre_key["pk_hex"]
                content.append(
                    f"Public Key: {pk_hex[:32]}{'...' if len(pk_hex) > 32 else ''}\n",
                    style="white",
                )

                # Add ColCa fingerprint display for PRE keys
                try:
                    fingerprint = KeyManager.generate_pre_key_fingerprint(
                        pk_hex, "public"
                    )
                    content.append(
                        f"ColCa Fingerprint: {fingerprint}\n", style="dim green"
                    )
                    # Add hierarchical nesting info for PRE
                    content.append(
                        "Properties: Hierarchical nesting, context-dependent\n",
                        style="dim blue",
                    )
                except Exception as e:
                    content.append(
                        f"Fingerprint: [Error generating: {e}]\n", style="red"
                    )

                if "sk_hex" in pre_key:
                    sk_hex = pre_key["sk_hex"]
                    content.append(
                        "Private Key: [AVAILABLE - Click 'View Details' to display]\n",
                        style="yellow",
                    )
                    try:
                        sk_fingerprint = KeyManager.generate_pre_key_fingerprint(
                            sk_hex, "private"
                        )
                        content.append(
                            f"Private Key Fingerprint: {sk_fingerprint}\n",
                            style="dim yellow",
                        )
                    except Exception as e:
                        content.append(
                            f"Private Key Fingerprint: [Error: {e}]\n", style="red"
                        )
                else:
                    content.append("Private Key: [NOT AVAILABLE]\n", style="red")
                content.append("Status: Initialized\n", style="green")
            else:
                content.append("Status: Not initialized\n", style="yellow")
                content.append(
                    "Click 'Init PRE' to enable proxy recryption\n", style="dim"
                )
        else:
            content.append("Status: Not available\n", style="red")
            content.append(
                "PRE enables secure data sharing without key exposure\n", style="dim"
            )

        pre_keys.update(content)

    def update_crypto_context_section(self) -> None:
        """Update the crypto context section"""
        crypto_context = self.query_one("#crypto-context-content", Static)

        content = Text()
        content.append("═══ CRYPTO CONTEXT ═══\n", style="bold magenta")

        if self.identity_info and "crypto_context" in self.identity_info:
            crypto_ctx = self.identity_info["crypto_context"]
            if "context_source" in crypto_ctx:
                content.append(
                    f"Source: {crypto_ctx['context_source']}\n", style="white"
                )
            if "context_size" in crypto_ctx:
                size_kb = crypto_ctx["context_size"] / 1024
                content.append(f"Size: {size_kb:.1f} KB\n", style="white")
            if "context_bytes_hex" in crypto_ctx:
                context_hex = crypto_ctx["context_bytes_hex"]
                content.append(
                    f"Context Hash: {context_hex[:16]}...{context_hex[-16:]}\n",
                    style="dim",
                )
            content.append("Status: Available\n", style="green")
        else:
            content.append("Status: Not available\n", style="red")
            content.append(
                "Crypto context is required for PRE operations\n", style="dim"
            )

        crypto_context.update(content)

    def update_security_info_section(self) -> None:
        """Update the security information section"""
        security_info = self.query_one("#security-info-content", Static)

        content = Text()
        content.append("═══ SECURITY INFORMATION ═══\n", style="bold red")
        content.append("• Private keys are encrypted in identity file\n", style="dim")
        content.append("• Mnemonic allows full key recovery\n", style="dim")
        content.append("• Compatible with server crypto context\n", style="dim")

        if self.identity_info and self.identity_info.get("derivable", False):
            content.append("• Keys can be rotated using mnemonic\n", style="dim")

        # Add ColCa security information
        content.append("\n🔒 ColCa Fingerprint Technology:\n", style="bold cyan")
        content.append(
            "• Half-Split Recursive algorithm with 1000+ bit security\n",
            style="dim cyan",
        )
        content.append(
            "• Hierarchical nesting enables progressive disclosure\n", style="dim cyan"
        )
        content.append(
            "• Deterministic prefix matching for system compatibility\n",
            style="dim cyan",
        )
        content.append("• Quantum-safe cryptographic strength\n", style="dim cyan")

        content.append(
            "\nAlways backup your identity file and mnemonic securely!\n",
            style="yellow",
        )
        security_info.update(content)

    def create_identity_info_panel(self) -> Panel:
        """Create the comprehensive identity information panel"""
        # This method is now replaced by individual section updates
        # Keeping for backward compatibility
        return self.create_no_identity_panel()

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
        # Individual key management buttons
        elif button_id == "rotate-classic-btn":
            self.action_rotate_classic_key()
        elif button_id == "rotate-pq-btn":
            self.action_rotate_pq_keys()
        elif button_id == "rotate-pre-btn":
            self.action_rotate_pre_key()
        elif button_id == "init-pre-btn":
            self.action_initialize_pre()
        elif button_id == "export-classic-btn":
            self.action_export_classic_key()
        elif button_id == "export-pq-btn":
            self.action_export_pq_keys()
        elif button_id == "export-pre-btn":
            self.action_export_pre_key()
        # New key management buttons
        elif button_id == "add-pq-btn":
            self.action_add_pq_key()
        elif button_id == "remove-pq-btn":
            self.action_remove_pq_key()
        elif button_id == "rotate-pq-btn":
            self.action_rotate_pq_keys()
        elif button_id == "view-pq-btn":
            self.action_view_pq_key()
        elif button_id == "export-pq-btn":
            self.action_export_pq_keys()
        elif button_id == "remove-pre-btn":
            self.action_remove_pre_key()
        elif button_id == "view-pre-btn":
            self.action_view_pre_key()
        elif button_id == "view-context-btn":
            self.action_view_crypto_context()
        # Handle individual PQ key operations
        elif button_id and button_id.startswith("rotate-pq-"):
            try:
                pq_index = int(button_id.split("-")[-1])
                self.action_rotate_individual_pq_key(pq_index)
            except (ValueError, IndexError):
                self.notify("Invalid PQ key rotation button", severity="error")
        elif button_id and button_id.startswith("view-pq-"):
            try:
                pq_index = int(button_id.split("-")[-1])
                self.action_view_individual_pq_key(pq_index)
            except (ValueError, IndexError):
                self.notify("Invalid PQ key view button", severity="error")
        elif button_id and button_id.startswith("export-pq-"):
            try:
                pq_index = int(button_id.split("-")[-1])
                self.action_export_individual_pq_key(pq_index)
            except (ValueError, IndexError):
                self.notify("Invalid PQ key export button", severity="error")
        elif button_id and button_id.startswith("remove-pq-"):
            try:
                pq_index = int(button_id.split("-")[-1])
                self.action_remove_individual_pq_key(pq_index)
            except (ValueError, IndexError):
                self.notify("Invalid PQ key remove button", severity="error")

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
            self.notify(
                "Creating identity with server context...", severity="information"
            )

            # Create the directory if it doesn't exist
            dcypher_home.mkdir(parents=True, exist_ok=True)

            # Use the app's unified identity creation method
            create_method = getattr(self.app, "create_identity_file", None)
            if create_method and callable(create_method):
                try:
                    result = create_method(name, dcypher_home, overwrite=False)
                    # Handle result tuple unpacking safely
                    if isinstance(result, (tuple, list)) and len(result) == 2:
                        mnemonic, file_path = result
                        self.notify(
                            f"Identity '{name}' created successfully!",
                            severity="information",
                        )
                        self.notify(
                            "Please backup your mnemonic phrase securely!",
                            severity="warning",
                        )

                        # Update app state with new identity - use setattr to trigger reactive watchers
                        setattr(self.app, "current_identity_path", str(file_path))

                        # Clear inputs and refresh file list
                        name_input.value = ""
                        self.refresh_identity_files()
                    else:
                        self.notify(
                            f"Unexpected result format from identity creation",
                            severity="error",
                        )
                except (TypeError, ValueError) as create_error:
                    self.notify(
                        f"Identity creation failed: {create_error}", severity="error"
                    )
            else:
                self.notify("Identity creation method not available", severity="error")

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

            setattr(self.app, "current_identity_path", str(identity_path))

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
                    f"Identity loaded successfully: {expected_path.name}",
                    severity="information",
                )
                # Display will be updated automatically by the watchers
            else:
                self.notify(
                    "⚠ Identity path set but info not loaded", severity="warning"
                )
        else:
            self.notify(
                f"Identity path not updated. Expected: {expected_path}, Got: {current_path}",
                severity="error",
            )

    def action_unload_identity(self) -> None:
        """Unload the current identity"""
        if self.current_identity_path:
            # Clear the identity from app state - this will trigger reactive updates
            setattr(self.app, "current_identity_path", None)
            self.notify("Identity unloaded", severity="information")
        else:
            self.notify("No identity loaded", severity="warning")

    def update_identity_status(
        self, status_info: Optional[Dict[str, Any]] = None
    ) -> None:
        """Update identity status from external source (called by app)"""
        # This method is called by the app's broadcast_identity_change method
        self.update_identity_display()

    def action_rotate_keys(self) -> None:
        """Rotate keys in the current identity"""
        if not self.current_identity_path:
            self.notify("No identity loaded", severity="warning")
            return

        try:
            # Check if identity is derivable
            if not self.identity_info or not self.identity_info.get("derivable", False):
                self.notify(
                    "Cannot rotate keys in non-derivable identity", severity="error"
                )
                return

            self.notify("Rotating keys...", severity="information")

            # Use the app's unified key rotation method
            rotate_method = getattr(self.app, "rotate_identity_keys", None)
            if rotate_method and callable(rotate_method):
                rotation_info = rotate_method(self.current_identity_path, "manual")
            else:
                self.notify("Key rotation method not available", severity="error")
                return

            # rotation_info should be a dict with rotation details
            rotation_count = "unknown"
            try:
                if hasattr(rotation_info, "get") and callable(
                    getattr(rotation_info, "get")
                ):
                    rotation_count = getattr(rotation_info, "get")(
                        "rotation_count", "unknown"
                    )
                elif hasattr(rotation_info, "rotation_count"):
                    rotation_count = getattr(rotation_info, "rotation_count", "unknown")
            except (AttributeError, TypeError):
                pass  # Use default "unknown" value

            self.notify(
                f"Keys rotated successfully! Rotation count: {rotation_count}",
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
            # Use the app's unified backup creation method
            backup_method = getattr(self.app, "create_backup_of_identity", None)
            if backup_method and callable(backup_method):
                backup_path = backup_method(self.current_identity_path)
                # backup_path should be a Path object with .name attribute
                backup_name = "backup file"
                if hasattr(backup_path, "name"):
                    backup_name = getattr(backup_path, "name", str(backup_path))
                else:
                    backup_name = str(backup_path)  # fallback to string representation
                self.notify(f"Backup created: {backup_name}", severity="information")
                self.refresh_identity_files()
            else:
                self.notify("Backup creation method not available", severity="error")

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
            # Check if PRE is already initialized
            if self.identity_info and "pre" in self.identity_info.get("auth_keys", {}):
                pre_keys = self.identity_info["auth_keys"]["pre"]
                if "pk_hex" in pre_keys and pre_keys["pk_hex"]:
                    self.notify(
                        "PRE already initialized for this identity", severity="warning"
                    )
                    return

            self.notify("Initializing PRE capabilities...", severity="information")

            # Use the app's unified PRE initialization method
            init_method = getattr(self.app, "initialize_pre_for_identity", None)
            if init_method and callable(init_method):
                init_method(self.current_identity_path)
            else:
                self.notify("PRE initialization method not available", severity="error")
                return

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

    def action_rotate_classic_key(self) -> None:
        """Rotate only the classic key"""
        if not self.current_identity_path:
            self.notify("No identity loaded", severity="warning")
            return

        try:
            # Check if identity is derivable
            if not self.identity_info or not self.identity_info.get("derivable", False):
                self.notify(
                    "Cannot rotate keys in non-derivable identity", severity="error"
                )
                return

            self.notify("Rotating classic key...", severity="information")

            # Use the app's rotation method (currently rotates all keys)
            rotate_method = getattr(self.app, "rotate_identity_keys", None)
            if rotate_method and callable(rotate_method):
                rotation_info = rotate_method(
                    self.current_identity_path, "classic_rotation"
                )
            else:
                self.notify("Key rotation method not available", severity="error")
                return

            self.notify(
                "Classic key rotated successfully! (Note: All keys were rotated)",
                severity="information",
            )

        except Exception as e:
            self.notify(f"Failed to rotate classic key: {e}", severity="error")

    def action_rotate_pq_keys(self) -> None:
        """Rotate only the post-quantum keys"""
        if not self.current_identity_path:
            self.notify("No identity loaded", severity="warning")
            return

        try:
            # Check if identity is derivable
            if not self.identity_info or not self.identity_info.get("derivable", False):
                self.notify(
                    "Cannot rotate keys in non-derivable identity", severity="error"
                )
                return

            self.notify("Rotating post-quantum keys...", severity="information")

            # Use the KeyManager to rotate all keys (KeyManager doesn't have individual rotation methods)
            # TODO: Implement individual key rotation in KeyManager
            from dcypher.lib.key_manager import KeyManager

            rotation_info = KeyManager.rotate_keys_in_identity(
                Path(self.current_identity_path), "pq_rotation"
            )

            # Reload identity info
            load_identity_info = getattr(self.app, "load_identity_info", None)
            if load_identity_info:
                load_identity_info(self.current_identity_path)
            broadcast_identity_change = getattr(
                self.app, "broadcast_identity_change", None
            )
            if broadcast_identity_change:
                broadcast_identity_change()

            self.notify(
                "Post-quantum keys rotated successfully! (Note: All keys were rotated)",
                severity="information",
            )

        except Exception as e:
            self.notify(f"Failed to rotate post-quantum keys: {e}", severity="error")

    def action_rotate_pre_key(self) -> None:
        """Rotate only the PRE key"""
        if not self.current_identity_path:
            self.notify("No identity loaded", severity="warning")
            return

        try:
            # Check if identity is derivable
            if not self.identity_info or not self.identity_info.get("derivable", False):
                self.notify(
                    "Cannot rotate keys in non-derivable identity", severity="error"
                )
                return

            # Check if PRE is initialized
            if not self.identity_info or "pre" not in self.identity_info.get(
                "auth_keys", {}
            ):
                self.notify(
                    "PRE not initialized. Use 'Init PRE' first.", severity="error"
                )
                return

            self.notify("Rotating PRE key...", severity="information")

            # For PRE keys, we need to regenerate them with the same crypto context
            # This is more complex than the other keys because PRE keys depend on crypto context
            try:
                # Get the current crypto context from the identity
                crypto_context = self.identity_info.get("crypto_context", {})
                if not crypto_context:
                    self.notify("No crypto context found in identity", severity="error")
                    return

                # Get crypto context bytes from the stored context
                context_bytes_hex = crypto_context.get("context_bytes_hex", "")
                if not context_bytes_hex:
                    self.notify(
                        "No crypto context bytes found in identity", severity="error"
                    )
                    return

                context_bytes = bytes.fromhex(context_bytes_hex)

                # Use the API client to get a fresh crypto context object
                client = self.api_client
                if client:
                    # Generate new PRE keys with the stored context
                    from dcypher.lib import pre
                    import base64
                    from dcypher.crypto.context_manager import CryptoContextManager

                    with CryptoContextManager(
                        serialized_data=base64.b64encode(context_bytes).decode("ascii")
                    ) as manager:
                        cc = manager.get_context()
                        keys = pre.generate_keys(cc)
                        pk_bytes = pre.serialize_to_bytes(keys.publicKey)
                        sk_bytes = pre.serialize_to_bytes(keys.secretKey)

                        # Update the identity file
                        identity_path = Path(self.current_identity_path)
                        with open(identity_path, "r") as f:
                            identity_data = json.load(f)

                        # Update PRE keys
                        identity_data["auth_keys"]["pre"] = {
                            "pk_hex": pk_bytes.hex(),
                            "sk_hex": sk_bytes.hex(),
                        }

                        # Update rotation metadata
                        if "rotation_count" in identity_data:
                            identity_data["rotation_count"] += 1
                        import time

                        identity_data["last_rotation"] = time.time()
                        identity_data["rotation_reason"] = "rotated_pre_keys"

                        # Save updated identity
                        with open(identity_path, "w") as f:
                            json.dump(identity_data, f, indent=2)

                        self.notify(
                            "✓ PRE keys rotated successfully!", severity="information"
                        )

                        # Reload identity info to reflect changes
                        load_identity_info = getattr(
                            self.app, "load_identity_info", None
                        )
                        if load_identity_info:
                            load_identity_info(str(identity_path))

                        # Broadcast identity change to update all screens
                        broadcast_identity_change = getattr(
                            self.app, "broadcast_identity_change", None
                        )
                        if broadcast_identity_change:
                            broadcast_identity_change()
                else:
                    self.notify(
                        "API client not available for PRE operations", severity="error"
                    )

            except Exception as e:
                self.notify(f"Failed to rotate PRE key: {e}", severity="error")

        except Exception as e:
            self.notify(f"Failed to rotate PRE key: {e}", severity="error")

    def action_export_classic_key(self) -> None:
        """Export classic key"""
        if not self.current_identity_path:
            self.notify("No identity loaded", severity="warning")
            return

        try:
            # TODO: Implement classic key export
            self.notify(
                "Classic key export not yet implemented", severity="information"
            )
        except Exception as e:
            self.notify(f"Failed to export classic key: {e}", severity="error")

    def action_export_pq_keys(self) -> None:
        """Export post-quantum keys"""
        if not self.current_identity_path:
            self.notify("No identity loaded", severity="warning")
            return

        try:
            # TODO: Implement PQ key export
            self.notify("PQ key export not yet implemented", severity="information")
        except Exception as e:
            self.notify(f"Failed to export PQ keys: {e}", severity="error")

    def action_export_pre_key(self) -> None:
        """Export PRE key"""
        if not self.current_identity_path:
            self.notify("No identity loaded", severity="warning")
            return

        try:
            # TODO: Implement PRE key export
            self.notify("PRE key export not yet implemented", severity="information")
        except Exception as e:
            self.notify(f"Failed to export PRE key: {e}", severity="error")

    def action_add_pq_key(self) -> None:
        """Add a new post-quantum key algorithm to the identity"""
        if not self.current_identity_path:
            self.notify("No identity loaded", severity="warning")
            return

        try:
            # Get available algorithms from the API server
            client = self.api_client
            if not client:
                self.notify("API client not available", severity="error")
                return

            self.notify("Loading available algorithms...", severity="information")
            # Cast to DCypherClient to get proper method access
            from dcypher.lib.api_client import DCypherClient

            api_client = client if isinstance(client, DCypherClient) else None
            if not api_client:
                self.notify("Invalid API client type", severity="error")
                return

            available_algorithms = api_client.get_supported_algorithms()

            if not available_algorithms:
                self.notify("No algorithms available from server", severity="error")
                return

            # Get current identity to check what algorithms are already added
            if self.identity_info and "auth_keys" in self.identity_info:
                existing_algorithms = set()
                pq_keys = self.identity_info["auth_keys"].get("pq", [])
                for pq_key in pq_keys:
                    existing_algorithms.add(pq_key.get("alg", ""))

                # Filter out already existing algorithms
                available_algorithms = [
                    alg
                    for alg in available_algorithms
                    if alg not in existing_algorithms
                ]

                if not available_algorithms:
                    self.notify(
                        "All supported algorithms are already added to your identity",
                        severity="warning",
                    )
                    return

            # Show modal for algorithm selection
            def on_algorithm_selected(result: Optional[str]) -> None:
                if result:
                    self._add_pq_key_to_identity(result)

            modal = PQKeySelectionModal(available_algorithms)
            self.app.push_screen(modal, on_algorithm_selected)

        except Exception as e:
            self.notify(f"Failed to get available algorithms: {e}", severity="error")

    def _add_pq_key_to_identity(self, algorithm: str) -> None:
        """Add the selected PQ key algorithm to the identity file"""
        try:
            self.notify(f"Generating {algorithm} keypair...", severity="information")

            # Generate new keypair for the selected algorithm
            pq_pk, pq_sk = KeyManager.generate_pq_keypair(algorithm)

            # Load the current identity file
            if not self.current_identity_path:
                self.notify("No identity path available", severity="error")
                return

            identity_path = Path(self.current_identity_path)
            with open(identity_path, "r") as f:
                identity_data = json.load(f)

            # Add the new PQ key to the identity
            if "auth_keys" not in identity_data:
                identity_data["auth_keys"] = {}
            if "pq" not in identity_data["auth_keys"]:
                identity_data["auth_keys"]["pq"] = []

            new_pq_key = {
                "alg": algorithm,
                "pk_hex": pq_pk.hex(),
                "sk_hex": pq_sk.hex(),
            }
            identity_data["auth_keys"]["pq"].append(new_pq_key)

            # Update the rotation count and timestamp
            if "rotation_count" in identity_data:
                identity_data["rotation_count"] += 1
            import time

            identity_data["last_rotation"] = time.time()
            identity_data["rotation_reason"] = f"added_{algorithm}_key"

            # Save the updated identity file
            with open(identity_path, "w") as f:
                json.dump(identity_data, f, indent=2)

            self.notify(f"✓ Added {algorithm} key to identity!", severity="information")

            # Reload identity info to reflect changes
            load_identity_info = getattr(self.app, "load_identity_info", None)
            if load_identity_info:
                load_identity_info(str(identity_path))

            # Broadcast identity change to update all screens
            broadcast_identity_change = getattr(
                self.app, "broadcast_identity_change", None
            )
            if broadcast_identity_change:
                broadcast_identity_change()

            # Update the PQ keys display
            self.update_pq_keys_section()

        except Exception as e:
            self.notify(f"Failed to add {algorithm} key: {e}", severity="error")

    def action_remove_pq_key(self) -> None:
        """Remove a post-quantum key algorithm from the identity"""
        if not self.current_identity_path:
            self.notify("No identity loaded", severity="warning")
            return

        try:
            # Get current PQ keys to show options
            if not self.identity_info or "auth_keys" not in self.identity_info:
                self.notify("No PQ keys available to remove", severity="warning")
                return

            pq_keys = self.identity_info["auth_keys"].get("pq", [])
            if not pq_keys:
                self.notify("No PQ keys found in identity", severity="warning")
                return

            if len(pq_keys) <= 1:
                self.notify(
                    "Cannot remove last PQ key - at least one required",
                    severity="error",
                )
                return

            # For now, remove the last PQ key (TODO: implement selection dialog)
            self._remove_pq_key_by_index(len(pq_keys) - 1)

        except Exception as e:
            self.notify(f"Failed to remove PQ key: {e}", severity="error")

    def _remove_pq_key_by_index(self, pq_index: int) -> None:
        """Remove a PQ key by index from the identity file"""
        try:
            if not self.current_identity_path:
                return

            identity_path = Path(self.current_identity_path)
            with open(identity_path, "r") as f:
                identity_data = json.load(f)

            pq_keys = identity_data["auth_keys"]["pq"]
            if pq_index >= len(pq_keys) or pq_index < 0:
                self.notify(f"Invalid PQ key index: {pq_index}", severity="error")
                return

            removed_alg = pq_keys[pq_index].get("alg", "unknown")

            # Remove the PQ key
            pq_keys.pop(pq_index)

            # Update rotation metadata
            if "rotation_count" in identity_data:
                identity_data["rotation_count"] += 1
            import time

            identity_data["last_rotation"] = time.time()
            identity_data["rotation_reason"] = f"removed_{removed_alg}_key"

            # Save updated identity
            with open(identity_path, "w") as f:
                json.dump(identity_data, f, indent=2)

            self.notify(
                f"✓ Removed {removed_alg} key from identity!", severity="information"
            )

            # Reload identity info to reflect changes
            load_identity_info = getattr(self.app, "load_identity_info", None)
            if load_identity_info:
                load_identity_info(str(identity_path))

            # Broadcast identity change to update all screens
            broadcast_identity_change = getattr(
                self.app, "broadcast_identity_change", None
            )
            if broadcast_identity_change:
                broadcast_identity_change()

            # Update the PQ keys display
            self.update_pq_keys_section()

        except Exception as e:
            self.notify(
                f"Failed to remove PQ key at index {pq_index}: {e}", severity="error"
            )

    def action_view_pq_key(self) -> None:
        """View details of post-quantum keys"""
        if not self.current_identity_path:
            self.notify("No identity loaded", severity="warning")
            return

        try:
            if (
                self.identity_info
                and "auth_keys" in self.identity_info
                and "pq" in self.identity_info["auth_keys"]
            ):
                pq_key_list = self.identity_info["auth_keys"]["pq"]
                if pq_key_list:
                    modal = PQKeyDetailsModal(pq_key_list)
                    self.app.push_screen(modal)
                else:
                    self.notify("No PQ keys found in identity", severity="warning")
            else:
                self.notify("No PQ keys available", severity="warning")
        except Exception as e:
            self.notify(f"Failed to view PQ keys: {e}", severity="error")

    def action_remove_pre_key(self) -> None:
        """Remove PRE capabilities from the identity"""
        if not self.current_identity_path:
            self.notify("No identity loaded", severity="warning")
            return

        try:
            # Check if PRE is initialized
            if not self.identity_info or "pre" not in self.identity_info.get(
                "auth_keys", {}
            ):
                self.notify(
                    "PRE not initialized, nothing to remove", severity="warning"
                )
                return

            # Remove PRE keys from identity file
            identity_path = Path(self.current_identity_path)
            with open(identity_path, "r") as f:
                identity_data = json.load(f)

            # Clear PRE keys
            identity_data["auth_keys"]["pre"] = {}

            # Update rotation metadata
            if "rotation_count" in identity_data:
                identity_data["rotation_count"] += 1
            import time

            identity_data["last_rotation"] = time.time()
            identity_data["rotation_reason"] = "removed_pre_keys"

            # Save updated identity
            with open(identity_path, "w") as f:
                json.dump(identity_data, f, indent=2)

            self.notify(
                "✓ PRE capabilities removed from identity!", severity="information"
            )

            # Reload identity info to reflect changes
            load_identity_info = getattr(self.app, "load_identity_info", None)
            if load_identity_info:
                load_identity_info(str(identity_path))

            # Broadcast identity change to update all screens
            broadcast_identity_change = getattr(
                self.app, "broadcast_identity_change", None
            )
            if broadcast_identity_change:
                broadcast_identity_change()

        except Exception as e:
            self.notify(f"Failed to remove PRE key: {e}", severity="error")

    def action_view_pre_key(self) -> None:
        """View details of PRE keys"""
        if not self.current_identity_path:
            self.notify("No identity loaded", severity="warning")
            return

        try:
            if (
                self.identity_info
                and "auth_keys" in self.identity_info
                and "pre" in self.identity_info["auth_keys"]
            ):
                pre_keys = self.identity_info["auth_keys"]["pre"]
                modal = PREKeyDetailsModal(pre_keys)
                self.app.push_screen(modal)
            else:
                self.notify("No PRE keys available", severity="warning")
        except Exception as e:
            self.notify(f"Failed to view PRE keys: {e}", severity="error")

    def action_view_crypto_context(self) -> None:
        """View details of the crypto context"""
        if not self.current_identity_path:
            self.notify("No identity loaded", severity="warning")
            return

        try:
            if self.identity_info and "crypto_context" in self.identity_info:
                crypto_context = self.identity_info["crypto_context"]
                modal = CryptoContextDetailsModal(crypto_context)
                self.app.push_screen(modal)
            else:
                self.notify("No crypto context available", severity="warning")
        except Exception as e:
            self.notify(f"Failed to view crypto context: {e}", severity="error")

    def action_rotate_individual_pq_key(self, pq_index: int) -> None:
        """Rotate a specific PQ key by index"""
        if not self.current_identity_path:
            self.notify("No identity loaded", severity="warning")
            return

        try:
            # Check if identity is derivable
            if not self.identity_info or not self.identity_info.get("derivable", False):
                self.notify(
                    "Cannot rotate keys in non-derivable identity", severity="error"
                )
                return

            # Check if the PQ key index is valid
            if not self.identity_info or "auth_keys" not in self.identity_info:
                self.notify("No PQ keys available", severity="error")
                return

            pq_keys = self.identity_info["auth_keys"].get("pq", [])
            if pq_index >= len(pq_keys) or pq_index < 0:
                self.notify(f"Invalid PQ key index: {pq_index}", severity="error")
                return

            algorithm = pq_keys[pq_index].get("alg", "unknown")
            self.notify(
                f"Rotating PQ key [{pq_index + 1}] {algorithm}...",
                severity="information",
            )

            # Generate new keypair for this algorithm
            from dcypher.lib.key_manager import KeyManager

            pq_pk, pq_sk = KeyManager.generate_pq_keypair(algorithm)

            # Update the identity file
            identity_path = Path(self.current_identity_path)
            with open(identity_path, "r") as f:
                identity_data = json.load(f)

            # Update the specific PQ key
            identity_data["auth_keys"]["pq"][pq_index] = {
                "alg": algorithm,
                "pk_hex": pq_pk.hex(),
                "sk_hex": pq_sk.hex(),
            }

            # Update rotation metadata
            if "rotation_count" in identity_data:
                identity_data["rotation_count"] += 1
            import time

            identity_data["last_rotation"] = time.time()
            identity_data["rotation_reason"] = f"rotated_{algorithm}_key"

            # Save updated identity
            with open(identity_path, "w") as f:
                json.dump(identity_data, f, indent=2)

            self.notify(
                f"✓ Rotated {algorithm} key successfully!", severity="information"
            )

            # Reload identity info to reflect changes
            load_identity_info = getattr(self.app, "load_identity_info", None)
            if load_identity_info:
                load_identity_info(str(identity_path))

            # Broadcast identity change to update all screens
            broadcast_identity_change = getattr(
                self.app, "broadcast_identity_change", None
            )
            if broadcast_identity_change:
                broadcast_identity_change()

            # Update the PQ keys display
            self.update_pq_keys_section()

        except Exception as e:
            self.notify(f"Failed to rotate PQ key {pq_index}: {e}", severity="error")

    def action_view_individual_pq_key(self, pq_index: int) -> None:
        """View details of a specific PQ key by index"""
        if not self.current_identity_path:
            self.notify("No identity loaded", severity="warning")
            return

        try:
            if not self.identity_info or "auth_keys" not in self.identity_info:
                self.notify("No PQ keys available", severity="error")
                return

            pq_keys = self.identity_info["auth_keys"].get("pq", [])
            if pq_index >= len(pq_keys) or pq_index < 0:
                self.notify(f"Invalid PQ key index: {pq_index}", severity="error")
                return

            pq_key = pq_keys[pq_index]
            algorithm = pq_key.get("alg", "unknown")
            pk_hex = pq_key.get("pk_hex", "")
            sk_hex = pq_key.get("sk_hex", "")

            pk_len = len(pk_hex) // 2  # Convert hex to bytes
            sk_len = len(sk_hex) // 2  # Convert hex to bytes

            details = f"PQ Key [{pq_index + 1}] Details:\n"
            details += f"Algorithm: {algorithm}\n"
            details += f"Public Key: {pk_len} bytes\n"
            details += f"Private Key: {sk_len} bytes\n"
            details += f"Key Preview: {pk_hex[:16]}...{pk_hex[-16:] if len(pk_hex) > 32 else ''}"

            self.notify(details, severity="information")

        except Exception as e:
            self.notify(f"Failed to view PQ key {pq_index}: {e}", severity="error")

    def action_export_individual_pq_key(self, pq_index: int) -> None:
        """Export a specific PQ key by index"""
        if not self.current_identity_path:
            self.notify("No identity loaded", severity="warning")
            return

        try:
            if not self.identity_info or "auth_keys" not in self.identity_info:
                self.notify("No PQ keys available", severity="error")
                return

            pq_keys = self.identity_info["auth_keys"].get("pq", [])
            if pq_index >= len(pq_keys) or pq_index < 0:
                self.notify(f"Invalid PQ key index: {pq_index}", severity="error")
                return

            algorithm = pq_keys[pq_index].get("alg", "unknown")

            # TODO: Implement individual PQ key export
            self.notify(
                f"Individual PQ key export not yet implemented", severity="information"
            )
            self.notify(
                f"Would export: [{pq_index + 1}] {algorithm}", severity="information"
            )

        except Exception as e:
            self.notify(f"Failed to export PQ key {pq_index}: {e}", severity="error")

    def action_remove_individual_pq_key(self, pq_index: int) -> None:
        """Remove a specific PQ key by index"""
        if not self.current_identity_path:
            self.notify("No identity loaded", severity="warning")
            return

        try:
            if not self.identity_info or "auth_keys" not in self.identity_info:
                self.notify("No PQ keys available", severity="error")
                return

            pq_keys = self.identity_info["auth_keys"].get("pq", [])
            if pq_index >= len(pq_keys) or pq_index < 0:
                self.notify(f"Invalid PQ key index: {pq_index}", severity="error")
                return

            if len(pq_keys) <= 1:
                self.notify(
                    "Cannot remove last PQ key - at least one required",
                    severity="error",
                )
                return

            algorithm = pq_keys[pq_index].get("alg", "unknown")

            # Use the helper method to remove the PQ key
            self._remove_pq_key_by_index(pq_index)

        except Exception as e:
            self.notify(f"Failed to remove PQ key {pq_index}: {e}", severity="error")
