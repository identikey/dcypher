"""
Accounts Management Screen
Handles account creation, listing, and management operations
"""

import json
from pathlib import Path
from textual.containers import Container, Horizontal, Vertical
from textual.widgets import Static, Button, Input, DataTable, Label, Select, TextArea
from textual.widget import Widget
from textual.reactive import reactive
from rich.panel import Panel
from rich.text import Text

# Import API client and related modules
try:
    from src.lib.api_client import DCypherClient, DCypherAPIError, ResourceNotFoundError
    from src.lib.key_manager import KeyManager

    api_available = True
except ImportError:
    api_available = False
    # Define placeholder exceptions to avoid NameError
    DCypherAPIError = Exception
    ResourceNotFoundError = Exception


class AccountsScreen(Widget):
    """
    Accounts management screen with CLI feature parity
    Supports: list-accounts, create-account, get-account, add-pq-keys, remove-pq-keys, supported-algorithms
    """

    # Reactive state
    accounts_data = reactive([])
    operation_results = reactive("")

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
        """Compose the accounts management interface"""
        if not api_available:
            yield Static(
                "⚠️ API client not available. Please install dependencies.",
                classes="error",
            )
            return

        with Container(id="accounts-container"):
            yield Static("◢ ACCOUNT MANAGEMENT ◣", classes="title")

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
                # Account operations
                with Vertical(id="account-ops-panel"):
                    yield Label("Account Operations")
                    yield Button(
                        "List Accounts", id="list-accounts-btn", variant="primary"
                    )
                    yield Button("Create Account", id="create-account-btn")
                    yield Button("Supported Algorithms", id="supported-algs-btn")

                    yield Label("Get Account Info")
                    yield Input(id="account-pubkey-input")
                    yield Input(placeholder="Enter public key", id="public-key-input")
                    yield Button("Get Account", id="get-account-btn")

                # PQ key management
                with Vertical(id="pq-keys-panel"):
                    yield Label("Post-Quantum Keys")
                    yield Select(
                        [
                            ("Falcon-512", "Falcon-512"),
                            ("SPHINCS+-SHA2-128f", "SPHINCS+-SHA2-128f"),
                            ("Dilithium2", "Dilithium2"),
                            ("Dilithium3", "Dilithium3"),
                        ],
                        id="pq-algorithm-select",
                        allow_blank=False,
                    )
                    yield Button("Add PQ Keys", id="add-pq-keys-btn")
                    yield Button("Remove PQ Keys", id="remove-pq-keys-btn")
                    yield Button("List Files", id="list-files-btn")
                    yield Button("Get Graveyard", id="get-graveyard-btn")

            # Results area
            yield Static(id="account-results")

            # Accounts table
            yield DataTable(id="accounts-table")

    def on_mount(self) -> None:
        """Initialize accounts screen"""
        if api_available:
            self.setup_accounts_table()
            self.update_status_display()
            self.update_results_display()

    def setup_accounts_table(self) -> None:
        """Setup the accounts table"""
        table = self.query_one("#accounts-table", DataTable)
        table.add_columns("Public Key", "Created", "PQ Keys", "PRE Status", "Files")

    def update_status_display(self) -> None:
        """Update connection and identity status"""
        connection_widget = self.query_one("#connection-status", Static)
        identity_widget = self.query_one("#current-identity-status", Static)

        # Connection status
        connection_status = getattr(self.app, "connection_status", "disconnected")
        connection_content = Panel(
            Text(
                f"API URL: {self.api_url}\nStatus: {connection_status}",
                style="yellow" if connection_status == "disconnected" else "green",
            ),
            title="[bold]Connection[/bold]",
            border_style="yellow" if connection_status == "disconnected" else "green",
        )
        connection_widget.update(connection_content)

        # Identity status
        if self.current_identity_path:
            identity_text = f"Identity: {Path(self.current_identity_path).name}\nPath: {self.current_identity_path}"
            style = "green"
        else:
            identity_text = "No identity loaded\nLoad identity to manage accounts"
            style = "red"

        identity_content = Panel(
            Text(identity_text, style=style),
            title="[bold]Identity[/bold]",
            border_style=style,
        )
        identity_widget.update(identity_content)

    def update_results_display(self) -> None:
        """Update the results display"""
        results_widget = self.query_one("#account-results", Static)

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
        """Handle account operation buttons"""
        if not api_available:
            self.notify("API client not available", severity="error")
            return

        button_id = event.button.id

        if button_id == "set-identity-btn":
            self.action_set_identity()
        elif button_id == "list-accounts-btn":
            self.action_list_accounts()
        elif button_id == "create-account-btn":
            self.action_create_account()
        elif button_id == "get-account-btn":
            self.action_get_account()
        elif button_id == "supported-algs-btn":
            self.action_supported_algorithms()
        elif button_id == "add-pq-keys-btn":
            self.action_add_pq_keys()
        elif button_id == "remove-pq-keys-btn":
            self.action_remove_pq_keys()
        elif button_id == "list-files-btn":
            self.action_list_files()
        elif button_id == "get-graveyard-btn":
            self.action_get_graveyard()

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

        # Update app state instead of instance attributes
        setattr(self.app, "current_identity_path", identity_path)
        setattr(self.app, "api_url", api_url)
        self.update_status_display()
        self.notify(f"Identity set: {Path(identity_path).name}", severity="information")

    def action_list_accounts(self) -> None:
        """List all accounts (equivalent to CLI list-accounts)"""
        try:
            self.notify("Loading accounts...", severity="information")

            # Get API client
            client = self.api_client
            if not client:
                self.notify("API client not initialized", severity="error")
                return

            accounts = client.list_accounts()  # type: ignore

            # Clear and update table
            table = self.query_one("#accounts-table", DataTable)
            table.clear()

            if not accounts:
                self.operation_results = "No accounts found"
            else:
                for account_pk in accounts:
                    # Get detailed account info
                    try:
                        account_info = client.get_account(account_pk)  # type: ignore
                        created = account_info.get("created_at", "Unknown")
                        pq_keys_count = len(account_info.get("pq_keys", []))
                        pre_status = (
                            "Enabled"
                            if account_info.get("pre_public_key")
                            else "Disabled"
                        )
                        files_count = len(account_info.get("files", []))

                        table.add_row(
                            account_pk[:20] + "...",
                            created,
                            str(pq_keys_count),
                            pre_status,
                            str(files_count),
                        )
                    except Exception:
                        table.add_row(account_pk[:20] + "...", "Error", "?", "?", "?")

                self.operation_results = f"✓ Found {len(accounts)} account(s)"

            self.update_results_display()
            self.notify(f"Listed {len(accounts)} accounts", severity="information")

        except DCypherAPIError as e:
            self.notify(f"Failed to list accounts: {e}", severity="error")
        except Exception as e:
            self.notify(f"Error: {e}", severity="error")

    def action_create_account(self) -> None:
        """Create new account (equivalent to CLI create-account)"""
        if not self.current_identity_path:
            self.notify("Load an identity first", severity="warning")
            return

        try:
            self.notify("Creating account...", severity="information")

            # Get API client
            client = self.api_client
            if not client:
                self.notify("API client not initialized", severity="error")
                return

            # Load keys to get PQ key info for account creation
            if not api_available:
                self.notify("API dependencies not available", severity="error")
                return

            keys_data = KeyManager.load_keys_unified(Path(self.current_identity_path))

            pk_classic_hex = client.get_classic_public_key()  # type: ignore
            pq_keys = [
                {"pk_hex": key["pk_hex"], "alg": key["alg"]}
                for key in keys_data["pq_keys"]
            ]

            result = client.create_account(pk_classic_hex, pq_keys)  # type: ignore

            self.operation_results = f"✓ Account created successfully!\n  Account ID: {pk_classic_hex[:20]}...\n  PQ Keys: {len(pq_keys)}"
            self.update_results_display()
            self.notify("Account created successfully", severity="information")

            # Refresh accounts list
            self.action_list_accounts()

        except DCypherAPIError as e:
            self.notify(f"Failed to create account: {e}", severity="error")
        except Exception as e:
            self.notify(f"Error: {e}", severity="error")

    def action_get_account(self) -> None:
        """Get account details (equivalent to CLI get-account)"""
        pubkey_input = self.query_one("#account-pubkey-input", Input)
        public_key = pubkey_input.value

        if not public_key:
            self.notify("Enter account public key", severity="warning")
            return

        try:
            self.notify("Getting account details...", severity="information")

            # Get API client
            client = self.api_client
            if not client:
                self.notify("API client not initialized", severity="error")
                return

            account_info = client.get_account(public_key)  # type: ignore

            # Format account details
            result_lines = [
                f"✓ Account Details:",
                f"  Public Key: {public_key[:40]}...",
                f"  Created: {account_info.get('created_at', 'Unknown')}",
                f"  PRE Key: {'Yes' if account_info.get('pre_public_key') else 'No'}",
                f"  PQ Keys ({len(account_info.get('pq_keys', []))}):",
            ]

            for i, pq_key in enumerate(account_info.get("pq_keys", [])):
                result_lines.append(f"    {i + 1}. {pq_key.get('alg', 'Unknown')}")

            self.operation_results = "\n".join(result_lines)
            self.update_results_display()
            self.notify("Account details retrieved", severity="information")

        except ResourceNotFoundError:
            self.notify(f"Account not found: {public_key[:20]}...", severity="error")
        except DCypherAPIError as e:
            self.notify(f"Failed to get account: {e}", severity="error")
        except Exception as e:
            self.notify(f"Error: {e}", severity="error")

    def action_supported_algorithms(self) -> None:
        """List supported algorithms (equivalent to CLI supported-algorithms)"""
        try:
            self.notify("Getting supported algorithms...", severity="information")

            # Get API client
            client = self.api_client
            if not client:
                self.notify("API client not initialized", severity="error")
                return

            algorithms = client.get_supported_algorithms()  # type: ignore

            self.operation_results = f"✓ Supported PQ Algorithms:\n" + "\n".join(
                f"  - {alg}" for alg in algorithms
            )
            self.update_results_display()
            self.notify("Loaded supported algorithms", severity="information")

        except DCypherAPIError as e:
            self.notify(f"Failed to get algorithms: {e}", severity="error")
        except Exception as e:
            self.notify(f"Error: {e}", severity="error")

    def action_add_pq_keys(self) -> None:
        """Add PQ keys to account (equivalent to CLI add-pq-keys)"""
        if not self.current_identity_path:
            self.notify("Load an identity first", severity="warning")
            return

        try:
            algorithm_select = self.query_one("#pq-algorithm-select", Select)
            algorithm = algorithm_select.value

            if not algorithm or algorithm == Select.BLANK:
                self.notify("Select an algorithm", severity="warning")
                return

            self.notify(
                f"Adding {algorithm} keys to account...", severity="information"
            )

            # Get API client
            client = self.api_client
            if not client:
                self.notify("API client not initialized", severity="error")
                return

            pk_classic_hex = client.get_classic_public_key()  # type: ignore

            # Generate new PQ keypair for the selected algorithm
            from src.lib.key_manager import KeyManager

            pq_pk, pq_sk = KeyManager.generate_pq_keypair(str(algorithm))
            new_keys = [{"pk_hex": pq_pk.hex(), "alg": str(algorithm)}]

            result = client.add_pq_keys(pk_classic_hex, new_keys)  # type: ignore

            self.operation_results = f"✓ Successfully added {algorithm} keys to account!\n  Note: Keys added to server but not saved locally"
            self.update_results_display()
            self.notify("PQ keys added successfully", severity="information")

        except DCypherAPIError as e:
            self.notify(f"Failed to add PQ keys: {e}", severity="error")
        except Exception as e:
            self.notify(f"Error: {e}", severity="error")

    def action_remove_pq_keys(self) -> None:
        """Remove PQ keys from account (equivalent to CLI remove-pq-keys)"""
        if not self.current_identity_path:
            self.notify("Load an identity first", severity="warning")
            return

        try:
            algorithm_select = self.query_one("#pq-algorithm-select", Select)
            algorithm = algorithm_select.value

            if not algorithm:
                self.notify("Select an algorithm to remove", severity="warning")
                return

            self.notify(
                f"Removing {algorithm} keys from account...", severity="information"
            )

            # Get API client
            client = self.api_client
            if not client:
                self.notify("API client not initialized", severity="error")
                return

            pk_classic_hex = client.get_classic_public_key()  # type: ignore

            result = client.remove_pq_keys(pk_classic_hex, [algorithm])  # type: ignore

            self.operation_results = f"✓ Successfully removed {algorithm} keys from account!\n  Note: Keys removed from server but still in local identity file"
            self.update_results_display()
            self.notify("PQ keys removed successfully", severity="information")

        except DCypherAPIError as e:
            self.notify(f"Failed to remove PQ keys: {e}", severity="error")
        except Exception as e:
            self.notify(f"Error: {e}", severity="error")

    def action_list_files(self) -> None:
        """List files for account (equivalent to CLI list-files)"""
        if not self.current_identity_path:
            self.notify("Load an identity first", severity="warning")
            return

        try:
            self.notify("Loading account files...", severity="information")

            # Get API client
            client = self.api_client
            if not client:
                self.notify("API client not initialized", severity="error")
                return

            pk_classic_hex = client.get_classic_public_key()  # type: ignore
            files = client.list_files(pk_classic_hex)  # type: ignore

            if not files:
                self.operation_results = "No files found for this account"
            else:
                file_list = []
                for file_info in files:
                    filename = file_info.get("filename", "N/A")
                    file_hash = file_info.get("hash", "N/A")
                    file_list.append(f"  - {filename} (hash: {file_hash[:16]}...)")

                self.operation_results = f"✓ Found {len(files)} file(s):\n" + "\n".join(
                    file_list
                )

            self.update_results_display()
            self.notify(f"Listed {len(files)} files", severity="information")

        except DCypherAPIError as e:
            self.notify(f"Failed to list files: {e}", severity="error")
        except Exception as e:
            self.notify(f"Error: {e}", severity="error")

    def action_get_graveyard(self) -> None:
        """Get graveyard (retired keys) for an account"""
        # TODO: Implement graveyard display
        self.notify("Graveyard feature coming soon", severity="information")

    def display_graveyard(self, graveyard_data: list) -> None:
        """Display graveyard data in the results area"""
        if not graveyard_data:
            self.operation_results = "No retired keys in graveyard"
        else:
            result_text = f"Graveyard - {len(graveyard_data)} retired keys:\n\n"
            for entry in graveyard_data:
                result_text += f"Algorithm: {entry.get('alg', 'Unknown')}\n"
                result_text += f"Public Key: {entry.get('public_key', '')[:32]}...\n"
                result_text += f"Retired: {entry.get('retired_at', 'Unknown')}\n"
                result_text += f"Reason: {entry.get('reason', 'Unknown')}\n"
                result_text += "-" * 40 + "\n"
            self.operation_results = result_text
        self.update_results_display()

    def watch_operation_results(self, results: str) -> None:
        """Update display when results change"""
        self.update_results_display()

    def watch_current_identity_path(self, path: str) -> None:
        """Update display when identity changes"""
        self.update_status_display()
