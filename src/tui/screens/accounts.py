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
    from lib.api_client import DCypherClient, DCypherAPIError
    from lib.key_manager import KeyManager

    api_available = True
except ImportError:
    api_available = False


class AccountsScreen(Widget):
    """
    Accounts management screen with CLI feature parity
    Supports: list-accounts, create-account, get-account, add-pq-keys, remove-pq-keys, supported-algorithms
    """

    # Reactive state
    current_identity_path = reactive(None)
    api_url = reactive("http://127.0.0.1:8000")
    accounts_data = reactive([])
    operation_results = reactive("")

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

        self.current_identity_path = identity_path
        self.api_url = api_url
        self.update_status_display()
        self.notify(f"Identity set: {Path(identity_path).name}", severity="information")

    def action_list_accounts(self) -> None:
        """List all accounts (equivalent to CLI list-accounts)"""
        try:
            self.notify("Loading accounts...", severity="information")

            client = DCypherClient(self.api_url)
            accounts = client.list_accounts()

            # Update table
            table = self.query_one("#accounts-table", DataTable)
            table.clear()

            if not accounts:
                self.operation_results = "No accounts found on server"
            else:
                for account in accounts:
                    table.add_row(
                        account[:16] + "..." if len(account) > 16 else account,
                        "Unknown",  # Created date not provided by API
                        "Unknown",  # PQ keys count
                        "Unknown",  # PRE status
                        "Unknown",  # Files count
                    )

                self.operation_results = (
                    f"✓ Found {len(accounts)} account(s):\n"
                    + "\n".join([f"  - {acc[:20]}..." for acc in accounts[:5]])
                )

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

            # Initialize API client with identity file
            client = DCypherClient(
                self.api_url, identity_path=self.current_identity_path
            )

            # Load keys to get PQ key info for account creation
            keys_data = KeyManager.load_keys_unified(Path(self.current_identity_path))

            pk_classic_hex = client.get_classic_public_key()
            pq_keys = [
                {"pk_hex": key["pk_hex"], "alg": key["alg"]}
                for key in keys_data["pq_keys"]
            ]

            result = client.create_account(pk_classic_hex, pq_keys)

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

            client = DCypherClient(self.api_url)
            account = client.get_account(public_key)

            # Format account details
            details = []
            details.append(f"Public Key: {account.get('public_key', 'N/A')}")
            details.append(f"Created: {account.get('created_at', 'N/A')}")

            if "pq_keys" in account:
                details.append(f"Post-Quantum Keys: {len(account['pq_keys'])}")
                for i, pq_key in enumerate(account["pq_keys"][:3]):  # Show first 3
                    details.append(f"  {i + 1}. {pq_key.get('alg', 'N/A')}")

            if "pre_public_key_hex" in account and account["pre_public_key_hex"]:
                details.append(
                    f"PRE: Enabled ({account['pre_public_key_hex'][:16]}...)"
                )
            else:
                details.append("PRE: Not initialized")

            self.operation_results = "✓ Account Details:\n" + "\n".join(details)
            self.update_results_display()
            self.notify("Account details retrieved", severity="information")

        except DCypherAPIError as e:
            self.notify(f"Failed to get account: {e}", severity="error")
        except Exception as e:
            self.notify(f"Error: {e}", severity="error")

    def action_supported_algorithms(self) -> None:
        """List supported algorithms (equivalent to CLI supported-algorithms)"""
        try:
            self.notify("Getting supported algorithms...", severity="information")

            client = DCypherClient(self.api_url)
            algorithms = client.get_supported_algorithms()

            self.operation_results = (
                "✓ Supported post-quantum signature algorithms:\n"
                + "\n".join([f"  - {alg}" for alg in algorithms])
            )
            self.update_results_display()
            self.notify(
                f"Found {len(algorithms)} supported algorithms", severity="information"
            )

        except DCypherAPIError as e:
            self.notify(f"Failed to get supported algorithms: {e}", severity="error")
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

            if not algorithm:
                self.notify("Select an algorithm", severity="warning")
                return

            self.notify(f"Adding {algorithm} key to account...", severity="information")

            # Initialize API client with identity file
            client = DCypherClient(
                self.api_url, identity_path=self.current_identity_path
            )
            pk_classic_hex = client.get_classic_public_key()

            # Generate new key for the specified algorithm
            import oqs

            sig = oqs.Signature(algorithm)
            sk = sig.generate_keypair()
            pk_hex = sig.public_key.hex()

            new_keys = [{"pk_hex": pk_hex, "alg": algorithm}]
            result = client.add_pq_keys(pk_classic_hex, new_keys)

            self.operation_results = f"✓ Successfully added {algorithm} key to account!\n  Key: {pk_hex[:16]}...\n  ⚠️  Key added to server but not saved locally"
            self.update_results_display()
            self.notify("PQ key added successfully", severity="information")

            # Clean up OQS object
            sig.free()

        except Exception as e:
            self.notify(f"Failed to add PQ keys: {e}", severity="error")

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

            # Initialize API client with identity file
            client = DCypherClient(
                self.api_url, identity_path=self.current_identity_path
            )
            pk_classic_hex = client.get_classic_public_key()

            result = client.remove_pq_keys(pk_classic_hex, [algorithm])

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

            # Initialize API client with identity file
            client = DCypherClient(
                self.api_url, identity_path=self.current_identity_path
            )
            pk_classic_hex = client.get_classic_public_key()
            files = client.list_files(pk_classic_hex)

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
