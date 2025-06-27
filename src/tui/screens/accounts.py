"""
Accounts Management Screen
Handles account creation, listing, and management operations
"""

from textual.containers import Container, Horizontal, Vertical
from textual.widgets import Static, Button, Input, DataTable, Label
from textual.widget import Widget
from rich.panel import Panel


class AccountsScreen(Widget):
    """
    Accounts management screen with CLI feature parity
    Supports: list-accounts, create-account, get-account, add-pq-keys, remove-pq-keys
    """
    
    def compose(self):
        """Compose the accounts management interface"""
        with Container(id="accounts-container"):
            yield Static("◢ ACCOUNT MANAGEMENT ◣", classes="title")
            
            with Horizontal():
                # Account operations
                with Vertical(id="account-ops-panel"):
                    yield Label("Account Operations")
                    yield Button("List Accounts", id="list-accounts-btn")
                    yield Button("Create Account", id="create-account-btn", variant="primary")
                    yield Button("Get Account Info", id="get-account-btn")
                
                # PQ key management
                with Vertical(id="pq-keys-panel"):
                    yield Label("Post-Quantum Keys")
                    yield Button("Add PQ Keys", id="add-pq-keys-btn")
                    yield Button("Remove PQ Keys", id="remove-pq-keys-btn")
                    yield Button("Supported Algorithms", id="supported-algs-btn")
            
            # Accounts table
            yield DataTable(id="accounts-table")
    
    def on_mount(self) -> None:
        """Initialize accounts screen"""
        self.setup_accounts_table()
    
    def setup_accounts_table(self) -> None:
        """Setup the accounts table"""
        table = self.query_one("#accounts-table", DataTable)
        table.add_columns("Public Key", "Created", "PQ Keys", "PRE Status", "Files")
    
    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle account operation buttons"""
        button_id = event.button.id
        
        if button_id == "list-accounts-btn":
            self.action_list_accounts()
        elif button_id == "create-account-btn":
            self.action_create_account()
        # Add other handlers...
    
    def action_list_accounts(self) -> None:
        """List all accounts"""
        self.notify("Loading accounts...", severity="information")
        # TODO: Implement account listing
    
    def action_create_account(self) -> None:
        """Create new account"""
        self.notify("Creating account...", severity="information")
        # TODO: Implement account creation