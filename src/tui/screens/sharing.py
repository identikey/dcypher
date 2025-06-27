"""
Sharing Management Screen
Handles proxy re-encryption sharing operations
"""

from textual.containers import Container, Horizontal, Vertical
from textual.widgets import Static, Button, Input, DataTable, Label
from textual.widget import Widget


class SharingScreen(Widget):
    """
    Sharing management screen with CLI feature parity
    Supports: init-pre, create-share, list-shares, download-shared, revoke-share
    """
    
    def compose(self):
        """Compose the sharing management interface"""
        with Container(id="sharing-container"):
            yield Static("◢ PROXY RE-ENCRYPTION SHARING ◣", classes="title")
            
            with Horizontal():
                # PRE operations
                with Vertical(id="pre-ops-panel"):
                    yield Label("PRE Operations")
                    yield Button("Initialize PRE", id="init-pre-btn", variant="primary")
                    yield Button("Get PRE Context", id="get-pre-context-btn")
                
                # Share operations
                with Vertical(id="share-ops-panel"):
                    yield Label("Share Management")
                    yield Input(placeholder="Recipient public key...", id="recipient-key-input")
                    yield Input(placeholder="File hash...", id="file-hash-input")
                    yield Button("Create Share", id="create-share-btn")
                    yield Button("Revoke Share", id="revoke-share-btn")
            
            # Shares table
            yield DataTable(id="shares-table")
    
    def on_mount(self) -> None:
        """Initialize sharing screen"""
        self.setup_shares_table()
    
    def setup_shares_table(self) -> None:
        """Setup the shares table"""
        table = self.query_one("#shares-table", DataTable)
        table.add_columns("Share ID", "File Hash", "Recipient", "Created", "Status")
    
    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle sharing operation buttons"""
        button_id = event.button.id
        
        if button_id == "init-pre-btn":
            self.action_init_pre()
        elif button_id == "create-share-btn":
            self.action_create_share()
        # Add other handlers...
    
    def action_init_pre(self) -> None:
        """Initialize PRE capabilities"""
        self.notify("Initializing PRE capabilities...", severity="information")
        # TODO: Implement PRE initialization
    
    def action_create_share(self) -> None:
        """Create a new share"""
        recipient_input = self.query_one("#recipient-key-input", Input)
        file_hash_input = self.query_one("#file-hash-input", Input)
        
        recipient = recipient_input.value
        file_hash = file_hash_input.value
        
        if not recipient or not file_hash:
            self.notify("Enter recipient key and file hash", severity="warning")
            return
        
        self.notify("Creating share...", severity="information")
        # TODO: Implement share creation