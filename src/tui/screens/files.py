"""
File Management Screen
Handles file upload, download, and management operations
"""

from textual.containers import Container, Horizontal, Vertical
from textual.widgets import Static, Button, Input, DataTable, Label, ProgressBar
from textual.widget import Widget


class FilesScreen(Widget):
    """
    File management screen with CLI feature parity
    Supports: upload, download, download-chunks
    """
    
    def compose(self):
        """Compose the file management interface"""
        with Container(id="files-container"):
            yield Static("◢ FILE MANAGEMENT ◣", classes="title")
            
            with Horizontal():
                # File operations
                with Vertical(id="file-ops-panel"):
                    yield Label("File Operations")
                    yield Input(placeholder="File path...", id="file-path-input")
                    yield Button("Upload File", id="upload-file-btn", variant="primary")
                    yield Button("Download File", id="download-file-btn")
                    yield ProgressBar(id="file-progress")
                
                # File info
                with Vertical(id="file-info-panel"):
                    yield Static(id="file-info-display")
            
            # Files table
            yield DataTable(id="files-table")
    
    def on_mount(self) -> None:
        """Initialize files screen"""
        self.setup_files_table()
    
    def setup_files_table(self) -> None:
        """Setup the files table"""
        table = self.query_one("#files-table", DataTable)
        table.add_columns("Filename", "Hash", "Size", "Uploaded", "Shares")
    
    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle file operation buttons"""
        button_id = event.button.id
        
        if button_id == "upload-file-btn":
            self.action_upload_file()
        elif button_id == "download-file-btn":
            self.action_download_file()
    
    def action_upload_file(self) -> None:
        """Upload file"""
        file_input = self.query_one("#file-path-input", Input)
        file_path = file_input.value
        
        if not file_path:
            self.notify("Enter file path", severity="warning")
            return
        
        self.notify("Starting file upload...", severity="information")
        # TODO: Implement file upload
    
    def action_download_file(self) -> None:
        """Download file"""
        self.notify("Starting file download...", severity="information")
        # TODO: Implement file download