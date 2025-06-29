#!/usr/bin/env python3
"""
Visual Demo of dCypher TUI
Shows what the interface looks like without crypto dependencies
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical
from textual.widgets import Header, Footer, TabbedContent, TabPane, Static, Button, DataTable, ProgressBar
from textual.reactive import reactive

# Import our TUI components
from tui.theme import CYBERPUNK_THEME
from tui.widgets.ascii_art import ASCIIBanner, CyberpunkBorder
from tui.widgets.system_monitor import SystemMonitor, CryptoMonitor


class VisualDemoApp(App):
    """
    Visual demo of the dCypher TUI without crypto dependencies
    """
    
    CSS = CYBERPUNK_THEME
    
    TITLE = "dCypher TUI - Visual Demo"
    SUB_TITLE = "Cyberpunk Terminal Interface"
    
    BINDINGS = [
        ("ctrl+c", "quit", "Exit"),
        ("ctrl+d", "toggle_dark", "Toggle Dark Mode"),
        ("f1", "help", "Help"),
        ("f12", "screenshot", "Screenshot"),
    ]
    
    def compose(self) -> ComposeResult:
        """Compose the demo interface"""
        yield Header()
        
        with Container(id="main-container"):
            # ASCII Banner at top
            yield ASCIIBanner(compact=False)
            
            # Main tabbed content
            with TabbedContent():
                # Dashboard Tab
                with TabPane("Dashboard", id="dashboard"):
                    yield self.create_dashboard()
                
                # Identity Tab  
                with TabPane("Identity", id="identity"):
                    yield self.create_identity_demo()
                
                # Crypto Tab
                with TabPane("Crypto", id="crypto"):
                    yield self.create_crypto_demo()
                
                # Files Tab
                with TabPane("Files", id="files"):
                    yield self.create_files_demo()
                
                # Monitor Tab
                with TabPane("Monitor", id="monitor"):
                    yield self.create_monitor_demo()
        
        yield Footer()
    
    def create_dashboard(self) -> Container:
        """Create dashboard demo"""
        with Container(id="dashboard-container"):
            # Top row - Monitors
            with Horizontal(id="monitors-row"):
                yield SystemMonitor(id="system-monitor")
                yield CryptoMonitor(id="crypto-monitor")
            
            # Middle row - Status panels
            with Horizontal(id="status-row"):
                yield Static(self.create_status_panel("IDENTITY STATUS", "✓ Loaded", "green"), id="identity-status")
                yield Static(self.create_status_panel("API CONNECTION", "✓ Connected", "green"), id="api-status")
                yield Static(self.create_status_panel("FILES & SHARES", "Files: 12\nShares: 5", "cyan"), id="files-status")
            
            # Bottom row - Quick actions
            with Horizontal(id="actions-row"):
                yield Button("Load Identity", id="load-identity-btn", variant="primary")
                yield Button("Upload File", id="upload-file-btn")
                yield Button("Create Share", id="create-share-btn")
                yield Button("View Logs", id="view-logs-btn")
        
        return Container()
    
    def create_identity_demo(self) -> Container:
        """Create identity management demo"""
        with Container():
            yield Static("◢ IDENTITY MANAGEMENT ◣", classes="title")
            
            with Horizontal():
                # Current identity info
                yield Static(self.create_identity_panel(), id="identity-info")
                
                # Identity actions
                with Vertical():
                    yield Button("Create New Identity", variant="primary")
                    yield Button("Load Identity")
                    yield Button("Rotate Keys")
                    yield Button("Backup Identity")
            
            # Identity history table
            table = DataTable()
            table.add_columns("Name", "Path", "Created", "Status")
            table.add_rows([
                ("default", "~/.dcypher/default.json", "2024-01-15", "Active"),
                ("backup", "~/.dcypher/backup.json", "2024-01-10", "Inactive"),
                ("test", "~/.dcypher/test.json", "2024-01-05", "Inactive"),
            ])
            yield table
        
        return Container()
    
    def create_crypto_demo(self) -> Container:
        """Create crypto operations demo"""
        with Container():
            yield Static("◢ CRYPTOGRAPHIC OPERATIONS ◣", classes="title")
            
            with Horizontal():
                # Key generation
                with Vertical():
                    yield Static("Key Generation", classes="section-title")
                    yield Button("Generate Crypto Context")
                    yield Button("Generate Key Pair")
                    yield Button("Generate Signing Keys")
                
                # Encryption operations
                with Vertical():
                    yield Static("Encryption Operations", classes="section-title")
                    yield Button("Encrypt Data", variant="primary")
                    yield Button("Decrypt Data")
                    yield Button("Re-encrypt Data")
            
            # Progress and results
            yield ProgressBar(total=100, progress=75, id="crypto-progress")
            yield Static("Last operation: File encrypted successfully ✓", id="crypto-results")
        
        return Container()
    
    def create_files_demo(self) -> Container:
        """Create files management demo"""
        with Container():
            yield Static("◢ FILE MANAGEMENT ◣", classes="title")
            
            with Horizontal():
                # File operations
                with Vertical():
                    yield Static("File Operations", classes="section-title")
                    yield Button("Upload File", variant="primary")
                    yield Button("Download File")
                    yield Button("Browse Files")
                
                # File info
                with Vertical():
                    yield Static("File Information", classes="section-title")
                    yield Static("Selected: document.pdf\nSize: 2.3MB\nEncrypted: Yes\nShares: 3")
            
            # Files table
            table = DataTable()
            table.add_columns("Filename", "Size", "Encrypted", "Shares", "Modified")
            table.add_rows([
                ("document.pdf", "2.3MB", "Yes", "3", "2024-01-20"),
                ("image.jpg", "1.8MB", "Yes", "1", "2024-01-19"),
                ("data.csv", "856KB", "Yes", "0", "2024-01-18"),
            ])
            yield table
        
        return Container()
    
    def create_monitor_demo(self) -> Container:
        """Create monitoring demo"""
        with Container():
            yield Static("◢ SYSTEM & CRYPTO MONITORING ◣", classes="title")
            
            with Horizontal():
                # System monitor (larger)
                yield SystemMonitor(id="main-system-monitor")
                
                # Crypto monitor
                with Vertical():
                    yield CryptoMonitor(id="main-crypto-monitor")
                    
                    # Additional stats
                    yield Static("""
PERFORMANCE STATS

Encryption Rate: 45.2 MB/s
Decryption Rate: 52.1 MB/s
Key Generation: 156 keys/min
Operations Today: 1,247
Success Rate: 99.8%
                    """, id="perf-stats")
        
        return Container()
    
    def create_status_panel(self, title: str, content: str, color: str) -> str:
        """Create a status panel with border"""
        border = CyberpunkBorder(pattern="cyber")
        return f"""[bold {color}]{title}[/bold {color}]

{content}

Status: Online
Last Update: Just now"""
    
    def create_identity_panel(self) -> str:
        """Create identity information panel"""
        return """[bold green]CURRENT IDENTITY[/bold green]

Path: ~/.dcypher/default.json
Version: 1.0
Derivable: True

[cyan]Classic Key:[/cyan] a1b2c3d4...
[cyan]PQ Keys:[/cyan] 3 algorithms
  • Falcon-512
  • Dilithium-3
  • SPHINCS+-128s

[green]PRE: Enabled[/green]
Created: 2024-01-15
Last Used: Just now"""
    
    def on_mount(self) -> None:
        """Set up demo data when app starts"""
        # Simulate some system activity
        system_monitor = self.query_one("#system-monitor", SystemMonitor)
        system_monitor.cpu_percent = 45.2
        system_monitor.memory_percent = 67.8
        system_monitor.disk_percent = 34.1
        system_monitor.cpu_history = [40, 42, 45, 47, 45, 43, 45]
        system_monitor.memory_history = [65, 66, 67, 68, 67, 68, 67]
        
        # Simulate crypto activity
        crypto_monitor = self.query_one("#crypto-monitor", CryptoMonitor)
        crypto_monitor.active_operations = 2
        crypto_monitor.completed_operations = 156
        crypto_monitor.failed_operations = 3
        crypto_monitor.operation_history = [
            {"time": "14:32:15", "operation": "encrypt", "status": "completed"},
            {"time": "14:31:42", "operation": "decrypt", "status": "completed"},
            {"time": "14:30:18", "operation": "keygen", "status": "active"},
        ]
    
    def action_help(self) -> None:
        """Show help information"""
        self.notify("dCypher TUI Demo - Use tabs to navigate, Ctrl+C to exit", severity="information")
    
    def action_screenshot(self) -> None:
        """Take a screenshot"""
        self.save_screenshot()
        self.notify("Screenshot saved!", severity="information")


def main():
    """Run the visual demo"""
    print("🚀 Starting dCypher TUI Visual Demo...")
    print("Use Ctrl+C to exit, Tab to navigate between screens")
    print("=" * 60)
    
    app = VisualDemoApp()
    app.run()


if __name__ == "__main__":
    main()