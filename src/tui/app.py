"""
dCypher TUI Main Application
Cyberpunk-inspired terminal interface with @repligate aesthetics
"""

from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical
from textual.widgets import Header, Footer, Static, TabbedContent, TabPane
from textual.binding import Binding
from textual.reactive import reactive
from textual.screen import Screen

from .theme import CYBERPUNK_THEME
from .widgets.ascii_art import ASCIIBanner
from .widgets.system_monitor import SystemMonitor
from .screens.dashboard import DashboardScreen
from .screens.identity import IdentityScreen
from .screens.crypto import CryptoScreen
from .screens.accounts import AccountsScreen
from .screens.files import FilesScreen
from .screens.sharing import SharingScreen


class DCypherTUI(App):
    """
    dCypher Terminal User Interface
    
    A cyberpunk-inspired TUI for quantum-resistant encryption operations.
    Influences: btop, cipherpunk aesthetics, art deco, @repligate
    """
    
    CSS = CYBERPUNK_THEME
    
    TITLE = "dCypher - Quantum-Resistant Encryption TUI"
    SUB_TITLE = "REPLICANT TERMINAL v2.1.0"
    
    BINDINGS = [
        Binding("ctrl+c", "quit", "Quit", priority=True),
        Binding("ctrl+d", "toggle_dark", "Toggle Dark Mode"),
        Binding("f1", "show_help", "Help"),
        Binding("f2", "show_logs", "Logs"),
        Binding("f12", "screenshot", "Screenshot"),
    ]
    
    # Reactive state
    current_identity = reactive(None)
    api_url = reactive("http://127.0.0.1:8000")
    connection_status = reactive("disconnected")
    
    def __init__(self, identity_path=None, api_url=None):
        super().__init__()
        if identity_path:
            self.current_identity = identity_path
        if api_url:
            self.api_url = api_url
    
    def compose(self) -> ComposeResult:
        """Create the main UI layout"""
        yield Header(show_clock=True)
        
        with Container(id="main-container"):
            # ASCII Banner
            yield ASCIIBanner()
            
            # Main content area with tabs
            with TabbedContent(initial="dashboard"):
                with TabPane("Dashboard", id="dashboard"):
                    yield DashboardScreen()
                
                with TabPane("Identity", id="identity"):
                    yield IdentityScreen()
                
                with TabPane("Crypto", id="crypto"):
                    yield CryptoScreen()
                
                with TabPane("Accounts", id="accounts"):
                    yield AccountsScreen()
                
                with TabPane("Files", id="files"):
                    yield FilesScreen()
                
                with TabPane("Sharing", id="sharing"):
                    yield SharingScreen()
        
        yield Footer()
    
    def on_mount(self) -> None:
        """Initialize the application"""
        self.title = self.TITLE
        self.sub_title = self.SUB_TITLE
        
        # Start background tasks
        self.set_interval(1.0, self.update_system_status)
        self.set_interval(5.0, self.check_api_connection)
    
    def update_system_status(self) -> None:
        """Update system status information"""
        # This will be called every second to update real-time data
        pass
    
    def check_api_connection(self) -> None:
        """Check API connection status"""
        # This will be called every 5 seconds to check API connectivity
        try:
            # TODO: Implement actual API ping
            self.connection_status = "connected"
        except Exception:
            self.connection_status = "disconnected"
    
    def action_toggle_dark(self) -> None:
        """Toggle dark mode"""
        self.dark = not self.dark
    
    def action_show_help(self) -> None:
        """Show help screen"""
        # TODO: Implement help screen
        pass
    
    def action_show_logs(self) -> None:
        """Show logs screen"""
        # TODO: Implement logs screen
        pass
    
    def action_screenshot(self) -> None:
        """Take a screenshot"""
        self.save_screenshot()


def run_tui(identity_path=None, api_url=None):
    """Run the dCypher TUI application"""
    app = DCypherTUI(identity_path=identity_path, api_url=api_url)
    app.run()


if __name__ == "__main__":
    run_tui()