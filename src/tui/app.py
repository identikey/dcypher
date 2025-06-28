"""
dCypher TUI Main Application
Cyberpunk-inspired terminal interface with @repligate aesthetics
"""

from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical
from textual.widgets import Header, Footer, Static, TabbedContent, Tabs, Button
from textual.binding import Binding
from textual.reactive import reactive
from textual.screen import Screen

from .theme import CYBERPUNK_THEME, get_cyberpunk_theme
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

    TITLE = "dCypher - Quantum-Resistant Encryption TUI"
    SUB_TITLE = "REPLICANT TERMINAL v2.1.0"

    BINDINGS = [
        Binding("ctrl+c", "quit", "Quit", priority=True),
        Binding("ctrl+d", "toggle_dark", "Toggle Dark Mode"),
        Binding("ctrl+t", "toggle_transparent", "Toggle Transparent Background"),
        Binding("f1", "show_help", "Help"),
        Binding("f2", "show_logs", "Logs"),
        Binding("f12", "screenshot", "Screenshot"),
        # Tab navigation
        Binding("left", "previous_tab", "Previous Tab"),
        Binding("right", "next_tab", "Next Tab"),
        Binding("shift+tab", "previous_tab", "Previous Tab"),
        Binding("tab", "next_tab", "Next Tab"),
        # Quick tab access
        Binding("1", "switch_tab('dashboard')", "Dashboard"),
        Binding("2", "switch_tab('identity')", "Identity"),
        Binding("3", "switch_tab('crypto')", "Crypto"),
        Binding("4", "switch_tab('accounts')", "Accounts"),
        Binding("5", "switch_tab('files')", "Files"),
        Binding("6", "switch_tab('sharing')", "Sharing"),
    ]

    # Reactive state
    current_identity = reactive(None)
    api_url = reactive("http://127.0.0.1:8000")
    connection_status = reactive("disconnected")
    transparent_background = reactive(False)

    def __init__(self, identity_path=None, api_url=None):
        super().__init__()
        if identity_path:
            self.current_identity = identity_path
        if api_url:
            self.api_url = api_url

    @property
    def CSS(self) -> str:
        """Dynamic CSS based on transparency setting"""
        return get_cyberpunk_theme(transparent_background=self.transparent_background)

    def watch_transparent_background(self, transparent: bool) -> None:
        """Update CSS when transparency mode changes"""
        if hasattr(self, "_dom"):  # Only refresh if app is running
            self.refresh_css()

    def compose(self) -> ComposeResult:
        """Create the main UI layout"""
        yield Header(show_clock=True)

        with Container(id="main-container"):
            # ASCII Banner
            yield ASCIIBanner()

            # Simplified TabbedContent test - just Static widgets
            with TabbedContent(
                "Dashboard", "Identity", "Crypto", "Accounts", "Files", "Sharing"
            ):
                yield Static(
                    "🎛️  Dashboard Content\n\nThis is where system monitoring and quick actions would appear.\n\nSystem Status: ✅ Online\nIdentity: Not loaded\nAPI: Connecting...",
                    id="dashboard-content",
                )
                yield Static(
                    "🆔  Identity Management\n\nLoad and manage your digital identities here.\n\nStatus: No identity loaded\nActions: Load, Create, Backup",
                    id="identity-content",
                )
                yield Static(
                    "🔐  Cryptography Operations\n\nEncrypt and decrypt files with quantum-resistant algorithms.\n\nAvailable: CRYSTALS-Kyber, CRYSTALS-Dilithium\nStatus: Ready",
                    id="crypto-content",
                )
                yield Static(
                    "👥  Account Management\n\nManage contacts and shared keys.\n\nContacts: 0\nShared Keys: 0",
                    id="accounts-content",
                )
                yield Static(
                    "📁  File Operations\n\nSecure file storage and sharing.\n\nEncrypted Files: 0\nShared Files: 0",
                    id="files-content",
                )
                yield Static(
                    "🔗  Secure Sharing\n\nShare encrypted content securely.\n\nActive Shares: 0\nPending Invites: 0",
                    id="sharing-content",
                )

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
        # Use Textual's built-in theme switching
        if self.theme == "textual-dark":
            self.theme = "textual-light"
        else:
            self.theme = "textual-dark"

    def action_toggle_transparent(self) -> None:
        """Toggle transparent background mode"""
        self.transparent_background = not self.transparent_background
        self.refresh_css()  # Refresh the CSS to apply changes

    def action_show_help(self) -> None:
        """Show help screen"""
        # TODO: Implement help screen
        pass

    def action_show_logs(self) -> None:
        """Show logs screen"""
        # TODO: Implement logs screen
        pass

    def action_screenshot(
        self, filename: str | None = None, path: str | None = None
    ) -> None:
        """Take a screenshot"""
        import os
        from datetime import datetime

        # Ensure screenshots directory exists
        screenshots_dir = "screenshots"
        os.makedirs(screenshots_dir, exist_ok=True)

        # Generate timestamped filename if not provided
        if not filename:
            timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            filename = f"dcypher_tui_{timestamp}.svg"

        # Save screenshot to the screenshots directory
        filepath = os.path.join(screenshots_dir, filename)
        self.save_screenshot(filename, path=screenshots_dir)
        self.log.info(f"Screenshot saved to {filepath}")

    def action_previous_tab(self) -> None:
        """Navigate to previous tab"""
        try:
            tabs = self.query_one(TabbedContent)
            # Access the internal Tabs widget for navigation
            tabs_widget = tabs.query_one(Tabs)
            tabs_widget.action_previous_tab()
        except Exception as e:
            self.log.warning(f"Could not navigate to previous tab: {e}")

    def action_next_tab(self) -> None:
        """Navigate to next tab"""
        try:
            tabs = self.query_one(TabbedContent)
            # Access the internal Tabs widget for navigation
            tabs_widget = tabs.query_one(Tabs)
            tabs_widget.action_next_tab()
        except Exception as e:
            self.log.warning(f"Could not navigate to next tab: {e}")

    def action_switch_tab(self, tab_id: str) -> None:
        """Switch to specific tab by ID"""
        try:
            tabs = self.query_one(TabbedContent)
            # Map our friendly names to auto-generated tab IDs
            tab_mapping = {
                "dashboard": "tab-1",
                "identity": "tab-2",
                "crypto": "tab-3",
                "accounts": "tab-4",
                "files": "tab-5",
                "sharing": "tab-6",
            }
            actual_tab_id = tab_mapping.get(tab_id, tab_id)
            tabs.active = actual_tab_id
        except Exception as e:
            self.log.warning(f"Could not switch to tab {tab_id}: {e}")


def run_tui(identity_path=None, api_url=None):
    """Run the dCypher TUI application"""
    app = DCypherTUI(identity_path=identity_path, api_url=api_url)
    app.run()


if __name__ == "__main__":
    run_tui()
