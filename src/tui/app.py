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


class DCypherTUI(App[None]):
    """
    dCypher Terminal User Interface

    A cyberpunk-inspired TUI for quantum-resistant encryption operations.
    Influences: btop, cipherpunk aesthetics, art deco, @repligate
    """

    TITLE = "dCypher - Quantum-Resistant Encryption TUI"
    SUB_TITLE = "REPLICANT TERMINAL v2.1.0"
    CSS = CYBERPUNK_THEME

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

    # Reactive properties for app state
    current_identity: reactive[str | None] = reactive(None)
    api_url: reactive[str] = reactive("http://127.0.0.1:8000")
    connection_status: reactive[str] = reactive("disconnected")
    transparent_background: reactive[bool] = reactive(False)

    def __init__(self, identity_path=None, api_url=None):
        super().__init__()
        if identity_path:
            self.current_identity = identity_path
        if api_url:
            self.api_url = api_url

    def watch_transparent_background(self, transparent: bool) -> None:
        """Update CSS when transparency mode changes"""
        # TODO: Implement dynamic CSS updates in future version
        pass

    def compose(self) -> ComposeResult:
        """Create the main UI layout"""
        yield Header(show_clock=True)

        with Container(id="main-container"):
            # ASCII Banner
            yield ASCIIBanner()

            # Main content area with tabs - Each tab gets proper screen widgets
            with TabbedContent(
                "Dashboard",
                "Identity",
                "Crypto",
                "Accounts",
                "Files",
                "Sharing",
                id="main-tabs",
            ):
                # Dashboard content as a proper container with widgets
                with Container(id="dashboard"):
                    with Horizontal(id="monitors-row"):
                        yield SystemMonitor(id="system-monitor")
                        # yield CryptoMonitor(id="crypto-monitor")  # Comment out for now

                    with Horizontal(id="status-row"):
                        yield Static(
                            "🔍 Loading identity status...", id="identity-status"
                        )
                        yield Static("🌐 Checking API connection...", id="api-status")
                        yield Static("📁 Loading file status...", id="files-status")

                    with Horizontal(id="actions-row"):
                        yield Button(
                            "Load Identity", id="load-identity-btn", variant="primary"
                        )
                        yield Button("Generate Keys", id="generate-keys-btn")
                        yield Button("System Info", id="system-info-btn")
                        yield Button("Help", id="help-btn")

                # Identity Management - Use proper IdentityScreen
                yield IdentityScreen(id="identity")

                # Crypto Operations - Use proper CryptoScreen
                yield CryptoScreen(id="crypto")

                # Accounts Management - Use proper AccountsScreen
                yield AccountsScreen(id="accounts")

                # File Operations - Use proper FilesScreen
                yield FilesScreen(id="files")

                # Sharing & Collaboration - Use proper SharingScreen
                yield SharingScreen(id="sharing")

        yield Footer()

    def on_mount(self) -> None:
        """Initialize the application"""
        # Note: title and sub_title are set via class attributes TITLE and SUB_TITLE

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
        # Note: CSS transparency will be implemented in a future update
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
