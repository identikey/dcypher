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
from typing import Optional, Dict, Any
from pathlib import Path
import json

from .theme import CYBERPUNK_THEME, get_cyberpunk_theme
from .widgets.ascii_art import ASCIIBanner
from .widgets.system_monitor import SystemMonitor
from .widgets.process_monitor import ProcessCPUDivider, ProcessMemoryDivider
from .screens.dashboard import DashboardScreen
from .screens.identity import IdentityScreen
from .screens.crypto import CryptoScreen
from .screens.accounts import AccountsScreen
from .screens.files import FilesScreen
from .screens.sharing import SharingScreen

# Import API client
from src.lib.api_client import DCypherClient


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
    current_identity_path: reactive[Optional[str]] = reactive(None)
    identity_info: reactive[Optional[Dict[str, Any]]] = reactive(None)
    api_url: reactive[str] = reactive("http://127.0.0.1:8000")
    connection_status: reactive[str] = reactive("disconnected")
    transparent_background: reactive[bool] = reactive(False)

    # Centralized API client
    _api_client: Optional[DCypherClient] = None

    def __init__(self, identity_path=None, api_url=None):
        super().__init__()
        if identity_path:
            self.current_identity_path = identity_path
        if api_url:
            self.api_url = api_url

        # Initialize process monitoring widgets
        self.cpu_divider: Optional[ProcessCPUDivider] = None
        self.memory_divider: Optional[ProcessMemoryDivider] = None

    @property
    def api_client(self) -> Optional[DCypherClient]:
        """Get the current API client instance"""
        return self._api_client

    def get_or_create_api_client(self) -> DCypherClient:
        """Get existing API client or create a new one"""
        if self._api_client is None:
            self._api_client = DCypherClient(
                self.api_url, identity_path=self.current_identity_path
            )
        return self._api_client

    def watch_current_identity_path(
        self, old_path: Optional[str], new_path: Optional[str]
    ) -> None:
        """React to identity path changes"""
        if new_path != old_path:
            # Update API client with new identity
            if self._api_client:
                self._api_client.keys_path = new_path
            else:
                self._api_client = DCypherClient(self.api_url, identity_path=new_path)

            # Load identity info
            if new_path:
                self.load_identity_info(new_path)
            else:
                self.identity_info = None

            # Notify all screens about identity change
            self.broadcast_identity_change()

    def watch_api_url(self, old_url: str, new_url: str) -> None:
        """React to API URL changes"""
        if new_url != old_url:
            # Create new API client with updated URL
            self._api_client = DCypherClient(
                new_url, identity_path=self.current_identity_path
            )
            # Check connection
            self.check_api_connection()

    def load_identity_info(self, identity_path: str) -> None:
        """Load identity information from file"""
        try:
            path = Path(identity_path)
            if path.exists():
                with open(path, "r") as f:
                    self.identity_info = json.load(f)
            else:
                self.identity_info = None
                self.notify(
                    f"Identity file not found: {identity_path}", severity="error"
                )
        except Exception as e:
            self.identity_info = None
            self.notify(f"Failed to load identity: {e}", severity="error")

    def broadcast_identity_change(self) -> None:
        """Notify all screens about identity change"""
        # Update dashboard screen
        try:
            dashboard = self.query_one("#dashboard", DashboardScreen)
            dashboard.update_identity_status(
                {
                    "loaded": self.current_identity_path is not None,
                    "path": self.current_identity_path,
                    "info": self.identity_info,
                }
            )
        except Exception:
            pass

        # Update other screens' status displays
        for screen_id in ["#accounts", "#files", "#sharing"]:
            try:
                screen = self.query_one(screen_id)
                # Call update_status_display if it exists on the screen
                update_method = getattr(screen, "update_status_display", None)
                if update_method and callable(update_method):
                    update_method()
            except Exception:
                pass

    def watch_transparent_background(self, transparent: bool) -> None:
        """Update CSS when transparency mode changes"""
        # TODO: Implement dynamic CSS updates in future version
        pass

    def compose(self) -> ComposeResult:
        """Create the main UI layout"""
        yield Header(show_clock=True)

        # CPU usage divider - positioned under header
        self.cpu_divider = ProcessCPUDivider(id="cpu-divider")
        yield self.cpu_divider

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
                # Dashboard - Use proper DashboardScreen
                yield DashboardScreen(id="dashboard")

                # Identity Management - Use proper IdentityScreen with API URL
                yield IdentityScreen(id="identity")

                # Crypto Operations - Use proper CryptoScreen
                yield CryptoScreen(id="crypto")

                # Accounts Management - Use proper AccountsScreen
                yield AccountsScreen(id="accounts")

                # File Operations - Use proper FilesScreen
                yield FilesScreen(id="files")

                # Sharing & Collaboration - Use proper SharingScreen
                yield SharingScreen(id="sharing")

        # Memory usage divider - positioned above footer
        self.memory_divider = ProcessMemoryDivider(id="memory-divider")
        yield self.memory_divider

        yield Footer()

    def on_mount(self) -> None:
        """Initialize the application"""
        # Note: title and sub_title are set via class attributes TITLE and SUB_TITLE

        # Start background tasks
        self.set_interval(1.0, self.update_system_status)
        self.set_interval(5.0, self.check_api_connection)

        # Load identity if provided at startup
        if self.current_identity_path:
            self.load_identity_info(self.current_identity_path)
            self.broadcast_identity_change()

    def update_system_status(self) -> None:
        """Update system status information"""
        # This will be called every second to update real-time data

        # Update process monitoring widgets
        if self.cpu_divider:
            self.cpu_divider.update_cpu_usage()
        if self.memory_divider:
            self.memory_divider.update_memory_usage()

    def check_api_connection(self) -> None:
        """Check API connection status"""
        # This will be called every 5 seconds to check API connectivity
        try:
            if self._api_client:
                # Try to get nonce to check connection
                self._api_client.get_nonce()
                self.connection_status = "connected"
            else:
                self.connection_status = "disconnected"
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

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """
        Global button event handler that delegates to appropriate child widgets.

        This ensures button events from child widgets (like IdentityScreen)
        are properly handled even when embedded in TabbedContent.
        """
        button_id = event.button.id

        # Let the event bubble up to child widgets first
        # by not stopping propagation immediately

        # Get the current active tab to determine which widget should handle the event
        try:
            tabs = self.query_one(TabbedContent)
            active_tab = tabs.active

            # Map tab IDs to our screen widgets
            if active_tab == "tab-2":  # Identity tab
                try:
                    identity_screen = self.query_one("#identity", IdentityScreen)
                    # The child widget should have already handled the event
                    # This is just a fallback to ensure events are processed
                    if hasattr(identity_screen, "on_button_pressed"):
                        # Let the child handle it directly if it hasn't already
                        pass
                except Exception as e:
                    self.log.warning(f"Could not delegate to identity screen: {e}")

            # Handle dashboard buttons directly (since they're part of main app)
            elif button_id in [
                "load-identity-btn",
                "generate-keys-btn",
                "system-info-btn",
                "help-btn",
            ]:
                self.handle_dashboard_button(button_id)

        except Exception as e:
            self.log.warning(f"Error in global button handler: {e}")

    def handle_dashboard_button(self, button_id: str) -> None:
        """Handle dashboard-specific button presses"""
        if button_id == "load-identity-btn":
            # TODO: Implement dashboard identity loading
            pass
        elif button_id == "generate-keys-btn":
            # TODO: Implement key generation from dashboard
            pass
        elif button_id == "system-info-btn":
            # TODO: Show system information
            pass
        elif button_id == "help-btn":
            self.action_show_help()


def run_tui(identity_path=None, api_url=None):
    """Run the dCypher TUI application"""
    app = DCypherTUI(identity_path=identity_path, api_url=api_url)
    app.run()


if __name__ == "__main__":
    run_tui()
