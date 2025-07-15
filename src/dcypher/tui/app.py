"""
dCypher TUI Main Application
Cyberpunk-inspired terminal interface with @repligate aesthetics
NOW WITH COMPREHENSIVE PROFILING FOR FULL CPU ANALYSIS
"""

from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical
from textual.widgets import Header, Footer, Static, TabbedContent, Tabs, Button
from textual.binding import Binding
from textual.reactive import reactive
from textual.screen import Screen
from typing import Optional, Dict, Any, Tuple
from pathlib import Path
import json
import time
from datetime import datetime, timedelta
from rich.text import Text

from dcypher.tui.theme import CYBERPUNK_THEME, get_cyberpunk_theme
from dcypher.tui.widgets.process_monitor import (
    ProcessCPUDivider,
    ProcessCPU15MinDivider,
)
from dcypher.tui.widgets.ascii_art import ASCIIBanner
from dcypher.tui.widgets.system_monitor import SystemMonitor
from dcypher.tui.screens.dashboard import DashboardScreen
from dcypher.tui.screens.identity import IdentityScreen
from dcypher.tui.screens.crypto import CryptoScreen
from dcypher.tui.screens.accounts import AccountsScreen
from dcypher.tui.screens.files import FilesScreen
from dcypher.tui.screens.sharing import SharingScreen

# Import API client
from dcypher.lib.api_client import DCypherClient

# Import comprehensive profiling tools
try:
    from dcypher.lib.profiling import profile, profile_block, create_animation_profiler  # type: ignore

    profiling_available = True
except ImportError:
    # Create no-op decorators if profiling not available
    from typing import Any, Callable, TypeVar
    from contextlib import nullcontext

    F = TypeVar("F", bound=Callable[..., Any])

    def profile(name: Any = None, backend: str = "cprofile") -> Callable[[F], F]:
        def decorator(func: F) -> F:
            return func

        return decorator

    def profile_block(name: Any, backend: str = "cprofile"):
        return nullcontext()

    def create_animation_profiler():
        return None

    profiling_available = False


class DCypherHeader(Static):
    """Custom header widget that displays title, uptime information, and clock"""

    DEFAULT_CSS = """
    DCypherHeader {
        dock: top;
        width: 100%;
        background: $accent;
        color: $text;
        text-align: center;
        height: 1;
        content-align: center middle;
    }
    """

    def __init__(self, app_instance, **kwargs):
        super().__init__(**kwargs)
        self.app_instance = app_instance

    def on_mount(self):
        """Update the header every second"""
        # PERFORMANCE OPTIMIZATION: Reduce header update frequency
        # Header was taking 0.5% of CPU with 86 calls - reduce to every 2 seconds
        self.set_interval(2.0, self.update_header)  # Reduced from 1.0s
        self.update_header()

    @profile("DCypherHeader.update_header")
    def update_header(self):
        """Update the header content with current uptime and time"""
        with profile_block("DCypherHeader.update_header.time_calculation"):
            # Get current time
            current_time = datetime.now().strftime("%H:%M:%S")

            # Get uptime info
            local_uptime = self.app_instance.get_uptime_string()
            connection_uptime = self.app_instance.get_connection_uptime_string()
            server_uptime = self.app_instance.get_server_uptime_string()

        with profile_block("DCypherHeader.update_header.text_formatting"):
            # Build header text with colors optimized for cyan background
            header_text = Text()
            header_text.append(
                f"{self.app_instance.TITLE} | ", style="bold bright_white"
            )
            header_text.append("Client ", style="bright_black")
            header_text.append(local_uptime, style="bold dark_green")

            header_text.append(" | Conn ", style="bright_black")
            if connection_uptime == "XX:XX:XX":
                header_text.append(connection_uptime, style="bold dark_red")
            else:
                header_text.append(connection_uptime, style="bold dark_green")

            if server_uptime:
                header_text.append(" | Server ", style="bold bright_black")
                header_text.append(server_uptime, style="bold dark_green")
            else:
                header_text.append(" | Server ", style="bold bright_black")
                header_text.append("XX:XX:XX", style="bold dark_red")

            # Add API server name/URL
            header_text.append(" | API ", style="bold bright_black")
            # Extract just the host:port from the URL for cleaner display
            api_display = self.app_instance.api_url.replace("http://", "").replace(
                "https://", ""
            )
            if server_uptime:
                header_text.append(api_display, style="bold dark_green")
            else:
                header_text.append(api_display, style="bold dark_red")

            header_text.append(f" | {current_time}", style="bold bright_white")

        with profile_block("DCypherHeader.update_header.widget_update"):
            self.update(header_text)


class DCypherTUI(App[None]):
    """
    dCypher Terminal User Interface

    A cyberpunk-inspired TUI for quantum-resistant encryption operations.
    Influences: btop, cipherpunk aesthetics, art deco, @repligate

    NOW WITH COMPREHENSIVE PROFILING FOR FULL CPU ANALYSIS
    """

    TITLE = "v0.0.1 dCypher Terminal"
    SUB_TITLE = "REPLICANT TERMINAL v2.1.0"
    CSS = CYBERPUNK_THEME

    BINDINGS = [
        Binding("ctrl+c", "quit", "Quit", priority=True),
        Binding("ctrl+d", "toggle_dark", "Toggle Dark Mode"),
        Binding("ctrl+r", "connect", "Connect to Server"),
        Binding("ctrl+shift+r", "disconnect", "Disconnect from Server"),
        Binding("f1", "show_help", "Help"),
        Binding("f2", "show_logs", "Logs"),
        Binding("f12", "screenshot", "Screenshot"),
        # Matrix effects
        Binding("f3", "toggle_matrix_rain", "Toggle Matrix Rain"),
        Binding("f4", "toggle_scrolling_code", "Toggle Scrolling Code"),
        # Matrix framerate controls
        Binding("plus,equal", "increase_matrix_framerate", "Increase Matrix FPS"),
        Binding("minus", "decrease_matrix_framerate", "Decrease Matrix FPS"),
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

    # Centralized API client
    _api_client: Optional[DCypherClient] = None

    def __init__(
        self,
        identity_path=None,
        api_url=None,
        profiling_config=None,
        profile_animations=False,
    ):
        super().__init__()
        if identity_path:
            self.current_identity_path = identity_path
        if api_url:
            self.api_url = api_url

        # Store profiling configuration
        self.profiling_config = profiling_config
        self.profile_animations = profile_animations

        # Initialize process monitoring widgets
        self.cpu_divider: Optional[ProcessCPUDivider] = None
        self.memory_divider: Optional[ProcessCPU15MinDivider] = None

        # Track application start time for uptime calculation
        self.start_time = time.time()

        # Track server uptime and health data
        self.server_uptime: Optional[str] = None
        self.server_health_data: Optional[Dict[str, Any]] = None

        # Track connection start time for connection uptime calculation
        self.connection_start_time: Optional[float] = None

    def get_uptime_string(self) -> str:
        """Calculate and format application uptime in HH:MM:SS format"""
        uptime_seconds = int(time.time() - self.start_time)

        # Convert to hours, minutes, seconds
        hours = uptime_seconds // 3600
        minutes = (uptime_seconds % 3600) // 60
        seconds = uptime_seconds % 60

        return f"{hours:02d}:{minutes:02d}:{seconds:02d}"

    def get_server_uptime_string(self) -> Optional[str]:
        """Get formatted server uptime string"""
        return self.server_uptime

    def get_connection_uptime_string(self) -> str:
        """Get formatted connection uptime string or 'XX:XX:XX' if disconnected"""
        if (
            self.connection_start_time is None
            or self.connection_status == "disconnected"
        ):
            return "XX:XX:XX"

        uptime_seconds = int(time.time() - self.connection_start_time)
        return self.format_uptime_seconds(uptime_seconds)

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

            # Update client status bar
            self.update_client_status_bar()

    def watch_api_url(self, old_url: str, new_url: str) -> None:
        """React to API URL changes"""
        if new_url != old_url:
            # Create new API client with updated URL
            self._api_client = DCypherClient(
                new_url, identity_path=self.current_identity_path
            )
            # Check connection
            self.check_api_connection()
            # Update client status bar
            self.update_client_status_bar()

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

    def create_identity_file(
        self, identity_name: str, key_dir: Path, overwrite: bool = False
    ) -> Tuple[str, Path]:
        """Create a new identity file using the API client"""
        try:
            client = self.get_or_create_api_client()
            return client.create_identity_file(identity_name, key_dir, overwrite)
        except Exception as e:
            self.notify(f"Failed to create identity: {e}", severity="error")
            raise

    def rotate_identity_keys(
        self, identity_path: str, reason: str = "manual"
    ) -> Dict[str, Any]:
        """Rotate keys in the current identity file"""
        try:
            from dcypher.lib.key_manager import KeyManager

            rotation_info = KeyManager.rotate_keys_in_identity(
                Path(identity_path), reason
            )

            # Reload identity info after rotation
            self.load_identity_info(identity_path)
            self.broadcast_identity_change()

            return rotation_info
        except Exception as e:
            self.notify(f"Failed to rotate keys: {e}", severity="error")
            raise

    def initialize_pre_for_identity(self, identity_path: str) -> None:
        """Initialize PRE capabilities for the identity"""
        try:
            client = self.get_or_create_api_client()
            # Temporarily set the identity path on the client
            old_path = client.keys_path
            client.keys_path = identity_path

            try:
                client.initialize_pre_for_identity()

                # Reload identity info after PRE initialization
                self.load_identity_info(identity_path)
                self.broadcast_identity_change()

            finally:
                # Restore original path
                client.keys_path = old_path

        except Exception as e:
            self.notify(f"Failed to initialize PRE: {e}", severity="error")
            raise

    def create_backup_of_identity(self, identity_path: str) -> Path:
        """Create a backup of the current identity file"""
        try:
            from dcypher.lib.key_manager import KeyManager

            identity_file = Path(identity_path)
            backup_dir = identity_file.parent / "backups"
            backup_path = KeyManager.backup_identity_securely(identity_file, backup_dir)

            return backup_path
        except Exception as e:
            self.notify(f"Failed to create backup: {e}", severity="error")
            raise

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

        # Update identity screen
        try:
            identity_screen = self.query_one("#identity")
            update_method = getattr(identity_screen, "update_identity_status", None)
            if update_method and callable(update_method):
                update_method(
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

    def compose(self) -> ComposeResult:
        """Create the main UI layout"""
        yield DCypherHeader(self)

        # CPU usage divider - positioned under header
        self.cpu_divider = ProcessCPUDivider(id="cpu-divider")
        yield self.cpu_divider

        # ASCII Banner
        yield ASCIIBanner()

        # Client Status Bar
        yield Static("", id="client-status-bar")

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
        self.memory_divider = ProcessCPU15MinDivider(id="memory-divider")
        yield self.memory_divider

        yield Footer()

    @profile("DCypherTUI.on_mount")
    def on_mount(self) -> None:
        """Initialize the application"""
        # PERFORMANCE OPTIMIZATION: Reduce background task frequency to save CPU
        # Previously: 1s system status, 5s API check
        # Now: 2s system status (50% reduction), 10s API check (50% reduction)
        self.set_interval(2.0, self.update_system_status)  # Reduced from 1.0s
        self.set_interval(10.0, self.check_api_connection)  # Reduced from 5.0s

        # Load identity if provided at startup
        if self.current_identity_path:
            self.load_identity_info(self.current_identity_path)
            self.broadcast_identity_change()

        # Initialize matrix background based on connection status
        self.update_matrix_for_connection_status()

        # Initialize client status bar
        self.update_client_status_bar()

    @profile("DCypherTUI.update_client_status_bar")
    def update_client_status_bar(self) -> None:
        """Update the client status bar with connection and identity information"""
        try:
            status_bar = self.query_one("#client-status-bar", Static)

            # Build status text with colors
            status_text = Text()
            status_text.append("CLIENT STATUS: ", style="bold bright_white")

            # Connection status
            if self.connection_status == "connected":
                status_text.append("● CONNECTED", style="bold bright_green")
            else:
                status_text.append("● DISCONNECTED", style="bold bright_red")

            # Identity status
            status_text.append(" | IDENTITY: ", style="bold bright_white")
            if self.current_identity_path:
                identity_name = Path(self.current_identity_path).stem
                status_text.append(f"● {identity_name}", style="bold bright_cyan")
            else:
                status_text.append("● NONE", style="bold bright_yellow")

            # API URL
            status_text.append(" | API: ", style="bold bright_white")
            api_display = self.api_url.replace("http://", "").replace("https://", "")
            status_text.append(api_display, style="bold bright_magenta")

            status_bar.update(status_text)

        except Exception as e:
            self.log.warning(f"Failed to update client status bar: {e}")

    @profile("DCypherTUI.update_system_status")
    def update_system_status(self) -> None:
        """Update system status information"""
        # This will be called every second to update real-time data
        with profile_block("DCypherTUI.update_system_status.cpu_monitoring"):
            # Update process monitoring widgets
            if self.cpu_divider:
                self.cpu_divider.update_cpu_usage()

        with profile_block("DCypherTUI.update_system_status.memory_monitoring"):
            if self.memory_divider:
                self.memory_divider.update_memory_usage()

    @profile("DCypherTUI.check_api_connection")
    def check_api_connection(self) -> None:
        """Check API connection status and get server uptime"""
        # This will be called every 5 seconds to check API connectivity
        old_status = self.connection_status

        with profile_block("DCypherTUI.check_api_connection.connection_test"):
            try:
                if self._api_client:
                    # Try to get nonce to check connection first
                    self._api_client.get_nonce()

                    # If we weren't connected before, mark connection start time
                    if self.connection_status == "disconnected":
                        self.connection_start_time = time.time()

                    self.connection_status = "connected"

                    with profile_block("DCypherTUI.check_api_connection.server_uptime"):
                        # Try to get server uptime only if connection succeeded
                        self.fetch_server_uptime()
                else:
                    self.connection_status = "disconnected"
                    self.connection_start_time = None
                    self.server_uptime = None
                    self.server_health_data = None
            except Exception:
                # If connection fails, mark as disconnected
                self.connection_status = "disconnected"
                self.connection_start_time = None
                self.server_uptime = None
                self.server_health_data = None
                # Update dashboard to show disconnected state
                self.update_dashboard_server_stats()
                # Only clear the API client if we're not manually connecting
                # This prevents clearing during manual connect attempts

        with profile_block("DCypherTUI.check_api_connection.matrix_update"):
            # Update matrix background if connection status changed
            if old_status != self.connection_status:
                self.update_matrix_for_connection_status()
                self.update_client_status_bar()

    @profile("DCypherTUI.fetch_server_uptime")
    def fetch_server_uptime(self) -> None:
        """Fetch server uptime and health data from the API"""
        try:
            if self._api_client:
                # Get server health information including uptime and stats
                health_data = self._api_client.get_health()
                uptime_seconds = health_data.get("uptime_seconds", 0)
                self.server_uptime = self.format_uptime_seconds(uptime_seconds)
                self.server_health_data = health_data

                # Update dashboard server stats
                self.update_dashboard_server_stats()
        except Exception:
            # If health endpoint doesn't exist or fails, just set to None
            self.server_uptime = None
            self.server_health_data = None

    def format_uptime_seconds(self, uptime_seconds: int) -> str:
        """Format uptime seconds into HH:MM:SS format"""
        # Convert to hours, minutes, seconds
        hours = uptime_seconds // 3600
        minutes = (uptime_seconds % 3600) // 60
        seconds = uptime_seconds % 60

        return f"{hours:02d}:{minutes:02d}:{seconds:02d}"

    def update_dashboard_server_stats(self) -> None:
        """Update dashboard server statistics display"""
        try:
            dashboard = self.query_one("#dashboard", DashboardScreen)
            dashboard.update_server_stats()
        except Exception:
            # Dashboard may not be mounted yet
            pass

    def action_toggle_dark(self) -> None:
        """Toggle dark mode"""
        # Use Textual's built-in theme switching
        if self.theme == "textual-dark":
            self.theme = "textual-light"
        else:
            self.theme = "textual-dark"

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

    def action_connect(self) -> None:
        """Connect to the server"""
        try:
            # Create or recreate API client
            self._api_client = DCypherClient(
                self.api_url, identity_path=self.current_identity_path
            )

            # Test connection by getting nonce
            self._api_client.get_nonce()

            # If successful, update connection status and start time
            self.connection_status = "connected"
            self.connection_start_time = time.time()
            self.notify("Connected to server successfully", severity="information")

            # Fetch server uptime immediately
            self.fetch_server_uptime()

            # Update matrix background for connection
            self.update_matrix_for_connection_status()
            # Update client status bar
            self.update_client_status_bar()

        except Exception as e:
            self.connection_status = "disconnected"
            self.connection_start_time = None
            self.server_uptime = None
            self.server_health_data = None
            self.notify(f"Failed to connect to server: {e}", severity="error")
            # Update matrix background for disconnection
            self.update_matrix_for_connection_status()
            # Update client status bar
            self.update_client_status_bar()

    def action_disconnect(self) -> None:
        """Disconnect from the server"""
        try:
            # Clear API client
            self._api_client = None

            # Update connection status and reset connection time
            self.connection_status = "disconnected"
            self.connection_start_time = None
            self.server_uptime = None
            self.server_health_data = None

            self.notify("Disconnected from server", severity="information")

            # Update matrix background for disconnection
            self.update_matrix_for_connection_status()
            # Update client status bar
            self.update_client_status_bar()

        except Exception as e:
            self.notify(f"Error during disconnect: {e}", severity="warning")

    def action_toggle_matrix_rain(self) -> None:
        """Toggle matrix rain background effect"""
        try:
            ascii_banner = self.query_one(ASCIIBanner)
            ascii_banner.matrix_background = not ascii_banner.matrix_background
            # Note: No need to call toggle_rain() manually - the reactive property
            # watch_matrix_background() handles enabling/disabling automatically

            status = "enabled" if ascii_banner.matrix_background else "disabled"
            self.notify(f"Matrix rain effect {status}", severity="information")
        except Exception as e:
            self.notify(f"Failed to toggle matrix rain: {e}", severity="error")

    def action_toggle_scrolling_code(self) -> None:
        """Toggle scrolling code background effect"""
        try:
            ascii_banner = self.query_one(ASCIIBanner)
            ascii_banner.scrolling_code = not ascii_banner.scrolling_code

            status = "enabled" if ascii_banner.scrolling_code else "disabled"
            self.notify(f"Scrolling code effect {status}", severity="information")
        except Exception as e:
            self.notify(f"Failed to toggle scrolling code: {e}", severity="error")

    def action_increase_matrix_framerate(self) -> None:
        """Increase matrix rain framerate globally"""
        try:
            ascii_banner = self.query_one(ASCIIBanner)
            ascii_banner.increase_framerate()
        except Exception as e:
            self.notify(f"Failed to increase matrix framerate: {e}", severity="error")

    def action_decrease_matrix_framerate(self) -> None:
        """Decrease matrix rain framerate globally"""
        try:
            ascii_banner = self.query_one(ASCIIBanner)
            ascii_banner.decrease_framerate()
        except Exception as e:
            self.notify(f"Failed to decrease matrix framerate: {e}", severity="error")

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

            # No dashboard buttons to handle anymore

        except Exception as e:
            self.log.warning(f"Error in global button handler: {e}")

    def update_matrix_for_connection_status(self) -> None:
        """Update matrix background based on connection status"""
        try:
            ascii_banner = self.query_one(ASCIIBanner)
            connected = self.connection_status == "connected"
            ascii_banner.update_matrix_for_connection(connected)
        except Exception as e:
            self.log.warning(f"Failed to update matrix background: {e}")


def run_tui(
    identity_path=None, api_url=None, profiling_config=None, profile_animations=False
):
    """Run the dCypher TUI application with optional profiling"""
    app = DCypherTUI(
        identity_path=identity_path,
        api_url=api_url,
        profiling_config=profiling_config,
        profile_animations=profile_animations,
    )
    app.run()


if __name__ == "__main__":
    run_tui()
