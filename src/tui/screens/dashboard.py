"""
Dashboard Screen
Main overview screen with system status and quick actions
"""

from textual.containers import Container, Horizontal, Vertical
from textual.widgets import Static, Button, DataTable, ProgressBar
from textual.widget import Widget
from textual.reactive import reactive
from rich.panel import Panel
from rich.text import Text
from rich.table import Table
from rich.columns import Columns
from typing import Dict, Any, Optional, Literal
from pathlib import Path

from ..widgets.system_monitor import SystemMonitor, CryptoMonitor


class DashboardScreen(Widget):
    """
    Main dashboard screen showing system overview
    Features real-time monitoring and quick access to common operations
    """

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._system_info: Dict[str, Any] = {}

    @property
    def current_identity_path(self):
        """Get current identity path from app state"""
        return getattr(self.app, "current_identity_path", None)

    @property
    def identity_info(self):
        """Get identity info from app state"""
        return getattr(self.app, "identity_info", None)

    @property
    def api_connected(self):
        """Get API connection status from app state"""
        return getattr(self.app, "connection_status", "disconnected") == "connected"

    @property
    def api_client(self):
        """Get API client from app"""
        get_client_method = getattr(self.app, "get_or_create_api_client", None)
        if get_client_method and callable(get_client_method):
            return get_client_method()
        return None

    def compose(self):
        """Compose the dashboard interface"""
        with Container(id="dashboard-container"):
            yield Static("◢ DASHBOARD ◣", classes="title")

            # Status panels row
            with Horizontal(id="status-row"):
                yield Static(id="system-status")
                yield Static(id="identity-status")
                yield Static(id="network-status")
                yield Static(id="storage-status")

            # Quick actions
            with Horizontal(id="actions-row"):
                yield Button("Load Identity", id="load-identity-btn", variant="primary")
                yield Button("Upload File", id="upload-file-btn")
                yield Button("Create Share", id="create-share-btn")
                yield Button("View Logs", id="view-logs-btn")

            # Quick stats
            yield QuickStats(id="quick-stats")

            # Recent activity
            yield RecentActivity(id="activity-log")

    def on_mount(self) -> None:
        """Initialize dashboard when mounted"""
        self.set_interval(2.0, self.update_status)
        self.update_status()

    def update_status(self) -> None:
        """Update all status panels"""
        self.update_system_status_display()
        self.update_identity_status_display()
        self.update_api_status_display()
        self.update_files_status_display()

    def update_system_status_display(self) -> None:
        """Update system status panel"""
        system_widget = self.query_one("#system-status", Static)

        # Create system status panel
        content = Text()
        content.append("SYSTEM STATUS\n", style="bold cyan")
        content.append("CPU: ", style="dim")
        content.append("42%\n", style="green")
        content.append("Memory: ", style="dim")
        content.append("3.2GB / 16GB\n", style="yellow")
        content.append("Disk: ", style="dim")
        content.append("120GB free\n", style="green")

        panel = Panel(
            content,
            title="[bold cyan]◢SYSTEM◣[/bold cyan]",
            border_style="cyan",
        )
        system_widget.update(panel)

    def update_identity_status_display(self) -> None:
        """Update identity status panel"""
        identity_widget = self.query_one("#identity-status", Static)

        if self.current_identity_path and self.identity_info:
            content = Text()
            content.append("IDENTITY LOADED\n", style="bold green")
            content.append(
                f"File: {Path(self.current_identity_path).name}\n", style="dim"
            )

            # Show key info
            auth_keys = self.identity_info.get("auth_keys", {})
            if "classic" in auth_keys:
                pk = auth_keys["classic"]["pk_hex"]
                content.append(f"Classic: {pk[:16]}...\n", style="cyan")

            if "pq" in auth_keys:
                content.append(f"PQ Keys: {len(auth_keys['pq'])}\n", style="cyan")

            if "pre" in auth_keys and auth_keys["pre"]:
                content.append("PRE: Enabled\n", style="green")
            else:
                content.append("PRE: Not initialized\n", style="yellow")

            panel = Panel(
                content,
                title="[bold green]◢IDENTITY◣[/bold green]",
                border_style="green",
            )
        else:
            content = Text()
            content.append("NO IDENTITY\n", style="bold red")
            content.append("Load an identity to begin\n", style="dim")
            content.append("using dCypher operations", style="dim")

            panel = Panel(
                content,
                title="[bold red]◢IDENTITY◣[/bold red]",
                border_style="red",
            )

        identity_widget.update(panel)

    def update_api_status_display(self) -> None:
        """Update network/API status panel"""
        network_widget = self.query_one("#network-status", Static)

        content = Text()
        content.append("NETWORK STATUS\n", style="bold")

        if self.api_connected:
            content.append("API: Connected\n", style="green")
            content.append(f"URL: {getattr(self.app, 'api_url', 'N/A')}\n", style="dim")
            content.append("Latency: 12ms", style="cyan")

            panel = Panel(
                content,
                title="[bold green]◢NETWORK◣[/bold green]",
                border_style="green",
            )
        else:
            content.append("API: Disconnected\n", style="red")
            content.append(f"URL: {getattr(self.app, 'api_url', 'N/A')}\n", style="dim")
            content.append("Check connection", style="yellow")

            panel = Panel(
                content,
                title="[bold red]◢NETWORK◣[/bold red]",
                border_style="red",
            )

        network_widget.update(panel)

    def update_files_status_display(self) -> None:
        """Update storage/files status panel"""
        storage_widget = self.query_one("#storage-status", Static)

        content = Text()
        content.append("STORAGE STATUS\n", style="bold magenta")

        # These would be fetched from API in real implementation
        files_count = 0
        shares_count = 0

        content.append(f"Files: {files_count}\n", style="white")
        content.append(f"Shares: {shares_count}\n", style="white")
        content.append(f"Usage: 0 MB", style="dim")

        panel = Panel(
            content,
            title="[bold magenta]◢STORAGE◣[/bold magenta]",
            border_style="magenta",
        )
        storage_widget.update(panel)

    def update_identity_status(
        self, status_info: Optional[Dict[str, Any]] = None
    ) -> None:
        """Update identity status from external source (called by app)"""
        # Just trigger a refresh of the display
        self.update_identity_status_display()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button presses"""
        button_id = event.button.id

        if button_id == "load-identity-btn":
            self.action_load_identity()
        elif button_id == "upload-file-btn":
            self.action_upload_file()
        elif button_id == "create-share-btn":
            self.action_create_share()
        elif button_id == "view-logs-btn":
            self.action_view_logs()

    def action_load_identity(self) -> None:
        """Load identity file - navigate to Identity tab"""
        # Switch to identity tab
        try:
            action_method = getattr(self.app, "action_switch_tab", None)
            if action_method and callable(action_method):
                action_method("identity")
            self.notify(
                "Navigate to Identity tab to load an identity", severity="information"
            )
        except Exception:
            self.notify(
                "Use the Identity tab to load an identity", severity="information"
            )

    def action_upload_file(self) -> None:
        """Upload file action"""
        if not self.current_identity_path:
            self.notify("Load identity first", severity="warning")
            return

        # Switch to files tab
        try:
            action_method = getattr(self.app, "action_switch_tab", None)
            if action_method and callable(action_method):
                action_method("files")
            self.notify("Navigate to Files tab to upload", severity="information")
        except Exception:
            self.notify("Use the Files tab to upload files", severity="information")

    def action_create_share(self) -> None:
        """Create share action"""
        if not self.current_identity_path:
            self.notify("Load identity first", severity="warning")
            return

        # Switch to sharing tab
        try:
            action_method = getattr(self.app, "action_switch_tab", None)
            if action_method and callable(action_method):
                action_method("sharing")
            self.notify(
                "Navigate to Sharing tab to create shares", severity="information"
            )
        except Exception:
            self.notify("Use the Sharing tab to create shares", severity="information")

    def action_view_logs(self) -> None:
        """View logs action"""
        # TODO: Implement logs viewer
        self.notify("Logs viewer coming soon", severity="information")

    def update_system_status(self, status_info: Dict[str, Any]) -> None:
        """Update system status with CPU, memory, disk info"""
        self._system_info = status_info
        self.update_status()

    def update_network_status(self, status_info: Dict[str, Any]) -> None:
        """Update network/API connection status"""
        self.update_status()

    def update_storage_status(self, status_info: Dict[str, Any]) -> None:
        """Update storage/files status"""
        self.update_status()


class QuickStats(Widget):
    """
    Quick statistics widget for the dashboard
    Shows key metrics at a glance
    """

    def render(self):
        """Render quick stats"""
        table = Table(title="QUICK STATS", border_style="cyan")
        table.add_column("Metric", style="bold")
        table.add_column("Value", justify="right", style="cyan")
        table.add_column("Change", justify="right")

        table.add_row("Files Encrypted", "1,247", "+23")
        table.add_row("Shares Active", "89", "+5")
        table.add_row("Keys Generated", "156", "+2")
        table.add_row("Data Processed", "45.2GB", "+2.1GB")

        return Panel(
            table,
            border_style="cyan",
            title="[bold cyan]◢STATS◣[/bold cyan]",
            title_align="center",
        )


class RecentActivity(Widget):
    """
    Recent activity feed for the dashboard
    Shows latest operations and events
    """

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.activities = [
            {"time": "14:32:15", "action": "File encrypted", "status": "success"},
            {"time": "14:31:42", "action": "Share created", "status": "success"},
            {"time": "14:30:18", "action": "Identity loaded", "status": "success"},
            {"time": "14:29:55", "action": "API connected", "status": "success"},
            {"time": "14:29:12", "action": "Key rotation", "status": "warning"},
        ]

    def render(self):
        """Render recent activity"""
        content = Text()
        content.append("RECENT ACTIVITY\n\n", style="bold magenta")

        for activity in self.activities[:5]:  # Show last 5
            time_style = "dim"
            if activity["status"] == "success":
                status_style = "green"
                icon = "✓"
            elif activity["status"] == "warning":
                status_style = "yellow"
                icon = "⚠"
            else:
                status_style = "red"
                icon = "✗"

            content.append(f"{activity['time']} ", style=time_style)
            content.append(f"{icon} ", style=status_style)
            content.append(f"{activity['action']}\n", style="white")

        return Panel(
            content,
            border_style="magenta",
            title="[bold magenta]◢ACTIVITY◣[/bold magenta]",
            title_align="center",
        )
