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

from ..widgets.system_monitor import SystemMonitor, CryptoMonitor


class DashboardScreen(Widget):
    """
    Main dashboard screen showing system overview
    Features real-time monitoring and quick access to common operations
    """

    # Reactive state
    identity_loaded = reactive(False)
    api_connected = reactive(False)
    active_files = reactive(0)
    active_shares = reactive(0)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._system_info: Dict[str, Any] = {}

    def compose(self):
        """Compose the dashboard interface"""
        with Container(id="dashboard-container"):
            yield Static("◢ DASHBOARD ◣", classes="title")

            # Status panels row
            with Horizontal(id="status-row"):
                yield Static("System Status", id="system-status")
                yield Static("Identity: Not loaded", id="identity-status")
                yield Static("Network: Disconnected", id="network-status")
                yield Static("Storage: 0 files", id="storage-status")

            # Quick actions
            with Horizontal(id="actions-row"):
                yield Button("Load Identity", id="load-identity-btn", variant="primary")
                yield Button("Upload File", id="upload-file-btn")
                yield Button("Create Share", id="create-share-btn")
                yield Button("View Logs", id="view-logs-btn")

            # Quick stats
            yield QuickStats(id="quick-stats")

            # Recent activity
            yield Static("Recent Activity", id="activity-log")

    def on_mount(self) -> None:
        """Initialize dashboard when mounted"""
        self.set_interval(2.0, self.update_status)
        self.update_status()

    def update_status(self) -> None:
        """Update status panels"""
        # Call status update methods with empty dict if no data
        self.update_identity_status({})
        self.update_api_status()
        self.update_files_status()

    def update_identity_status(
        self, status_info: Optional[Dict[str, Any]] = None
    ) -> None:
        """Update identity status from external source"""
        if status_info is None:
            status_info = {}
        if status_info.get("loaded", False):
            self.identity_loaded = True

        # Update the status display
        identity_widget = self.query_one("#identity-status", Static)
        if self.identity_loaded:
            identity_widget.update("✅ Identity loaded")
        else:
            identity_widget.update("❌ No identity loaded")

    def update_api_status(self) -> None:
        """Update API connection status"""
        network_widget = self.query_one("#network-status", Static)
        if self.api_connected:
            network_widget.update("Network: Connected")
        else:
            network_widget.update("Network: Disconnected")

    def update_files_status(self) -> None:
        """Update files and shares status"""
        storage_widget = self.query_one("#storage-status", Static)
        storage_widget.update(
            f"Storage: {self.active_files} files, {self.active_shares} shares"
        )

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
        """Load identity file"""
        # TODO: Implement identity loading dialog
        self.identity_loaded = True
        self.notify("Identity loaded successfully", severity="information")

    def action_upload_file(self) -> None:
        """Upload file action"""
        if not self.identity_loaded:
            self.notify("Load identity first", severity="warning")
            return
        # TODO: Implement file upload dialog
        self.notify("File upload started", severity="information")

    def action_create_share(self) -> None:
        """Create share action"""
        if not self.identity_loaded:
            self.notify("Load identity first", severity="warning")
            return
        # TODO: Implement share creation dialog
        self.notify("Share creation started", severity="information")

    def action_view_logs(self) -> None:
        """View logs action"""
        # TODO: Implement logs viewer
        self.notify("Opening logs viewer", severity="information")

    def update_system_status(self, status_info: Dict[str, Any]) -> None:
        """Update system status with CPU, memory, disk info"""
        # Store the status info for display
        if not hasattr(self, "_system_info"):
            self._system_info = {}
        self._system_info = status_info
        self.update_status()

    def update_network_status(self, status_info: Dict[str, Any]) -> None:
        """Update network/API connection status"""
        self.api_connected = status_info.get("api_connected", False)
        self.update_status()

    def update_storage_status(self, status_info: Dict[str, Any]) -> None:
        """Update storage/files status"""
        self.active_files = status_info.get("files_count", 0)
        self.active_shares = status_info.get("shares_active", 0)
        self.update_status()

    def add_activity(self, message: str, status: str = "info") -> None:
        """Add an activity to the recent activity log"""
        # For now, just notify
        severity: Literal["information", "warning", "error"] = "information"
        if status == "error":
            severity = "error"
        elif status == "warning":
            severity = "warning"
        self.notify(f"Activity: {message}", severity=severity)

    def show_error(self, message: str, critical: bool = False) -> None:
        """Show an error message"""
        severity = "error" if critical else "warning"
        self.notify(message, severity=severity)

    def check_api_connection(self) -> Dict[str, Any]:
        """Check API connection and return status"""
        # TODO: Implement actual API check
        return {"connected": self.api_connected, "version": "1.0.0"}


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
