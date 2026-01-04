"""
Dashboard Screen
Main overview screen with system status and quick actions
"""

from textual.containers import Container, Horizontal, Vertical, ScrollableContainer
from textual.widgets import Static, DataTable, ProgressBar
from textual.widget import Widget
from textual.reactive import reactive
from rich.panel import Panel
from rich.text import Text
from rich.table import Table
from rich.columns import Columns
from typing import Dict, Any, Optional, Literal
from pathlib import Path

from dcypher.tui.widgets.system_monitor import SystemMonitor, CryptoMonitor


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
    def identity_loaded(self):
        """Check if an identity is currently loaded"""
        return self.current_identity_path is not None

    @property
    def api_client(self):
        """Get API client from app"""
        get_client_method = getattr(self.app, "get_or_create_api_client", None)
        if get_client_method and callable(get_client_method):
            return get_client_method()
        return None

    def compose(self):
        """Compose the dashboard interface"""
        with ScrollableContainer(id="dashboard-container"):
            # Status panels row (removed system-status)
            with Horizontal(id="status-row"):
                yield Static(id="identity-status")
                yield Static(id="network-status")
                yield Static(id="storage-status")

            # Server statistics
            yield QuickStats(id="quick-stats")

            # Recent activity
            yield RecentActivity(id="activity-log")

    def on_mount(self) -> None:
        """Initialize dashboard when mounted"""
        self.set_interval(2.0, self.update_status)
        self.update_status()

    def update_status(self) -> None:
        """Update all status panels"""
        self.update_identity_status_display()
        self.update_api_status_display()
        self.update_files_status_display()

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

    def update_server_stats(self) -> None:
        """Update server statistics display"""
        # Refresh the quick stats widget
        try:
            stats_widget = self.query_one("#quick-stats", QuickStats)
            stats_widget.refresh()
        except Exception:
            # Widget may not be mounted yet
            pass

    def check_api_connection(self) -> bool:
        """Check API connection status"""
        return self.api_connected

    def show_error(self, message: str, critical: bool = False) -> None:
        """Show error message to user"""
        severity = "error" if critical else "warning"
        self.notify(message, severity=severity)

    def add_activity(self, action: str, status: str = "success") -> None:
        """Add activity to recent activity log"""
        import datetime

        current_time = datetime.datetime.now().strftime("%H:%M:%S")

        # Add to the activity log
        activity_widget = self.query_one("#activity-log", RecentActivity)
        if activity_widget:
            new_activity = {"time": current_time, "action": action, "status": status}
            activity_widget.activities.insert(0, new_activity)
            # Keep only the last 10 activities
            activity_widget.activities = activity_widget.activities[:10]
            # Refresh the widget
            activity_widget.refresh()


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
        table.add_column("Status", justify="right")

        # Get server health data from app if connected
        server_health = getattr(self.app, "server_health_data", None)

        if (
            server_health
            and getattr(self.app, "connection_status", "disconnected") == "connected"
        ):
            # Show server statistics when connected
            stats = server_health.get("statistics", {})
            version = server_health.get("version", "Unknown")
            service = server_health.get("service", "dCypher")

            table.add_row("Server Version", version, "[green]✓[/green]")
            table.add_row("Service", service, "[green]ACTIVE[/green]")
            table.add_row(
                "Total Accounts", str(stats.get("accounts", 0)), "[cyan]LIVE[/cyan]"
            )
            table.add_row(
                "Total Files", str(stats.get("files", 0)), "[cyan]LIVE[/cyan]"
            )

            # Add server uptime if available
            uptime = getattr(self.app, "server_uptime", None)
            if uptime:
                table.add_row("Server Uptime", uptime, "[green]RUNNING[/green]")

            title_color = "green"
            border_color = "green"
        else:
            # Show disconnected state
            table.add_row("Server Status", "DISCONNECTED", "[red]✗[/red]")
            table.add_row("Data Source", "N/A", "[red]OFFLINE[/red]")
            table.add_row("Statistics", "Unavailable", "[red]NO DATA[/red]")
            table.add_row("Connection", "Required", "[yellow]CONNECT[/yellow]")

            title_color = "red"
            border_color = "red"

        return Panel(
            table,
            border_style=border_color,
            title=f"[bold {title_color}]◢SERVER STATS◣[/bold {title_color}]",
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
