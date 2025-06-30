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

    def compose(self):
        """Compose the dashboard layout"""
        with Container(id="dashboard-container"):
            # Top row - System monitors
            with Horizontal(id="monitors-row"):
                yield SystemMonitor(id="system-monitor")
                yield CryptoMonitor(id="crypto-monitor")

            # Middle row - Status panels
            with Horizontal(id="status-row"):
                yield Static("Loading identity status...", id="identity-status")
                yield Static("Checking API connection...", id="api-status")
                yield Static("Loading file status...", id="files-status")

            # Bottom row - Quick actions
            with Horizontal(id="actions-row"):
                yield Button("Load Identity", id="load-identity-btn", variant="primary")
                yield Button("Upload File", id="upload-file-btn")
                yield Button("Create Share", id="create-share-btn")
                yield Button("View Logs", id="view-logs-btn")

    def on_mount(self) -> None:
        """Initialize dashboard when mounted"""
        self.set_interval(2.0, self.update_status)
        self.update_status()

    def update_status(self) -> None:
        """Update status panels"""
        self.update_identity_status()
        self.update_api_status()
        self.update_files_status()

    def update_identity_status(self) -> None:
        """Update identity status panel"""
        identity_panel = self.query_one("#identity-status", Static)

        if self.identity_loaded:
            content = Text()
            content.append("IDENTITY STATUS\n", style="bold green")
            content.append("✓ Loaded\n", style="green")
            content.append("Keys: 3/3\n", style="dim")
            content.append("Type: Quantum-Safe", style="dim")
        else:
            content = Text()
            content.append("IDENTITY STATUS\n", style="bold yellow")
            content.append("⚠ Not Loaded\n", style="yellow")
            content.append("Load identity file\n", style="dim")
            content.append("to begin operations", style="dim")

        panel = Panel(
            content,
            border_style="green" if self.identity_loaded else "yellow",
            title="[bold]◢IDENTITY◣[/bold]",
            title_align="center",
        )
        identity_panel.update(panel)

    def update_api_status(self) -> None:
        """Update API connection status panel"""
        api_panel = self.query_one("#api-status", Static)

        if self.api_connected:
            content = Text()
            content.append("API CONNECTION\n", style="bold green")
            content.append("✓ Connected\n", style="green")
            content.append("Latency: 45ms\n", style="dim")
            content.append("Server: Online", style="dim")
        else:
            content = Text()
            content.append("API CONNECTION\n", style="bold red")
            content.append("✗ Disconnected\n", style="red")
            content.append("Check network\n", style="dim")
            content.append("or server status", style="dim")

        panel = Panel(
            content,
            border_style="green" if self.api_connected else "red",
            title="[bold]◢API◣[/bold]",
            title_align="center",
        )
        api_panel.update(panel)

    def update_files_status(self) -> None:
        """Update files and shares status panel"""
        files_panel = self.query_one("#files-status", Static)

        content = Text()
        content.append("FILES & SHARES\n", style="bold cyan")
        content.append(f"Files: {self.active_files}\n", style="cyan")
        content.append(f"Shares: {self.active_shares}\n", style="cyan")
        content.append("Storage: 2.3GB", style="dim")

        panel = Panel(
            content,
            border_style="cyan",
            title="[bold]◢DATA◣[/bold]",
            title_align="center",
        )
        files_panel.update(panel)

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
