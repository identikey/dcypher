"""
System Monitor Widget
Inspired by btop with cyberpunk aesthetics
"""

import psutil
import time
from typing import Dict, List, Tuple
from textual.widget import Widget
from textual.reactive import reactive
from textual.containers import Horizontal, Vertical
from textual.widgets import Static, ProgressBar
from rich.console import Console, ConsoleOptions, RenderResult
from rich.text import Text
from rich.table import Table
from rich.panel import Panel
from rich.columns import Columns
from rich.bar import Bar


class SystemMonitor(Widget):
    """
    Real-time system monitoring widget
    Shows CPU, memory, disk, network stats with cyberpunk styling
    """

    # Reactive properties for real-time updates
    cpu_percent = reactive(0.0)
    memory_percent = reactive(0.0)
    disk_percent = reactive(0.0)
    network_sent = reactive(0)
    network_recv = reactive(0)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.last_network = None
        self.max_history = 50  # Keep last 50 data points
        # Initialize history as instance attributes
        self.cpu_history: List[float] = []
        self.memory_history: List[float] = []

    def compose(self):
        """Compose the system monitor layout"""
        with Vertical():
            yield Static("◢ SYSTEM MONITOR ◣", classes="title")
            with Horizontal():
                yield Static(id="cpu-panel")
                yield Static(id="memory-panel")
            with Horizontal():
                yield Static(id="disk-panel")
                yield Static(id="network-panel")

    def on_mount(self) -> None:
        """Start monitoring when mounted"""
        self.set_interval(1.0, self.update_stats)
        self.update_stats()  # Initial update

    def update_stats(self) -> None:
        """Update system statistics"""
        try:
            # CPU usage
            self.cpu_percent = psutil.cpu_percent(interval=None)
            self.cpu_history.append(self.cpu_percent)
            if len(self.cpu_history) > self.max_history:
                self.cpu_history.pop(0)

            # Memory usage
            memory = psutil.virtual_memory()
            self.memory_percent = memory.percent
            self.memory_history.append(self.memory_percent)
            if len(self.memory_history) > self.max_history:
                self.memory_history.pop(0)

            # Disk usage (root partition)
            disk = psutil.disk_usage("/")
            self.disk_percent = (disk.used / disk.total) * 100

            # Network I/O
            network = psutil.net_io_counters()
            if self.last_network:
                self.network_sent = network.bytes_sent - self.last_network.bytes_sent
                self.network_recv = network.bytes_recv - self.last_network.bytes_recv
            self.last_network = network

            # Update display
            self.update_display()

        except Exception as e:
            # Handle any psutil errors gracefully
            self.log.error(f"Error updating system stats: {e}")

    def update_display(self) -> None:
        """Update the display panels"""
        # Update CPU panel
        cpu_panel = self.query_one("#cpu-panel", Static)
        cpu_panel.update(self.create_cpu_panel())

        # Update memory panel
        memory_panel = self.query_one("#memory-panel", Static)
        memory_panel.update(self.create_memory_panel())

        # Update disk panel
        disk_panel = self.query_one("#disk-panel", Static)
        disk_panel.update(self.create_disk_panel())

        # Update network panel
        network_panel = self.query_one("#network-panel", Static)
        network_panel.update(self.create_network_panel())

    def create_cpu_panel(self) -> Panel:
        """Create CPU usage panel"""
        # Create sparkline from history
        sparkline = self.create_sparkline(self.cpu_history, width=20)

        # CPU info
        cpu_count = psutil.cpu_count()
        cpu_freq = psutil.cpu_freq()
        freq_text = f"{cpu_freq.current:.0f}MHz" if cpu_freq else "N/A"

        content = Text()
        content.append("CPU USAGE\n", style="bold green")
        content.append(f"{self.cpu_percent:5.1f}%\n", style="bold cyan")
        content.append(f"Cores: {cpu_count}\n", style="dim")
        content.append(f"Freq:  {freq_text}\n", style="dim")
        content.append(sparkline)

        return Panel(
            content,
            border_style="green",
            title="[bold green]◢CPU◣[/bold green]",
            title_align="center",
        )

    def create_memory_panel(self) -> Panel:
        """Create memory usage panel"""
        memory = psutil.virtual_memory()

        # Create sparkline
        sparkline = self.create_sparkline(self.memory_history, width=20)

        content = Text()
        content.append("MEMORY USAGE\n", style="bold cyan")
        content.append(f"{self.memory_percent:5.1f}%\n", style="bold yellow")
        content.append(f"Used:  {self.format_bytes(memory.used)}\n", style="dim")
        content.append(f"Total: {self.format_bytes(memory.total)}\n", style="dim")
        content.append(sparkline)

        return Panel(
            content,
            border_style="cyan",
            title="[bold cyan]◢RAM◣[/bold cyan]",
            title_align="center",
        )

    def create_disk_panel(self) -> Panel:
        """Create disk usage panel"""
        disk = psutil.disk_usage("/")

        content = Text()
        content.append("DISK USAGE\n", style="bold yellow")
        content.append(f"{self.disk_percent:5.1f}%\n", style="bold red")
        content.append(f"Used:  {self.format_bytes(disk.used)}\n", style="dim")
        content.append(f"Free:  {self.format_bytes(disk.free)}\n", style="dim")
        content.append(f"Total: {self.format_bytes(disk.total)}", style="dim")

        return Panel(
            content,
            border_style="yellow",
            title="[bold yellow]◢DISK◣[/bold yellow]",
            title_align="center",
        )

    def create_network_panel(self) -> Panel:
        """Create network I/O panel"""
        content = Text()
        content.append("NETWORK I/O\n", style="bold magenta")
        content.append(f"↑ {self.format_bytes(self.network_sent)}/s\n", style="green")
        content.append(f"↓ {self.format_bytes(self.network_recv)}/s\n", style="red")

        # Get network interfaces
        try:
            interfaces = psutil.net_if_stats()
            active_interfaces = [
                name for name, stats in interfaces.items() if stats.isup
            ]
            content.append(f"Interfaces: {len(active_interfaces)}", style="dim")
        except:
            content.append("Interfaces: N/A", style="dim")

        return Panel(
            content,
            border_style="magenta",
            title="[bold magenta]◢NET◣[/bold magenta]",
            title_align="center",
        )

    def create_sparkline(self, data: List[float], width: int = 20) -> Text:
        """Create a sparkline from data points"""
        if not data:
            return Text("▁" * width, style="dim")

        # Normalize data to 0-7 range for block characters
        min_val = min(data)
        max_val = max(data)

        if max_val == min_val:
            normalized = [4] * len(data)  # Middle value
        else:
            normalized = [
                int(((val - min_val) / (max_val - min_val)) * 7) for val in data
            ]

        # Block characters for sparkline
        blocks = " ▁▂▃▄▅▆▇█"

        # Take last 'width' points
        recent_data = normalized[-width:] if len(normalized) >= width else normalized

        sparkline_text = Text()
        for value in recent_data:
            char = blocks[min(value, 7)]
            # Color based on value
            if value >= 6:
                style = "bold red"
            elif value >= 4:
                style = "bold yellow"
            else:
                style = "bold green"
            sparkline_text.append(char, style=style)

        # Pad if needed
        while len(sparkline_text.plain) < width:
            sparkline_text.append("▁", style="dim")

        return sparkline_text

    @staticmethod
    def format_bytes(bytes_value: int) -> str:
        """Format bytes in human readable format"""
        for unit in ["B", "KB", "MB", "GB", "TB"]:
            if bytes_value < 1024.0:
                return f"{bytes_value:3.1f}{unit}"
            bytes_value /= 1024.0
        return f"{bytes_value:.1f}PB"


class CryptoMonitor(Widget):
    """
    Monitor for cryptographic operations
    Shows active encryption/decryption tasks, key operations, etc.
    """

    active_operations = reactive(0)
    completed_operations = reactive(0)
    failed_operations = reactive(0)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.operation_history = []

    def render(self) -> RenderResult:
        """Render crypto operations monitor"""
        table = Table(title="CRYPTO OPERATIONS", border_style="green")
        table.add_column("Status", style="bold")
        table.add_column("Count", justify="right")
        table.add_column("Rate", justify="right")

        table.add_row("Active", str(self.active_operations), "0/s")
        table.add_row("Completed", str(self.completed_operations), "0/s")
        table.add_row("Failed", str(self.failed_operations), "0/s")

        return Panel(
            table,
            border_style="green",
            title="[bold green]◢CRYPTO◣[/bold green]",
            title_align="center",
        )

    def add_operation(self, operation_type: str, status: str) -> None:
        """Add a crypto operation to the monitor"""
        timestamp = time.time()
        self.operation_history.append(
            {"type": operation_type, "status": status, "timestamp": timestamp}
        )

        # Update counters
        if status == "active":
            self.active_operations += 1
        elif status == "completed":
            self.completed_operations += 1
            if self.active_operations > 0:
                self.active_operations -= 1
        elif status == "failed":
            self.failed_operations += 1
            if self.active_operations > 0:
                self.active_operations -= 1
