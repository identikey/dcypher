"""
Process monitoring widgets for dCypher TUI
Tracks CPU and memory usage of the dCypher process and children
"""

import os
import time
from typing import List, Dict, Any, Optional
from collections import deque

from textual.widget import Widget
from textual.reactive import reactive
from textual.widgets import Sparkline, Static
from textual.containers import Horizontal, Container, Vertical
from rich.console import Console
from rich.text import Text
from rich.panel import Panel
from rich.progress import BarColumn, Progress, TaskID
from rich import box

try:
    import psutil

    _psutil_available = True
except ImportError:
    psutil = None  # type: ignore
    _psutil_available = False

PSUTIL_AVAILABLE = _psutil_available


class ProcessCPUDivider(Widget):
    """
    CPU usage divider widget - displays horizontal CPU history chart
    Positioned under the header as a visual divider
    """

    cpu_percent: reactive[float] = reactive(0.0)
    # Note: actual type is deque, but reactive typing doesn't support deque well
    cpu_history: reactive[Any] = reactive(list)
    cpu_history_5min: reactive[Any] = reactive(list)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.max_history = 60  # Keep 60 data points (1 minute at 1 sec intervals)
        self.max_history_5min = (
            300  # Keep 300 data points (5 minutes at 1 sec intervals)
        )
        self.cpu_history = deque(maxlen=self.max_history)
        self.cpu_history_5min = deque(maxlen=self.max_history_5min)
        self.process = None
        self.children_processes = []

        if PSUTIL_AVAILABLE and psutil is not None:
            try:
                self.process = psutil.Process(os.getpid())
                # Initial CPU measurement (first call returns 0.0)
                self.process.cpu_percent()

                # Add some initial data points for immediate display
                for _ in range(10):
                    self.cpu_history.append(0.0)
                    self.cpu_history_5min.append(0.0)

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

    def compose(self):
        """Compose the CPU divider with custom dual-period display"""
        # Return empty - we'll use render() method instead
        return []

    def render(self):
        """Render both 1-minute and 5-minute CPU data in a single seamless display"""
        if not PSUTIL_AVAILABLE:
            return Panel(
                Text("psutil not available - CPU monitoring disabled", style="red"),
                title="[red]◢CPU MONITOR◣[/red]",
                border_style="red",
                box=box.DOUBLE,
                expand=True,
            )

        # Create content with both time periods
        content = Text()

        # 1-minute sparkline (top half)
        content.append("1min: ", style="bold cyan")
        if len(self.cpu_history) > 0:
            sparkline_1min = self._create_ascii_chart(list(self.cpu_history), width=100)
            content.append(sparkline_1min, style="cyan")
        else:
            content.append("▁" * 50 + " (collecting...)", style="dim cyan")

        content.append("\n")

        # 5-minute sparkline (bottom half)
        content.append("5min: ", style="bold green")
        if len(self.cpu_history_5min) > 0:
            sparkline_5min = self._create_ascii_chart(
                list(self.cpu_history_5min), width=100
            )
            content.append(sparkline_5min, style="green")
        else:
            content.append("▁" * 50 + " (collecting...)", style="dim green")

        return Panel(
            content,
            title=f"[bold cyan]◢dCYPHER CPU: {self.cpu_percent:.1f}% ({len(self.children_processes)} children)◣[/bold cyan]",
            border_style="cyan",
            box=box.DOUBLE,
            expand=True,
        )

    def _create_ascii_chart(self, data: List[float], width: int = 50) -> str:
        """Create a simple ASCII sparkline chart"""
        if not data:
            return "─" * width

        # Normalize data to chart height (use max 8 levels)
        max_val = max(max(data), 1.0)  # Avoid division by zero
        levels = ["▁", "▂", "▃", "▄", "▅", "▆", "▇", "█"]

        chart = ""
        for value in data[-width:]:  # Take last 'width' values
            level_idx = min(int((value / max_val) * len(levels)), len(levels) - 1)
            chart += levels[level_idx]

        # Pad with empty chars if needed
        while len(chart) < width:
            chart = "▁" + chart

        return chart

    def update_cpu_usage(self) -> None:
        """Update CPU usage metrics for dCypher process and children"""
        if not PSUTIL_AVAILABLE or not self.process:
            return

        try:
            # Get main process CPU usage
            main_cpu = self.process.cpu_percent()

            # Get children processes CPU usage
            children_cpu = 0.0
            self.children_processes = []

            try:
                children = self.process.children(recursive=True)
                for child in children:
                    try:
                        child_cpu = child.cpu_percent()
                        children_cpu += child_cpu
                        self.children_processes.append(
                            {"pid": child.pid, "name": child.name(), "cpu": child_cpu}
                        )
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

            # Total CPU usage
            total_cpu = main_cpu + children_cpu
            self.cpu_percent = total_cpu
            self.cpu_history.append(total_cpu)
            self.cpu_history_5min.append(total_cpu)

            # Refresh the display to show updated data
            self.refresh()

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            self.cpu_percent = 0.0
            self.cpu_history.append(0.0)
            self.cpu_history_5min.append(0.0)
            self.refresh()

    def watch_cpu_history(self):
        """Update the display when CPU history changes"""
        self.refresh()

    def watch_cpu_percent(self):
        """Update the display when CPU percentage changes"""
        self.refresh()


class ProcessMemoryDivider(Widget):
    """
    Memory usage divider widget - displays memory usage bar
    Positioned above the footer as a visual divider
    """

    memory_mb: reactive[float] = reactive(0.0)
    memory_percent: reactive[float] = reactive(0.0)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.process = None
        self.children_processes = []

        if PSUTIL_AVAILABLE:
            try:
                self.process = psutil.Process(os.getpid())
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

    def update_memory_usage(self) -> None:
        """Update memory usage metrics for dCypher process and children"""
        if not PSUTIL_AVAILABLE or not self.process:
            return

        try:
            # Get main process memory usage
            main_memory = self.process.memory_info()
            total_memory_bytes = main_memory.rss

            # Get children processes memory usage
            children_memory_bytes = 0
            self.children_processes = []

            try:
                children = self.process.children(recursive=True)
                for child in children:
                    try:
                        child_memory = child.memory_info()
                        children_memory_bytes += child_memory.rss
                        self.children_processes.append(
                            {
                                "pid": child.pid,
                                "name": child.name(),
                                "memory_mb": child_memory.rss / (1024 * 1024),
                            }
                        )
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

            # Total memory usage
            total_memory_mb = (total_memory_bytes + children_memory_bytes) / (
                1024 * 1024
            )
            self.memory_mb = total_memory_mb

            # Calculate percentage of system memory
            try:
                system_memory = psutil.virtual_memory()
                self.memory_percent = (
                    (total_memory_bytes + children_memory_bytes)
                    / system_memory.total
                    * 100
                )
            except:
                self.memory_percent = 0.0

            # Trigger refresh to update display
            self.refresh()

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            self.memory_mb = 0.0
            self.memory_percent = 0.0
            self.refresh()

    def render(self):
        """Render the memory usage divider"""
        if not PSUTIL_AVAILABLE:
            return Panel(
                Text("psutil not available - Memory monitoring disabled", style="red"),
                title="[red]◢MEMORY MONITOR◣[/red]",
                border_style="red",
                box=box.DOUBLE,
                expand=True,
            )

        # Create memory usage visualization
        memory_text = Text()

        # Add current usage info
        memory_text.append(f"Memory: {self.memory_mb:.1f} MB ", style="bold yellow")
        memory_text.append(f"({self.memory_percent:.1f}% of system) ", style="dim")
        memory_text.append(f"({len(self.children_processes)} children) ", style="dim")

        # Create memory usage bar with maximum width - let Panel truncate naturally
        bar_width = 200  # Use very large width, Panel will truncate to fit
        filled_width = int((self.memory_percent / 100) * bar_width)
        bar = "█" * filled_width + "░" * (bar_width - filled_width)
        memory_text.append(f"[{bar}]", style="yellow")

        return Panel(
            memory_text,
            title="[bold yellow]◢dCYPHER MEMORY USAGE◣[/bold yellow]",
            border_style="yellow",
            box=box.DOUBLE,
            expand=True,
        )


class ProcessMonitorWidget(Widget):
    """
    Combined process monitoring widget for dashboard use
    Shows both CPU and memory statistics in a compact format
    """

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.cpu_divider = ProcessCPUDivider()
        self.memory_divider = ProcessMemoryDivider()

    def update_metrics(self) -> None:
        """Update all process metrics"""
        self.cpu_divider.update_cpu_usage()
        self.memory_divider.update_memory_usage()

    def get_process_stats(self) -> Dict[str, Any]:
        """Get current process statistics for other components"""
        return {
            "cpu_percent": self.cpu_divider.cpu_percent,
            "memory_mb": self.memory_divider.memory_mb,
            "memory_percent": self.memory_divider.memory_percent,
            "children_count": len(self.cpu_divider.children_processes),
            "psutil_available": PSUTIL_AVAILABLE,
        }

    def render(self):
        """Render combined process monitor for dashboard"""
        if not PSUTIL_AVAILABLE:
            return Panel(
                Text(
                    "Process monitoring requires 'psutil' package\nInstall with: pip install psutil",
                    style="red",
                    justify="center",
                ),
                title="[red]◢PROCESS MONITOR◣[/red]",
                border_style="red",
            )

        content = Text()
        content.append("dCypher Process Monitor\n\n", style="bold cyan")
        content.append(
            f"CPU Usage: {self.cpu_divider.cpu_percent:.1f}%\n", style="green"
        )
        content.append(
            f"Memory Usage: {self.memory_divider.memory_mb:.1f} MB ", style="yellow"
        )
        content.append(f"({self.memory_divider.memory_percent:.1f}%)\n", style="dim")
        content.append(
            f"Child Processes: {len(self.cpu_divider.children_processes)}", style="cyan"
        )

        return Panel(
            content, title="[bold cyan]◢PROCESS STATS◣[/bold cyan]", border_style="cyan"
        )
