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

    # CSS to remove spacing
    DEFAULT_CSS = """
    ProcessCPUDivider {
        margin: 0;
        padding: 0;
        min-height: 5;
        max-height: 5;
        height: 5;
    }
    """

    cpu_percent: reactive[float] = reactive(0.0)
    # Note: actual type is deque, but reactive typing doesn't support deque well
    cpu_history: reactive[Any] = reactive(list)
    cpu_history_5min: reactive[Any] = reactive(list)
    cpu_history_15min: reactive[Any] = reactive(list)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.max_history = 60  # Keep 60 data points (1 minute at 1 sec intervals)
        self.max_history_5min = (
            300  # Keep 300 data points (5 minutes at 1 sec intervals)
        )
        self.max_history_15min = (
            900  # Keep 900 data points (15 minutes at 1 sec intervals)
        )
        self.cpu_history = deque(maxlen=self.max_history)
        self.cpu_history_5min = deque(maxlen=self.max_history_5min)
        self.cpu_history_15min = deque(maxlen=self.max_history_15min)
        self.process = None
        self.children_processes = []

        if PSUTIL_AVAILABLE and psutil is not None:
            try:
                self.process = psutil.Process(os.getpid())
                # Initial CPU measurement (first call returns 0.0)
                self.process.cpu_percent()

            except (psutil.NoSuchProcess, psutil.AccessDenied):  # type: ignore
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

        # Calculate available width dynamically
        # Get console width and subtract space for labels and margins
        try:
            console_width = self.app.size.width if hasattr(self.app, "size") else 120
            # Subtract space for "15min: " (7 chars) and some margin
            available_width = max(console_width - 11, 40)  # Minimum 40 chars
        except:
            available_width = 100  # Fallback

        # 1-minute sparkline (top half) - 60 data points across full width
        content.append("1min:  ", style="bold cyan")
        if len(self.cpu_history) > 0:
            sparkline_1min = self._create_ascii_chart(
                list(self.cpu_history), 60, available_width
            )
            content.append(sparkline_1min)  # Already has color styling
        else:
            content.append(" " * available_width + " (collecting...)", style="dim cyan")

        content.append("\n")

        # 5-minute sparkline (bottom half) - 300 data points across full width, reversed
        content.append("5min:  ", style="bold green")
        if len(self.cpu_history_5min) > 0:
            sparkline_5min = self._create_ascii_chart(
                list(self.cpu_history_5min), 300, available_width, reverse=True
            )
            content.append(sparkline_5min)  # Already has color styling
        else:
            content.append(
                " " * available_width + " (collecting...)", style="dim green"
            )

        content.append("\n")

        # 15-minute sparkline (bottom) - 900 data points across full width, normal direction
        content.append("15min: ", style="bold yellow")
        if len(self.cpu_history_15min) > 0:
            sparkline_15min = self._create_ascii_chart(
                list(self.cpu_history_15min), 900, available_width
            )
            content.append(sparkline_15min)  # Already has color styling
        else:
            content.append(
                " " * available_width + " (collecting...)", style="dim yellow"
            )

        return Panel(
            content,
            title=f"[bold cyan]◢dCYPHER CPU: {self.cpu_percent:.2f}% ({len(self.children_processes)} children)◣[/bold cyan]",
            border_style="cyan",
            box=box.DOUBLE,
            expand=False,
            height=5,  # Fixed height: 3 lines of content + 2 for borders
        )

    def _create_ascii_chart(
        self,
        data: List[float],
        num_data_points: int,
        total_width: int,
        reverse: bool = False,
    ) -> Text:
        """Create ASCII sparkline chart with color gradient based on CPU values"""
        chart_text = Text()

        if not data:
            chart_text.append(" " * total_width, style="dim")
            return chart_text

        # Use adaptive scaling for better sensitivity to small changes
        min_val = min(data)
        max_val = max(data)
        data_range = max_val - min_val

        # If the range is very small (less than 1% for CPU), use a more sensitive approach
        if data_range < 1.0:
            # For very small ranges, amplify the differences
            # Use the range itself as the scale, with a minimum scale of 0.1%
            scale_range = max(data_range, 0.1)
            use_relative_scaling = True
        else:
            # For larger ranges, use traditional max scaling
            scale_range = max_val
            use_relative_scaling = False

        levels = ["▁", "▂", "▃", "▄", "▅", "▆", "▇", "█"]
        data_to_use = list(reversed(data)) if reverse else data

        # Sample data to fit available width
        if len(data_to_use) > 0:
            step = len(data_to_use) / total_width
            for i in range(total_width):
                idx = int(i * step)
                if idx < len(data_to_use):
                    value = data_to_use[idx]

                    if use_relative_scaling:
                        # Scale relative to the range for better sensitivity
                        if scale_range > 0:
                            normalized_value = (value - min_val) / scale_range
                        else:
                            normalized_value = 0
                    else:
                        # Traditional scaling
                        normalized_value = value / scale_range if scale_range > 0 else 0

                    level_idx = min(
                        int(normalized_value * len(levels)), len(levels) - 1
                    )
                    char = levels[level_idx] if normalized_value > 0 else " "

                    # Apply color gradient based on original CPU value
                    color_style = self._get_cpu_color_style(value)
                    chart_text.append(char, style=color_style)
                else:
                    chart_text.append(" ", style="dim")
        else:
            chart_text.append(" " * total_width, style="dim")

        return chart_text

    def _get_cpu_color_style(self, cpu_value: float) -> str:
        """Get color style based on CPU percentage value"""
        if cpu_value <= 0:
            return "dim"
        elif cpu_value < 20:
            return "bright_green"
        elif cpu_value < 40:
            return "green"
        elif cpu_value < 60:
            return "yellow"
        elif cpu_value < 80:
            return "bright_yellow"
        elif cpu_value < 95:
            return "red"
        else:
            return "bright_red bold"

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
                    except (psutil.NoSuchProcess, psutil.AccessDenied):  # type: ignore
                        continue
            except (psutil.NoSuchProcess, psutil.AccessDenied):  # type: ignore
                pass

            # Total CPU usage
            total_cpu = main_cpu + children_cpu
            self.cpu_percent = total_cpu
            self.cpu_history.append(total_cpu)
            self.cpu_history_5min.append(total_cpu)
            self.cpu_history_15min.append(total_cpu)

            # Refresh the display to show updated data
            self.refresh()

        except (psutil.NoSuchProcess, psutil.AccessDenied):  # type: ignore
            self.cpu_percent = 0.0
            self.cpu_history.append(0.0)
            self.cpu_history_5min.append(0.0)
            self.cpu_history_15min.append(0.0)
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

    # CSS to remove spacing
    DEFAULT_CSS = """
    ProcessMemoryDivider {
        margin: 0;
        padding: 0;
        min-height: 3;
        max-height: 3;
        height: 3;
    }
    """

    memory_mb: reactive[float] = reactive(0.0)
    memory_percent: reactive[float] = reactive(0.0)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.process = None
        self.children_processes = []

        if PSUTIL_AVAILABLE:
            try:
                self.process = psutil.Process(os.getpid())  # type: ignore
            except (psutil.NoSuchProcess, psutil.AccessDenied):  # type: ignore
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
                    except (psutil.NoSuchProcess, psutil.AccessDenied):  # type: ignore
                        continue
            except (psutil.NoSuchProcess, psutil.AccessDenied):  # type: ignore
                pass

            # Total memory usage
            total_memory_mb = (total_memory_bytes + children_memory_bytes) / (
                1024 * 1024
            )
            self.memory_mb = total_memory_mb

            # Calculate percentage of system memory
            try:
                system_memory = psutil.virtual_memory()  # type: ignore
                self.memory_percent = (
                    (total_memory_bytes + children_memory_bytes)
                    / system_memory.total
                    * 100
                )
            except:
                self.memory_percent = 0.0

            # Trigger refresh to update display
            self.refresh()

        except (psutil.NoSuchProcess, psutil.AccessDenied):  # type: ignore
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
            expand=False,
            height=3,  # Fixed height: 1 line of content + 2 for borders
        )


class ProcessCPU15MinDivider(Widget):
    """
    Memory usage divider widget - displays only 15-minute horizontal memory history chart
    Simplified version for memory section position
    """

    # CSS to remove spacing
    DEFAULT_CSS = """
    ProcessCPU15MinDivider {
        margin: 0;
        padding: 0;
        min-height: 3;
        max-height: 3;
        height: 3;
    }
    """

    memory_percent: reactive[float] = reactive(0.0)
    memory_mb: reactive[float] = reactive(0.0)
    memory_history_15min: reactive[Any] = reactive(list)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.max_history_15min = (
            900  # Keep 900 data points (15 minutes at 1 sec intervals)
        )
        self.memory_history_15min = deque(maxlen=self.max_history_15min)
        self.process = None
        self.children_processes = []

        if PSUTIL_AVAILABLE:
            try:
                self.process = psutil.Process(os.getpid())  # type: ignore

            except (psutil.NoSuchProcess, psutil.AccessDenied):  # type: ignore
                pass

    def compose(self):
        """Compose the memory divider with 15-minute display only"""
        return []

    def render(self):
        """Render only 15-minute memory data"""
        if not PSUTIL_AVAILABLE:
            return Panel(
                Text("psutil not available - Memory monitoring disabled", style="red"),
                title="[red]◢MEMORY MONITOR◣[/red]",
                border_style="red",
                box=box.DOUBLE,
                expand=True,
            )

        # Create content with only 15-minute period
        content = Text()

        # Calculate available width dynamically
        try:
            console_width = self.app.size.width if hasattr(self.app, "size") else 120
            # Subtract space for "15min: " (7 chars) and some margin
            available_width = max(console_width - 11, 40)  # Minimum 40 chars
        except:
            available_width = 100  # Fallback

        # 15-minute sparkline only
        content.append("15min: ", style="bold yellow")
        if len(self.memory_history_15min) > 0:
            sparkline_15min = self._create_ascii_chart(
                list(self.memory_history_15min), 900, available_width
            )
            content.append(sparkline_15min)  # Already has color styling
        else:
            content.append(
                " " * available_width + " (collecting...)", style="dim yellow"
            )

        return Panel(
            content,
            title=f"[bold yellow]◢dCYPHER MEMORY 15min: {self.memory_mb:.2f}MB ({self.memory_percent:.3f}%) ({len(self.children_processes)} children)◣[/bold yellow]",
            border_style="yellow",
            box=box.DOUBLE,
            expand=False,
            height=3,  # Fixed height: 1 line of content + 2 for borders
        )

    def _create_ascii_chart(
        self,
        data: List[float],
        num_data_points: int,
        total_width: int,
        reverse: bool = False,
    ) -> Text:
        """Create ASCII sparkline chart with color gradient based on memory values"""
        chart_text = Text()

        if not data:
            chart_text.append(" " * total_width, style="dim")
            return chart_text

        # Use adaptive scaling for better sensitivity to small changes
        min_val = min(data)
        max_val = max(data)
        data_range = max_val - min_val

        # If the range is very small (less than 0.1%), use a more sensitive approach
        if data_range < 0.1:
            # For very small ranges, amplify the differences
            # Use the range itself as the scale, with a minimum scale of 0.01%
            scale_range = max(data_range, 0.01)
            use_relative_scaling = True
        else:
            # For larger ranges, use traditional max scaling
            scale_range = max_val
            use_relative_scaling = False

        levels = ["▁", "▂", "▃", "▄", "▅", "▆", "▇", "█"]
        data_to_use = list(reversed(data)) if reverse else data

        # Sample data to fit available width
        if len(data_to_use) > 0:
            step = len(data_to_use) / total_width
            for i in range(total_width):
                idx = int(i * step)
                if idx < len(data_to_use):
                    value = data_to_use[idx]

                    if use_relative_scaling:
                        # Scale relative to the range for better sensitivity
                        if scale_range > 0:
                            normalized_value = (value - min_val) / scale_range
                        else:
                            normalized_value = 0
                    else:
                        # Traditional scaling
                        normalized_value = value / scale_range if scale_range > 0 else 0

                    level_idx = min(
                        int(normalized_value * len(levels)), len(levels) - 1
                    )
                    char = levels[level_idx] if normalized_value > 0 else " "

                    # Apply color gradient based on original memory value
                    color_style = self._get_memory_color_style(value)
                    chart_text.append(char, style=color_style)
                else:
                    chart_text.append(" ", style="dim")
        else:
            chart_text.append(" " * total_width, style="dim")

        return chart_text

    def _get_memory_color_style(self, memory_value: float) -> str:
        """Get color style based on memory percentage value"""
        if memory_value <= 0:
            return "dim"
        elif memory_value < 20:
            return "bright_green"
        elif memory_value < 40:
            return "green"
        elif memory_value < 60:
            return "yellow"
        elif memory_value < 80:
            return "bright_yellow"
        elif memory_value < 95:
            return "red"
        else:
            return "bright_red bold"

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
                    except (psutil.NoSuchProcess, psutil.AccessDenied):  # type: ignore
                        continue
            except (psutil.NoSuchProcess, psutil.AccessDenied):  # type: ignore
                pass

            # Total memory usage
            total_memory_mb = (total_memory_bytes + children_memory_bytes) / (
                1024 * 1024
            )
            self.memory_mb = total_memory_mb

            # Calculate percentage of system memory
            try:
                system_memory = psutil.virtual_memory()  # type: ignore
                self.memory_percent = (
                    (total_memory_bytes + children_memory_bytes)
                    / system_memory.total
                    * 100
                )
            except:
                self.memory_percent = 0.0

            # Store memory percentage in history for sparkline
            self.memory_history_15min.append(self.memory_percent)

            # Refresh the display to show updated data
            self.refresh()

        except (psutil.NoSuchProcess, psutil.AccessDenied):  # type: ignore
            self.memory_mb = 0.0
            self.memory_percent = 0.0
            self.memory_history_15min.append(0.0)
            self.refresh()

    def watch_memory_history_15min(self):
        """Update the display when memory history changes"""
        self.refresh()

    def watch_memory_percent(self):
        """Update the display when memory percentage changes"""
        self.refresh()


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
