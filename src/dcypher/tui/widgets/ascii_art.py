"""
ASCII Art Banner Widget
Cyberpunk-inspired banner with @repligate aesthetics
"""

import random
import time
import os
import pkgutil
import inspect
from pathlib import Path
from textual.widget import Widget
from textual.reactive import reactive
from textual.app import RenderResult
from textual.color import Color
from rich.console import Console, ConsoleOptions
from rich.text import Text
from rich.align import Align
from rich.panel import Panel
from rich.syntax import Syntax

import dill
import dill.source

from dcypher.tui.widgets.matrix_rain import MatrixRain
from dcypher.tui.widgets.scrolling_code import ScrollingCode


class ASCIIBanner(Widget):
    """
    ASCII art banner for dCypher TUI
    Features cyberpunk styling with matrix-style effects
    """

    DEFAULT_CSS = """
    ASCIIBanner {
        width: 100%;
        height: auto;
        content-align: center middle;
        text-align: center;
        margin: 0;
        padding: 0;
        border: none;
        max-height: 12;
    }
    """

    # Reactive properties
    show_subtitle = reactive(True)
    animation_frame = reactive(0)
    matrix_background = reactive(True)
    scrolling_code = reactive(False)

    # ASCII art for dCypher logo
    DCYPHER_ASCII = """
██████╗  ██████╗██╗   ██╗██████╗ ██╗  ██╗███████╗██████╗ 
██╔══██╗██╔════╝╚██╗ ██╔╝██╔══██╗██║  ██║██╔════╝██╔══██╗
██║  ██║██║      ╚████╔╝ ██████╔╝███████║█████╗  ██████╔╝
██║  ██║██║       ╚██╔╝  ██╔═══╝ ██╔══██║██╔══╝  ██╔══██╗
██████╔╝╚██████╗   ██║   ██║     ██║  ██║███████╗██║  ██║
╚═════╝  ╚═════╝   ╚═╝   ╚═╝     ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
"""

    # Alternative compact ASCII
    DCYPHER_COMPACT = """
▓█████▄  ▄████▄▓██   ██▓ ██▓███   ██░ ██ ▓█████  ██▀███  
▒██▀ ██▌▒██▀ ▀█ ▒██  ██▒▓██░  ██▒▓██░ ██▒▓█   ▀ ▓██ ▒ ██▒
░██   █▌▒▓█    ▄ ▒██ ██░▓██░ ██▓▒▒██▀▀██░▒███   ▓██ ░▄█ ▒
░▓█▄   ▌▒▓▓▄ ▄██▒░ ▐██▓░▒██▄█▓▒ ▒░▓█ ░██ ▒▓█  ▄ ▒██▀▀█▄  
░▒████▓ ▒ ▓███▀ ░░ ██▒▓░▒██▒ ░  ░░▓█▒░██▓░▒████▒░██▓ ▒██▒
 ▒▒▓  ▒ ░ ░▒ ▒  ░ ██▒▒▒ ▒▓▒░ ░  ░ ▒ ░░▒░▒░░ ▒░ ░░ ▒▓ ░▒▓░
"""

    # Subtitle text
    SUBTITLE = "QUANTUM-RESISTANT ENCRYPTION • REPLICANT TERMINAL v2.1.0"

    def __init__(self, compact=False, **kwargs):
        super().__init__(**kwargs)
        self.ascii_art = self.DCYPHER_COMPACT if compact else self.DCYPHER_ASCII

        # Initialize matrix rain controller
        self.matrix_rain = MatrixRain()
        self.frame_count = 0

        # Initialize scrolling code controller
        self.scrolling_code_controller = ScrollingCode()

    def on_mount(self) -> None:
        """Start animation timer when mounted"""
        self.set_interval(0.5, self.animate_banner)

    def animate_banner(self) -> None:
        """Animate the banner (subtle effects)"""
        self.animation_frame = (self.animation_frame + 1) % 10

    def increase_framerate(self) -> None:
        """Increase framerate for active effects (matrix rain and/or scrolling code)"""
        effects_updated = []

        # Update matrix rain framerate if enabled
        if self.matrix_rain.enabled:
            current_fps = round(1.0 / self.matrix_rain.update_interval)
            new_fps = min(10, current_fps + 1)
            self.matrix_rain.update_interval = 1.0 / new_fps
            effects_updated.append(f"Matrix: {new_fps} FPS")

        # Update scrolling code framerate if enabled
        if self.scrolling_code_controller.enabled:
            current_fps = round(1.0 / self.scrolling_code_controller.update_interval)
            new_fps = min(10, current_fps + 1)
            self.scrolling_code_controller.update_interval = 1.0 / new_fps
            effects_updated.append(f"Code: {new_fps} FPS")

        # Update auto-refresh to handle faster effect speeds
        self._update_auto_refresh_for_speeds()

        if effects_updated:
            self.notify(" | ".join(effects_updated), timeout=1.0)
        else:
            self.notify("No effects enabled", timeout=1.0)

    def decrease_framerate(self) -> None:
        """Decrease framerate for active effects (matrix rain and/or scrolling code)"""
        effects_updated = []

        # Update matrix rain framerate if enabled
        if self.matrix_rain.enabled:
            current_fps = round(1.0 / self.matrix_rain.update_interval)
            new_fps = max(1, current_fps - 1)
            self.matrix_rain.update_interval = 1.0 / new_fps
            effects_updated.append(f"Matrix: {new_fps} FPS")

        # Update scrolling code framerate if enabled
        if self.scrolling_code_controller.enabled:
            current_fps = round(1.0 / self.scrolling_code_controller.update_interval)
            new_fps = max(1, current_fps - 1)
            self.scrolling_code_controller.update_interval = 1.0 / new_fps
            effects_updated.append(f"Code: {new_fps} FPS")

        # Update auto-refresh to handle slower effect speeds
        self._update_auto_refresh_for_speeds()

        if effects_updated:
            self.notify(" | ".join(effects_updated), timeout=1.0)
        else:
            self.notify("No effects enabled", timeout=1.0)

    def _update_auto_refresh_for_speeds(self) -> None:
        """Update auto-refresh rate based on the current effect speeds"""
        if not (self.matrix_background or self.scrolling_code):
            self.auto_refresh = 0
            return

        # Find the fastest enabled effect to determine minimum refresh needed
        min_interval = float("inf")

        if self.matrix_rain.enabled:
            min_interval = min(min_interval, self.matrix_rain.update_interval)

        if self.scrolling_code_controller.enabled:
            min_interval = min(
                min_interval, self.scrolling_code_controller.update_interval
            )

        if min_interval == float("inf"):
            # No effects enabled
            self.auto_refresh = 0
        else:
            # Set auto-refresh to match the fastest effect, but cap at reasonable limits
            # Min 1 FPS (1.0s), Max 5 FPS (0.2s) for banner refresh
            self.auto_refresh = max(0.2, min(1.0, min_interval))

    def _update_auto_refresh(self) -> None:
        """Update auto-refresh rate based on active effects using unified timing"""
        if self.matrix_background or self.scrolling_code:
            # Use speed-aware refresh rate
            self._update_auto_refresh_for_speeds()
        else:
            # No effects enabled, no need to refresh
            self.auto_refresh = 0
        self.refresh()

    def watch_matrix_background(self, matrix_enabled: bool) -> None:
        """React to matrix background toggle"""
        self.matrix_rain.enabled = matrix_enabled
        self._update_auto_refresh()

    def watch_scrolling_code(self, scrolling_enabled: bool) -> None:
        """React to scrolling code toggle"""
        self.scrolling_code_controller.enabled = scrolling_enabled
        self._update_auto_refresh()

    def render(self) -> RenderResult:
        """Render the banner with optional matrix background"""
        # Calculate dimensions based on ASCII content (fixed)
        ascii_lines = self.ascii_art.strip().split("\n")
        content_height = len(ascii_lines) + 2  # ASCII + padding
        if self.show_subtitle:
            content_height += 1

        # Get container dimensions
        container_width = max(80, self.size.width - 4)
        container_height = content_height  # Fixed height for ASCII banner

        # Update matrix rain dimensions if needed
        if (
            self.matrix_rain.width != container_width
            or self.matrix_rain.height != container_height
        ):
            self.matrix_rain.width = container_width
            self.matrix_rain.height = container_height
            self.matrix_rain.reset_grid()

        # Update scrolling code dimensions if needed
        if (
            self.scrolling_code_controller.width != container_width
            or self.scrolling_code_controller.height != container_height
        ):
            self.scrolling_code_controller.width = container_width
            self.scrolling_code_controller.height = container_height

        # Create ASCII content
        ascii_text = Text()

        # Add the ASCII art
        ascii_text.append("\n")  # Top padding
        for line in ascii_lines:
            ascii_text.append(line + "\n", style="bold green")

        # Add subtitle if enabled
        if self.show_subtitle:
            ascii_text.append(self.SUBTITLE, style="dim cyan")

        ascii_text.append("\n")  # Bottom padding

        # If matrix background or scrolling code is enabled, render with layered effects
        if self.matrix_background or self.scrolling_code:
            # Update animations
            self.matrix_rain.update()
            self.scrolling_code_controller.update()
            self.frame_count += 1

            # Create layered content with scrolling code, matrix rain, and ASCII overlay
            layered_content = self._render_with_layered_effects(
                ascii_text, container_width, container_height
            )
            centered_content = Align.center(layered_content)

            # Create panel with layered content
            effects_enabled = []
            if self.matrix_background:
                effects_enabled.append("MATRIX RAIN")
            if self.scrolling_code:
                effects_enabled.append("SCROLLING CODE")

            if effects_enabled:
                effects_str = " + ".join(effects_enabled)
                title = f"[bold red]◢[/bold red][bold yellow]{effects_str} ENABLED - Post Quantum Lattice FHE System[/bold yellow][bold red]◣[/bold red]"
            else:
                title = "[bold red]◢[/bold red][bold yellow]Post Quantum Lattice FHE System[/bold yellow][bold red]◣[/bold red]"

            panel = Panel(
                centered_content,
                border_style="bright_green",
                padding=(0, 1),
                height=content_height + 2,
                title=title,
                title_align="center",
            )
        else:
            # Normal static banner
            centered_content = Align.center(ascii_text)
            panel = Panel(
                centered_content,
                border_style="bright_green",
                padding=(0, 1),
                height=content_height + 2,
                title="[bold red]◢[/bold red][bold yellow]Post Quantum Lattice FHE System[/bold yellow][bold red]◣[/bold red]",
                title_align="center",
            )

        return panel

    def _render_with_layered_effects(
        self, ascii_content: Text, width: int, height: int
    ) -> Text:
        """Render layered effects: scrolling code (back), matrix rain (middle), ASCII art (front)"""
        # Get framebuffers for all layers
        scrolling_framebuffer = (
            self.scrolling_code_controller.get_framebuffer()
            if self.scrolling_code
            else None
        )
        matrix_framebuffer = (
            self.matrix_rain.get_framebuffer() if self.matrix_background else None
        )

        # Convert ASCII to lines for overlay logic
        ascii_lines = str(ascii_content).strip().split("\n")
        ascii_width = max(len(line) for line in ascii_lines) if ascii_lines else 0

        # Create final content with fixed dimensions
        layered_content = Text()

        for y in range(height):
            line_text = Text()

            # Calculate ASCII positioning (centered vertically and horizontally)
            ascii_start_row = (height - len(ascii_lines)) // 2
            ascii_start_col = (width - ascii_width) // 2

            # Determine if this row has ASCII content
            ascii_line_idx = -1
            if ascii_start_row <= y < ascii_start_row + len(ascii_lines):
                ascii_line_idx = y - ascii_start_row

            for x in range(width):
                char = " "
                style = "dim green"

                # Check if we should place ASCII content here (highest priority)
                has_ascii = False
                if 0 <= ascii_line_idx < len(ascii_lines):
                    ascii_line = ascii_lines[ascii_line_idx]
                    if ascii_start_col <= x < ascii_start_col + len(ascii_line):
                        ascii_char = ascii_line[x - ascii_start_col]
                        if ascii_char != " " and ascii_char != "\n":
                            char = ascii_char
                            style = "bold green"
                            has_ascii = True

                # If no ASCII content, check matrix rain (middle layer)
                if (
                    not has_ascii
                    and matrix_framebuffer
                    and y < len(matrix_framebuffer)
                    and x < len(matrix_framebuffer[0])
                ):
                    matrix_char, matrix_style = matrix_framebuffer[y][x]
                    if matrix_char != " ":
                        char = matrix_char
                        style = matrix_style
                    else:
                        # Matrix is transparent, check scrolling code (back layer)
                        if (
                            scrolling_framebuffer
                            and y < len(scrolling_framebuffer)
                            and x < len(scrolling_framebuffer[0])
                        ):
                            char, style = scrolling_framebuffer[y][x]
                elif (
                    not has_ascii
                    and scrolling_framebuffer
                    and y < len(scrolling_framebuffer)
                    and x < len(scrolling_framebuffer[0])
                ):
                    # No matrix rain, use scrolling code as background
                    char, style = scrolling_framebuffer[y][x]

                line_text.append(char, style=style)

            layered_content.append(line_text)
            if y < height - 1:  # Don't add newline after last row
                layered_content.append("\n")

        return layered_content

    def toggle_subtitle(self) -> None:
        """Toggle subtitle visibility"""
        self.show_subtitle = not self.show_subtitle

    def toggle_scrolling_code(self) -> None:
        """Toggle scrolling code effect"""
        self.scrolling_code = not self.scrolling_code


class CyberpunkBorder(Widget):
    """
    Decorative cyberpunk-style border widget
    Art deco inspired geometric patterns
    """

    BORDER_PATTERNS = {
        "cyber": "▔▁▔▁▔▁▔▁",
        "neon": "═══════════",
        "circuit": "━╋━╋━╋━╋━",
    }

    def __init__(self, pattern="cyber", **kwargs):
        super().__init__(**kwargs)
        self.pattern = pattern

    def render(self) -> RenderResult:
        """Render cyberpunk border"""
        return Text(self.BORDER_PATTERNS.get(self.pattern, "▔▁▔▁▔▁▔▁"))
