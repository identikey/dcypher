"""
ASCII Art Banner Widget
Cyberpunk-inspired banner with @repligate aesthetics
NOW WITH COMPREHENSIVE PROFILING FOR CPU ANALYSIS
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


class ASCIIBanner(Widget):
    """
    ASCII art banner for dCypher TUI
    Features cyberpunk styling with matrix-style effects
    NOW WITH COMPREHENSIVE PROFILING FOR CPU ANALYSIS
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
    matrix_background = reactive(
        False
    )  # Start disabled, will be enabled when server connects
    scrolling_code = reactive(True)  # Start enabled by default

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

        # PERFORMANCE OPTIMIZATION: Add layer composition cache
        self._layer_cache = None
        self._layer_cache_key = None
        self._last_render_time = 0.0
        self._min_render_interval = 0.1  # Minimum 100ms between renders (10 FPS max)

    def on_mount(self) -> None:
        """Start animation timer when mounted"""
        self.set_interval(0.5, self.animate_banner)

    @profile("ASCIIBanner.animate_banner")
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
        if matrix_enabled:
            # Clear framebuffer when enabling for a fresh start
            self.matrix_rain.reset_grid()
        self._update_auto_refresh()

    def watch_scrolling_code(self, scrolling_enabled: bool) -> None:
        """React to scrolling code toggle"""
        self.scrolling_code_controller.enabled = scrolling_enabled
        if scrolling_enabled:
            # Clear buffer when enabling for a fresh start
            self.scrolling_code_controller.clear_buffer()
        self._update_auto_refresh()

    @profile("ASCIIBanner.render")
    def render(self) -> RenderResult:
        """Render the banner with optional matrix background"""
        with profile_block("ASCIIBanner.render.dimension_calculation"):
            # Calculate dimensions based on ASCII content (fixed)
            ascii_lines = self.ascii_art.strip().split("\n")
            content_height = len(ascii_lines) + 2  # ASCII + padding
            if self.show_subtitle:
                content_height += 1

            # Get container dimensions
            container_width = max(80, self.size.width - 4)
            container_height = content_height  # Fixed height for ASCII banner

        # PERFORMANCE OPTIMIZATION: More aggressive cache strategy
        current_time = time.time()

        # Check if we can use cached result (less sensitive cache key)
        if (
            self._layer_cache is not None
            and current_time - self._last_render_time < 0.05
        ):  # 50ms cache (20 FPS max)
            return self._layer_cache

        with profile_block("ASCIIBanner.render.animation_resize"):
            # Update matrix rain dimensions if needed
            if (
                self.matrix_rain.width != container_width
                or self.matrix_rain.height != container_height
            ):
                self.matrix_rain.width = container_width
                self.matrix_rain.height = container_height
                self.matrix_rain.reset_grid()
                # Invalidate cache on size change
                self._layer_cache = None

            # Update scrolling code dimensions if needed
            if (
                self.scrolling_code_controller.width != container_width
                or self.scrolling_code_controller.height != container_height
            ):
                self.scrolling_code_controller.width = container_width
                self.scrolling_code_controller.height = container_height
                # Invalidate cache on size change
                self._layer_cache = None

        with profile_block("ASCIIBanner.render.ascii_text_creation"):
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
            with profile_block("ASCIIBanner.render.animation_updates"):
                # Update animations with synchronized timing
                self.matrix_rain.update(current_time)
                self.scrolling_code_controller.update(current_time)
                self.frame_count += 1

            # PERFORMANCE FIX: Simplified cache - only re-render every 3 frames minimum
            with profile_block("ASCIIBanner.render.cache_check"):
                should_render = (
                    self._layer_cache is None  # No cache yet
                    or self.frame_count % 3 == 0  # Every 3rd frame
                    or current_time - self._last_render_time > 0.1  # Or every 100ms
                )

                if not should_render and self._layer_cache is not None:
                    return self._layer_cache

            with profile_block("ASCIIBanner.render.layered_effects"):
                # Create layered content with scrolling code, matrix rain, and ASCII overlay
                layered_content = self._render_with_layered_effects(
                    ascii_text, container_width, container_height
                )

            with profile_block("ASCIIBanner.render.panel_creation"):
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

            # PERFORMANCE OPTIMIZATION: Cache the result with simpler strategy
            self._layer_cache = panel
            self._last_render_time = current_time
        else:
            with profile_block("ASCIIBanner.render.static_panel"):
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

            # Cache static panel too
            self._layer_cache = panel
            self._last_render_time = current_time

        return panel

    @profile("ASCIIBanner._render_with_layered_effects")
    def _render_with_layered_effects(
        self, ascii_content: Text, width: int, height: int
    ) -> Text:
        """Render layered effects: scrolling code (back), matrix rain (middle), ASCII art (front)"""
        with profile_block(
            "ASCIIBanner._render_with_layered_effects.framebuffer_fetch"
        ):
            # Get framebuffers for all layers
            scrolling_framebuffer = (
                self.scrolling_code_controller.get_framebuffer()
                if self.scrolling_code
                else None
            )
            matrix_framebuffer = (
                self.matrix_rain.get_framebuffer() if self.matrix_background else None
            )

        with profile_block("ASCIIBanner._render_with_layered_effects.ascii_processing"):
            # Convert ASCII to lines for overlay logic
            ascii_lines = str(ascii_content).strip().split("\n")
            ascii_width = max(len(line) for line in ascii_lines) if ascii_lines else 0

            # Create final content with fixed dimensions
            layered_content = Text()

        with profile_block(
            "ASCIIBanner._render_with_layered_effects.layer_composition"
        ):
            # ULTIMATE OPTIMIZATION: Eliminate 2500+ Rich function calls by batch building
            # Instead of character-by-character Rich.append(), build entire content at once

            # Pre-calculate positioning to avoid repeated calculations
            ascii_start_row = (height - len(ascii_lines)) // 2
            ascii_start_col = (width - ascii_width) // 2

            # Build entire content as one string, then create single Rich Text object
            content_lines = []

            for y in range(height):
                # Determine if this row has ASCII content
                ascii_line_idx = -1
                ascii_line = ""
                if ascii_start_row <= y < ascii_start_row + len(ascii_lines):
                    ascii_line_idx = y - ascii_start_row
                    ascii_line = ascii_lines[ascii_line_idx]

                # Build entire line as string segments with consistent styling
                line_segments = []
                current_text = ""
                current_style = None

                for x in range(width):
                    char = " "
                    style = "dim green"

                    # Check if we should place ASCII content here (highest priority)
                    has_ascii = False
                    if 0 <= ascii_line_idx < len(
                        ascii_lines
                    ) and ascii_start_col <= x < ascii_start_col + len(ascii_line):
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
                        elif (
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
                        char, style = scrolling_framebuffer[y][x]

                    # OPTIMIZATION: Batch characters with same style
                    if style == current_style:
                        current_text += char
                    else:
                        if current_text:
                            line_segments.append((current_text, current_style))
                        current_text = char
                        current_style = style

                # Add final segment
                if current_text:
                    line_segments.append((current_text, current_style))

                content_lines.append(line_segments)

            # ULTRA-OPTIMIZATION: Build entire Rich content in ONE operation
            # This reduces 2500+ function calls to just a few dozen
            for y, line_segments in enumerate(content_lines):
                line_text = Text()
                for text_chunk, style in line_segments:
                    line_text.append(
                        text_chunk, style=style
                    )  # Batch append entire chunks

                layered_content.append(line_text)
                if y < height - 1:
                    layered_content.append("\n")

        return layered_content

    def toggle_subtitle(self) -> None:
        """Toggle subtitle visibility"""
        self.show_subtitle = not self.show_subtitle

    def toggle_scrolling_code(self) -> None:
        """Toggle scrolling code effect"""
        self.scrolling_code = not self.scrolling_code

    def set_matrix_saturation(self, saturation: int) -> None:
        """Set matrix rain saturation (0-100%)"""
        self.matrix_rain.set_saturation(saturation)
        self.notify(f"Matrix saturation: {saturation}%", timeout=1.0)

    def set_code_saturation(self, saturation: int) -> None:
        """Set scrolling code saturation (0-100%)"""
        self.scrolling_code_controller.set_saturation(saturation)
        self.notify(f"Code saturation: {saturation}%", timeout=1.0)

    def increase_matrix_saturation(self) -> None:
        """Increase matrix rain saturation by 10%"""
        current_saturation = self.matrix_rain.color_pool.saturation
        new_saturation = min(100, current_saturation + 10)
        self.matrix_rain.set_saturation(new_saturation)
        self.notify(f"Matrix saturation: {new_saturation}%", timeout=1.0)

    def decrease_matrix_saturation(self) -> None:
        """Decrease matrix rain saturation by 10%"""
        current_saturation = self.matrix_rain.color_pool.saturation
        new_saturation = max(0, current_saturation - 10)
        self.matrix_rain.set_saturation(new_saturation)
        self.notify(f"Matrix saturation: {new_saturation}%", timeout=1.0)

    def increase_code_saturation(self) -> None:
        """Increase scrolling code saturation by 10%"""
        self.scrolling_code_controller.increase_saturation()
        self.notify(
            f"Code saturation: {self.scrolling_code_controller.saturation}%",
            timeout=1.0,
        )

    def decrease_code_saturation(self) -> None:
        """Decrease scrolling code saturation by 10%"""
        self.scrolling_code_controller.decrease_saturation()
        self.notify(
            f"Code saturation: {self.scrolling_code_controller.saturation}%",
            timeout=1.0,
        )

    def update_matrix_for_connection(self, connected: bool) -> None:
        """Update matrix background based on server connection status"""
        self.matrix_background = connected
        if connected:
            # Clear framebuffer when enabling for a fresh start
            self.matrix_rain.reset_grid()
            self.notify("Matrix rain activated - Server connected", timeout=2.0)
        else:
            self.notify("Matrix rain deactivated - Server disconnected", timeout=2.0)


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
