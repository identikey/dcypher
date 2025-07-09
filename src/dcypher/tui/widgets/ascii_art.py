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
from typing import Optional, Tuple
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

    def profile_block(name: str, backend: str = "cprofile"):  # type: ignore
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

        # SMART CACHING: Add render frequency synchronization
        self._last_render_time = 0.0
        self._min_render_interval = 0.1  # Maximum 10 FPS for banner rendering

        # SMART LAYER COMPOSITION CACHING (no deep copy)
        self._layer_cache_key: Optional[Tuple[int, int, int, bool, bool]] = None
        self._layer_cache_result: Optional[Text] = None
        self._matrix_state_hash: int = 0
        self._code_state_hash: int = 0
        self._cache_timestamp: float = 0.0  # Time-based cache validation

        # DISABLED CACHING (for design finalization):
        # - Layer composition result caching (_layer_cache)
        # - Render time-based caching (50ms intervals)
        # - Frame-based render skipping (every 3rd frame)
        # - Cache invalidation on size changes
        # TODO: Re-enable these caches after design is settled

    def on_mount(self) -> None:
        """Start animation timer when mounted"""
        self.set_interval(0.5, self.animate_banner)

    @profile("ASCIIBanner.animate_banner")
    def animate_banner(self) -> None:
        """Animate the banner (subtle effects)"""
        self.animation_frame = (self.animation_frame + 1) % 10

    def increase_framerate(self) -> None:
        """Increase framerate for active effects (matrix rain and/or scrolling code) - SYNCHRONIZED"""
        effects_updated = []

        # Get current FPS from any enabled effect to determine synchronized target
        current_fps = 2  # Default starting point
        if self.matrix_rain.enabled:
            current_fps = round(1.0 / self.matrix_rain.update_interval)
        elif self.scrolling_code_controller.enabled:
            current_fps = round(1.0 / self.scrolling_code_controller.update_interval)

        # Calculate new synchronized FPS
        new_fps = min(10, current_fps + 1)
        new_interval = 1.0 / new_fps

        # Apply the same FPS to both effects if enabled
        if self.matrix_rain.enabled:
            self.matrix_rain.update_interval = new_interval
            effects_updated.append(f"Matrix: {new_fps} FPS")

        if self.scrolling_code_controller.enabled:
            self.scrolling_code_controller.update_interval = new_interval
            effects_updated.append(f"Code: {new_fps} FPS")

        # Update auto-refresh to handle faster effect speeds
        self._update_auto_refresh_for_speeds()

        if effects_updated:
            self.notify(
                f"Synchronized FPS: {new_fps} | " + " | ".join(effects_updated),
                timeout=1.0,
            )
        else:
            self.notify("No effects enabled", timeout=1.0)

    def decrease_framerate(self) -> None:
        """Decrease framerate for active effects (matrix rain and/or scrolling code) - SYNCHRONIZED"""
        effects_updated = []

        # Get current FPS from any enabled effect to determine synchronized target
        current_fps = 2  # Default starting point
        if self.matrix_rain.enabled:
            current_fps = round(1.0 / self.matrix_rain.update_interval)
        elif self.scrolling_code_controller.enabled:
            current_fps = round(1.0 / self.scrolling_code_controller.update_interval)

        # Calculate new synchronized FPS
        new_fps = max(1, current_fps - 1)
        new_interval = 1.0 / new_fps

        # Apply the same FPS to both effects if enabled
        if self.matrix_rain.enabled:
            self.matrix_rain.update_interval = new_interval
            effects_updated.append(f"Matrix: {new_fps} FPS")

        if self.scrolling_code_controller.enabled:
            self.scrolling_code_controller.update_interval = new_interval
            effects_updated.append(f"Code: {new_fps} FPS")

        # Update auto-refresh to handle slower effect speeds
        self._update_auto_refresh_for_speeds()

        if effects_updated:
            self.notify(
                f"Synchronized FPS: {new_fps} | " + " | ".join(effects_updated),
                timeout=1.0,
            )
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
        self._invalidate_layer_cache()
        self._update_auto_refresh()

    def watch_scrolling_code(self, scrolling_enabled: bool) -> None:
        """React to scrolling code toggle"""
        self.scrolling_code_controller.enabled = scrolling_enabled
        if scrolling_enabled:
            # Clear buffer when enabling for a fresh start
            self.scrolling_code_controller.clear_buffer()
        self._invalidate_layer_cache()
        self._update_auto_refresh()

    def _invalidate_layer_cache(self) -> None:
        """Invalidate the layer composition cache"""
        self._layer_cache_key = None
        self._layer_cache_result = None
        self._cache_timestamp = 0.0  # Reset timestamp to force regeneration

    @profile("ASCIIBanner.render")
    def render(self) -> RenderResult:
        """Render the banner with optional matrix background"""
        current_time = time.time()

        # SMART CACHING: Skip rendering if called too frequently
        if current_time - self._last_render_time < self._min_render_interval:
            # Force a refresh instead of using cached result to avoid render issues
            pass

        with profile_block("ASCIIBanner.render.dimension_calculation"):
            # Calculate dimensions based on ASCII content (fixed)
            ascii_lines = self.ascii_art.strip().split("\n")
            content_height = len(ascii_lines) + 2  # ASCII + padding
            if self.show_subtitle:
                content_height += 1

            # Get container dimensions
            container_width = max(80, self.size.width - 4)
            container_height = content_height  # Fixed height for ASCII banner

        with profile_block("ASCIIBanner.render.animation_resize"):
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

                # SMART CACHING: Update timing
        self._last_render_time = current_time

        return panel

    @profile("ASCIIBanner._render_with_layered_effects")
    def _render_with_layered_effects(
        self, ascii_content: Text, width: int, height: int
    ) -> Text:
        """ULTRA-OPTIMIZED: Render layered effects with minimal Rich Text operations"""

        # SMART CACHING: Check if we can use cached result
        with profile_block("ASCIIBanner._render_with_layered_effects.cache_check"):
            # Generate BUCKETED state hashes for better cache hit rates
            matrix_state_hash = (
                hash(
                    (
                        self.matrix_rain._current_frame // 5,  # Bucket frames by 5
                        self.matrix_rain.enabled,
                        len(self.matrix_rain.sprites)
                        if self.matrix_rain.sprites
                        else 0,
                    )
                )
                if self.matrix_background
                else 0
            )
            code_state_hash = (
                hash(
                    (
                        self.scrolling_code_controller.revealed_chars
                        // 50,  # Bucket characters by 50
                        self.scrolling_code_controller.enabled,
                        len(self.scrolling_code_controller.display_lines)
                        // 3,  # Bucket lines by 3
                    )
                )
                if self.scrolling_code
                else 0
            )
            ascii_state_hash = hash(str(ascii_content))

            # Create cache key
            cache_key = (
                matrix_state_hash,
                code_state_hash,
                ascii_state_hash,
                self.matrix_background,
                self.scrolling_code,
            )

            # TIME-BASED CACHE: Allow cache usage for 200ms even with minor changes
            current_time = time.time()
            cache_age = current_time - self._cache_timestamp

            # Check if cache is valid (state match OR recent cache)
            if (
                self._layer_cache_key == cache_key or cache_age < 0.2
            ) and self._layer_cache_result is not None:
                return self._layer_cache_result

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

        with profile_block(
            "ASCIIBanner._render_with_layered_effects.layer_composition"
        ):
            # ULTRA-OPTIMIZED: Build segments efficiently without Rich markup overhead
            # Avoiding both expensive markup parsing AND excessive append calls

            # Pre-calculate positioning once
            ascii_start_row = (height - len(ascii_lines)) // 2
            ascii_start_col = (width - ascii_width) // 2

            # Pre-allocate segment list for single append operation
            all_segments = []

            for y in range(height):
                # Build entire row as string first, then determine styling
                row_chars = [" "] * width
                row_styles = ["dim green"] * width

                # Layer 1: Background (scrolling code or matrix)
                if scrolling_framebuffer and y < len(scrolling_framebuffer):
                    scrolling_row = scrolling_framebuffer[y]
                    for x in range(min(width, len(scrolling_row))):
                        char, style = scrolling_row[x]
                        if char != " ":
                            row_chars[x] = char
                            row_styles[x] = str(style)  # Ensure string type

                # Layer 2: Matrix rain (overrides background where present)
                if matrix_framebuffer and y < len(matrix_framebuffer):
                    matrix_row = matrix_framebuffer[y]
                    for x in range(min(width, len(matrix_row))):
                        char, style = matrix_row[x]
                        if char != " ":
                            row_chars[x] = char
                            row_styles[x] = str(style)  # Ensure string type

                # Layer 3: ASCII art (highest priority, overrides everything)
                if ascii_start_row <= y < ascii_start_row + len(ascii_lines):
                    ascii_line_idx = y - ascii_start_row
                    ascii_line = ascii_lines[ascii_line_idx]

                    # Apply ASCII characters with bounds checking
                    ascii_end = min(len(ascii_line), width - ascii_start_col)
                    for i in range(ascii_end):
                        ascii_char = ascii_line[i]
                        if ascii_char not in (" ", "\n"):
                            x_pos = ascii_start_col + i
                            if 0 <= x_pos < width:
                                row_chars[x_pos] = ascii_char
                                row_styles[x_pos] = "bold green"

                # Build segments for this row with maximum efficiency
                current_text = ""
                current_style = row_styles[0]

                for x in range(width):
                    char = row_chars[x]
                    style = row_styles[x]

                    if style == current_style:
                        current_text += char
                    else:
                        # Style changed - save current segment and start new one
                        if current_text:
                            all_segments.append((current_text, current_style))
                        current_text = char
                        current_style = style

                # Don't forget the last segment of the row
                if current_text:
                    all_segments.append((current_text, current_style))

                # Add newline except for last row
                if y < height - 1:
                    all_segments.append(("\n", current_style))

            # ULTRA-OPTIMIZATION: Merge segments across lines to reduce Rich operations
            merged_segments = []
            if all_segments:
                current_text = all_segments[0][0]
                current_style = all_segments[0][1]

                for text_chunk, style in all_segments[1:]:
                    if style == current_style:
                        current_text += text_chunk
                    else:
                        if current_text:
                            merged_segments.append((current_text, current_style))
                        current_text = text_chunk
                        current_style = style

                # Don't forget the last segment
                if current_text:
                    merged_segments.append((current_text, current_style))

            # Create Rich content with MINIMAL operations (typically 5-15 total calls)
            layered_content = Text()
            for text_chunk, style in merged_segments:
                layered_content.append(text_chunk, style=style)

        # SMART CACHING: Store result for future use (reference, not copy)
        self._layer_cache_key = cache_key
        self._layer_cache_result = layered_content
        self._cache_timestamp = time.time()  # Update cache timestamp

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
