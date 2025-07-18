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
from typing import Optional, Tuple, List
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
    SUBTITLE = "FREEDOM CANNOT BE GIVEN, IT MUST BE TAKEN • RECRYPTION BY IDENTIKEY"

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
        self._layer_cache_key: Optional[Tuple[int, int, int, bool, bool, bool]] = None
        self._layer_cache_result: Optional[Text] = None
        self._matrix_state_hash: int = 0
        self._code_state_hash: int = 0
        self._cache_timestamp: float = 0.0  # Time-based cache validation

        # PERFORMANCE OPTIMIZATION: Cache static ASCII content
        self._ascii_lines_cache: Optional[List[str]] = None
        self._ascii_text_cache: Optional[Text] = None
        self._dimension_cache: Optional[Tuple[int, List[str]]] = None
        self._last_subtitle_state: Optional[bool] = None

        # RE-ENABLED CACHING (design is now settled):
        # - Layer composition result caching (_layer_cache) - RE-ENABLED
        # - Render time-based caching (50ms intervals) - RE-ENABLED
        # - Frame-based render skipping (every 3rd frame) - RE-ENABLED
        # - Cache invalidation on size changes - RE-ENABLED

        # ULTRA-AGGRESSIVE CACHING: Re-enable all disabled optimizations
        self._render_cache: Optional[Text] = (
            None  # Cache the layered content, not the Panel
        )
        self._render_cache_timestamp: float = 0.0
        self._render_cache_interval: float = 0.05  # 50ms intervals
        self._frame_skip_counter: int = 0
        self._frame_skip_modulo: int = 3  # Every 3rd frame
        self._last_container_size: Optional[Tuple[int, int]] = None
        self._static_panel_cache: Optional[RenderResult] = (
            None  # Only cache static panels
        )

        # DISPLAY-SYNCHRONIZED ANIMATION: Only update when visually needed
        self._last_animation_update: float = 0.0
        self._animation_update_interval: float = 1.0  # Match slowest effect (1 FPS)
        self._visual_frame_counter: int = 0

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

        # RE-ENABLED OPTIMIZATION: Also invalidate static panel cache
        self._static_panel_cache = None
        self._render_cache_timestamp = 0.0
        self._frame_skip_counter = 0  # Reset frame counter

        # DISPLAY-SYNCHRONIZED ANIMATION: Reset animation timing
        self._last_animation_update = 0.0
        self._visual_frame_counter = 0

    def _get_cached_ascii_lines(self) -> List[str]:
        """PERFORMANCE: Get cached ASCII lines to avoid repeated string splitting"""
        if self._ascii_lines_cache is None:
            self._ascii_lines_cache = self.ascii_art.strip().split("\n")
        return self._ascii_lines_cache

    def _get_cached_ascii_text(self) -> Text:
        """PERFORMANCE: Get cached ASCII text to avoid repeated Rich Text creation"""
        # Check if we need to invalidate cache due to subtitle change
        if self._last_subtitle_state != self.show_subtitle:
            self._ascii_text_cache = None
            self._last_subtitle_state = self.show_subtitle

        if self._ascii_text_cache is None:
            # Create ASCII content once and cache it
            ascii_text = Text()
            ascii_lines = self._get_cached_ascii_lines()

            # Add the ASCII art
            ascii_text.append("\n")  # Top padding
            for line in ascii_lines:
                ascii_text.append(line + "\n", style="bold green")

            # Add subtitle if enabled
            if self.show_subtitle:
                ascii_text.append(self.SUBTITLE, style="dim cyan")

            ascii_text.append("\n")  # Bottom padding

            self._ascii_text_cache = ascii_text

        return self._ascii_text_cache

    def _get_cached_dimensions(self) -> Tuple[int, List[str]]:
        """PERFORMANCE: Get cached dimensions to avoid repeated calculation"""
        # Check if we need to invalidate cache due to subtitle change
        if self._last_subtitle_state != self.show_subtitle:
            self._dimension_cache = None
            self._last_subtitle_state = self.show_subtitle

        if self._dimension_cache is None:
            ascii_lines = self._get_cached_ascii_lines()
            content_height = len(ascii_lines) + 2  # ASCII + padding
            if self.show_subtitle:
                content_height += 1

            self._dimension_cache = (content_height, ascii_lines)

        return self._dimension_cache

    @profile("ASCIIBanner.render")
    def render(self) -> RenderResult:
        """Render the banner with optional matrix background"""
        current_time = time.time()

        # RE-ENABLED OPTIMIZATION 1: Render time-based caching (50ms intervals)
        # Only for static content - dynamic effects always render fresh
        if (
            not (self.matrix_background or self.scrolling_code)
            and self._static_panel_cache is not None
            and current_time - self._render_cache_timestamp
            < self._render_cache_interval
        ):
            return self._static_panel_cache

        # RE-ENABLED OPTIMIZATION 2: Frame-based render skipping (every 3rd frame)
        # Only for static content
        self._frame_skip_counter += 1
        if (
            not (self.matrix_background or self.scrolling_code)
            and self._frame_skip_counter % self._frame_skip_modulo != 0
            and self._static_panel_cache is not None
        ):
            return self._static_panel_cache

        # RE-ENABLED OPTIMIZATION 3: Cache invalidation on size changes
        current_size = (self.size.width, self.size.height)
        if (
            self._last_container_size is not None
            and self._last_container_size != current_size
        ):
            # Size changed - invalidate all caches
            self._static_panel_cache = None
            self._layer_cache_key = None
            self._layer_cache_result = None
            self._ascii_text_cache = None
            self._dimension_cache = None

        self._last_container_size = current_size

        # SMART CACHING: Skip rendering if called too frequently
        if current_time - self._last_render_time < self._min_render_interval:
            # Force a refresh instead of using cached result to avoid render issues
            pass

        with profile_block("ASCIIBanner.render.dimension_calculation"):
            # PERFORMANCE: Use cached dimensions instead of recalculating
            content_height, ascii_lines = self._get_cached_dimensions()

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
            # PERFORMANCE: Use cached ASCII text instead of recreating every render
            ascii_text = self._get_cached_ascii_text()

        # If matrix background or scrolling code is enabled, render with layered effects
        if self.matrix_background or self.scrolling_code:
            # Clear static cache when effects are active
            self._static_panel_cache = None

            # DISPLAY-SYNCHRONIZED ANIMATION: Only update when visually needed
            should_update_animations = (
                current_time - self._last_animation_update
                >= self._animation_update_interval
            )

            with profile_block("ASCIIBanner.render.animation_updates"):
                if should_update_animations:
                    # Update animations with synchronized timing - ONLY when visually needed
                    self.matrix_rain.update(current_time)
                    self.scrolling_code_controller.update(current_time)
                    self.frame_count += 1
                    self._last_animation_update = current_time
                    self._visual_frame_counter += 1

                    # Invalidate layer cache when animations actually update
                    self._layer_cache_key = None
                    self._layer_cache_result = None
                # ELSE: Skip animation updates - use cached visual state

            with profile_block("ASCIIBanner.render.layered_effects"):
                # Create layered content with scrolling code, matrix rain, and ASCII overlay
                layered_content = self._render_with_layered_effects(
                    container_width, container_height
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

                # Cache static panel for reuse
                self._static_panel_cache = panel

        # SMART CACHING: Update timing
        self._last_render_time = current_time
        self._render_cache_timestamp = current_time

        return panel

    @profile("ASCIIBanner._render_with_layered_effects")
    def _render_with_layered_effects(self, width: int, height: int) -> Text:
        """ULTRA-OPTIMIZED: Render with layered effects using bulk operations and vectorized processing"""

        # PERFORMANCE: Quick cache check first
        with profile_block("ASCIIBanner._render_with_layered_effects.cache_check"):
            cache_key = (
                width,
                height,
                self._visual_frame_counter,  # Use visual frame counter instead of raw frame_count
                self.show_subtitle,
                self.scrolling_code_controller.enabled,
                self.matrix_rain.enabled,
            )

            if (
                self._layer_cache_key == cache_key
                and self._layer_cache_result is not None
            ):
                return self._layer_cache_result

        # SYNCHRONIZED FRAMEBUFFER FETCH: Get all layer data at once
        with profile_block(
            "ASCIIBanner._render_with_layered_effects.framebuffer_fetch"
        ):
            # Get all framebuffers simultaneously - NO REDUNDANT UPDATES
            # Animation updates are now handled centrally in render()
            scrolling_framebuffer = None
            matrix_framebuffer = None

            if self.scrolling_code_controller.enabled:
                scrolling_framebuffer = self.scrolling_code_controller.get_framebuffer()

            if self.matrix_rain.enabled:
                matrix_framebuffer = self.matrix_rain.get_framebuffer()

        # ASCII PROCESSING: Pre-compute ASCII positioning
        with profile_block("ASCIIBanner._render_with_layered_effects.ascii_processing"):
            ascii_lines = self._get_cached_ascii_lines()
            ascii_width = max(len(line) for line in ascii_lines) if ascii_lines else 0
            ascii_start_row = (height - len(ascii_lines)) // 2
            ascii_start_col = (width - ascii_width) // 2

            # Pre-compute ASCII character positions for bulk overlay
            ascii_positions = {}  # {(y, x): (char, style)}
            for line_idx, line in enumerate(ascii_lines):
                y = ascii_start_row + line_idx
                if 0 <= y < height:
                    for col_idx, char in enumerate(line):
                        x = ascii_start_col + col_idx
                        if 0 <= x < width and char not in (" ", "\n"):
                            ascii_positions[(y, x)] = (char, "bold green")

            # SUBTITLE BUG FIX: Add subtitle positioning when enabled
            if self.show_subtitle:
                subtitle_y = ascii_start_row + len(
                    ascii_lines
                )  # Position after ASCII art
                subtitle_start_col = (width - len(self.SUBTITLE)) // 2

                for col_idx, char in enumerate(self.SUBTITLE):
                    x = subtitle_start_col + col_idx
                    if 0 <= subtitle_y < height and 0 <= x < width:
                        ascii_positions[(subtitle_y, x)] = (char, "dim cyan")

        # ULTRA-VECTORIZED LAYER COMPOSITION
        with profile_block(
            "ASCIIBanner._render_with_layered_effects.layer_composition"
        ):
            # Create layer priority map: higher number = higher priority
            # ASCII art = priority 3, Matrix rain = priority 2, Scrolling code = priority 1

            # Initialize output arrays for bulk processing
            final_chars = [[" " for _ in range(width)] for _ in range(height)]
            final_styles = [["dim green" for _ in range(width)] for _ in range(height)]

            # BULK LAYER 1: Scrolling code background (priority 1)
            if scrolling_framebuffer:
                for y in range(min(height, len(scrolling_framebuffer))):
                    scrolling_row = scrolling_framebuffer[y]
                    for x in range(min(width, len(scrolling_row))):
                        char, style = scrolling_row[x]
                        if char != " ":
                            final_chars[y][x] = char
                            final_styles[y][x] = str(style)

            # BULK LAYER 2: Matrix rain overlay (priority 2)
            if matrix_framebuffer:
                for y in range(min(height, len(matrix_framebuffer))):
                    matrix_row = matrix_framebuffer[y]
                    for x in range(min(width, len(matrix_row))):
                        char, style = matrix_row[x]
                        if char != " ":
                            final_chars[y][x] = char
                            final_styles[y][x] = str(style)

            # BULK LAYER 3: ASCII art overlay (priority 3 - highest)
            for (y, x), (char, style) in ascii_positions.items():
                final_chars[y][x] = char
                final_styles[y][x] = style

            # OPTIMIZED RICH TEXT CONSTRUCTION: Build content in large chunks
            layered_content = Text()

            # Process entire rows at once instead of character-by-character
            for y in range(height):
                row_chars = final_chars[y]
                row_styles = final_styles[y]

                # MEGA-OPTIMIZATION: Run-length encode entire row in one pass
                if row_chars:
                    # Find style transitions and group characters
                    segments = []
                    current_chars = []
                    current_style = row_styles[0]

                    for x in range(width):
                        char = row_chars[x]
                        style = row_styles[x]

                        if style == current_style:
                            current_chars.append(char)
                        else:
                            # Style transition - finalize current segment
                            if current_chars:
                                segments.append(("".join(current_chars), current_style))
                            current_chars = [char]
                            current_style = style

                    # Don't forget the last segment
                    if current_chars:
                        segments.append(("".join(current_chars), current_style))

                    # Append all segments for this row at once
                    for text_chunk, style in segments:
                        layered_content.append(text_chunk, style=style)

                # Add newline except for last row
                if y < height - 1:
                    layered_content.append("\n", style="dim green")

        # SMART CACHE: Store result
        self._layer_cache_key = cache_key
        self._layer_cache_result = layered_content
        self._cache_timestamp = time.time()

        return layered_content

    def toggle_subtitle(self) -> None:
        """Toggle subtitle visibility"""
        self.show_subtitle = not self.show_subtitle
        # PERFORMANCE: Invalidate caches when subtitle state changes
        self._ascii_text_cache = None
        self._dimension_cache = None
        self._layer_cache_key = None  # Invalidate layer cache
        self._layer_cache_result = None

        # RE-ENABLED OPTIMIZATION: Also invalidate static panel cache
        self._static_panel_cache = None
        self._render_cache_timestamp = 0.0
        self._frame_skip_counter = 0

        # DISPLAY-SYNCHRONIZED ANIMATION: Reset animation timing
        self._last_animation_update = 0.0
        self._visual_frame_counter = 0

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

    def set_animation_fps(self, fps: float) -> None:
        """Set animation FPS for display-synchronized updates"""
        self._animation_update_interval = 1.0 / max(
            0.5, min(10.0, fps)
        )  # 0.5-10 FPS range
        self._invalidate_layer_cache()  # Force immediate update with new timing
        self.notify(
            f"Animation FPS: {fps:.1f} (interval: {self._animation_update_interval:.3f}s)",
            timeout=1.0,
        )


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
