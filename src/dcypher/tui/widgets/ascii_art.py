"""
ASCII Art Banner Widget
Cyberpunk-inspired banner with @repligate aesthetics
"""

import random
from textual.widget import Widget
from textual.reactive import reactive
from textual.app import RenderResult
from textual.color import Color
from rich.console import Console, ConsoleOptions
from rich.text import Text
from rich.align import Align
from rich.panel import Panel


class MatrixRain:
    """
    Matrix rain effect controller implementing hex-chunk-based upward-moving pattern
    Uses hex-meaningful widths (2, 4, 8 characters) for authentic crypto aesthetic
    """

    def __init__(self, width: int = 80, height: int = 20):
        self.width = width
        self.height = height
        self.enabled = False
        self.hex_chars = "0123456789ABCDEF"

        # Hex chunk widths that make sense for crypto/hex work
        self.chunk_widths = [2, 4, 8]  # bytes, words, dwords

        # Column chunks - each chunk spans multiple columns
        self.column_chunks = []
        # Grid to track fade states: 0=empty, 1=white/head, 2+=fading trail
        self.grid = []
        # Character grid to store what character is at each position
        self.char_grid = []
        # Maximum fade states (determines tail length)
        self.max_fade_states = 12
        self.reset_grid()

    def reset_grid(self):
        """Initialize/reset the grid and column chunks"""
        self.column_chunks = []
        self.grid = []
        self.char_grid = []

        # Create more hex chunks that can overlap - much denser
        num_chunks = self.width // 2  # Create way more chunks than width allows

        for _ in range(num_chunks):
            # Choose random chunk width
            chunk_width = random.choice(self.chunk_widths)

            # Random x position - chunks can overlap and run over each other
            x_start = random.randint(0, max(0, self.width - chunk_width))

            # Create chunk data
            # 50/50 chance: start from bottom or random position
            if random.random() < 0.5:
                start_y = self.height - 1  # Bottom spawn
            else:
                start_y = random.randint(0, self.height - 1)  # Random position

            chunk = {
                "x_start": x_start,
                "width": chunk_width,
                "y": start_y,
                "last_y": start_y,
                "hex_value": self._generate_hex_string(chunk_width),
                "active": random.random() < 0.3,  # 30% start active - reduced density
                "spawn_cooldown": random.randint(0, 20),  # Adjusted spawn timing
                "speed_counter": 0,
                "speed": random.randint(1, 4),  # Wider speed range for overtaking
                "tail_length": random.randint(4, 12),
            }

            self.column_chunks.append(chunk)

        # Initialize empty grid
        for y in range(self.height):
            row = []
            char_row = []
            for x in range(self.width):
                row.append(0)  # Empty state
                char_row.append(" ")  # Empty char
            self.grid.append(row)
            self.char_grid.append(char_row)

    def _generate_hex_string(self, width: int) -> str:
        """Generate a random hex string of specified width"""
        return "".join(random.choice(self.hex_chars) for _ in range(width))

    def toggle_rain(self):
        """Toggle matrix rain effect on/off"""
        self.enabled = not self.enabled
        if not self.enabled:
            # Clear all when disabled
            self.reset_grid()

    def update(self):
        """Update matrix rain animation - call this each frame"""
        if not self.enabled:
            return

        # First, age all existing characters (fade them)
        for y in range(self.height):
            for x in range(self.width):
                if self.grid[y][x] > 0:
                    self.grid[y][x] += 1
                    # Remove characters that have faded completely
                    if self.grid[y][x] > self.max_fade_states:
                        self.grid[y][x] = 0
                        self.char_grid[y][x] = " "

        # Now update each hex chunk
        for chunk in self.column_chunks:
            # Handle spawn cooldown for inactive chunks
            if not chunk["active"]:
                if chunk["spawn_cooldown"] > 0:
                    chunk["spawn_cooldown"] -= 1
                else:
                    # Random chance to spawn a new chunk
                    if (
                        random.random() < 0.08
                    ):  # 8% chance per frame - reduced spawn rate
                        chunk["active"] = True

                        # 50/50 chance: spawn from bottom or random position
                        if random.random() < 0.5:
                            # Spawn from bottom (traditional)
                            chunk["y"] = self.height - 1
                        else:
                            # Spawn from random position in screen
                            chunk["y"] = random.randint(0, self.height - 1)

                        chunk["last_y"] = chunk["y"]
                        chunk["hex_value"] = self._generate_hex_string(chunk["width"])
                        chunk["speed_counter"] = 0
                        chunk["tail_length"] = random.randint(4, 12)
                        # Randomize position for more chaos and overlapping
                        chunk["x_start"] = random.randint(
                            0, max(0, self.width - chunk["width"])
                        )
            else:
                # Handle speed timing for active chunks
                chunk["speed_counter"] += 1

                # While staying in same position, keep changing hex value (processing effect)
                if chunk["speed_counter"] < chunk["speed"]:
                    # Still in same position - keep changing characters
                    chunk["hex_value"] = self._generate_hex_string(chunk["width"])

                if chunk["speed_counter"] >= chunk["speed"]:
                    chunk["speed_counter"] = 0

                    # Place current chunk characters (frozen from last change)
                    if 0 <= chunk["y"] < self.height:
                        for i, char in enumerate(chunk["hex_value"]):
                            x_pos = chunk["x_start"] + i
                            if x_pos < self.width:
                                self.grid[chunk["y"]][x_pos] = 1  # White/head state
                                self.char_grid[chunk["y"]][x_pos] = char

                    # Move chunk up
                    chunk["last_y"] = chunk["y"]
                    chunk["y"] -= 1

                    # Generate new hex value for next position
                    chunk["hex_value"] = self._generate_hex_string(chunk["width"])

                    # Reset chunk when it goes off screen
                    if chunk["y"] < -1:
                        chunk["active"] = False
                        chunk["spawn_cooldown"] = random.randint(
                            5, 25
                        )  # Longer cooldown since spawn rate is reduced
                        chunk["speed"] = random.randint(1, 4)  # Wide speed range
                        # Randomize x position for next run (allows repositioning)
                        chunk["x_start"] = random.randint(
                            0, max(0, self.width - chunk["width"])
                        )
                        chunk["last_y"] = self.height - 1
                else:
                    # Still in same position - place the changing characters
                    if 0 <= chunk["y"] < self.height:
                        for i, char in enumerate(chunk["hex_value"]):
                            x_pos = chunk["x_start"] + i
                            if x_pos < self.width:
                                self.grid[chunk["y"]][x_pos] = 1  # White/head state
                                self.char_grid[chunk["y"]][x_pos] = char

    def get_framebuffer(self):
        """Generate framebuffer with current matrix rain state"""
        # Define precise hex colors for Matrix rain effect
        white = Color.parse("#FFFFFF")  # Pure white head
        matrix_green = Color.parse("#00FF41")  # Classic Matrix green
        dim_matrix_green = Color.parse("#00AA2B")  # Dimmed Matrix green
        dark_green = Color.parse("#004400")  # Very dark green
        black = Color.parse("#333333")  # Pure black

        # Create the 50/50 white/matrix green blend
        white_green_blend = white.blend(matrix_green, 0.5)

        # Create the 50/50 dark green/black blend for final fade
        dark_green_black_blend = dark_green.blend(black, 0.75)

        framebuffer = []
        for y in range(self.height):
            row = []
            for x in range(self.width):
                if self.grid[y][x] == 0:
                    # Empty cell - pure black
                    row.append((" ", black.hex))
                elif self.grid[y][x] == 1:
                    # Head - bright white
                    row.append((self.char_grid[y][x], white.hex))
                elif self.grid[y][x] == 2:
                    # Second position - 50/50 white/green blend
                    row.append((self.char_grid[y][x], white_green_blend.hex))
                else:
                    # Positions 3+ - gradual fade from blend to green to black
                    fade_level = (
                        self.grid[y][x] - 2
                    )  # 1-10 (since grid starts at 2 after head)
                    max_fade = self.max_fade_states - 2  # 10
                    fade_progress = fade_level / max_fade  # 0.0 to 1.0

                    if fade_progress <= 0.2:  # First 20% - blend to matrix green
                        # Blend from white_green_blend to matrix green
                        blend_factor = fade_progress / 0.2
                        color = white_green_blend.blend(matrix_green, blend_factor)
                        row.append((self.char_grid[y][x], color.hex))
                    elif fade_progress <= 0.4:  # Next 20% - pure matrix green
                        row.append((self.char_grid[y][x], matrix_green.hex))
                    elif fade_progress <= 0.6:  # Next 20% - start dimming
                        row.append((self.char_grid[y][x], dim_matrix_green.hex))
                    else:  # Final 40% - gradual fade to black
                        # Create smooth fade to black over the final 40%
                        black_fade_progress = (fade_progress - 0.6) / 0.4  # 0.0 to 1.0

                        if (
                            black_fade_progress <= 0.5
                        ):  # First half - dim green to darker green
                            blend_factor = black_fade_progress * 2  # 0.0 to 1.0
                            color = dim_matrix_green.blend(dark_green, blend_factor)
                            row.append((self.char_grid[y][x], color.hex))
                        else:  # Second half - dark green to dark green/black blend
                            blend_factor = (black_fade_progress - 0.5) * 2  # 0.0 to 1.0
                            color = dark_green.blend(
                                dark_green_black_blend, blend_factor
                            )
                            row.append((self.char_grid[y][x], color.hex))

            framebuffer.append(row)

        return framebuffer


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
    matrix_background = reactive(False)
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

    def on_mount(self) -> None:
        """Start animation timer when mounted"""
        self.set_interval(0.5, self.animate_banner)

    def animate_banner(self) -> None:
        """Animate the banner (subtle effects)"""
        self.animation_frame = (self.animation_frame + 1) % 10

    def watch_matrix_background(self, matrix_enabled: bool) -> None:
        """React to matrix background toggle"""
        if matrix_enabled:
            # Start matrix animation at 1 FPS
            self.auto_refresh = 1
            self.matrix_rain.enabled = True
        else:
            # Stop auto refresh when disabled
            self.auto_refresh = 0
            self.matrix_rain.enabled = False

    def render(self) -> RenderResult:
        """Render the banner with optional matrix background"""
        # Calculate dimensions
        ascii_lines = self.ascii_art.strip().split("\n")
        content_height = len(ascii_lines) + 2  # ASCII + padding
        if self.show_subtitle:
            content_height += 1

        # Get container dimensions
        container_width = max(80, self.size.width - 4)
        container_height = content_height

        # Update matrix rain dimensions if needed
        if (
            self.matrix_rain.width != container_width
            or self.matrix_rain.height != container_height
        ):
            self.matrix_rain.width = container_width
            self.matrix_rain.height = container_height
            self.matrix_rain.reset_grid()

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

        # If matrix background is enabled, render with matrix rain
        if self.matrix_background:
            # Update matrix rain animation
            self.matrix_rain.update()
            self.frame_count += 1

            # Create matrix content with ASCII overlay
            matrix_content = self._render_with_matrix_overlay(
                ascii_text, container_width, container_height
            )
            centered_content = Align.center(matrix_content)

            # Create panel with matrix content
            panel = Panel(
                centered_content,
                border_style="bright_green",
                padding=(0, 1),
                height=content_height + 2,
                title="[bold red]◢[/bold red][bold yellow]MATRIX RAIN ENABLED - Post Quantum Lattice FHE System[/bold yellow][bold red]◣[/bold red]",
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

    def _render_with_matrix_overlay(
        self, ascii_content: Text, width: int, height: int
    ) -> Text:
        """Render matrix background with ASCII content overlaid"""
        # Get current matrix framebuffer
        framebuffer = self.matrix_rain.get_framebuffer()

        # Convert ASCII to lines for overlay logic
        ascii_lines = str(ascii_content).strip().split("\n")
        ascii_width = max(len(line) for line in ascii_lines) if ascii_lines else 0

        # Create final content
        matrix_content = Text()

        for y in range(height):
            line_text = Text()

            # Calculate ASCII positioning (centered)
            ascii_start_col = (width - ascii_width) // 2

            # Determine if this row has ASCII content
            ascii_line_idx = -1
            if 0 < y < len(ascii_lines) + 1:  # Skip first empty line
                ascii_line_idx = y - 1

            for x in range(width):
                char = " "
                style = "dim green"

                # Check if we should place ASCII content here
                has_ascii = False
                if 0 <= ascii_line_idx < len(ascii_lines):
                    ascii_line = ascii_lines[ascii_line_idx]
                    if ascii_start_col <= x < ascii_start_col + len(ascii_line):
                        ascii_char = ascii_line[x - ascii_start_col]
                        if ascii_char != " ":
                            char = ascii_char
                            style = "bold green"
                            has_ascii = True

                # If no ASCII content, use matrix rain
                if not has_ascii and y < len(framebuffer) and x < len(framebuffer[0]):
                    char, style = framebuffer[y][x]

                line_text.append(char, style=style)

            matrix_content.append(line_text)
            if y < height - 1:  # Don't add newline after last row
                matrix_content.append("\n")

        return matrix_content

    def toggle_subtitle(self) -> None:
        """Toggle subtitle visibility"""
        self.show_subtitle = not self.show_subtitle

    def watch_scrolling_code(self, scrolling_enabled: bool) -> None:
        """React to scrolling code toggle"""
        # TODO: Implement scrolling code effect
        self.refresh()


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
