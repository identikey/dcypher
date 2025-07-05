"""
ASCII Art Banner Widget
Cyberpunk-inspired banner with @repligate aesthetics
"""

import random
from textual.widget import Widget
from textual.reactive import reactive
from textual.app import RenderResult
from rich.console import Console, ConsoleOptions
from rich.text import Text
from rich.align import Align
from rich.panel import Panel


class MatrixRain:
    """
    Matrix rain effect controller implementing proper column-based drops
    """

    def __init__(self, width: int = 80, height: int = 20):
        self.width = width
        self.height = height
        self.enabled = False
        self.matrix_chars = list("0123456789ABCDEF01")  # Hex + binary

        # Column-based drops - each column can have multiple active drops
        self.columns = []
        self.reset_columns()

    def reset_columns(self):
        """Initialize/reset all columns"""
        self.columns = []
        for x in range(self.width):
            self.columns.append(
                {
                    "drops": [],  # List of active drops in this column
                    "spawn_cooldown": 0,
                }
            )

    def toggle_rain(self):
        """Toggle matrix rain effect on/off"""
        self.enabled = not self.enabled
        if not self.enabled:
            # Clear all drops when disabled
            self.reset_columns()

    def update(self):
        """Update matrix rain animation - call this each frame"""
        if not self.enabled:
            return

        # Update existing drops
        for col_idx, column in enumerate(self.columns):
            # Update each drop in this column
            for drop in column["drops"][
                :
            ]:  # Copy list to avoid modification during iteration
                drop["y"] += drop["speed"]
                drop["age"] += 1

                # Remove drops that have fallen off screen or aged out
                if drop["y"] > self.height + drop["length"]:
                    column["drops"].remove(drop)

            # Handle spawn cooldown
            if column["spawn_cooldown"] > 0:
                column["spawn_cooldown"] -= 1

            # Spawn new drops randomly
            if column["spawn_cooldown"] <= 0 and random.random() < 0.05:  # 5% chance
                new_drop = {
                    "y": 0,
                    "length": random.randint(3, 12),
                    "speed": random.uniform(0.5, 2.0),
                    "age": 0,
                    "chars": [
                        random.choice(self.matrix_chars)
                        for _ in range(random.randint(3, 12))
                    ],
                }
                column["drops"].append(new_drop)
                column["spawn_cooldown"] = random.randint(
                    5, 30
                )  # Cooldown before next spawn

    def get_framebuffer(self):
        """Generate framebuffer with current matrix rain state"""
        framebuffer = []
        for y in range(self.height):
            row = []
            for x in range(self.width):
                row.append((" ", "dim green"))  # Default empty cell
            framebuffer.append(row)

        if not self.enabled:
            return framebuffer

        # Draw all active drops
        for col_idx, column in enumerate(self.columns):
            for drop in column["drops"]:
                # Draw each character in the drop
                for i, char in enumerate(drop["chars"]):
                    char_y = int(drop["y"]) + i
                    if 0 <= char_y < self.height:
                        # Calculate brightness based on position in drop
                        if i == 0:  # Head of drop
                            style = "bright_white"
                        elif i == 1:  # Just behind head
                            style = "bright_green"
                        elif i < len(drop["chars"]) // 2:  # Middle
                            style = "green"
                        else:  # Tail
                            style = "dim green"

                        framebuffer[char_y][col_idx] = (char, style)

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
            self.matrix_rain.reset_columns()

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
