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


class ASCIIBanner(Widget):
    """
    ASCII art banner for dCypher TUI
    Features cyberpunk styling with matrix-style effects
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

    # Matrix-style characters for animation
    MATRIX_CHARS = "01アイウエオカキクケコサシスセソタチツテトナニヌネノハヒフヘホマミムメモヤユヨラリルレロワヲン"

    def __init__(self, compact=False, **kwargs):
        super().__init__(**kwargs)
        self.compact = compact
        self.ascii_art = self.DCYPHER_COMPACT if compact else self.DCYPHER_ASCII
        self.matrix_rain = MatrixRain()
        self._matrix_timer_started = False

    def render(self) -> RenderResult:
        """Render the ASCII banner with optional matrix rain background"""
        # Create the main ASCII art and subtitle content
        content_lines = []

        # Split ASCII art into lines
        ascii_lines = self.ascii_art.strip().split("\n")
        content_lines.extend(ascii_lines)

        # Add subtitle if enabled
        if self.show_subtitle:
            content_lines.append("")  # Empty line separator
            content_lines.append(self.SUBTITLE)

        # Determine panel dimensions to fill the entire container
        ascii_width = max(len(line) for line in ascii_lines)

        # Use a much larger width to ensure it fills the container
        panel_width = max(ascii_width + 80, 160)  # Much wider to fill container

        # Fixed height regardless of matrix background state
        panel_height = len(ascii_lines) + 6  # More height for better matrix coverage
        if self.show_subtitle:
            panel_height += 3  # Space for subtitle

        # Create the final rendered content
        final_content = Text()

        # Always add consistent top padding
        final_content.append("\n")

        # Render content with or without matrix background
        for y in range(panel_height):
            line_text = Text()

            # Determine if this line should have ASCII content
            ascii_line = ""
            ascii_start_col = (panel_width - ascii_width) // 2  # Center ASCII art

            # Check if we're in the ASCII art region
            ascii_line_idx = y - 2  # Account for more top padding for better centering
            if 0 <= ascii_line_idx < len(ascii_lines):
                ascii_line = ascii_lines[ascii_line_idx]
            elif ascii_line_idx == len(ascii_lines) + 2 and self.show_subtitle:
                ascii_line = self.SUBTITLE
                ascii_start_col = (
                    panel_width - len(self.SUBTITLE)
                ) // 2  # Center subtitle

            # Build the line character by character
            for x in range(panel_width):
                char = " "
                style = "dim green"

                # Check if we should place ASCII content here
                if ascii_line and ascii_start_col <= x < ascii_start_col + len(
                    ascii_line
                ):
                    ascii_char = ascii_line[x - ascii_start_col]
                    if ascii_char != " ":
                        # Use ASCII character with bold styling
                        if ascii_line_idx < len(ascii_lines):
                            char = ascii_char
                            style = "bold green"  # ASCII art
                        else:  # Subtitle
                            char = ascii_char
                            style = "bold cyan"  # Subtitle
                    else:
                        # ASCII art has space, potentially use matrix rain
                        if self.matrix_background and random.random() < 0.05:
                            char = random.choice(self.MATRIX_CHARS)
                            style = "dim green"
                        else:
                            char = " "
                else:
                    # Not in ASCII area, use matrix rain if enabled
                    if (
                        self.matrix_background and random.random() < 0.18
                    ):  # Increased probability
                        char = random.choice(self.MATRIX_CHARS)
                        style = "dim green"
                    else:
                        char = " "

                line_text.append(char, style=style)

            final_content.append(line_text)
            final_content.append("\n")

        # Always add consistent bottom padding
        final_content.append("\n")

        # Apply subtitle styling
        if self.show_subtitle:
            full_text = str(final_content)
            if self.SUBTITLE in full_text:
                subtitle_start = full_text.find(self.SUBTITLE)
                if subtitle_start != -1:
                    subtitle_end = subtitle_start + len(self.SUBTITLE)
                    final_content.stylize(
                        "dim",
                        subtitle_start,
                        subtitle_start + len("QUANTUM-RESISTANT ENCRYPTION"),
                    )
                    final_content.stylize(
                        "bold yellow",
                        subtitle_start + len("QUANTUM-RESISTANT ENCRYPTION • "),
                        subtitle_end,
                    )

        # Create panel with cyberpunk border and title
        panel = Panel(
            final_content,  # Use final_content directly instead of aligned
            border_style="bright_green",
            padding=(0, 0),  # No padding to let content fill entire area
            title="[bold red]◢[/bold red][bold yellow]Post Quantum Lattice FHE System[/bold yellow][bold red]◣[/bold red]",
            title_align="center",
        )

        return panel

    def on_mount(self) -> None:
        """Start animation timer when mounted"""
        self.set_interval(0.5, self.animate_banner)

    def animate_banner(self) -> None:
        """Animate the banner (subtle effects)"""
        self.animation_frame = (self.animation_frame + 1) % 10
        # Could add matrix rain or other effects here

    def toggle_subtitle(self) -> None:
        """Toggle subtitle visibility"""
        self.show_subtitle = not self.show_subtitle

    def watch_matrix_background(self, matrix_enabled: bool) -> None:
        """React to matrix background toggle"""
        if matrix_enabled:
            # Start matrix rain animation
            self.matrix_rain.enabled = True
            # Start the animation timer if not already running
            if not hasattr(self, "_matrix_timer_started"):
                self.set_interval(0.5, self.update_matrix_background)
                self._matrix_timer_started = True
        else:
            # Stop matrix rain animation
            self.matrix_rain.enabled = False
        self.refresh()

    def update_matrix_background(self) -> None:
        """Update the matrix rain background with proper column-based animation"""
        if self.matrix_background:
            # Update the matrix rain animation state
            if hasattr(self, "matrix_rain"):
                self.matrix_rain.update_rain()
            # Trigger a refresh to update the background
            self.refresh()

    def watch_scrolling_code(self, scrolling_enabled: bool) -> None:
        """React to scrolling code toggle"""
        # TODO: Implement scrolling code effect
        self.refresh()


class MatrixCell:
    """Individual cell in a matrix column"""

    def __init__(self, row: int):
        self.row = row
        self.char = ""
        self.active_for = 0  # How many ticks this cell is active
        self.retain_char = 0  # How many ticks to retain current character
        self.retain_color = 0  # How many ticks to retain current color
        self.color = "dim green"


class MatrixColumn:
    """Column of matrix rain cells following proper matrix rules"""

    def __init__(self, column_index: int, height: int):
        self.column_index = column_index
        self.cells = [MatrixCell(row) for row in range(height)]
        self.head_position = -1  # Position of the head (-1 means no active drop)
        self.trail_length = 0  # Length of the current trail
        self.ticks_left = 0  # Ticks remaining for current animation
        self.speed = 1  # Speed factor (higher = slower)
        self.spawn_delay = 0  # Random delay before next spawn


class MatrixRain(Widget):
    """
    Matrix-style digital rain effect following proper matrix rules
    Based on research from maartenhus.nl and film analysis
    """

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.columns = []
        self.tick_count = 0
        self.enabled = False
        self.max_columns = 80
        self.max_rows = 24

        # Authentic matrix character set
        self.matrix_chars = "アイウエオカキクケコサシスセソタチツテトナニヌネノハヒフヘホマミムメモヤユヨラリルレロワヲン"
        self.matrix_chars += "0123456789"
        self.matrix_chars += "+-*/=<>[]{}()"

        # Matrix rain configuration (following web research)
        self.spawn_rate = 0.15  # 15% chance per tick to spawn new drop
        self.min_trail_length = 5
        self.max_trail_length = 25
        self.min_speed = 1
        self.max_speed = 4

        # Green color variations for trail
        self.green_colors = [
            "bright_green",
            "green",
            "dim green",
            "#00ff00",
            "#00dd00",
            "#00bb00",
            "#009900",
        ]

    def _initialize_columns(self, width: int, height: int):
        """Initialize matrix columns with proper structure"""
        if len(self.columns) != width or (
            self.columns and len(self.columns[0].cells) != height
        ):
            self.columns = [MatrixColumn(i, height) for i in range(width)]
            self.max_columns = width
            self.max_rows = height

    def render(self) -> RenderResult:
        """Render authentic matrix rain effect using column-based approach"""
        if not self.enabled:
            return Text("")

        # This method is used for standalone rendering - for background use,
        # we return empty as the ASCIIBanner handles the matrix background directly
        return Text("")

    def on_mount(self) -> None:
        """Initialize matrix rain with 1 second intervals"""
        self.set_interval(1.0, self.update_rain)  # 1 second per tick as requested

    def update_rain(self) -> None:
        """Update rain animation following authentic matrix rules"""
        if not self.enabled:
            return

        self.tick_count += 1

        # Initialize columns if needed
        self._initialize_columns(self.max_columns, self.max_rows)

        # Update each column following matrix rain rules
        for column in self.columns:
            # Only update column if it should tick based on its speed
            if self.tick_count % column.speed != 0:
                continue

            # Check if animation is complete and potentially spawn new raindrop
            animation_complete = column.ticks_left <= 0

            if animation_complete and column.spawn_delay <= 0:
                if random.random() < self.spawn_rate:
                    # Spawn new raindrop
                    column.trail_length = random.randint(
                        self.min_trail_length, self.max_trail_length
                    )
                    column.head_position = 0
                    column.ticks_left = self.max_rows + column.trail_length
                    column.speed = random.randint(self.min_speed, self.max_speed)
                    column.spawn_delay = random.randint(
                        5, 30
                    )  # Random delay before next spawn
                else:
                    column.spawn_delay = max(0, column.spawn_delay - 1)
            elif not animation_complete:
                # Update active raindrop
                self._update_column_animation(column)
                column.ticks_left -= 1
            else:
                column.spawn_delay = max(0, column.spawn_delay - 1)

    def _update_column_animation(self, column: MatrixColumn) -> None:
        """Update animation for a single column following matrix rules"""
        # Clear all cells first
        for cell in column.cells:
            if cell.active_for > 0:
                cell.active_for -= 1
            else:
                cell.char = ""
                cell.color = "dim green"

        # Set active cells for current raindrop
        for i in range(column.trail_length):
            cell_row = column.head_position - i
            if 0 <= cell_row < len(column.cells):
                cell = column.cells[cell_row]
                cell.active_for = 1

                if i == 0:  # Head of raindrop
                    cell.color = "bright_white"  # Head is always white
                    cell.char = random.choice(self.matrix_chars)
                    cell.retain_char = 0  # Head always changes
                else:  # Trail
                    # Update character if retention timer expired
                    if cell.retain_char <= 0:
                        cell.char = random.choice(self.matrix_chars)
                        cell.retain_char = random.randint(1, 10)
                    else:
                        cell.retain_char -= 1

                    # Update color if retention timer expired
                    if cell.retain_color <= 0:
                        cell.color = random.choice(self.green_colors)
                        cell.retain_color = random.randint(1, 10)
                    else:
                        cell.retain_color -= 1

        # Move head down
        column.head_position += 1

    def toggle_rain(self) -> None:
        """Toggle matrix rain effect on/off"""
        self.enabled = not self.enabled
        if not self.enabled:
            # Clear all columns when disabled
            for col in self.columns:
                col["active"] = False
                col["chars"] = []
                col["positions"] = []
        self.refresh()

    def set_speed(self, speed: float) -> None:
        """Set rain animation speed"""
        self.rain_speed = max(0.05, min(1.0, speed))
        # Update the interval
        self.set_interval(self.rain_speed, self.update_rain)


class CyberpunkBorder(Widget):
    """
    Decorative cyberpunk-style border widget
    Art deco inspired geometric patterns
    """

    BORDER_PATTERNS = {
        "simple": "─│┌┐└┘",
        "double": "═║╔╗╚╝",
        "thick": "━┃┏┓┗┛",
        "art_deco": "▬▌▛▜▙▟",
        "cyber": "▓▒░█▄▀",
    }

    def __init__(self, pattern="cyber", **kwargs):
        super().__init__(**kwargs)
        self.pattern = pattern

    def render(self) -> RenderResult:
        """Render cyberpunk border"""
        chars = self.BORDER_PATTERNS.get(self.pattern, self.BORDER_PATTERNS["cyber"])
        border_text = Text(f"[{chars}] CYBERPUNK BORDER [{chars}]", style="bold cyan")
        return Align.center(border_text)
