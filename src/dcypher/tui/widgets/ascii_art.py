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
        # Split ASCII art into lines
        ascii_lines = self.ascii_art.strip().split("\n")

        # Create ASCII art section with blank lines before and after
        content_lines = []

        # Add blank line before content
        content_lines.append("")

        # Add ASCII art lines
        content_lines.extend(ascii_lines)

        # Add subtitle if enabled
        if self.show_subtitle:
            content_lines.append(self.SUBTITLE)

        # Add blank line after content
        content_lines.append("")

        # Join with newlines and strip trailing whitespace
        content_string = "\n".join(content_lines).rstrip()

        # Calculate exact content height (number of lines)
        content_height = len(content_lines)

        # Create Text object with the final content
        ascii_text = Text(content_string)

        # Apply styling to ASCII lines
        for i, line in enumerate(ascii_lines):
            start_pos = content_string.find(line)
            if start_pos != -1:
                ascii_text.stylize("bold green", start_pos, start_pos + len(line))

        # Apply styling to subtitle if enabled
        if self.show_subtitle:
            subtitle_start = content_string.find(self.SUBTITLE)
            if subtitle_start != -1:
                # Style different parts of the subtitle
                subtitle_end = subtitle_start + len(self.SUBTITLE)
                encryption_end = subtitle_start + len("QUANTUM-RESISTANT ENCRYPTION")
                separator_end = encryption_end + len(" • ")

                ascii_text.stylize("dim cyan", subtitle_start, encryption_end)
                ascii_text.stylize("bold white", encryption_end, separator_end)
                ascii_text.stylize("bold yellow", separator_end, subtitle_end)

        # Center the content using Rich.Align
        centered_content = Align.center(ascii_text)

        # If matrix background is enabled, render with matrix rain
        if self.matrix_background:
            # Initialize matrix rain with proper dimensions
            terminal_width = 120  # Standard terminal width
            # Calculate exact height based on our controlled spacing
            terminal_height = (
                1 + len(ascii_lines) + 1
            )  # blank line + ASCII lines + blank line
            if self.show_subtitle:
                terminal_height += 1  # subtitle line

            if hasattr(self, "matrix_rain") and self.matrix_rain.columns:
                # For matrix background, we need to handle centering differently
                # Render matrix background with ASCII overlay
                matrix_content = self._render_with_matrix_background(
                    ascii_text, terminal_width, terminal_height
                )
                centered_matrix_content = Align.center(matrix_content)
            else:
                # Fallback to simple ASCII
                centered_matrix_content = centered_content

            # Create panel with matrix content (minimal padding and exact height)
            panel = Panel(
                centered_matrix_content,
                border_style="bright_green",
                padding=(0, 1),  # Minimal horizontal padding for proper centering
                height=content_height + 2,  # Content height + 2 for borders only
                title="[bold red]◢[/bold red][bold yellow]Post Quantum Lattice FHE System[/bold yellow][bold red]◣[/bold red]",
                title_align="center",
            )
        else:
            # Create panel with centered content (minimal padding and exact height)
            panel = Panel(
                centered_content,
                border_style="bright_green",
                padding=(0, 1),  # Minimal horizontal padding for proper centering
                height=content_height + 2,  # Content height + 2 for borders only
                title="[bold red]◢[/bold red][bold yellow]Post Quantum Lattice FHE System[/bold yellow][bold red]◣[/bold red]",
                title_align="center",
            )

        return panel

    def _render_with_matrix_background(
        self, ascii_content: Text, width: int, height: int
    ) -> Text:
        """Render ASCII content with matrix rain background"""
        # Split ASCII content into lines for overlay
        ascii_lines = str(ascii_content).split("\n")
        ascii_width = max(len(line) for line in ascii_lines) if ascii_lines else 0

        # Initialize matrix rain columns if needed
        if not hasattr(self, "matrix_rain") or not self.matrix_rain.columns:
            self.matrix_rain._initialize_columns(width, height)

        # Create matrix background with ASCII overlay
        matrix_content = Text()

        for y in range(height):
            line_text = Text()

            # Calculate ASCII positioning (centered horizontally)
            ascii_start_col = (width - ascii_width) // 2

            # Map y position to content line based on our controlled spacing
            # Structure: blank line + ASCII lines + subtitle + blank line
            ascii_line_idx = -1
            if y == 0:
                ascii_line_idx = -1  # First blank line
            elif 1 <= y <= len(self.ascii_art.strip().split("\n")):
                ascii_line_idx = y - 1  # ASCII art lines (offset by 1 for blank line)
            elif (
                y == len(self.ascii_art.strip().split("\n")) + 1 and self.show_subtitle
            ):
                ascii_line_idx = len(
                    self.ascii_art.strip().split("\n")
                )  # Subtitle line (special marker)
            else:
                ascii_line_idx = -1  # Other empty lines (including final blank line)

            # Build line character by character
            for x in range(width):
                char = " "
                style = "dim green"

                # Check if we should place ASCII content here
                if 0 <= ascii_line_idx < len(self.ascii_art.strip().split("\n")):
                    # ASCII art line
                    ascii_art_lines = self.ascii_art.strip().split("\n")
                    ascii_line = ascii_art_lines[ascii_line_idx]
                    if ascii_start_col <= x < ascii_start_col + len(ascii_line):
                        ascii_char = ascii_line[x - ascii_start_col]
                        if ascii_char != " ":
                            char = ascii_char
                            style = "bold green"
                        else:
                            # ASCII has space, use matrix rain
                            if self.matrix_rain.columns and x < len(
                                self.matrix_rain.columns
                            ):
                                char, style = self.matrix_rain.get_matrix_char_at(x, y)
                                if style != "dim green":
                                    style = "dim green"  # Dimmer in ASCII space
                elif (
                    ascii_line_idx == len(self.ascii_art.strip().split("\n"))
                    and self.show_subtitle
                ):
                    # Subtitle line
                    subtitle_line = (
                        "QUANTUM-RESISTANT ENCRYPTION • REPLICANT TERMINAL v2.1.0"
                    )
                    subtitle_start_col = (width - len(subtitle_line)) // 2
                    if (
                        subtitle_start_col
                        <= x
                        < subtitle_start_col + len(subtitle_line)
                    ):
                        subtitle_char = subtitle_line[x - subtitle_start_col]
                        if subtitle_char != " ":
                            char = subtitle_char
                            # Apply different styles to different parts of subtitle
                            char_pos = x - subtitle_start_col
                            if char_pos < len("QUANTUM-RESISTANT ENCRYPTION"):
                                style = "dim cyan"
                            elif char_pos < len("QUANTUM-RESISTANT ENCRYPTION • "):
                                style = "bold white"
                            else:
                                style = "bold yellow"
                        else:
                            # Subtitle has space, use matrix rain
                            if self.matrix_rain.columns and x < len(
                                self.matrix_rain.columns
                            ):
                                char, style = self.matrix_rain.get_matrix_char_at(x, y)
                                if style != "dim green":
                                    style = "dim green"  # Dimmer in subtitle space
                else:
                    # Not in ASCII area, use matrix rain
                    if self.matrix_rain.columns and x < len(self.matrix_rain.columns):
                        char, style = self.matrix_rain.get_matrix_char_at(x, y)

                line_text.append(char, style=style)

            matrix_content.append(line_text)
            matrix_content.append("\n")

        return matrix_content

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
            # Initialize matrix rain with proper dimensions
            self.matrix_rain.max_columns = 120  # Standard terminal width
            self.matrix_rain.max_rows = 20  # Adequate height for banner
            self.matrix_rain.enabled = True

            # Start the animation timer if not already running (1 second intervals)
            if not hasattr(self, "_matrix_timer_started"):
                self.set_interval(1.0, self.update_matrix_background)
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
            for column in self.columns:
                column.head_position = -1
                column.ticks_left = 0
                column.spawn_delay = 0
                for cell in column.cells:
                    cell.char = ""
                    cell.active_for = 0

    def get_matrix_char_at(self, x: int, y: int) -> tuple[str, str]:
        """Get matrix character and style at specific position for background rendering"""
        if (
            not self.enabled
            or x >= len(self.columns)
            or y >= len(self.columns[0].cells)
        ):
            return " ", "dim green"

        cell = self.columns[x].cells[y]
        if cell.active_for > 0 and cell.char:
            return cell.char, cell.color
        else:
            return " ", "dim green"


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
