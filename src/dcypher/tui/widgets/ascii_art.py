"""
ASCII Art Banner Widget
Cyberpunk-inspired banner with @repligate aesthetics
"""

import random
import time
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

        # Timing control for consistent 2 FPS updates (default)
        self.last_update_time = 0
        self.update_interval = 0.5  # 0.5 seconds = 2 FPS default

        # Hex chunk dimensions that make sense for crypto/hex work
        self.chunk_sizes = [2, 4, 8]  # bytes, words, dwords

        # Column chunks - each chunk spans multiple columns
        self.column_chunks = []
        # Grid to track fade states: 0=empty, 1=white/head, 2+=fading trail
        self.grid = []
        # Character grid to store what character is at each position
        self.char_grid = []
        # Z-order grid to track which chunk is on top at each position
        self.z_order_grid = []
        # Glitch grid to track red glitch cells: 0=normal, 1-N=glitch fade levels
        self.glitch_grid = []
        # Maximum fade states (determines tail length)
        self.max_fade_states = 12
        # Maximum glitch fade states (how long glitch lasts)
        self.max_glitch_states = 8
        self.reset_grid()

    def reset_grid(self):
        """Initialize/reset the grid and column chunks"""
        self.column_chunks = []
        self.grid = []
        self.char_grid = []
        self.z_order_grid = []
        self.glitch_grid = []

        # Create more hex chunks that can overlap - much denser
        num_chunks = self.width // 2  # Create way more chunks than width allows

        for _ in range(num_chunks):
            # 50/50 chance: vertical chunks (up/down) or horizontal chunks (left/right)
            if random.random() < 0.5:
                # Vertical chunks - move up/down, have width
                direction = random.choice(["up", "down"])
                chunk_width = random.choice(self.chunk_sizes)
                chunk_height = 1

                # Random x position for vertical chunks
                x_start = random.randint(0, max(0, self.width - chunk_width))

                if direction == "up":
                    # 50/50 chance: start from bottom or random position
                    if random.random() < 0.5:
                        start_y = self.height - 1  # Bottom spawn
                    else:
                        start_y = random.randint(0, self.height - 1)  # Random position
                else:  # direction == "down"
                    # 50/50 chance: start from top or random position
                    if random.random() < 0.5:
                        start_y = 0  # Top spawn
                    else:
                        start_y = random.randint(0, self.height - 1)  # Random position

                start_x = x_start
                hex_value = self._generate_hex_string(chunk_width)

            else:
                # Horizontal chunks - move left/right, have height
                direction = random.choice(["left", "right"])
                chunk_width = 1
                chunk_height = random.choice(self.chunk_sizes)

                # Random y position for horizontal chunks
                start_y = random.randint(0, max(0, self.height - chunk_height))

                if direction == "left":
                    # 50/50 chance: start from right edge or random position
                    if random.random() < 0.5:
                        start_x = self.width - 1  # Right edge spawn
                    else:
                        start_x = random.randint(0, self.width - 1)  # Random position
                else:  # direction == "right"
                    # 50/50 chance: start from left edge or random position
                    if random.random() < 0.5:
                        start_x = 0  # Left edge spawn
                    else:
                        start_x = random.randint(0, self.width - 1)  # Random position

                # Generate vertical stack of hex characters
                hex_value = "".join(
                    random.choice(self.hex_chars) for _ in range(chunk_height)
                )

            chunk = {
                "x_start": start_x,
                "width": chunk_width,
                "height": chunk_height,
                "y": start_y,
                "last_y": start_y,
                "last_x": start_x,
                "direction": direction,
                "z_order": random.randint(1, 100),  # Random z-order for layering
                "hex_value": hex_value,
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
            z_row = []
            glitch_row = []
            for x in range(self.width):
                row.append(0)  # Empty state
                char_row.append(" ")  # Empty char
                z_row.append(0)  # No z-order
                glitch_row.append(0)  # No glitch
            self.grid.append(row)
            self.char_grid.append(char_row)
            self.z_order_grid.append(z_row)
            self.glitch_grid.append(glitch_row)

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
        """Update matrix rain animation - call this each frame with 1 FPS timing control"""
        if not self.enabled:
            return

        # Timing control: only update every 1 second
        current_time = time.time()
        if current_time - self.last_update_time < self.update_interval:
            return

        self.last_update_time = current_time

        # First, age all existing characters (fade them) and handle glitch cells
        active_cells = []  # Track active cells for glitch selection
        for y in range(self.height):
            for x in range(self.width):
                if self.grid[y][x] > 0:
                    self.grid[y][x] += 1
                    # Track active cells for potential glitching
                    active_cells.append((y, x))
                    # Remove characters that have faded completely
                    if self.grid[y][x] > self.max_fade_states:
                        self.grid[y][x] = 0
                        self.char_grid[y][x] = " "
                        self.z_order_grid[y][x] = 0
                        self.glitch_grid[y][x] = 0  # Reset glitch state

                # Handle glitch cells
                if self.glitch_grid[y][x] > 0:
                    # Cycle through random characters in glitch cells
                    self.char_grid[y][x] = random.choice(self.hex_chars)
                    self.glitch_grid[y][x] += 1
                    # Remove glitch when it has faded completely
                    if self.glitch_grid[y][x] > self.max_glitch_states:
                        self.glitch_grid[y][x] = 0
                        # If the underlying cell has also faded, clear it
                        if self.grid[y][x] == 0:
                            self.char_grid[y][x] = " "
                            self.z_order_grid[y][x] = 0

        # Randomly select 1% of active cells to become glitch cells
        if active_cells:
            num_glitch = max(1, int(len(active_cells) * 0.01))  # At least 1 glitch
            glitch_candidates = [
                (y, x)
                for (y, x) in active_cells
                if self.glitch_grid[y][x] == 0  # Only non-glitch cells
            ]
            if glitch_candidates:
                new_glitch_cells = random.sample(
                    glitch_candidates, min(num_glitch, len(glitch_candidates))
                )
                for y, x in new_glitch_cells:
                    self.glitch_grid[y][x] = 1  # Start glitch sequence

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

                        # Reset direction and position
                        # 50/50 chance: vertical chunks (up/down) or horizontal chunks (left/right)
                        if random.random() < 0.5:
                            # Vertical chunks - move up/down, have width
                            chunk["direction"] = random.choice(["up", "down"])
                            chunk["width"] = random.choice(self.chunk_sizes)
                            chunk["height"] = 1
                            chunk["z_order"] = random.randint(1, 100)

                            # Random x position for vertical chunks
                            chunk["x_start"] = random.randint(
                                0, max(0, self.width - chunk["width"])
                            )

                            if chunk["direction"] == "up":
                                # 50/50 chance: spawn from bottom or random position
                                if random.random() < 0.5:
                                    chunk["y"] = self.height - 1
                                else:
                                    chunk["y"] = random.randint(0, self.height - 1)
                            else:  # direction == "down"
                                # 50/50 chance: spawn from top or random position
                                if random.random() < 0.5:
                                    chunk["y"] = 0
                                else:
                                    chunk["y"] = random.randint(0, self.height - 1)

                            chunk["hex_value"] = self._generate_hex_string(
                                chunk["width"]
                            )
                        else:
                            # Horizontal chunks - move left/right, have height
                            chunk["direction"] = random.choice(["left", "right"])
                            chunk["width"] = 1
                            chunk["height"] = random.choice(self.chunk_sizes)
                            chunk["z_order"] = random.randint(1, 100)

                            # Random y position for horizontal chunks
                            chunk["y"] = random.randint(
                                0, max(0, self.height - chunk["height"])
                            )

                            if chunk["direction"] == "left":
                                # 50/50 chance: spawn from right edge or random position
                                if random.random() < 0.5:
                                    chunk["x_start"] = self.width - 1
                                else:
                                    chunk["x_start"] = random.randint(0, self.width - 1)
                            else:  # direction == "right"
                                # 50/50 chance: spawn from left edge or random position
                                if random.random() < 0.5:
                                    chunk["x_start"] = 0
                                else:
                                    chunk["x_start"] = random.randint(0, self.width - 1)

                            chunk["hex_value"] = "".join(
                                random.choice(self.hex_chars)
                                for _ in range(chunk["height"])
                            )

                        chunk["last_y"] = chunk["y"]
                        chunk["last_x"] = chunk["x_start"]
                        chunk["speed_counter"] = 0
                        chunk["tail_length"] = random.randint(4, 12)
            else:
                # Handle speed timing for active chunks
                chunk["speed_counter"] += 1

                # While staying in same position, keep changing hex value (processing effect)
                if chunk["speed_counter"] < chunk["speed"]:
                    # Still in same position - keep changing characters
                    if chunk["direction"] in ["up", "down"]:
                        # Vertical chunks - generate horizontal hex string
                        chunk["hex_value"] = self._generate_hex_string(chunk["width"])
                    else:
                        # Horizontal chunks - generate vertical hex string
                        chunk["hex_value"] = "".join(
                            random.choice(self.hex_chars)
                            for _ in range(chunk["height"])
                        )

                if chunk["speed_counter"] >= chunk["speed"]:
                    chunk["speed_counter"] = 0

                    # Place current chunk characters (frozen from last change) with z-ordering
                    if chunk["direction"] in ["up", "down"]:
                        # Vertical chunks - place horizontally
                        if 0 <= chunk["y"] < self.height:
                            for i, char in enumerate(chunk["hex_value"]):
                                x_pos = chunk["x_start"] + i
                                if 0 <= x_pos < self.width:
                                    # Only place if higher z-order or empty
                                    if (
                                        self.grid[chunk["y"]][x_pos] == 0
                                        or chunk["z_order"]
                                        > self.z_order_grid[chunk["y"]][x_pos]
                                    ):
                                        self.grid[chunk["y"]][x_pos] = (
                                            1  # White/head state
                                        )
                                        self.char_grid[chunk["y"]][x_pos] = char
                                        self.z_order_grid[chunk["y"]][x_pos] = chunk[
                                            "z_order"
                                        ]
                    else:
                        # Horizontal chunks - place vertically
                        if 0 <= chunk["x_start"] < self.width:
                            for i, char in enumerate(chunk["hex_value"]):
                                y_pos = chunk["y"] + i
                                if 0 <= y_pos < self.height:
                                    # Only place if higher z-order or empty
                                    if (
                                        self.grid[y_pos][chunk["x_start"]] == 0
                                        or chunk["z_order"]
                                        > self.z_order_grid[y_pos][chunk["x_start"]]
                                    ):
                                        self.grid[y_pos][chunk["x_start"]] = (
                                            1  # White/head state
                                        )
                                        self.char_grid[y_pos][chunk["x_start"]] = char
                                        self.z_order_grid[y_pos][chunk["x_start"]] = (
                                            chunk["z_order"]
                                        )

                    # Move chunk based on direction
                    chunk["last_y"] = chunk["y"]
                    chunk["last_x"] = chunk["x_start"]
                    if chunk["direction"] == "up":
                        chunk["y"] -= 1
                    elif chunk["direction"] == "down":
                        chunk["y"] += 1
                    elif chunk["direction"] == "left":
                        chunk["x_start"] -= 1
                    else:  # direction == "right"
                        chunk["x_start"] += 1

                    # Generate new hex value for next position
                    if chunk["direction"] in ["up", "down"]:
                        # Vertical chunks - generate horizontal hex string
                        chunk["hex_value"] = self._generate_hex_string(chunk["width"])
                    else:
                        # Horizontal chunks - generate vertical hex string
                        chunk["hex_value"] = "".join(
                            random.choice(self.hex_chars)
                            for _ in range(chunk["height"])
                        )

                    # Reset chunk when it goes off screen
                    off_screen = (
                        (chunk["direction"] == "up" and chunk["y"] < -1)
                        or (chunk["direction"] == "down" and chunk["y"] > self.height)
                        or (chunk["direction"] == "left" and chunk["x_start"] < -1)
                        or (
                            chunk["direction"] == "right"
                            and chunk["x_start"] > self.width
                        )
                    )

                    if off_screen:
                        chunk["active"] = False
                        chunk["spawn_cooldown"] = random.randint(
                            5, 25
                        )  # Longer cooldown since spawn rate is reduced
                        chunk["speed"] = random.randint(1, 4)  # Wide speed range
                        # Reset position for next spawn
                        if chunk["direction"] in ["up", "down"]:
                            chunk["last_y"] = (
                                self.height - 1 if chunk["direction"] == "up" else 0
                            )
                        else:  # left or right
                            chunk["last_x"] = (
                                self.width - 1 if chunk["direction"] == "left" else 0
                            )
                            chunk["last_y"] = chunk["y"]
                else:
                    # Still in same position - place the changing characters with z-ordering
                    if chunk["direction"] in ["up", "down"]:
                        # Vertical chunks - place horizontally
                        if 0 <= chunk["y"] < self.height:
                            for i, char in enumerate(chunk["hex_value"]):
                                x_pos = chunk["x_start"] + i
                                if 0 <= x_pos < self.width:
                                    # Only place if higher z-order or empty
                                    if (
                                        self.grid[chunk["y"]][x_pos] == 0
                                        or chunk["z_order"]
                                        > self.z_order_grid[chunk["y"]][x_pos]
                                    ):
                                        self.grid[chunk["y"]][x_pos] = (
                                            1  # White/head state
                                        )
                                        self.char_grid[chunk["y"]][x_pos] = char
                                        self.z_order_grid[chunk["y"]][x_pos] = chunk[
                                            "z_order"
                                        ]
                    else:
                        # Horizontal chunks - place vertically
                        if 0 <= chunk["x_start"] < self.width:
                            for i, char in enumerate(chunk["hex_value"]):
                                y_pos = chunk["y"] + i
                                if 0 <= y_pos < self.height:
                                    # Only place if higher z-order or empty
                                    if (
                                        self.grid[y_pos][chunk["x_start"]] == 0
                                        or chunk["z_order"]
                                        > self.z_order_grid[y_pos][chunk["x_start"]]
                                    ):
                                        self.grid[y_pos][chunk["x_start"]] = (
                                            1  # White/head state
                                        )
                                        self.char_grid[y_pos][chunk["x_start"]] = char
                                        self.z_order_grid[y_pos][chunk["x_start"]] = (
                                            chunk["z_order"]
                                        )

    def get_framebuffer(self):
        """Generate framebuffer with current matrix rain state"""
        # Define precise hex colors for Matrix rain effect
        white = Color.parse("#FFFFFF")  # Pure white head
        matrix_green = Color.parse("#00FF41")  # Classic Matrix green
        dim_matrix_green = Color.parse("#00AA2B")  # Dimmed Matrix green
        dark_green = Color.parse("#004400")  # Very dark green
        black = Color.parse("#333333")  # Pure black

        # Glitch colors - cyan spectrum
        bright_cyan = Color.parse("#00FFFF")  # Bright cyan
        dim_cyan = Color.parse("#00AAAA")  # Dimmed cyan
        dark_cyan = Color.parse("#004444")  # Very dark cyan

        # Create the 50/50 white/matrix green blend
        white_green_blend = white.blend(matrix_green, 0.5)

        # Create the 50/50 dark green/black blend for final fade
        dark_green_black_blend = dark_green.blend(black, 0.75)

        framebuffer = []
        for y in range(self.height):
            row = []
            for x in range(self.width):
                # Check if this cell is in glitch state
                if self.glitch_grid[y][x] > 0:
                    # Handle glitch cells (red spectrum)
                    glitch_level = self.glitch_grid[y][x]
                    glitch_progress = (
                        glitch_level / self.max_glitch_states
                    )  # 0.0 to 1.0

                    if glitch_progress <= 0.3:  # First 30% - bright cyan
                        row.append((self.char_grid[y][x], bright_cyan.hex))
                    elif glitch_progress <= 0.6:  # Next 30% - dimmed cyan
                        row.append((self.char_grid[y][x], dim_cyan.hex))
                    else:  # Final 40% - fade to black
                        # Fade from dark cyan to black
                        black_fade_progress = (
                            glitch_progress - 0.6
                        ) / 0.4  # 0.0 to 1.0
                        color = dark_cyan.blend(black, black_fade_progress)
                        row.append((self.char_grid[y][x], color.hex))
                elif self.grid[y][x] == 0:
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

    def increase_framerate(self) -> None:
        """Increase matrix rain framerate (decrease update interval)"""
        if not self.matrix_rain.enabled:
            return

        # Get current FPS as integer
        current_fps = round(1.0 / self.matrix_rain.update_interval)

        # Increment by 1 FPS, maximum 10 FPS
        new_fps = min(10, current_fps + 1)
        self.matrix_rain.update_interval = 1.0 / new_fps

        # Show current FPS
        self.notify(f"Matrix FPS: {new_fps}", timeout=1.0)

    def decrease_framerate(self) -> None:
        """Decrease matrix rain framerate (increase update interval)"""
        if not self.matrix_rain.enabled:
            return

        # Get current FPS as integer
        current_fps = round(1.0 / self.matrix_rain.update_interval)

        # Decrement by 1 FPS, minimum 1 FPS (every 1 second)
        new_fps = max(1, current_fps - 1)
        self.matrix_rain.update_interval = 1.0 / new_fps

        # Show current FPS
        self.notify(f"Matrix FPS: {new_fps}", timeout=1.0)

    def watch_matrix_background(self, matrix_enabled: bool) -> None:
        """React to matrix background toggle"""
        if matrix_enabled:
            # Start matrix animation at 2 frames per second (default)
            self.auto_refresh = 0.5
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
