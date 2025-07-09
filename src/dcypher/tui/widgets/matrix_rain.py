"""
ASCII Art Banner Widget - OPTIMIZED VERSION
Cyberpunk-inspired banner with @repligate aesthetics
High-performance matrix rain with efficient rendering
"""

import random
import time
from textual.widget import Widget
from textual.reactive import reactive
from textual.app import RenderResult
from textual.color import Color


class MatrixRain:
    """
    OPTIMIZED Matrix rain effect controller implementing hex-chunk-based upward-moving pattern
    Uses hex-meaningful widths (2, 4, 8 characters) for authentic crypto aesthetic

    Performance improvements:
    - Pre-generated hex strings cache
    - Selective grid updates (only active cells)
    - Optimized color calculations with caching
    - Batch operations where possible
    - Reduced function call overhead
    """

    def __init__(self, width: int = 80, height: int = 20):
        self.width = width
        self.height = height
        self.enabled = True

        # Pre-generate hex characters for faster access
        self.hex_chars = "0123456789ABCDEF"
        self.hex_chars_tuple = tuple(
            self.hex_chars
        )  # Tuple is faster than string for random.choice

        # Saturation control (0-100%)
        self.saturation = 75  # Default 75% saturation for matrix rain

        # Timing control for consistent 2 FPS updates (default)
        self.last_update_time = 0
        self.update_interval = 0.5  # 0.5 seconds = 2 FPS default

        # Hex chunk dimensions that make sense for crypto/hex work
        self.chunk_sizes = [2, 4, 8]  # bytes, words, dwords

        # OPTIMIZATION: Pre-generate hex strings cache
        self.hex_string_cache = {}
        self._populate_hex_string_cache()

        # Color cache for z_order based colors
        self.color_cache = {}
        # Pre-computed color objects for common use
        self.white = Color.parse("#FFFFFF")
        self.black = Color.parse("#333333")

        # Column chunks - each chunk spans multiple columns
        self.column_chunks = []

        # OPTIMIZATION: Use flat arrays instead of nested lists where possible
        self.grid = []  # Grid to track fade states: 0=empty, 1=white/head, 2+=fading trail
        self.char_grid = []  # Character grid to store what character is at each position
        self.z_order_grid = []  # Z-order grid to track which chunk is on top at each position
        self.glitch_grid = []  # Glitch grid to track red glitch cells: 0=normal, 1-N=glitch fade levels

        # OPTIMIZATION: Track only active cells to avoid full grid iteration
        self.active_cells = set()  # Set of (y, x) tuples for active cells
        self.glitch_cells = set()  # Set of (y, x) tuples for glitch cells

        # Maximum fade states (determines tail length)
        self.max_fade_states = 12
        # Maximum glitch fade states (how long glitch lasts)
        self.max_glitch_states = 8

        self.reset_grid()

    def _populate_hex_string_cache(self):
        """Pre-generate commonly used hex strings for performance"""
        for width in self.chunk_sizes:
            if width not in self.hex_string_cache:
                self.hex_string_cache[width] = []
                # Generate 100 pre-computed hex strings for each width
                for _ in range(100):
                    hex_str = "".join(
                        random.choice(self.hex_chars_tuple) for _ in range(width)
                    )
                    self.hex_string_cache[width].append(hex_str)

    def reset_grid(self):
        """Initialize/reset the grid and column chunks"""
        self.column_chunks = []
        self.grid = []
        self.char_grid = []
        self.z_order_grid = []
        self.glitch_grid = []
        self.active_cells = set()
        self.glitch_cells = set()

        # Create more hex chunks that can overlap - much denser
        num_chunks = self.width // 2  # Create way more chunks than width allows

        # Calculate aspect ratio to determine sprite direction bias
        aspect_ratio = self.width / max(self.height, 1)  # Avoid division by zero
        vertical_probability = min(0.85, max(0.15, 0.5 + (aspect_ratio - 1.0) * 0.2))

        for _ in range(num_chunks):
            # Aspect-ratio-based chance: bias towards vertical for wide viewports
            if random.random() < vertical_probability:
                # Vertical chunks - move up/down, have width
                direction = random.choice(["up", "down"])
                chunk_width = random.choice(self.chunk_sizes)
                chunk_height = 1

                # Random x position for vertical chunks
                x_start = random.randint(0, max(0, self.width - chunk_width))

                if direction == "up":
                    start_y = (
                        self.height - 1
                        if random.random() < 0.5
                        else random.randint(0, self.height - 1)
                    )
                else:  # direction == "down"
                    start_y = (
                        0
                        if random.random() < 0.5
                        else random.randint(0, self.height - 1)
                    )

                start_x = x_start
                hex_value = self._get_cached_hex_string(chunk_width)

            else:
                # Horizontal chunks - move left/right, have height
                direction = random.choice(["left", "right"])
                chunk_width = 1
                chunk_height = random.choice(self.chunk_sizes)

                # Random y position for horizontal chunks
                start_y = random.randint(0, max(0, self.height - chunk_height))

                if direction == "left":
                    start_x = (
                        self.width - 1
                        if random.random() < 0.5
                        else random.randint(0, self.width - 1)
                    )
                else:  # direction == "right"
                    start_x = (
                        0
                        if random.random() < 0.5
                        else random.randint(0, self.width - 1)
                    )

                # Generate vertical stack of hex characters
                hex_value = "".join(
                    random.choice(self.hex_chars_tuple) for _ in range(chunk_height)
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

        # Initialize empty grid using list comprehension (faster)
        self.grid = [[0 for _ in range(self.width)] for _ in range(self.height)]
        self.char_grid = [[" " for _ in range(self.width)] for _ in range(self.height)]
        self.z_order_grid = [[0 for _ in range(self.width)] for _ in range(self.height)]
        self.glitch_grid = [[0 for _ in range(self.width)] for _ in range(self.height)]

    def _get_cached_hex_string(self, width: int) -> str:
        """Get a pre-generated hex string from cache for better performance"""
        if width in self.hex_string_cache:
            return random.choice(self.hex_string_cache[width])
        else:
            # Fallback for unexpected widths
            return "".join(random.choice(self.hex_chars_tuple) for _ in range(width))

    def _get_chunk_color(self, z_order: int) -> tuple[Color, Color, Color]:
        """Get a consistent 100% saturated vibrant color for a given z_order - OPTIMIZED"""
        if z_order not in self.color_cache:
            # Use z_order as seed for consistent color generation
            random_state = random.getstate()
            random.seed(z_order)

            # Generate random hue with configurable saturation and optimal lightness
            hue = random.randint(0, 360)
            saturation = self.saturation  # Use configurable saturation
            lightness = random.randint(50, 60)  # Optimal lightness for vibrant colors

            # Convert HSL to RGB - optimized version
            h = hue / 360.0
            s = saturation / 100.0
            l = lightness / 100.0

            # Optimized HSL to RGB conversion
            if s == 0:
                r = g = b = l
            else:

                def hue_to_rgb(p, q, t):
                    if t < 0:
                        t += 1
                    if t > 1:
                        t -= 1
                    if t < 1 / 6:
                        return p + (q - p) * 6 * t
                    if t < 1 / 2:
                        return q
                    if t < 2 / 3:
                        return p + (q - p) * (2 / 3 - t) * 6
                    return p

                q = l * (1 + s) if l < 0.5 else l + s - l * s
                p = 2 * l - q
                r = hue_to_rgb(p, q, h + 1 / 3)
                g = hue_to_rgb(p, q, h)
                b = hue_to_rgb(p, q, h - 1 / 3)

            # Convert to 0-255 range and create colors
            r_int = int(r * 255)
            g_int = int(g * 255)
            b_int = int(b * 255)

            # Create color objects using hex format
            base_color = Color.parse(f"#{r_int:02x}{g_int:02x}{b_int:02x}")
            dim_color = Color.parse(
                f"#{int(r_int * 0.7):02x}{int(g_int * 0.7):02x}{int(b_int * 0.7):02x}"
            )
            dark_color = Color.parse(
                f"#{int(r_int * 0.3):02x}{int(g_int * 0.3):02x}{int(b_int * 0.3):02x}"
            )

            self.color_cache[z_order] = (base_color, dim_color, dark_color)

            # Restore random state
            random.setstate(random_state)

        return self.color_cache[z_order]

    def _get_negative_color(self, z_order: int) -> tuple[Color, Color, Color]:
        """Get the negative/complement colors for a given z_order"""
        if z_order == 0:
            # Fallback to cyan if no z_order
            return (
                Color.parse("#00FFFF"),
                Color.parse("#00AAAA"),
                Color.parse("#004444"),
            )

        # Get the original colors
        base_color, dim_color, dark_color = self._get_chunk_color(z_order)

        # Parse original colors to get RGB values
        base_hex = base_color.hex
        r = int(base_hex[1:3], 16)
        g = int(base_hex[3:5], 16)
        b = int(base_hex[5:7], 16)

        # Calculate negative/complement colors (255 - original)
        neg_r = 255 - r
        neg_g = 255 - g
        neg_b = 255 - b

        # Create negative color variations
        neg_base = Color.parse(f"#{neg_r:02x}{neg_g:02x}{neg_b:02x}")
        neg_dim = Color.parse(
            f"#{int(neg_r * 0.7):02x}{int(neg_g * 0.7):02x}{int(neg_b * 0.7):02x}"
        )
        neg_dark = Color.parse(
            f"#{int(neg_r * 0.3):02x}{int(neg_g * 0.3):02x}{int(neg_b * 0.3):02x}"
        )

        return (neg_base, neg_dim, neg_dark)

    def toggle_rain(self):
        """Toggle matrix rain effect on/off"""
        self.enabled = not self.enabled
        if not self.enabled:
            # Clear all when disabled
            self.reset_grid()
            self.color_cache.clear()

    def set_saturation(self, saturation: int):
        """Set saturation level (0-100%)"""
        self.saturation = max(0, min(100, saturation))
        # Clear color cache to force regeneration with new saturation
        self.color_cache.clear()

    def increase_saturation(self):
        """Increase saturation by 10%"""
        self.set_saturation(self.saturation + 10)

    def decrease_saturation(self):
        """Decrease saturation by 10%"""
        self.set_saturation(self.saturation - 10)

    def get_stats(self):
        """Get statistics about matrix rain effect"""
        current_fps = (
            round(1.0 / self.update_interval) if self.update_interval > 0 else 0
        )
        active_chunks = sum(1 for chunk in self.column_chunks if chunk["active"])
        total_chunks = len(self.column_chunks)
        active_cells_count = len(self.active_cells)

        return f"Matrix Rain: {active_chunks}/{total_chunks} chunks | {active_cells_count} active cells | FPS: {current_fps} | Saturation: {self.saturation}%"

    def update(self):
        """OPTIMIZED Update matrix rain animation - selective updates only"""
        if not self.enabled:
            return

        # Timing control: only update every interval
        current_time = time.time()
        if current_time - self.last_update_time < self.update_interval:
            return

        self.last_update_time = current_time

        # OPTIMIZATION: Only process active cells instead of full grid iteration
        cells_to_remove = []
        for y, x in self.active_cells:
            if self.grid[y][x] > 0:
                self.grid[y][x] += 1
                # Remove characters that have faded completely
                if self.grid[y][x] > self.max_fade_states:
                    self.grid[y][x] = 0
                    self.char_grid[y][x] = " "
                    self.z_order_grid[y][x] = 0
                    self.glitch_grid[y][x] = 0  # Reset glitch state
                    cells_to_remove.append((y, x))

        # Remove faded cells from active set
        for cell in cells_to_remove:
            self.active_cells.discard(cell)

        # OPTIMIZATION: Handle glitch cells separately
        glitch_cells_to_remove = []
        for y, x in self.glitch_cells:
            if self.glitch_grid[y][x] > 0:
                # Cycle through random characters in glitch cells
                self.char_grid[y][x] = random.choice(self.hex_chars_tuple)
                self.glitch_grid[y][x] += 1
                # Remove glitch when it has faded completely
                if self.glitch_grid[y][x] > self.max_glitch_states:
                    self.glitch_grid[y][x] = 0
                    glitch_cells_to_remove.append((y, x))
                    # If the underlying cell has also faded, clear it
                    if self.grid[y][x] == 0:
                        self.char_grid[y][x] = " "
                        self.z_order_grid[y][x] = 0

        # Remove expired glitch cells
        for cell in glitch_cells_to_remove:
            self.glitch_cells.discard(cell)

        # OPTIMIZATION: Randomly select 1% of active cells to become glitch cells
        if self.active_cells:
            num_glitch = max(1, int(len(self.active_cells) * 0.01))
            glitch_candidates = list(self.active_cells - self.glitch_cells)
            if glitch_candidates:
                new_glitch_cells = random.sample(
                    glitch_candidates, min(num_glitch, len(glitch_candidates))
                )
                for y, x in new_glitch_cells:
                    self.glitch_grid[y][x] = 1  # Start glitch sequence
                    self.glitch_cells.add((y, x))

        # Now update each hex chunk
        for chunk in self.column_chunks:
            if not chunk["active"]:
                if chunk["spawn_cooldown"] > 0:
                    chunk["spawn_cooldown"] -= 1
                else:
                    # Random chance to spawn a new chunk
                    if random.random() < 0.08:  # 8% chance per frame
                        chunk["active"] = True
                        self._reset_chunk_position(chunk)
            else:
                # Handle speed timing for active chunks
                chunk["speed_counter"] += 1

                # OPTIMIZATION: Generate fresh hex value for every frame the sprite is active
                if chunk["direction"] in ["up", "down"]:
                    chunk["hex_value"] = self._get_cached_hex_string(chunk["width"])
                else:
                    chunk["hex_value"] = "".join(
                        random.choice(self.hex_chars_tuple)
                        for _ in range(chunk["height"])
                    )

                # Place current chunk characters with z-ordering
                self._place_chunk_chars(chunk)

                # Move chunk if it's time
                if chunk["speed_counter"] >= chunk["speed"]:
                    chunk["speed_counter"] = 0
                    self._move_chunk(chunk)

    def _reset_chunk_position(self, chunk):
        """Reset chunk position and properties for respawning"""
        aspect_ratio = self.width / max(self.height, 1)
        vertical_probability = min(0.85, max(0.15, 0.5 + (aspect_ratio - 1.0) * 0.2))

        if random.random() < vertical_probability:
            # Vertical chunks
            chunk["direction"] = random.choice(["up", "down"])
            chunk["width"] = random.choice(self.chunk_sizes)
            chunk["height"] = 1
            chunk["z_order"] = random.randint(1, 100)
            chunk["x_start"] = random.randint(0, max(0, self.width - chunk["width"]))

            if chunk["direction"] == "up":
                chunk["y"] = (
                    self.height - 1
                    if random.random() < 0.5
                    else random.randint(0, self.height - 1)
                )
            else:
                chunk["y"] = (
                    0 if random.random() < 0.5 else random.randint(0, self.height - 1)
                )

            chunk["hex_value"] = self._get_cached_hex_string(chunk["width"])
        else:
            # Horizontal chunks
            chunk["direction"] = random.choice(["left", "right"])
            chunk["width"] = 1
            chunk["height"] = random.choice(self.chunk_sizes)
            chunk["z_order"] = random.randint(1, 100)
            chunk["y"] = random.randint(0, max(0, self.height - chunk["height"]))

            if chunk["direction"] == "left":
                chunk["x_start"] = (
                    self.width - 1
                    if random.random() < 0.5
                    else random.randint(0, self.width - 1)
                )
            else:
                chunk["x_start"] = (
                    0 if random.random() < 0.5 else random.randint(0, self.width - 1)
                )

            chunk["hex_value"] = "".join(
                random.choice(self.hex_chars_tuple) for _ in range(chunk["height"])
            )

        chunk["last_y"] = chunk["y"]
        chunk["last_x"] = chunk["x_start"]
        chunk["speed_counter"] = 0
        chunk["tail_length"] = random.randint(4, 12)

    def _place_chunk_chars(self, chunk):
        """Place chunk characters in the grid with z-ordering"""
        if chunk["direction"] in ["up", "down"]:
            # Vertical chunks - place horizontally
            if 0 <= chunk["y"] < self.height:
                for i, char in enumerate(chunk["hex_value"]):
                    x_pos = chunk["x_start"] + i
                    if 0 <= x_pos < self.width:
                        # Place if higher z-order, empty, OR same z-order (for character rotation)
                        if (
                            self.grid[chunk["y"]][x_pos] == 0
                            or chunk["z_order"] >= self.z_order_grid[chunk["y"]][x_pos]
                        ):
                            self.grid[chunk["y"]][x_pos] = 1  # White/head state
                            self.char_grid[chunk["y"]][x_pos] = char
                            self.z_order_grid[chunk["y"]][x_pos] = chunk["z_order"]
                            self.active_cells.add((chunk["y"], x_pos))
        else:
            # Horizontal chunks - place vertically
            if 0 <= chunk["x_start"] < self.width:
                for i, char in enumerate(chunk["hex_value"]):
                    y_pos = chunk["y"] + i
                    if 0 <= y_pos < self.height:
                        # Place if higher z-order, empty, OR same z-order (for character rotation)
                        if (
                            self.grid[y_pos][chunk["x_start"]] == 0
                            or chunk["z_order"]
                            >= self.z_order_grid[y_pos][chunk["x_start"]]
                        ):
                            self.grid[y_pos][chunk["x_start"]] = 1  # White/head state
                            self.char_grid[y_pos][chunk["x_start"]] = char
                            self.z_order_grid[y_pos][chunk["x_start"]] = chunk[
                                "z_order"
                            ]
                            self.active_cells.add((y_pos, chunk["x_start"]))

    def _move_chunk(self, chunk):
        """Move chunk to next position"""
        # Store previous position
        chunk["last_y"] = chunk["y"]
        chunk["last_x"] = chunk["x_start"]

        # Move based on direction
        if chunk["direction"] == "up":
            chunk["y"] -= 1
        elif chunk["direction"] == "down":
            chunk["y"] += 1
        elif chunk["direction"] == "left":
            chunk["x_start"] -= 1
        else:  # direction == "right"
            chunk["x_start"] += 1

        # Check if chunk is off screen
        off_screen = (
            (chunk["direction"] == "up" and chunk["y"] < -1)
            or (chunk["direction"] == "down" and chunk["y"] > self.height)
            or (chunk["direction"] == "left" and chunk["x_start"] < -1)
            or (chunk["direction"] == "right" and chunk["x_start"] > self.width)
        )

        if off_screen:
            chunk["active"] = False
            chunk["spawn_cooldown"] = random.randint(5, 25)
            chunk["speed"] = random.randint(1, 4)
            # Reset position for next spawn
            if chunk["direction"] in ["up", "down"]:
                chunk["last_y"] = self.height - 1 if chunk["direction"] == "up" else 0
            else:
                chunk["last_x"] = self.width - 1 if chunk["direction"] == "left" else 0
                chunk["last_y"] = chunk["y"]

    def get_framebuffer(self):
        """OPTIMIZED Generate framebuffer with current matrix rain state"""
        framebuffer = []

        # Pre-compute color blend objects for better performance
        for y in range(self.height):
            row = []
            for x in range(self.width):
                # Check if this cell is in glitch state
                if self.glitch_grid[y][x] > 0:
                    # Handle glitch cells (negative color spectrum)
                    glitch_level = self.glitch_grid[y][x]
                    glitch_progress = (
                        glitch_level / self.max_glitch_states
                    )  # 0.0 to 1.0

                    # Get the negative color for this sprite
                    z_order = self.z_order_grid[y][x]
                    neg_bright, neg_dim, neg_dark = self._get_negative_color(z_order)

                    if glitch_progress <= 0.3:  # First 30% - bright negative
                        row.append((self.char_grid[y][x], neg_bright.hex))
                    elif glitch_progress <= 0.6:  # Next 30% - dimmed negative
                        row.append((self.char_grid[y][x], neg_dim.hex))
                    else:  # Final 40% - fade to black
                        black_fade_progress = (
                            glitch_progress - 0.6
                        ) / 0.4  # 0.0 to 1.0
                        color = neg_dark.blend(self.black, black_fade_progress)
                        row.append((self.char_grid[y][x], color.hex))

                elif self.grid[y][x] == 0:
                    # Empty cell - pure black
                    row.append((" ", self.black.hex))
                elif self.grid[y][x] == 1:
                    # Head - bright white
                    row.append((self.char_grid[y][x], self.white.hex))
                elif self.grid[y][x] == 2:
                    # Second position - 50/50 white/color blend
                    z_order = self.z_order_grid[y][x]
                    if z_order > 0:
                        base_color, dim_color, dark_color = self._get_chunk_color(
                            z_order
                        )
                        white_color_blend = self.white.blend(base_color, 0.5)
                        row.append((self.char_grid[y][x], white_color_blend.hex))
                    else:
                        row.append((self.char_grid[y][x], self.white.hex))
                else:
                    # Positions 3+ - gradual fade from blend to color to black
                    z_order = self.z_order_grid[y][x]
                    if z_order > 0:
                        base_color, dim_color, dark_color = self._get_chunk_color(
                            z_order
                        )
                        fade_level = self.grid[y][x] - 2  # 1-10
                        max_fade = self.max_fade_states - 2  # 10
                        fade_progress = fade_level / max_fade  # 0.0 to 1.0

                        if fade_progress <= 0.2:  # First 20% - blend to base color
                            white_color_blend = self.white.blend(base_color, 0.5)
                            blend_factor = fade_progress / 0.2
                            color = white_color_blend.blend(base_color, blend_factor)
                            row.append((self.char_grid[y][x], color.hex))
                        elif fade_progress <= 0.4:  # Next 20% - pure base color
                            row.append((self.char_grid[y][x], base_color.hex))
                        elif fade_progress <= 0.6:  # Next 20% - start dimming
                            row.append((self.char_grid[y][x], dim_color.hex))
                        else:  # Final 40% - gradual fade to black
                            black_fade_progress = (
                                fade_progress - 0.6
                            ) / 0.4  # 0.0 to 1.0
                            if black_fade_progress <= 0.5:
                                blend_factor = black_fade_progress * 2  # 0.0 to 1.0
                                color = dim_color.blend(dark_color, blend_factor)
                                row.append((self.char_grid[y][x], color.hex))
                            else:
                                blend_factor = (
                                    black_fade_progress - 0.5
                                ) * 2  # 0.0 to 1.0
                                dark_color_black_blend = dark_color.blend(
                                    self.black, 0.75
                                )
                                color = dark_color.blend(
                                    dark_color_black_blend, blend_factor
                                )
                                row.append((self.char_grid[y][x], color.hex))
                    else:
                        # Fallback to white if no z_order
                        row.append((self.char_grid[y][x], self.white.hex))

            framebuffer.append(row)

        return framebuffer
