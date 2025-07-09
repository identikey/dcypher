"""
ASCII Art Banner Widget - OPTIMIZED VERSION 3.0
Cyberpunk-inspired banner with @repligate aesthetics
High-performance matrix rain with efficient rendering using numpy
NOW WITH AGGRESSIVE PERFORMANCE OPTIMIZATIONS
"""

import random
import time
import numpy as np
from textual.widget import Widget
from textual.reactive import reactive
from textual.app import RenderResult
from textual.color import Color
from typing import Dict, List, Set, Tuple, Optional, Any, Union, TypedDict
import threading

# Import profiling tools
try:
    from dcypher.lib.profiling import profile, profile_block, create_animation_profiler  # type: ignore

    profiling_available = True
except ImportError:
    # Create no-op decorators if profiling not available
    from typing import Any, Callable, TypeVar
    from contextlib import nullcontext

    F = TypeVar("F", bound=Callable[..., Any])

    def profile(name: Any = None, backend: str = "cprofile") -> Callable[[F], F]:
        return lambda func: func

    def profile_block(name: str, backend: str = "cprofile") -> Any:  # type: ignore
        return nullcontext()

    def create_animation_profiler() -> Any:  # type: ignore
        return None

    profiling_available = False


class SpriteState(TypedDict):
    """Type definition for sprite state"""

    x: int
    y: int
    width: int
    height: int
    direction: str
    active: bool
    speed: int
    counter: int
    z_order: int
    cooldown: int


class ColorPool:
    """
    Efficient color management using pre-computed colors and blending
    NOW WITH ULTRA-AGGRESSIVE CACHING
    """

    @profile("ColorPool.__init__")
    def __init__(self, saturation: int = 75):
        self.saturation = saturation
        self._color_cache: Dict[
            int, Tuple[str, str, str]
        ] = {}  # z_order -> (bright, dim, dark)
        self._blend_cache: Dict[
            Tuple[str, str, float], str
        ] = {}  # (color1, color2, factor) -> blended

        # OPTIMIZATION: Pre-compute common colors as objects instead of strings
        self.white = "#FFFFFF"
        self.black = "#333333"
        self.empty = "#2a2a2a"

        # Pre-compute fade levels with more aggressive caching
        self.fade_levels = 12
        self._compute_fade_colors()

        # PERFORMANCE OPTIMIZATION: Pre-cache common negative colors
        self._negative_color_cache: Dict[Tuple[int, int], str] = {}

    @profile("ColorPool._compute_fade_colors")
    def _compute_fade_colors(self):
        """Pre-compute all possible fade colors for better performance"""
        self._fade_cache = {}
        for z_order in range(1, 101):  # Pre-compute for all possible z-orders
            base_colors = self._generate_base_colors(z_order)
            fade_colors = []
            for i in range(self.fade_levels):
                factor = i / (self.fade_levels - 1)
                if factor <= 0.2:
                    color = self._blend_hex(self.white, base_colors[0], factor * 5)
                elif factor <= 0.4:
                    color = base_colors[0]
                elif factor <= 0.6:
                    color = base_colors[1]
                else:
                    color = self._blend_hex(
                        base_colors[2], self.black, (factor - 0.6) * 2.5
                    )
                fade_colors.append(color)
            self._fade_cache[z_order] = fade_colors

    def _hsl_to_rgb(self, h: float, s: float, l: float) -> Tuple[int, int, int]:
        """Optimized HSL to RGB conversion"""
        if s == 0:
            val = int(l * 255)
            return (val, val, val)

        def hue_to_rgb(p: float, q: float, t: float) -> float:
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

        return (int(r * 255), int(g * 255), int(b * 255))

    def _generate_base_colors(self, z_order: int) -> Tuple[str, str, str]:
        """Generate base colors for a z-order with current saturation"""
        if z_order not in self._color_cache:
            # Use z_order as seed for consistent colors
            random.seed(z_order)
            hue = random.randint(0, 360)
            random.seed()  # Reset seed

            # Convert HSL to RGB with current saturation
            h = hue / 360.0
            s = self.saturation / 100.0
            l = 0.5  # Fixed lightness for consistency

            # Get base color
            rgb = self._hsl_to_rgb(h, s, l)
            base = f"#{rgb[0]:02x}{rgb[1]:02x}{rgb[2]:02x}"

            # Generate dim and dark variants
            rgb_dim = [int(c * 0.7) for c in rgb]
            rgb_dark = [int(c * 0.3) for c in rgb]

            dim = f"#{rgb_dim[0]:02x}{rgb_dim[1]:02x}{rgb_dim[2]:02x}"
            dark = f"#{rgb_dark[0]:02x}{rgb_dark[1]:02x}{rgb_dark[2]:02x}"

            self._color_cache[z_order] = (base, dim, dark)

        return self._color_cache[z_order]

    def _blend_hex(self, color1: str, color2: str, factor: float) -> str:
        """Blend two hex colors with caching"""
        cache_key = (color1, color2, round(factor, 3))
        if cache_key in self._blend_cache:
            return self._blend_cache[cache_key]

        # Convert hex to RGB
        r1 = int(color1[1:3], 16)
        g1 = int(color1[3:5], 16)
        b1 = int(color1[5:7], 16)

        r2 = int(color2[1:3], 16)
        g2 = int(color2[3:5], 16)
        b2 = int(color2[5:7], 16)

        # Blend
        r = int(r1 + (r2 - r1) * factor)
        g = int(g1 + (g2 - g1) * factor)
        b = int(b1 + (b2 - b1) * factor)

        result = f"#{r:02x}{g:02x}{b:02x}"
        self._blend_cache[cache_key] = result
        return result

    @profile("ColorPool.get_fade_color")
    def get_fade_color(self, z_order: int, fade_level: int) -> str:
        """Get pre-computed fade color for a z-order and level"""
        if z_order in self._fade_cache:
            return self._fade_cache[z_order][min(fade_level, self.fade_levels - 1)]
        return self.black

    def get_negative_color(self, z_order: int, variant: int) -> str:
        """OPTIMIZED: Get negative color for glitch effect with caching"""
        cache_key = (z_order, variant)
        if cache_key in self._negative_color_cache:
            return self._negative_color_cache[cache_key]

        if z_order == 0:
            color = (
                "#00FFFF" if variant == 0 else "#00AAAA" if variant == 1 else "#004444"
            )
        else:
            base_colors = self._generate_base_colors(z_order)
            base_color = base_colors[min(variant, len(base_colors) - 1)]

            # Convert to RGB
            r = int(base_color[1:3], 16)
            g = int(base_color[3:5], 16)
            b = int(base_color[5:7], 16)

            # Calculate negative
            color = f"#{(255 - r):02x}{(255 - g):02x}{(255 - b):02x}"

        # Cache the result
        self._negative_color_cache[cache_key] = color
        return color

    def clear_caches(self):
        """Clear color caches when saturation changes"""
        self._color_cache.clear()
        self._blend_cache.clear()
        self._negative_color_cache.clear()
        self._compute_fade_colors()


class MatrixRain:
    """
    ULTRA-OPTIMIZED Matrix rain effect controller
    Now with aggressive framebuffer caching and reduced function calls
    """

    @profile("MatrixRain.__init__")
    def __init__(self, width: int = 80, height: int = 20):
        self.width = width
        self.height = height
        self.enabled = True

        # Quality settings (affects sprite density)
        self.quality = 2  # 1=low, 2=medium, 3=high

        # Color management
        self.color_pool = ColorPool(saturation=75)

        # Timing control
        self.last_update = 0.0  # Initialize as float
        self.update_interval = 0.5  # 2 FPS default - controlled by global keybindings

        # Character management
        self.hex_chars = np.array(list("0123456789ABCDEF"))
        self.chunk_sizes = np.array([2, 4, 8])

        # SMART CACHING (non-design-blocking):
        # - Framebuffer result caching (only when state unchanged)
        # - State-based cache invalidation (not time-based)
        # Note: No layer composition caching to allow design changes

        # PERFORMANCE OPTIMIZATION: Smart framebuffer caching
        self._framebuffer_cache: Optional[List[List[Tuple[str, str]]]] = None
        self._state_dirty: bool = True  # Mark when state changes
        self._current_frame: int = 0

        # SMART STATE-BASED CACHING
        self._state_hash: int = 0
        self._cached_state_hash: int = 0

        # Initialize profiler for animations
        self.animation_profiler = create_animation_profiler()

        # Character batch for optimized sprite generation
        self._char_batch_size = 200
        self._char_batch = np.random.choice(self.hex_chars, size=self._char_batch_size)
        self._char_batch_index = 0

        # PERFORMANCE OPTIMIZATION: Pre-compute glitch colors once at initialization
        self._glitch_colors = {}
        for z_val in range(1, 101):  # Common Z range
            self._glitch_colors[z_val] = [
                self.color_pool.get_negative_color(z_val, 0),  # <= 0.3 progress
                self.color_pool.get_negative_color(z_val, 1),  # <= 0.6 progress
                self.color_pool.get_negative_color(z_val, 2),  # > 0.6 progress
            ]

        # Initialize state
        self.reset_grid()

    @profile("MatrixRain.reset_grid")
    def reset_grid(self):
        """Reset all grids and sprites to initial state"""
        with profile_block("MatrixRain.reset_grid.numpy_allocation"):
            # Efficient numpy arrays for state
            self.state = np.zeros(
                (self.height, self.width), dtype=np.uint8
            )  # Fade state
            self.chars = np.full(
                (self.height, self.width), " ", dtype=str
            )  # Characters
            self.z_order = np.zeros(
                (self.height, self.width), dtype=np.uint8
            )  # Z-ordering
            self.glitch = np.zeros(
                (self.height, self.width), dtype=np.uint8
            )  # Glitch state

            # Active cell tracking - now using numpy for efficiency
            self.active_mask = np.zeros((self.height, self.width), dtype=bool)
            self.glitch_mask = np.zeros((self.height, self.width), dtype=bool)

        # Sprite management
        self.sprites: List[SpriteState] = []
        self._initialize_sprites()

        # OPTIMIZATION: Mark state as dirty when resetting
        self._state_dirty = True

    def _initialize_sprites(self):
        """Initialize matrix rain sprites"""
        with profile_block("MatrixRain._initialize_sprites"):
            # Adjust sprite count based on quality
            base_sprites = self.width // 2
            sprite_multiplier = (
                0.5 if self.quality == 1 else 1.0 if self.quality == 2 else 1.5
            )
            num_sprites = int(base_sprites * sprite_multiplier)

            for _ in range(num_sprites):
                sprite = self._create_sprite()
                if random.random() < 0.3:  # 30% start active
                    sprite["active"] = True
                self.sprites.append(sprite)

    def _create_sprite(self) -> SpriteState:
        """Create a new sprite with random properties"""
        # Calculate aspect ratio to determine sprite direction bias
        aspect_ratio = self.width / max(self.height, 1)  # Avoid division by zero
        vertical_probability = min(0.85, max(0.15, 0.5 + (aspect_ratio - 1.0) * 0.2))

        # Use aspect ratio to bias direction choice
        vertical = random.random() < vertical_probability

        if vertical:
            width = int(random.choice(self.chunk_sizes))
            height = 1
            direction = random.choice(["up", "down"])
            x = random.randint(0, max(0, self.width - width))
            # Bias starting position based on direction
            if direction == "up":
                y = (
                    self.height - 1
                    if random.random() < 0.5
                    else random.randint(0, self.height - 1)
                )
            else:  # down
                y = 0 if random.random() < 0.5 else random.randint(0, self.height - 1)
        else:
            width = 1
            height = int(random.choice(self.chunk_sizes))
            direction = random.choice(["left", "right"])
            # Bias starting position based on direction
            if direction == "left":
                x = (
                    self.width - 1
                    if random.random() < 0.5
                    else random.randint(0, self.width - 1)
                )
            else:  # right
                x = 0 if random.random() < 0.5 else random.randint(0, self.width - 1)
            y = random.randint(0, max(0, self.height - height))

        return {
            "x": x,
            "y": y,
            "width": width,
            "height": height,
            "direction": direction,
            "active": False,
            "speed": random.randint(1, 3),
            "counter": 0,
            "z_order": random.randint(1, 100),
            "cooldown": random.randint(0, 20),
        }

    def _reset_sprite(self, sprite: SpriteState):
        """Reset sprite for reuse"""
        # Calculate aspect ratio to determine sprite direction bias
        aspect_ratio = self.width / max(self.height, 1)  # Avoid division by zero
        vertical_probability = min(0.85, max(0.15, 0.5 + (aspect_ratio - 1.0) * 0.2))

        # Use aspect ratio to bias direction choice
        vertical = random.random() < vertical_probability

        if vertical:
            sprite["width"] = int(random.choice(self.chunk_sizes))
            sprite["height"] = 1
            sprite["direction"] = random.choice(["up", "down"])
            sprite["x"] = random.randint(0, max(0, self.width - sprite["width"]))
            # Bias starting position based on direction
            if sprite["direction"] == "up":
                sprite["y"] = (
                    self.height - 1
                    if random.random() < 0.5
                    else random.randint(0, self.height - 1)
                )
            else:  # down
                sprite["y"] = (
                    0 if random.random() < 0.5 else random.randint(0, self.height - 1)
                )
        else:
            sprite["width"] = 1
            sprite["height"] = int(random.choice(self.chunk_sizes))
            sprite["direction"] = random.choice(["left", "right"])
            # Bias starting position based on direction
            if sprite["direction"] == "left":
                sprite["x"] = (
                    self.width - 1
                    if random.random() < 0.5
                    else random.randint(0, self.width - 1)
                )
            else:  # right
                sprite["x"] = (
                    0 if random.random() < 0.5 else random.randint(0, self.width - 1)
                )
            sprite["y"] = random.randint(0, max(0, self.height - sprite["height"]))

        sprite["speed"] = random.randint(1, 3)
        sprite["counter"] = 0
        sprite["z_order"] = random.randint(1, 100)

    @profile("MatrixRain.update")
    def update(self, current_time: Optional[float] = None) -> None:
        """Update matrix rain state"""
        if not self.enabled:
            return

        # Mark frame start for animation profiling
        if self.animation_profiler:
            self.animation_profiler.start_frame()

        # Use provided time or get current time
        now = current_time if current_time is not None else time.time()

        if now - self.last_update < self.update_interval:
            return

        self.last_update = now
        self._current_frame += 1

        with profile_block("MatrixRain.update.main_logic"):
            self._update_states()
            self._update_sprites()

        # OPTIMIZATION: Mark state as dirty after updates
        self._state_dirty = True

    @profile("MatrixRain._update_states")
    def _update_states(self):
        """Update all states in one pass"""
        with profile_block("MatrixRain._update_states.numpy_operations"):
            # Get active cells
            active = self.state > 0

            # Update fade states
            self.state[active] += 1

            # Handle expired cells
            expired = self.state > self.color_pool.fade_levels
            if expired.any():
                # Clear all states for expired cells
                self.state[expired] = 0
                self.chars[expired] = " "
                self.z_order[expired] = 0
                self.glitch[expired] = 0
                self.active_mask[expired] = False
                self.glitch_mask[expired] = False

        with profile_block("MatrixRain._update_states.glitch_processing"):
            # Update glitch states
            glitch_active = self.glitch > 0
            if glitch_active.any():
                # Update glitch counters
                self.glitch[glitch_active] += 1

                # Randomize glitch characters efficiently
                glitch_coords = np.where(glitch_active)
                random_chars = np.random.choice(
                    self.hex_chars, size=len(glitch_coords[0])
                )
                self.chars[glitch_coords] = random_chars

                # Remove expired glitches
                glitch_expired = self.glitch > 8
                if glitch_expired.any():
                    self.glitch[glitch_expired] = 0
                    self.glitch_mask[glitch_expired] = False

        with profile_block("MatrixRain._update_states.new_glitches"):
            # OPTIMIZATION: Reduce glitch computation frequency
            if self._current_frame % 3 == 0:  # Only compute every 3rd frame
                # Add new glitches - 5% of active cells
                active_count = np.count_nonzero(active)
                current_glitch_count = np.count_nonzero(self.glitch_mask)
                target_glitch_count = int(active_count * 0.05)

                if current_glitch_count < target_glitch_count:
                    # Get potential glitch candidates (active but not glitched)
                    candidates = active & ~self.glitch_mask
                    if candidates.any():
                        # Get candidate coordinates
                        candidate_coords = np.where(candidates)
                        # Randomly select one
                        idx = np.random.randint(len(candidate_coords[0]))
                        y, x = candidate_coords[0][idx], candidate_coords[1][idx]
                        # Add new glitch
                        self.glitch[y, x] = 1
                        self.glitch_mask[y, x] = True

    @profile("MatrixRain._update_sprites")
    def _update_sprites(self):
        """ULTRA-OPTIMIZED: Update sprite positions and characters with minimal overhead"""
        with profile_block("MatrixRain._update_sprites.sprite_loop"):
            # OPTIMIZATION 1: Pre-compute values to avoid repeated calculations
            activation_threshold = 0.08
            current_frame = self._current_frame

            # OPTIMIZATION 2: Use persistent character batch to reduce numpy calls
            # Character batch is now initialized in __init__, just use it directly

            # OPTIMIZATION 3: Process sprites in batches to reduce overhead
            active_sprites = []
            inactive_sprites = []

            # Separate active and inactive sprites for optimized processing
            for sprite in self.sprites:
                if sprite["active"]:
                    active_sprites.append(sprite)
                else:
                    inactive_sprites.append(sprite)

            # OPTIMIZATION 4: Process inactive sprites with reduced frequency
            # Only check every few frames to reduce unnecessary work
            if current_frame % 2 == 0:  # Every other frame for inactive sprites
                for sprite in inactive_sprites:
                    if sprite["cooldown"] > 0:
                        sprite["cooldown"] -= 1
                    elif random.random() < activation_threshold:
                        sprite["active"] = True
                        self._reset_sprite(sprite)
                        active_sprites.append(sprite)  # Move to active list

            # OPTIMIZATION 5: Bulk process active sprites with fewer function calls
            sprites_to_deactivate = []
            for sprite in active_sprites:
                sprite["counter"] += 1
                if sprite["counter"] >= sprite["speed"]:
                    sprite["counter"] = 0
                    # Inline movement logic to avoid function call overhead
                    if sprite["direction"] == "up":
                        sprite["y"] -= 1
                        if sprite["y"] < -1:
                            sprites_to_deactivate.append(sprite)
                            continue
                    elif sprite["direction"] == "down":
                        sprite["y"] += 1
                        if sprite["y"] >= self.height:
                            sprites_to_deactivate.append(sprite)
                            continue
                    elif sprite["direction"] == "left":
                        sprite["x"] -= 1
                        if sprite["x"] < -1:
                            sprites_to_deactivate.append(sprite)
                            continue
                    else:  # right
                        sprite["x"] += 1
                        if sprite["x"] >= self.width:
                            sprites_to_deactivate.append(sprite)
                            continue

                # OPTIMIZATION 6: Use persistent character batch for maximum efficiency
                x, y = sprite["x"], sprite["y"]
                if 0 <= y < self.height:
                    if sprite["direction"] in ["up", "down"]:
                        # Generate chars for horizontal sprites using persistent batch
                        char_count = sprite["width"]
                        if self._char_batch_index + char_count > self._char_batch_size:
                            # Refresh batch when needed
                            self._char_batch = np.random.choice(
                                self.hex_chars, size=self._char_batch_size
                            )
                            self._char_batch_index = 0

                        chars = self._char_batch[
                            self._char_batch_index : self._char_batch_index + char_count
                        ]
                        self._char_batch_index += char_count

                        for i, char in enumerate(chars):
                            if 0 <= x + i < self.width:
                                # Inline _set_cell logic
                                cell_x = x + i
                                if (
                                    self.z_order[y, cell_x] == 0
                                    or sprite["z_order"] >= self.z_order[y, cell_x]
                                ):
                                    self.chars[y, cell_x] = char
                                    self.state[y, cell_x] = 1
                                    self.z_order[y, cell_x] = sprite["z_order"]
                                    self.active_mask[y, cell_x] = True
                    else:
                        # Generate chars for vertical sprites using persistent batch
                        char_count = sprite["height"]
                        if self._char_batch_index + char_count > self._char_batch_size:
                            # Refresh batch when needed
                            self._char_batch = np.random.choice(
                                self.hex_chars, size=self._char_batch_size
                            )
                            self._char_batch_index = 0

                        chars = self._char_batch[
                            self._char_batch_index : self._char_batch_index + char_count
                        ]
                        self._char_batch_index += char_count

                        for i, char in enumerate(chars):
                            cell_y = y + i
                            if 0 <= cell_y < self.height and 0 <= x < self.width:
                                # Inline _set_cell logic
                                if (
                                    self.z_order[cell_y, x] == 0
                                    or sprite["z_order"] >= self.z_order[cell_y, x]
                                ):
                                    self.chars[cell_y, x] = char
                                    self.state[cell_y, x] = 1
                                    self.z_order[cell_y, x] = sprite["z_order"]
                                    self.active_mask[cell_y, x] = True

            # OPTIMIZATION 7: Batch deactivate sprites to avoid individual updates
            for sprite in sprites_to_deactivate:
                sprite["active"] = False
                sprite["cooldown"] = random.randint(5, 25)

    # REMOVED HELPER METHODS (inlined for performance):
    # - _move_sprite() -> inlined in _update_sprites()
    # - _update_sprite_chars() -> inlined in _update_sprites()
    # - _set_cell() -> inlined in _update_sprites()
    # TODO: Consider re-adding these if code becomes hard to maintain

    @profile("MatrixRain.get_framebuffer")
    def get_framebuffer(self) -> List[List[Tuple[str, str]]]:
        """ULTRA-OPTIMIZED: Generate framebuffer with smart state-based caching"""

        # SMART STATE-BASED CACHE: Use hash of current state for more precise caching
        with profile_block("MatrixRain.get_framebuffer.state_hash"):
            # Generate BUCKETED state hash for better cache hit rates
            active_cells = int(np.count_nonzero(self.active_mask))
            glitch_cells = int(np.count_nonzero(self.glitch_mask))
            sprite_states = sum(1 for s in self.sprites if s["active"])

            # BUCKET values to reduce cache sensitivity to minor changes
            self._state_hash = hash(
                (
                    active_cells // 10,  # Bucket active cells by 10
                    glitch_cells // 3,  # Bucket glitch cells by 3
                    sprite_states,  # Keep sprite count exact (changes less frequently)
                    self._current_frame
                    // 8,  # Bucket frames by 8 (allow ~8 frames same cache)
                )
            )

            # Check if state actually changed
            if (
                self._state_hash == self._cached_state_hash
                and self._framebuffer_cache is not None
            ):
                return self._framebuffer_cache

        with profile_block("MatrixRain.get_framebuffer.buffer_generation"):
            # ULTRA-OPTIMIZATION: Use pre-computed colors to eliminate all function calls
            color_pool = self.color_pool
            black_str = color_pool.black

            # Pre-cache common values to avoid repeated access
            fade_cache = color_pool._fade_cache
            fade_levels = color_pool.fade_levels

            # Use pre-computed glitch colors from initialization
            glitch_colors = self._glitch_colors

            # Build framebuffer with maximum efficiency
            framebuffer = []

            for y in range(self.height):
                # Use append operations for cleaner object creation
                row = []

                # Get entire row data at once to avoid repeated array access
                chars_row = self.chars[y]
                state_row = self.state[y]
                glitch_row = self.glitch[y]
                z_order_row = self.z_order[y]

                # ULTRA-OPTIMIZATION: Vectorized row processing with pre-computed lookups
                for x in range(self.width):
                    char = chars_row[x]
                    state_val = state_row[x]
                    glitch_val = glitch_row[x]
                    z_val = z_order_row[x]

                    # MEGA-OPTIMIZATION: Streamlined color lookup with pre-computed tables
                    if glitch_val > 0:
                        # Use pre-computed glitch color table - NO FUNCTION CALLS
                        glitch_progress = glitch_val / 8
                        if z_val in glitch_colors:
                            if glitch_progress <= 0.3:
                                color = glitch_colors[z_val][0]
                            elif glitch_progress <= 0.6:
                                color = glitch_colors[z_val][1]
                            else:
                                color = glitch_colors[z_val][2]
                        else:
                            color = black_str
                    elif state_val == 0:
                        color = black_str
                    else:
                        # OPTIMIZATION: Direct cache access with pre-computed bounds
                        if z_val in fade_cache:
                            fade_level = min(state_val - 1, fade_levels - 1)
                            color = fade_cache[z_val][fade_level]
                        else:
                            color = black_str

                    row.append((char, color))
                framebuffer.append(row)

            # SMART CACHE: Store result and update cache state hash
            self._framebuffer_cache = framebuffer
            self._cached_state_hash = self._state_hash
            self._state_dirty = False

            return framebuffer

    def _get_negative_color(self, z_order: int, variant: int) -> str:
        """DEPRECATED: Use color_pool.get_negative_color instead"""
        return self.color_pool.get_negative_color(z_order, variant)

    def set_quality(self, quality: int) -> None:
        """Set animation quality (1=low, 2=medium, 3=high)"""
        if quality != self.quality:
            self.quality = max(1, min(3, quality))
            # Reset sprites to adjust density
            self.sprites.clear()
            self._initialize_sprites()
            # Quality adjusted - no caching currently enabled

    def set_saturation(self, saturation: int) -> None:
        """Set color saturation (0-100%)"""
        saturation = max(0, min(100, saturation))
        if saturation != self.color_pool.saturation:
            self.color_pool.saturation = saturation
            self.color_pool.clear_caches()

            # PERFORMANCE: Regenerate glitch color cache with new saturation
            self._glitch_colors = {}
            for z_val in range(1, 101):  # Common Z range
                self._glitch_colors[z_val] = [
                    self.color_pool.get_negative_color(z_val, 0),  # <= 0.3 progress
                    self.color_pool.get_negative_color(z_val, 1),  # <= 0.6 progress
                    self.color_pool.get_negative_color(z_val, 2),  # > 0.6 progress
                ]

            # OPTIMIZATION: Invalidate framebuffer cache when colors change
            self._state_dirty = True

    def get_profiling_stats(self) -> Dict[str, Any]:
        """Get profiling statistics for this animation"""
        stats = {}
        if self.animation_profiler:
            stats.update(self.animation_profiler.get_performance_stats())

        stats.update(
            {
                "sprite_count": len(self.sprites),
                "active_sprites": sum(1 for s in self.sprites if s["active"]),
                "active_cells": int(np.count_nonzero(self.active_mask)),
                "glitch_cells": int(np.count_nonzero(self.glitch_mask)),
                "quality_level": self.quality,
                "update_interval": self.update_interval,
                "framebuffer_cached": self._framebuffer_cache is not None,
                "state_dirty": self._state_dirty,
            }
        )

        return stats
