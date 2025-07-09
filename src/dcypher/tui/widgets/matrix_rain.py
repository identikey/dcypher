"""
ASCII Art Banner Widget - OPTIMIZED VERSION 2.0
Cyberpunk-inspired banner with @repligate aesthetics
High-performance matrix rain with efficient rendering using numpy
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
    """

    def __init__(self, saturation: int = 75):
        self.saturation = saturation
        self._color_cache: Dict[
            int, Tuple[str, str, str]
        ] = {}  # z_order -> (bright, dim, dark)
        self._blend_cache: Dict[
            Tuple[str, str, float], str
        ] = {}  # (color1, color2, factor) -> blended

        # Pre-compute common colors
        self.white = "#FFFFFF"
        self.black = "#333333"
        self.empty = "#2a2a2a"

        # Pre-compute fade levels
        self.fade_levels = 12
        self._compute_fade_colors()

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

    def get_fade_color(self, z_order: int, fade_level: int) -> str:
        """Get pre-computed fade color for a z-order and level"""
        if z_order in self._fade_cache:
            return self._fade_cache[z_order][min(fade_level, self.fade_levels - 1)]
        return self.black

    def clear_caches(self):
        """Clear color caches when saturation changes"""
        self._color_cache.clear()
        self._blend_cache.clear()
        self._compute_fade_colors()


class MatrixRain:
    """
    OPTIMIZED Matrix rain effect controller implementing hex-chunk-based pattern
    Now using numpy arrays and efficient color management
    """

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

        # Initialize state
        self.reset_grid()

    def reset_grid(self):
        """Reset all grids and sprites to initial state"""
        # Efficient numpy arrays for state
        self.state = np.zeros((self.height, self.width), dtype=np.uint8)  # Fade state
        self.chars = np.full((self.height, self.width), " ", dtype=str)  # Characters
        self.z_order = np.zeros((self.height, self.width), dtype=np.uint8)  # Z-ordering
        self.glitch = np.zeros(
            (self.height, self.width), dtype=np.uint8
        )  # Glitch state

        # Active cell tracking - now using numpy for efficiency
        self.active_mask = np.zeros((self.height, self.width), dtype=bool)
        self.glitch_mask = np.zeros((self.height, self.width), dtype=bool)

        # Sprite management
        self.sprites: List[SpriteState] = []
        self._initialize_sprites()

    def _initialize_sprites(self):
        """Initialize matrix rain sprites"""
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

    def update(self, current_time: Optional[float] = None) -> None:
        """Update matrix rain state"""
        if not self.enabled:
            return

        # Use provided time or get current time
        now = current_time if current_time is not None else time.time()

        if now - self.last_update < self.update_interval:
            return

        self.last_update = now

        self._update_states()
        self._update_sprites()

    def _update_states(self):
        """Update all states in one pass"""
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

        # Update glitch states
        glitch_active = self.glitch > 0
        if glitch_active.any():
            # Update glitch counters
            self.glitch[glitch_active] += 1

            # Randomize glitch characters efficiently
            glitch_coords = np.where(glitch_active)
            random_chars = np.random.choice(self.hex_chars, size=len(glitch_coords[0]))
            self.chars[glitch_coords] = random_chars

            # Remove expired glitches
            glitch_expired = self.glitch > 8
            if glitch_expired.any():
                self.glitch[glitch_expired] = 0
                self.glitch_mask[glitch_expired] = False

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

    def _update_sprites(self):
        """Update sprite positions and characters"""
        for sprite in self.sprites:
            if not sprite["active"]:
                if sprite["cooldown"] > 0:
                    sprite["cooldown"] -= 1
                elif random.random() < 0.08:  # 8% chance to activate
                    sprite["active"] = True
                    self._reset_sprite(sprite)
                continue

            sprite["counter"] += 1
            if sprite["counter"] >= sprite["speed"]:
                sprite["counter"] = 0
                self._move_sprite(sprite)

            # Update sprite characters
            self._update_sprite_chars(sprite)

    def _move_sprite(self, sprite: SpriteState):
        """Move sprite based on direction"""
        if sprite["direction"] == "up":
            sprite["y"] -= 1
        elif sprite["direction"] == "down":
            sprite["y"] += 1
        elif sprite["direction"] == "left":
            sprite["x"] -= 1
        else:  # right
            sprite["x"] += 1

        # Check if off screen
        if (
            sprite["direction"] == "up"
            and sprite["y"] < -1
            or sprite["direction"] == "down"
            and sprite["y"] >= self.height
            or sprite["direction"] == "left"
            and sprite["x"] < -1
            or sprite["direction"] == "right"
            and sprite["x"] >= self.width
        ):
            sprite["active"] = False
            sprite["cooldown"] = random.randint(5, 25)

    def _update_sprite_chars(self, sprite: SpriteState):
        """Update sprite characters and states"""
        x, y = sprite["x"], sprite["y"]
        if not (0 <= y < self.height):
            return

        # Generate new characters
        if sprite["direction"] in ["up", "down"]:
            chars = np.random.choice(self.hex_chars, sprite["width"])
            for i, char in enumerate(chars):
                if 0 <= x + i < self.width:
                    self._set_cell(y, x + i, char, sprite["z_order"])
        else:
            chars = np.random.choice(self.hex_chars, sprite["height"])
            for i, char in enumerate(chars):
                if 0 <= y + i < self.height and 0 <= x < self.width:
                    self._set_cell(y + i, x, char, sprite["z_order"])

    def _set_cell(self, y: int, x: int, char: str, z_order: int):
        """Set cell state with z-order checking"""
        if self.z_order[y, x] == 0 or z_order >= self.z_order[y, x]:
            self.chars[y, x] = char
            self.state[y, x] = 1
            self.z_order[y, x] = z_order
            self.active_mask[y, x] = True

    def get_framebuffer(self) -> List[List[Tuple[str, str]]]:
        """Generate framebuffer with current state"""
        framebuffer = []

        for y in range(self.height):
            row = []
            for x in range(self.width):
                char = self.chars[y, x]
                if self.glitch[y, x] > 0:
                    # Glitch effect - negative colors
                    glitch_progress = self.glitch[y, x] / 8
                    z = self.z_order[y, x]
                    if glitch_progress <= 0.3:
                        color = self._get_negative_color(z, 0)
                    elif glitch_progress <= 0.6:
                        color = self._get_negative_color(z, 1)
                    else:
                        color = self._get_negative_color(z, 2)
                elif self.state[y, x] == 0:
                    color = self.color_pool.black
                else:
                    # Normal fade effect
                    z = self.z_order[y, x]
                    fade_level = self.state[y, x] - 1
                    color = self.color_pool.get_fade_color(z, fade_level)

                row.append((char, color))
            framebuffer.append(row)

        return framebuffer

    def _get_negative_color(self, z_order: int, variant: int) -> str:
        """Get negative color for glitch effect"""
        if z_order == 0:
            return (
                "#00FFFF" if variant == 0 else "#00AAAA" if variant == 1 else "#004444"
            )

        base_colors = self.color_pool._generate_base_colors(z_order)
        color = base_colors[variant]

        # Convert to RGB
        r = int(color[1:3], 16)
        g = int(color[3:5], 16)
        b = int(color[5:7], 16)

        # Calculate negative
        return f"#{(255 - r):02x}{(255 - g):02x}{(255 - b):02x}"

    def set_quality(self, quality: int) -> None:
        """Set animation quality (1=low, 2=medium, 3=high)"""
        if quality != self.quality:
            self.quality = max(1, min(3, quality))
            # Reset sprites to adjust density
            self.sprites.clear()
            self._initialize_sprites()

    def set_saturation(self, saturation: int) -> None:
        """Set color saturation (0-100%)"""
        saturation = max(0, min(100, saturation))
        if saturation != self.color_pool.saturation:
            self.color_pool.saturation = saturation
            self.color_pool.clear_caches()
