"""
Scrolling Code Widget
Displays random dcypher source code scrolling in the background
"""

import random
import time
import os
import pkgutil
import inspect
import importlib
import sys
from pathlib import Path
from textual.widget import Widget
from textual.reactive import reactive
from textual.app import RenderResult

try:
    import dill
    import dill.source

    dill_available = True
except ImportError:
    dill_available = False
    dill = None


class ScrollingCode:
    """
    Scrolling code effect controller that displays random dcypher source code
    Uses dill to extract source code from dcypher package functions and classes
    Features optimized character-by-character reveal with constant timing
    """

    def __init__(self, width: int = 80, height: int = 20):
        self.width = width
        self.height = height
        self.enabled = True

        # Timing control - much more conservative like MatrixRain
        self.last_update_time = 0
        self.update_interval = 0.5  # 0.5 seconds = 2 FPS default (same as MatrixRain)
        self.chars_per_update = 8  # Reveal more characters per update to compensate

        # Code content and reveal state
        self.current_code = ""
        self.revealed_chars = 0
        self.total_chars = 0

        # Cached data to avoid repeated calculations
        self.revealed_text_cache = ""
        self.revealed_lines_cache = []
        self.last_revealed_chars = -1  # Track when cache needs update

        # Scrolling state
        self.scroll_position = 0
        self.lines_per_screen = height
        self.scroll_speed = 1
        self.scroll_delay = 0.5  # Match scroll delay to update interval
        self.scroll_timer = 0  # Track when to scroll

        # Source code collection
        self.source_functions = []
        self.current_source_index = 0

        self._collect_dcypher_sources()
        self._load_next_source()

    def _collect_dcypher_sources(self):
        """Collect all functions and classes from dcypher package using modern importlib"""
        try:
            import dcypher

            self.source_functions = []

            # Use pkgutil.walk_packages to discover all modules
            for importer, modname, ispkg in pkgutil.walk_packages(
                dcypher.__path__, dcypher.__name__ + "."
            ):
                try:
                    # Use importlib to load the module
                    module = importlib.import_module(modname)

                    # Get all functions and classes from the module
                    for name, obj in inspect.getmembers(module):
                        # Only include objects defined in this specific module
                        if (
                            (inspect.isfunction(obj) or inspect.isclass(obj))
                            and hasattr(obj, "__module__")
                            and obj.__module__ == modname
                        ):
                            # Try to get source code to verify it's available
                            if dill_available and dill is not None:
                                try:
                                    dill.source.getsource(obj)
                                    self.source_functions.append((modname, name, obj))
                                except (OSError, TypeError):
                                    # Can't get source, skip this object
                                    continue
                            else:
                                try:
                                    inspect.getsource(obj)
                                    self.source_functions.append((modname, name, obj))
                                except (OSError, TypeError):
                                    # Can't get source, skip this object
                                    continue

                except Exception as e:
                    # Skip modules that can't be imported or processed
                    continue

            # Also add some built-in examples if we don't have much
            if len(self.source_functions) < 5:
                self._add_builtin_examples()

        except Exception as e:
            # Fallback to empty list if dcypher can't be imported
            self.source_functions = []
            self._add_builtin_examples()

    def _add_builtin_examples(self):
        """Add some built-in example code objects"""
        try:
            # Add some functions from the current module
            current_module = sys.modules[__name__]
            for name, obj in inspect.getmembers(current_module):
                if (
                    (inspect.isfunction(obj) or inspect.isclass(obj))
                    and hasattr(obj, "__module__")
                    and obj.__module__ == __name__
                ):
                    self.source_functions.append((__name__, name, obj))

            # Add some from common modules if available
            for module_name in ["random", "time", "os", "pathlib"]:
                try:
                    module = importlib.import_module(module_name)
                    for name, obj in inspect.getmembers(module):
                        if (
                            inspect.isfunction(obj)
                            and hasattr(obj, "__module__")
                            and obj.__module__ == module_name
                        ):
                            # Only add a few from each module
                            if (
                                len(
                                    [
                                        x
                                        for x in self.source_functions
                                        if x[0] == module_name
                                    ]
                                )
                                < 3
                            ):
                                try:
                                    inspect.getsource(obj)
                                    self.source_functions.append(
                                        (module_name, name, obj)
                                    )
                                except:
                                    continue
                except:
                    continue

        except Exception:
            pass

    def _load_next_source(self):
        """Load the next source code for scrolling"""
        if not self.source_functions:
            # Fallback code if no sources available
            self.current_code = """
# dCypher - Quantum-Resistant Encryption System
# No source code available for display

import random
import time
from typing import List, Optional

class CryptoSystem:
    def __init__(self):
        self.quantum_resistant = True
        self.lattice_based = True
        
    def encrypt(self, data: bytes) -> bytes:
        \"\"\"Encrypt data using post-quantum algorithms\"\"\"
        return b"encrypted_" + data
        
    def decrypt(self, ciphertext: bytes) -> bytes:
        \"\"\"Decrypt ciphertext\"\"\"
        return ciphertext[10:]  # Remove "encrypted_" prefix

def generate_random_key(length: int = 32) -> bytes:
    \"\"\"Generate a random cryptographic key\"\"\"
    return bytes(random.randint(0, 255) for _ in range(length))

# Matrix rain effect with hex characters
def create_hex_pattern():
    hex_chars = "0123456789ABCDEF"
    return ''.join(random.choice(hex_chars) for _ in range(16))

# End of fallback code
"""
        else:
            # Get source code using dill or inspect
            module_name, obj_name, obj = self.source_functions[
                self.current_source_index
            ]

            try:
                if dill_available and dill is not None:
                    source_code = dill.source.getsource(obj)
                else:
                    source_code = inspect.getsource(obj)

                self.current_code = f"# {module_name}.{obj_name}\n{source_code}"

            except Exception as e:
                # If we can't get source, create a descriptive placeholder
                obj_type = "class" if inspect.isclass(obj) else "function"
                self.current_code = f"""# {module_name}.{obj_name}
# {obj_type.title()} from {module_name}
# Source code not available: {str(e)[:50]}...

# This is a {obj_type} that would normally show here
# but the source code could not be retrieved.
# This often happens with C extensions or built-ins.

def placeholder_{obj_name.lower()}():
    \"\"\"
    This is a placeholder for {obj_name}
    The actual implementation is not accessible.
    \"\"\"
    pass
"""

            # Move to next source for next time
            self.current_source_index = (self.current_source_index + 1) % max(
                1, len(self.source_functions)
            )

        # Reset state for new source
        self.scroll_position = 0
        self.revealed_chars = 0
        self.total_chars = len(self.current_code)
        self.last_revealed_chars = -1  # Reset cache
        self.scroll_timer = 0  # Reset scroll timer

    def update(self):
        """Update character-by-character reveal and scrolling animation - same timing as MatrixRain"""
        if not self.enabled:
            return

        current_time = time.time()

        # Timing control: only update at the specified interval
        if current_time - self.last_update_time < self.update_interval:
            return

        self.last_update_time = current_time

        # Check if it's time to reveal the next chunk of characters
        if self.revealed_chars < self.total_chars:
            # Reveal multiple characters at once, but don't exceed total
            remaining_chars = self.total_chars - self.revealed_chars
            chars_to_reveal = min(self.chars_per_update, remaining_chars)
            self.revealed_chars += chars_to_reveal

            # Check if we need to scroll during character revelation
            self._check_and_scroll_during_reveal()

        # Check if we need to continue scrolling after all characters are revealed
        elif self.revealed_chars >= self.total_chars:
            # Start scroll timer when all characters are revealed
            if self.scroll_timer == 0:
                self.scroll_timer = current_time

            if current_time - self.scroll_timer > self.scroll_delay:
                # Use cached lines instead of string operations
                if (
                    self.scroll_position
                    < len(self.revealed_lines_cache) - self.lines_per_screen
                ):
                    self.scroll_position += self.scroll_speed
                    self.scroll_timer = current_time
                else:
                    # Finished scrolling, load next source
                    self._load_next_source()

    def _check_and_scroll_during_reveal(self):
        """Check if we need to scroll during character revelation - optimized"""
        if self.revealed_chars == 0:
            return

        # Use cached lines count instead of string operations
        lines = self.revealed_lines_cache

        # Count complete lines (lines that have been fully revealed)
        complete_lines = (
            len(lines) - 1
            if self.revealed_text_cache and not self.revealed_text_cache.endswith("\n")
            else len(lines)
        )

        # If we have more complete lines than can fit in the framebuffer, scroll up
        if complete_lines >= self.height:
            # Scroll to show the most recent lines
            self.scroll_position = complete_lines - self.height + 1

    def get_framebuffer(self):
        """Generate framebuffer with mirrored split-screen effect - chunked optimized"""
        if not self.current_code:
            # Pre-computed empty row for better performance
            empty_row = [(" ", "#2a2a2a")] * self.width
            return [empty_row.copy() for _ in range(self.height)]

        # Pre-compute empty character for padding
        empty_char = (" ", "#2a2a2a")

        # Update cache only if revealed_chars changed significantly
        if (
            abs(self.last_revealed_chars - self.revealed_chars) >= self.chars_per_update
            or self.last_revealed_chars == -1
        ):
            if self.revealed_chars > 0:
                self.revealed_text_cache = self.current_code[: self.revealed_chars]
                self.revealed_lines_cache = self.revealed_text_cache.split("\n")
            else:
                self.revealed_text_cache = ""
                self.revealed_lines_cache = []
            self.last_revealed_chars = self.revealed_chars

        # Use cached data
        lines = self.revealed_lines_cache
        half_width = self.width // 2
        framebuffer = []

        # Fill framebuffer with split-screen mirrored effect
        for y in range(self.height):
            # Calculate which line to show based on scroll position
            line_index = y + self.scroll_position

            if line_index < len(lines):
                line = lines[line_index]

                # Truncate line to fit in half width
                if len(line) > half_width:
                    line = line[:half_width]

                # Right side: normal text - optimized
                right_chars = []
                for char in line:
                    color = self._get_char_color_cached(char)
                    right_chars.append((char, color))

                # Pad right side to half width
                padding_needed = half_width - len(right_chars)
                right_chars.extend([empty_char] * padding_needed)

                # Left side: mirrored text - optimized
                left_chars = []
                for char, color in reversed(right_chars):
                    left_chars.append((self._mirror_character_cached(char), color))

                # Combine left (mirrored) + right (normal)
                row = left_chars + right_chars
            else:
                # Empty line - pre-computed
                row = [empty_char] * self.width

            framebuffer.append(row)

        return framebuffer

    # Cache for character colors to avoid repeated calculations
    _char_color_cache = {}

    def _get_char_color_cached(self, char):
        """Get color for a character based on its type - cached and optimized"""
        if char not in self._char_color_cache:
            if char.isalpha():
                color = "#4a4a4a"  # Keywords and identifiers - brighter
            elif char.isdigit():
                color = "#5a5a5a"  # Numbers - slightly brighter
            elif char in "()[]{}":
                color = "#606060"  # Brackets - more visible
            elif char in "+-*/=<>!&|":
                color = "#555555"  # Operators - visible
            elif char in "\"'":
                color = "#2a5a2a"  # String delimiters - brighter green
            elif char == "#":
                color = "#505050"  # Comments - medium brightness
            elif char in ".,;:":
                color = "#454545"  # Punctuation
            elif char in " \t":
                color = "#2a2a2a"  # Whitespace - dim
            else:
                color = "#404040"  # Other characters - medium dim

            self._char_color_cache[char] = color

        return self._char_color_cache[char]

    # Cache for mirrored characters
    _mirror_cache = {
        "(": ")",
        ")": "(",
        "[": "]",
        "]": "[",
        "{": "}",
        "}": "{",
        "<": ">",
        ">": "<",
        "/": "\\",
        "\\": "/",
    }

    def _mirror_character_cached(self, char):
        """Mirror directional characters for the split-screen effect - cached version"""
        return self._mirror_cache.get(char, char)

    def toggle_scrolling(self):
        """Toggle scrolling code effect on/off - same pattern as MatrixRain"""
        self.enabled = not self.enabled
        if self.enabled:
            self._load_next_source()
        else:
            # Reset state when disabled
            self.revealed_chars = 0
            self.scroll_position = 0
            self.scroll_timer = 0
            self.last_revealed_chars = -1

    def increase_framerate(self):
        """Increase scrolling code framerate (decrease update interval) - same pattern as MatrixRain"""
        if not self.enabled:
            return

        # Get current FPS as integer
        current_fps = round(1.0 / self.update_interval)

        # Increment by 1 FPS, maximum 10 FPS
        new_fps = min(10, current_fps + 1)
        self.update_interval = 1.0 / new_fps

    def decrease_framerate(self):
        """Decrease scrolling code framerate (increase update interval) - same pattern as MatrixRain"""
        if not self.enabled:
            return

        # Get current FPS as integer
        current_fps = round(1.0 / self.update_interval)

        # Decrement by 1 FPS, minimum 1 FPS
        new_fps = max(1, current_fps - 1)
        self.update_interval = 1.0 / new_fps

    def set_typing_speed(self, speed: float):
        """Set typing speed (characters per second) - works with framerate system"""
        if speed > 0:
            # Calculate how many characters per update to achieve desired speed
            fps = 1.0 / self.update_interval
            self.chars_per_update = max(1, int(speed / fps))

    def set_chunk_size(self, chunk_size: int):
        """Set how many characters to reveal per update"""
        self.chars_per_update = max(1, min(chunk_size, 10))  # Keep between 1-10

    def skip_to_next_source(self):
        """Skip to next source code immediately"""
        self._load_next_source()

    def get_stats(self):
        """Get statistics about discovered source functions"""
        if not self.source_functions:
            return "No source functions discovered"

        progress = (
            (self.revealed_chars / self.total_chars) * 100
            if self.total_chars > 0
            else 0
        )
        current_fps = (
            round(1.0 / self.update_interval) if self.update_interval > 0 else 0
        )
        actual_speed = self.chars_per_update * current_fps

        return f"Sources: {len(self.source_functions)} | Progress: {progress:.0f}% | Speed: {actual_speed:.0f} cps | FPS: {current_fps} | Chunk: {self.chars_per_update}"
