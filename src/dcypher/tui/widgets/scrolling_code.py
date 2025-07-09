"""
Scrolling Code Widget - OPTIMIZED VERSION
Displays random dcypher source code scrolling in the background with proper syntax highlighting
High-performance implementation with caching and optimizations
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
from rich.console import Console
from rich.syntax import Syntax
from rich.text import Text

try:
    import dill
    import dill.source

    dill_available = True
except ImportError:
    dill_available = False
    dill = None


class ScrollingCode:
    """
    OPTIMIZED Scrolling code effect controller that displays random dcypher source code
    Uses dill to extract source code from dcypher package functions and classes
    Features optimized character-by-character reveal with constant timing and proper syntax highlighting

    Performance improvements:
    - Cached syntax highlighting with invalidation
    - Pre-computed color mappings
    - Reduced string operations
    - Optimized character mirroring
    - Efficient line processing
    - Batch character reveals
    """

    def __init__(self, width: int = 80, height: int = 20):
        self.width = width
        self.height = height
        self.enabled = True

        # Saturation control (0-100%)
        self.saturation = 25  # Default 25% saturation for scrolling code

        # Timing control - much more conservative like MatrixRain
        self.last_update_time = 0
        self.update_interval = 0.5  # 0.5 seconds = 2 FPS default (same as MatrixRain)
        self.chars_per_update = 8  # Reveal more characters per update to compensate

        # Code content and reveal state - now persistent across sources
        self.combined_code = ""  # Persistent buffer containing all sources
        self.current_code = ""  # Current source being processed
        self.revealed_chars = 0
        self.total_chars = 0

        # OPTIMIZATION: Pre-computed values
        self.half_width = width // 2
        self.empty_char = (" ", "#2a2a2a")

        # OPTIMIZATION: Syntax highlighting cache with invalidation
        self.syntax_cache = {"code": "", "segments": [], "valid": False}

        # OPTIMIZATION: Pre-computed color mappings
        self.color_map = self._create_color_map()

        # OPTIMIZATION: Mirror character cache
        self.mirror_cache = {
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

        # Scrolling state
        self.scroll_position = 0
        self.lines_per_screen = height
        self.scroll_speed = 1
        self.scroll_delay = 0.5  # Match scroll delay to update interval
        self.scroll_timer = 0  # Track when to scroll

        # Source code collection
        self.source_functions = []
        self.current_source_index = 0  # Will be set randomly after collecting sources

        # Rich console for rendering syntax highlighting
        self.console = Console(width=width, legacy_windows=False)

        # OPTIMIZATION: Pre-compute Python keywords and builtins
        self.python_keywords = frozenset(
            {
                "def",
                "class",
                "if",
                "elif",
                "else",
                "for",
                "while",
                "try",
                "except",
                "finally",
                "with",
                "import",
                "from",
                "as",
                "return",
                "yield",
                "break",
                "continue",
                "pass",
                "raise",
                "assert",
                "del",
                "global",
                "nonlocal",
                "lambda",
                "and",
                "or",
                "not",
                "is",
                "in",
                "True",
                "False",
                "None",
            }
        )

        self.builtin_functions = frozenset(
            {
                "print",
                "len",
                "range",
                "enumerate",
                "zip",
                "map",
                "filter",
                "sum",
                "min",
                "max",
                "sorted",
                "reversed",
                "any",
                "all",
                "type",
                "isinstance",
                "hasattr",
                "getattr",
                "setattr",
                "delattr",
                "super",
                "open",
                "input",
            }
        )

        self._collect_dcypher_sources()
        self._load_next_source()

    def _create_color_map(self):
        """Create pre-computed color mappings for better performance"""
        return {
            "keyword": self._apply_saturation("#ff6b6b"),  # Bright red for keywords
            "builtin": self._apply_saturation(
                "#ffe66d"
            ),  # Yellow for built-in functions
            "function": self._apply_saturation("#4ecdc4"),  # Cyan for function names
            "class": self._apply_saturation("#4ecdc4"),  # Cyan for class names
            "string": self._apply_saturation("#95e1d3"),  # Light green for strings
            "comment": self._apply_saturation("#6c5ce7"),  # Purple for comments
            "number": self._apply_saturation("#ff6b6b"),  # Bright red for numbers
            "operator": self._apply_saturation("#ffe66d"),  # Yellow for operators
            "bracket": self._apply_saturation("#4ecdc4"),  # Cyan for brackets
            "punctuation": self._apply_saturation("#fd79a8"),  # Pink for punctuation
            "identifier": self._apply_saturation(
                "#00ff41"
            ),  # Matrix green for identifiers
            "other": self._apply_saturation(
                "#74b9ff"
            ),  # Light blue for other characters
            "whitespace": self._apply_saturation("#2a2a2a"),  # Dim for whitespace
        }

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
                            try:
                                if dill_available and dill is not None:
                                    dill.source.getsource(obj)
                                else:
                                    inspect.getsource(obj)
                                self.source_functions.append((modname, name, obj))
                            except (OSError, TypeError):
                                # Can't get source, skip this object
                                continue

                except Exception:
                    # Skip modules that can't be imported or processed
                    continue

            # Also add some built-in examples if we don't have much
            if len(self.source_functions) < 5:
                self._add_builtin_examples()

        except Exception:
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
        """Load the next source code for scrolling - now appends to combined buffer"""
        # If this is the first call and we have sources, select randomly
        if (
            self.source_functions
            and self.current_source_index == 0
            and self.current_code == ""
        ):
            self.current_source_index = random.randint(
                0, len(self.source_functions) - 1
            )

        if not self.source_functions:
            # Fallback code if no sources available
            new_source = self._get_fallback_code()
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

                new_source = f"# {module_name}.{obj_name}\n{source_code}"

            except Exception as e:
                # If we can't get source, create a descriptive placeholder
                obj_type = "class" if inspect.isclass(obj) else "function"
                new_source = f"""# {module_name}.{obj_name}
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

            # Move to next source for next time - select randomly
            if len(self.source_functions) > 1:
                # Avoid selecting the same source twice in a row
                available_indices = [
                    i
                    for i in range(len(self.source_functions))
                    if i != self.current_source_index
                ]
                self.current_source_index = random.choice(available_indices)
            else:
                self.current_source_index = 0

        # Append new source to combined buffer (with separator for first source)
        if self.combined_code:
            self.combined_code += "\n\n"

        # Add the new source to the combined code
        self.combined_code += new_source
        self.current_code = self.combined_code  # Use combined code for all operations

        # Update total characters but don't reset revealed chars (continue from where we left off)
        self.total_chars = len(self.combined_code)
        self.syntax_cache["valid"] = False  # Reset syntax highlighting cache

    def _get_fallback_code(self):
        """Get fallback code when no sources are available"""
        return """
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

    def _generate_syntax_highlighted_segments(self):
        """OPTIMIZED Generate properly syntax highlighted segments with caching"""
        # Check if cache is valid
        if (
            self.syntax_cache["valid"]
            and self.syntax_cache["code"] == self.current_code
        ):
            cached_segments = self.syntax_cache["segments"]
            # Type assertion to help the linter understand this is a list
            return cached_segments if isinstance(cached_segments, list) else []

        # Generate new segments
        segments = self._generate_optimized_highlighted_segments()

        # Update cache
        self.syntax_cache["code"] = self.current_code
        self.syntax_cache["segments"] = segments
        self.syntax_cache["valid"] = True

        return segments

    def _generate_optimized_highlighted_segments(self):
        """OPTIMIZED Enhanced Python-aware syntax highlighting with pre-computed colors"""
        lines = self.current_code.split("\n")
        segments = []

        for line in lines:
            line_segments = []
            i = 0
            in_string = False
            string_char = None
            in_comment = False

            while i < len(line):
                char = line[i]

                # Handle comments
                if char == "#" and not in_string:
                    in_comment = True
                    line_segments.append((char, self.color_map["comment"]))
                    i += 1
                    continue

                if in_comment:
                    line_segments.append((char, self.color_map["comment"]))
                    i += 1
                    continue

                # Handle strings
                if char in "\"'" and not in_string:
                    in_string = True
                    string_char = char
                    line_segments.append((char, self.color_map["string"]))
                    i += 1
                    continue
                elif char == string_char and in_string:
                    in_string = False
                    string_char = None
                    line_segments.append((char, self.color_map["string"]))
                    i += 1
                    continue
                elif in_string:
                    line_segments.append((char, self.color_map["string"]))
                    i += 1
                    continue

                # Handle keywords and identifiers
                if char.isalpha() or char == "_":
                    word_start = i
                    while i < len(line) and (line[i].isalnum() or line[i] == "_"):
                        i += 1
                    word = line[word_start:i]

                    if word in self.python_keywords:
                        color = self.color_map["keyword"]
                    elif word in self.builtin_functions:
                        color = self.color_map["builtin"]
                    elif self._is_function_def(line, word_start):
                        color = self.color_map["function"]
                    elif self._is_class_def(line, word_start):
                        color = self.color_map["class"]
                    else:
                        color = self.color_map["identifier"]

                    for c in word:
                        line_segments.append((c, color))
                    continue

                # Use optimized character coloring for everything else
                color = self._get_optimized_char_color(char)
                line_segments.append((char, color))
                i += 1

            segments.append(line_segments)

        return segments

    def _is_function_def(self, line, word_start):
        """Check if word is a function definition"""
        # Look for "def " before the word
        def_pos = line.find("def ")
        return def_pos != -1 and def_pos < word_start

    def _is_class_def(self, line, word_start):
        """Check if word is a class definition"""
        # Look for "class " before the word
        class_pos = line.find("class ")
        return class_pos != -1 and class_pos < word_start

    def _get_optimized_char_color(self, char):
        """OPTIMIZED Enhanced color mapping using pre-computed colors"""
        if char.isalpha():
            return self.color_map["identifier"]
        elif char.isdigit():
            return self.color_map["number"]
        elif char in "()[]{}":
            return self.color_map["bracket"]
        elif char in "+-*/=<>!&|":
            return self.color_map["operator"]
        elif char in "\"'":
            return self.color_map["string"]
        elif char == "#":
            return self.color_map["comment"]
        elif char in ".,;:":
            return self.color_map["punctuation"]
        elif char in " \t":
            return self.color_map["whitespace"]
        else:
            return self.color_map["other"]

    def _apply_saturation(self, hex_color: str) -> str:
        """OPTIMIZED Apply current saturation level to a hex color"""
        # Parse hex color
        if hex_color.startswith("#"):
            hex_color = hex_color[1:]

        r = int(hex_color[0:2], 16)
        g = int(hex_color[2:4], 16)
        b = int(hex_color[4:6], 16)

        # Convert RGB to HSL
        r_norm = r / 255.0
        g_norm = g / 255.0
        b_norm = b / 255.0

        max_val = max(r_norm, g_norm, b_norm)
        min_val = min(r_norm, g_norm, b_norm)
        diff = max_val - min_val

        # Calculate lightness
        lightness = (max_val + min_val) / 2.0

        if diff == 0:
            # Grayscale - no saturation to adjust
            return f"#{r:02x}{g:02x}{b:02x}"

        # Calculate saturation
        if lightness < 0.5:
            saturation = diff / (max_val + min_val)
        else:
            saturation = diff / (2.0 - max_val - min_val)

        # Calculate hue
        if max_val == r_norm:
            hue = (g_norm - b_norm) / diff
            if g_norm < b_norm:
                hue += 6
        elif max_val == g_norm:
            hue = (b_norm - r_norm) / diff + 2
        else:  # max_val == b_norm
            hue = (r_norm - g_norm) / diff + 4
        hue /= 6

        # Apply new saturation
        new_saturation = saturation * (self.saturation / 100.0)

        # Convert back to RGB
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

        if new_saturation == 0:
            new_r = new_g = new_b = lightness
        else:
            if lightness < 0.5:
                q = lightness * (1 + new_saturation)
            else:
                q = lightness + new_saturation - lightness * new_saturation
            p = 2 * lightness - q
            new_r = hue_to_rgb(p, q, hue + 1 / 3)
            new_g = hue_to_rgb(p, q, hue)
            new_b = hue_to_rgb(p, q, hue - 1 / 3)

        # Convert back to hex
        new_r = int(new_r * 255)
        new_g = int(new_g * 255)
        new_b = int(new_b * 255)

        return f"#{new_r:02x}{new_g:02x}{new_b:02x}"

    def update(self):
        """OPTIMIZED Update character-by-character reveal and scrolling animation"""
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
                highlighted_segments = self._generate_syntax_highlighted_segments()
                if (
                    self.scroll_position
                    <= len(highlighted_segments) - self.lines_per_screen
                ):
                    self.scroll_position += self.scroll_speed
                    self.scroll_timer = current_time
                else:
                    # Finished scrolling, load next source
                    self._load_next_source()

    def _check_and_scroll_during_reveal(self):
        """OPTIMIZED Check if we need to scroll during character revelation"""
        if self.revealed_chars == 0:
            return

        # Count complete lines that have been revealed
        revealed_text = self.current_code[: self.revealed_chars]
        complete_lines = revealed_text.count("\n") + 1  # More efficient than split()

        # If we have more complete lines than can fit in the framebuffer, scroll up
        if complete_lines > self.height:
            # Scroll to show the most recent lines
            self.scroll_position = complete_lines - self.height

    def get_framebuffer(self):
        """OPTIMIZED Generate framebuffer with mirrored split-screen effect"""
        if not self.current_code:
            # Pre-computed empty row for better performance
            empty_row = [self.empty_char] * self.width
            return [empty_row.copy() for _ in range(self.height)]

        # Get syntax highlighted segments
        highlighted_segments = self._generate_syntax_highlighted_segments()

        # Only show revealed portion - use slicing instead of split when possible
        if self.revealed_chars >= len(self.current_code):
            revealed_lines = self.current_code.split("\n")
        else:
            revealed_text = self.current_code[: self.revealed_chars]
            revealed_lines = revealed_text.split("\n")

        framebuffer = []

        # Fill framebuffer with split-screen mirrored effect
        for y in range(self.height):
            # Calculate which line to show based on scroll position
            line_index = y + self.scroll_position

            if line_index < len(revealed_lines) and line_index < len(
                highlighted_segments
            ):
                line = revealed_lines[line_index]
                line_segments = highlighted_segments[line_index]

                # Right side: normal text - fill the full half width properly
                right_chars = []
                for i in range(self.half_width):
                    if i < len(line):
                        char = line[i]
                        if i < len(line_segments):
                            right_chars.append(line_segments[i])
                        else:
                            # Fallback if segments don't match
                            color = self._get_optimized_char_color(char)
                            right_chars.append((char, color))
                    else:
                        # Pad with empty chars for proper centering
                        right_chars.append(self.empty_char)

                # Left side: mirrored text using cached mirror characters
                left_chars = []
                for char, color in reversed(right_chars):
                    mirrored_char = self.mirror_cache.get(char, char)
                    left_chars.append((mirrored_char, color))

                # Combine left (mirrored) + right (normal)
                row = left_chars + right_chars
            else:
                # Empty line - pre-computed
                row = [self.empty_char] * self.width

            framebuffer.append(row)

        return framebuffer

    def toggle_scrolling(self):
        """Toggle scrolling code effect on/off - preserves combined buffer"""
        self.enabled = not self.enabled
        if self.enabled:
            # If we have no content yet, load the first source
            if not self.combined_code:
                self._load_next_source()
        else:
            # When disabled, only reset scroll timer, keep the combined buffer
            self.scroll_timer = 0
            self.syntax_cache["valid"] = False

    def increase_framerate(self):
        """Increase scrolling code framerate (decrease update interval)"""
        if not self.enabled:
            return

        # Get current FPS as integer
        current_fps = round(1.0 / self.update_interval)

        # Increment by 1 FPS, maximum 10 FPS
        new_fps = min(10, current_fps + 1)
        self.update_interval = 1.0 / new_fps

    def decrease_framerate(self):
        """Decrease scrolling code framerate (increase update interval)"""
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
        """Skip to next source code immediately - appends to combined buffer"""
        self._load_next_source()

    def clear_buffer(self):
        """Clear the combined code buffer and start fresh"""
        self.combined_code = ""
        self.current_code = ""
        self.revealed_chars = 0
        self.total_chars = 0
        self.scroll_position = 0
        self.scroll_timer = 0
        self.syntax_cache["valid"] = False
        if self.enabled:
            self._load_next_source()

    def set_saturation(self, saturation: int):
        """Set saturation level (0-100%) and update color map"""
        self.saturation = max(0, min(100, saturation))
        # Regenerate color map with new saturation
        self.color_map = self._create_color_map()
        # Invalidate cache to force regeneration with new saturation
        self.syntax_cache["valid"] = False

    def increase_saturation(self):
        """Increase saturation by 10%"""
        self.set_saturation(self.saturation + 10)

    def decrease_saturation(self):
        """Decrease saturation by 10%"""
        self.set_saturation(self.saturation - 10)

    def get_stats(self):
        """Get statistics about discovered source functions and combined buffer"""
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

        # Calculate combined buffer stats
        combined_lines = self.combined_code.count("\n") + 1 if self.combined_code else 0

        return f"Sources: {len(self.source_functions)} | Lines: {combined_lines} | Progress: {progress:.0f}% | Speed: {actual_speed:.0f} cps | FPS: {current_fps} | Saturation: {self.saturation}%"
