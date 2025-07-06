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
from textual.color import Color
from rich.console import Console, ConsoleOptions
from rich.text import Text
from rich.align import Align
from rich.panel import Panel
from rich.syntax import Syntax
from rich.console import Console
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
    Scrolling code effect controller that displays random dcypher source code
    Uses dill to extract source code from dcypher package functions and classes
    Features character-by-character reveal with jitter support
    """

    def __init__(self, width: int = 80, height: int = 20):
        self.width = width
        self.height = height
        self.enabled = True

        # Timing control for character reveal
        self.last_update_time = 0
        self.update_interval = 0.05  # Base interval between characters (50ms)
        self.jitter_range = 0.03  # Random jitter ±30ms
        self.next_char_time = 0

        # Code content and reveal state
        self.current_code = ""
        self.current_code_lines = []
        self.syntax_highlighted_text = None
        self.revealed_chars = 0  # How many characters have been revealed
        self.total_chars = 0

        # Scrolling state
        self.scroll_position = 0
        self.lines_per_screen = height
        self.scroll_speed = 1  # Lines to scroll per update when scrolling
        self.scroll_delay = 0.5  # Delay between scroll steps

        # Source code collection
        self.source_functions = []
        self.current_source_index = 0

        # Rich console for syntax highlighting
        self.console = Console(width=width, legacy_windows=False)

        self._collect_dcypher_sources()

        # Load first source
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

        # Split into lines and reset scroll position
        self.current_code_lines = self.current_code.split("\n")
        self.scroll_position = 0
        self.revealed_chars = 0  # Reset character reveal

        # Generate syntax highlighted version
        self._generate_syntax_highlighting()

    def _generate_syntax_highlighting(self):
        """Generate syntax highlighted text using Rich for character-by-character reveal"""
        try:
            # Use Rich Syntax for Python highlighting
            syntax = Syntax(
                self.current_code,
                "python",
                theme="monokai",
                line_numbers=False,
                background_color="transparent",
                word_wrap=True,
                code_width=self.width,
            )

            # Render to Rich Text object
            self.syntax_highlighted_text = syntax

            # Calculate total characters for reveal animation
            self.total_chars = len(self.current_code)
            self.revealed_chars = 0

            # Reset timing for character reveal
            self.next_char_time = time.time() + self.update_interval

        except Exception as e:
            # Fallback to plain text if syntax highlighting fails
            self.syntax_highlighted_text = Text(self.current_code, style="dim green")
            self.total_chars = len(self.current_code)
            self.revealed_chars = 0
            self.next_char_time = time.time() + self.update_interval

    def update(self):
        """Update character-by-character reveal and scrolling animation"""
        if not self.enabled:
            return

        current_time = time.time()

        # Check if it's time to reveal the next character
        if self.revealed_chars < self.total_chars:
            if current_time >= self.next_char_time:
                self.revealed_chars += 1

                # Calculate next character time with jitter
                jitter = random.uniform(-self.jitter_range, self.jitter_range)
                self.next_char_time = current_time + self.update_interval + jitter

                # Check if we need to scroll during character revelation
                self._check_and_scroll_during_reveal()

        # Check if we need to continue scrolling after all characters are revealed
        elif self.revealed_chars >= self.total_chars:
            # All characters revealed, continue scrolling if needed
            if current_time - self.next_char_time > self.scroll_delay:
                # Get the revealed text as lines
                revealed_text = self.current_code[: self.revealed_chars]
                revealed_lines = revealed_text.split("\n")

                # Check if we need to scroll more
                if self.scroll_position < len(revealed_lines) - self.lines_per_screen:
                    self.scroll_position += self.scroll_speed
                    self.next_char_time = current_time  # Reset timer for next scroll
                else:
                    # Finished scrolling, load next source
                    self._load_next_source()

    def _check_and_scroll_during_reveal(self):
        """Check if we need to scroll during character revelation"""
        if self.revealed_chars == 0:
            return

        # Get the revealed text and split into lines
        revealed_text = self.current_code[: self.revealed_chars]
        revealed_lines = revealed_text.split("\n")

        # Count complete lines (lines that have been fully revealed)
        complete_lines = (
            len(revealed_lines) - 1
            if revealed_text and not revealed_text.endswith("\n")
            else len(revealed_lines)
        )

        # If we have more complete lines than can fit in the framebuffer, scroll up
        if complete_lines >= self.height:
            # Scroll to show the most recent lines
            self.scroll_position = complete_lines - self.height + 1

    def get_framebuffer(self):
        """Generate framebuffer with mirrored split-screen effect"""
        framebuffer = []

        if not self.syntax_highlighted_text:
            # Fill with empty characters if no content
            for y in range(self.height):
                row = []
                for x in range(self.width):
                    row.append((" ", "#2a2a2a"))
                framebuffer.append(row)
            return framebuffer

        # Split-screen mirrored framebuffer strategy
        try:
            # Get the text to reveal (up to revealed_chars)
            revealed_text = (
                self.current_code[: self.revealed_chars]
                if self.revealed_chars > 0
                else ""
            )

            # Split text into lines
            lines = revealed_text.split("\n")

            # Calculate half width for split screen
            half_width = self.width // 2

            # Fill framebuffer with split-screen mirrored effect
            for y in range(self.height):
                row = []

                # Calculate which line to show based on scroll position
                line_index = y + self.scroll_position

                if line_index < len(lines):
                    line = lines[line_index]

                    # Truncate line to fit in half width (no wrapping)
                    if len(line) > half_width:
                        line = line[:half_width]

                    # Right side: normal text (left to right)
                    right_chars = []
                    for char in line:
                        color = self._get_char_color(char)
                        right_chars.append((char, color))

                    # Pad right side to half width
                    while len(right_chars) < half_width:
                        right_chars.append((" ", "#2a2a2a"))

                    # Left side: mirrored text (right to left)
                    left_chars = []
                    for char, color in reversed(right_chars):
                        left_chars.append((self._mirror_character(char), color))

                    # Combine left (mirrored) + right (normal)
                    row = left_chars + right_chars
                else:
                    # Empty line (past end of content)
                    for _ in range(self.width):
                        row.append((" ", "#2a2a2a"))

                framebuffer.append(row)

        except Exception as e:
            # Fallback to simple split-screen effect
            for y in range(self.height):
                row = []

                # Calculate which characters to show on this line
                line_start_char = y * self.width

                for x in range(self.width):
                    char_pos = line_start_char + x

                    if char_pos < self.revealed_chars and char_pos < len(
                        self.current_code
                    ):
                        char = self.current_code[char_pos]
                        # Use very dim colors for background effect
                        row.append((char, "#303030"))
                    else:
                        row.append((" ", "#2a2a2a"))

                framebuffer.append(row)

        return framebuffer

    def _get_char_color(self, char):
        """Get color for a character based on its type"""
        if char.isalnum():
            return "#353535"  # Dimmer for background
        elif char in "()[]{}":
            return "#404040"  # Brackets
        elif char in "+-*/=<>":
            return "#383838"  # Operators
        elif char in "\"'":
            return "#2a4a2a"  # String delimiters in very dim green
        elif char == "#":
            return "#404040"  # Comments
        elif char in " \t":
            return "#2a2a2a"  # Whitespace
        else:
            return "#303030"  # Other characters very dim

    def _mirror_character(self, char):
        """Mirror directional characters for the split-screen effect"""
        mirror_map = {
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
        return mirror_map.get(char, char)

    def toggle_scrolling(self):
        """Toggle scrolling code effect on/off"""
        self.enabled = not self.enabled
        if self.enabled:
            self._load_next_source()

    def set_typing_speed(self, speed: float):
        """Set typing speed (characters per second)"""
        if speed > 0:
            self.update_interval = 1.0 / speed

    def set_jitter_range(self, jitter: float):
        """Set jitter range (±seconds)"""
        self.jitter_range = max(0, jitter)

    def set_scroll_speed(self, speed: int):
        """Set scrolling speed (lines per scroll step)"""
        self.scroll_speed = max(1, speed)

    def set_scroll_delay(self, delay: float):
        """Set delay between scroll steps (seconds)"""
        self.scroll_delay = max(0.1, delay)

    def skip_to_next_source(self):
        """Skip to next source code immediately"""
        self._load_next_source()

    def get_typing_stats(self):
        """Get current typing statistics"""
        if self.total_chars == 0:
            return "No code loaded"

        progress = (self.revealed_chars / self.total_chars) * 100
        chars_per_sec = 1.0 / self.update_interval if self.update_interval > 0 else 0

        return f"Progress: {progress:.1f}% ({self.revealed_chars}/{self.total_chars} chars) @ {chars_per_sec:.1f} cps"

    def get_stats(self):
        """Get statistics about discovered source functions"""
        if not self.source_functions:
            return "No source functions discovered"

        module_counts = {}
        for module_name, obj_name, obj in self.source_functions:
            module_counts[module_name] = module_counts.get(module_name, 0) + 1

        stats = f"Found {len(self.source_functions)} objects from {len(module_counts)} modules:\n"
        for module, count in sorted(module_counts.items()):
            stats += f"  {module}: {count} objects\n"

        return stats.strip()
