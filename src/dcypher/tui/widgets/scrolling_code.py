"""
Scrolling Code Widget - PYGMENTS/RICH OPTIMIZED
Uses Rich's Syntax class (Pygments under the hood) for professional syntax highlighting
Combined with targeted performance optimizations
"""

import random
import time
import os
import pkgutil
import inspect
import importlib
import sys
from pathlib import Path
from typing import List, Tuple, Any
from textual.widget import Widget
from textual.reactive import reactive
from textual.app import RenderResult
from rich.console import Console
from rich.syntax import Syntax
from rich.text import Text
from rich.style import Style

try:
    import dill
    import dill.source

    dill_available = True
except ImportError:
    dill_available = False
    dill = None


class ScrollingCode:
    """
    PYGMENTS-OPTIMIZED Scrolling code using Rich's Syntax class

    Key optimizations:
    1. Professional syntax highlighting via Rich/Pygments (once per source)
    2. Pre-split lines with caching
    3. Pre-allocated framebuffer rows
    4. Efficient character mirroring
    5. Minimal per-frame processing
    """

    def __init__(self, width: int = 80, height: int = 20):
        self.width = width
        self.height = height
        self.enabled = True

        # Timing control
        self.last_update_time = 0.0
        self.update_interval = 0.5
        self.chars_per_update = 8
        self.saturation = 25

        # OPTIMIZATION 1: Pre-computed constants
        self.left_width = width // 2
        self.right_width = width - self.left_width
        self.empty_char: Tuple[str, Style] = (" ", Style(color="#2a2a2a"))

        # OPTIMIZATION 2: Pre-allocated framebuffer rows (reuse same objects)
        self.framebuffer_rows: List[List[Tuple[str, Style]]] = [
            [self.empty_char for _ in range(self.width)] for _ in range(self.height)
        ]

        # OPTIMIZATION 3: Rich Console for syntax highlighting
        self.console = Console(width=width, legacy_windows=False, force_terminal=False)

        # OPTIMIZATION 4: Character mirroring as simple list for speed
        self.mirror_chars = [chr(i) for i in range(256)]  # Default: no change
        self._setup_mirroring()

        # OPTIMIZATION 5: Syntax highlighting cache (per source, not per line)
        self.highlighted_segments = []  # List of lines, each line is [(char, color), ...]
        self.highlight_valid = False
        self.current_syntax_hash = None

        # OPTIMIZATION 6: Pre-split lines cache
        self.lines_cache = []
        self.lines_valid = False

        # Code state
        self.combined_code = ""
        self.revealed_chars = 0
        self.total_chars = 0

        # Scrolling state
        self.scroll_position = 0
        self.scroll_speed = 1
        self.scroll_delay = 0.5
        self.scroll_timer = 0

        # Source collection
        self.source_functions = []
        self.current_source_index = 0

        self._collect_dcypher_sources()
        self._load_next_source()

    def _ensure_framebuffer_size(self):
        """Ensure framebuffer matches current width/height"""
        # Check if we need to resize the framebuffer
        if len(self.framebuffer_rows) != self.height or (
            self.framebuffer_rows and len(self.framebuffer_rows[0]) != self.width
        ):
            # Recreate framebuffer with current dimensions
            self.framebuffer_rows = [
                [self.empty_char for _ in range(self.width)] for _ in range(self.height)
            ]
            # Update pre-computed constants
            self.left_width = self.width // 2
            self.right_width = self.width - self.left_width

    def _setup_mirroring(self):
        """Setup character mirroring using simple array for O(1) access"""
        mirror_pairs = {
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

        for src, dst in mirror_pairs.items():
            self.mirror_chars[ord(src)] = dst

    def _invalidate_caches(self):
        """Invalidate all caches when code changes"""
        self.lines_valid = False
        self.highlight_valid = False

    def _get_lines(self):
        """Get lines with caching to avoid repeated splits"""
        if not self.lines_valid:
            self.lines_cache = self.combined_code.split("\n")
            self.lines_valid = True
        return self.lines_cache

    def _generate_rich_highlighting(self):
        """OPTIMIZED: Use Rich/Pygments for professional syntax highlighting"""
        # Create a hash to see if we need to re-highlight
        code_hash = hash(self.combined_code)
        if self.highlight_valid and self.current_syntax_hash == code_hash:
            return self.highlighted_segments

        # Use Rich's Syntax class for professional highlighting
        try:
            # Create syntax object - Rich auto-detects language or defaults to Python
            syntax = Syntax(
                self.combined_code,
                "python",  # Default to Python, Rich handles it well
                theme="monokai",  # Professional dark theme
                line_numbers=False,
                word_wrap=False,
                background_color="default",
            )

            # Render syntax to get Rich segments with proper colors
            console_options = self.console.options
            rendered_lines = self.console.render_lines(syntax, console_options)

            # Convert Rich segments to our format - use the Style objects directly!
            self.highlighted_segments = []
            for line in rendered_lines:
                line_segments = []
                for segment in line:
                    text = segment.text
                    style = segment.style or Style()  # Use Rich's Style object directly

                    # Add each character with the original Rich Style object
                    for char in text:
                        line_segments.append((char, style))

                self.highlighted_segments.append(line_segments)

        except Exception as e:
            # Fallback to plain text if Rich fails
            print(f"Rich highlighting failed: {e}")
            lines = self._get_lines()
            self.highlighted_segments = []
            default_style = Style(color="#74b9ff")  # Default blue
            for line in lines:
                line_segments = [(char, default_style) for char in line]
                self.highlighted_segments.append(line_segments)

        # Update cache state
        self.current_syntax_hash = code_hash
        self.highlight_valid = True
        return self.highlighted_segments

    def _convert_rich_text_to_segments(self, rich_text):
        """Convert Rich Text object to our segment format"""
        segments = []
        current_line = []

        # Rich Text has spans with style information
        for span in rich_text._spans:
            text = span.text
            style = span.style

            # Extract color from Rich style
            if style and hasattr(style, "color") and style.color:
                color = (
                    f"#{style.color.triplet.hex}"
                    if hasattr(style.color, "triplet")
                    else "#74b9ff"
                )
            else:
                color = "#74b9ff"  # Default color

            # Apply saturation to the color
            color = self._apply_saturation(color)

            # Process each character in the span
            for char in text:
                if char == "\n":
                    segments.append(current_line)
                    current_line = []
                else:
                    current_line.append((char, color))

        # Add the final line if it exists
        if current_line:
            segments.append(current_line)

        return segments

    def _apply_saturation(self, hex_color: str) -> str:
        """Fast saturation application"""
        if self.saturation == 100:
            return hex_color

        # Simple saturation scaling - much faster than full HSL conversion
        if hex_color.startswith("#"):
            hex_color = hex_color[1:]

        try:
            r = int(hex_color[0:2], 16)
            g = int(hex_color[2:4], 16)
            b = int(hex_color[4:6], 16)
        except (ValueError, IndexError):
            return "#74b9ff"  # Default color on parse error

        # Linear interpolation toward gray (128, 128, 128)
        factor = self.saturation / 100.0
        gray = 128

        r = int(gray + (r - gray) * factor)
        g = int(gray + (g - gray) * factor)
        b = int(gray + (b - gray) * factor)

        return f"#{r:02x}{g:02x}{b:02x}"

    def _collect_dcypher_sources(self):
        """Collect source functions (same as original)"""
        try:
            import dcypher

            self.source_functions = []

            for importer, modname, ispkg in pkgutil.walk_packages(
                dcypher.__path__, dcypher.__name__ + "."
            ):
                try:
                    module = importlib.import_module(modname)
                    for name, obj in inspect.getmembers(module):
                        if (
                            (inspect.isfunction(obj) or inspect.isclass(obj))
                            and hasattr(obj, "__module__")
                            and obj.__module__ == modname
                        ):
                            try:
                                if dill_available and dill is not None:
                                    dill.source.getsource(obj)
                                else:
                                    inspect.getsource(obj)
                                self.source_functions.append((modname, name, obj))
                            except (OSError, TypeError):
                                continue
                except Exception:
                    continue

            if len(self.source_functions) < 5:
                self._add_builtin_examples()
        except Exception:
            self.source_functions = []
            self._add_builtin_examples()

    def _add_builtin_examples(self):
        """Add fallback examples"""
        try:
            current_module = sys.modules[__name__]
            for name, obj in inspect.getmembers(current_module):
                if (
                    (inspect.isfunction(obj) or inspect.isclass(obj))
                    and hasattr(obj, "__module__")
                    and obj.__module__ == __name__
                ):
                    self.source_functions.append((__name__, name, obj))
        except Exception:
            pass

    def _load_next_source(self):
        """Load next source code"""
        if not self.source_functions:
            new_source = self._get_fallback_code()
        else:
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
                new_source = f"""# {module_name}.{obj_name}
# Source not available: {str(e)[:50]}...
def placeholder():
    pass
"""

            # Move to next source
            if len(self.source_functions) > 1:
                available_indices = [
                    i
                    for i in range(len(self.source_functions))
                    if i != self.current_source_index
                ]
                self.current_source_index = random.choice(available_indices)

        # Update combined buffer
        if self.combined_code:
            self.combined_code += "\n\n"
        self.combined_code += new_source
        self.total_chars = len(self.combined_code)

        # Invalidate caches
        self._invalidate_caches()

    def _get_fallback_code(self):
        """Fallback code"""
        return """# dCypher - Quantum-Resistant Encryption System
import random
import time
from typing import List, Optional

class CryptoSystem:
    def __init__(self):
        self.quantum_resistant = True
        self.lattice_based = True
        
    def encrypt(self, data: bytes) -> bytes:
        return b"encrypted_" + data
        
    def decrypt(self, ciphertext: bytes) -> bytes:
        return ciphertext[10:]

def generate_key(length: int = 32) -> bytes:
    return bytes(random.randint(0, 255) for _ in range(length))

class AdvancedCrypto:
    def __init__(self):
        self.algorithms = ["Kyber", "Dilithium", "SPHINCS+"]
    
    def process_data(self, data):
        # Complex processing logic
        for algorithm in self.algorithms:
            data = self._apply_algorithm(algorithm, data)
        return data
    
    def _apply_algorithm(self, alg, data):
        return f"{alg}({data})"
"""

    def update(self):
        """Update animation state"""
        if not self.enabled:
            return

        current_time = time.time()
        if current_time - self.last_update_time < self.update_interval:
            return

        self.last_update_time = current_time

        # Character revelation
        if self.revealed_chars < self.total_chars:
            remaining_chars = self.total_chars - self.revealed_chars
            chars_to_reveal = min(self.chars_per_update, remaining_chars)
            self.revealed_chars += chars_to_reveal
            self._update_scroll_position()

        # Continue scrolling after reveal
        elif self.revealed_chars >= self.total_chars:
            if self.scroll_timer == 0:
                self.scroll_timer = current_time

            if current_time - self.scroll_timer > self.scroll_delay:
                lines = self._get_lines()
                if self.scroll_position < len(lines) - self.height:
                    self.scroll_position += self.scroll_speed
                    self.scroll_timer = current_time
                else:
                    self._load_next_source()

    def _update_scroll_position(self):
        """Update scroll position efficiently"""
        if self.revealed_chars == 0:
            return

        # Count newlines in revealed text (faster than split)
        revealed_text = self.combined_code[: self.revealed_chars]
        complete_lines = revealed_text.count("\n") + 1

        if complete_lines > self.height:
            self.scroll_position = complete_lines - self.height

    def get_framebuffer(self):
        """OPTIMIZED: Generate framebuffer using Rich-highlighted segments"""
        if not self.combined_code:
            return [self.framebuffer_rows[i][:] for i in range(self.height)]

        # Check if we need to resize framebuffer
        self._ensure_framebuffer_size()

        # Get Rich-highlighted segments (cached)
        highlighted_segments = self._generate_rich_highlighting()
        lines = self._get_lines()

        # OPTIMIZATION: Reuse framebuffer row objects
        for y in range(self.height):
            # Clear row efficiently
            row = self.framebuffer_rows[y]
            for x in range(self.width):
                row[x] = self.empty_char

            line_index = y + self.scroll_position
            if line_index >= len(lines) or line_index >= len(highlighted_segments):
                continue

            line_text = lines[line_index]

            # Calculate if this line is revealed
            lines_before = line_index
            chars_before = sum(
                len(lines[i]) + 1 for i in range(lines_before)
            )  # +1 for \n
            chars_after = chars_before + len(line_text)

            if chars_before >= self.revealed_chars:
                continue  # Line not revealed yet

            # Clamp line to revealed characters
            if chars_after > self.revealed_chars:
                revealed_chars_in_line = self.revealed_chars - chars_before
                revealed_chars_in_line = max(
                    0, min(revealed_chars_in_line, len(line_text))
                )
            else:
                revealed_chars_in_line = len(line_text)

            if revealed_chars_in_line <= 0:
                continue

            # Get highlighted segments for this line
            line_segments = (
                highlighted_segments[line_index]
                if line_index < len(highlighted_segments)
                else []
            )

            # Ensure we have segments for revealed characters
            segments_to_show = line_segments[:revealed_chars_in_line]

            # OPTIMIZATION: Process right side efficiently
            right_end = min(self.right_width, len(segments_to_show))
            for i in range(right_end):
                char, color = segments_to_show[i]
                row[self.left_width + i] = (char, color)

            # OPTIMIZATION: Process left side (mirrored) efficiently - right-aligned against center
            mirror_count = min(self.left_width, right_end)
            for i in range(mirror_count):
                src_idx = i  # Take characters in forward order from right side
                char, color = segments_to_show[src_idx]
                mirrored_char = self.mirror_chars[ord(char)]
                # Place mirrored text right-aligned against the center divider
                # Start from the rightmost position of left half and work leftward
                left_pos = self.left_width - 1 - i
                row[left_pos] = (mirrored_char, color)

        # Return the reused row objects (they're already updated in place)
        return self.framebuffer_rows

    # Interface methods (same as original)
    def toggle_scrolling(self):
        self.enabled = not self.enabled
        if self.enabled and not self.combined_code:
            self._load_next_source()

    def increase_framerate(self):
        if not self.enabled:
            return
        current_fps = round(1.0 / self.update_interval)
        new_fps = min(10, current_fps + 1)
        self.update_interval = 1.0 / new_fps

    def decrease_framerate(self):
        if not self.enabled:
            return
        current_fps = round(1.0 / self.update_interval)
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
        self.revealed_chars = 0
        self.total_chars = 0
        self.scroll_position = 0
        self.scroll_timer = 0
        self._invalidate_caches()
        if self.enabled:
            self._load_next_source()

    def set_saturation(self, saturation: int):
        """Set saturation level (0-100%) and update color map"""
        self.saturation = max(0, min(100, saturation))
        # Force re-highlighting with new saturation
        self.highlight_valid = False

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
        lines = self._get_lines()

        return f"Sources: {len(self.source_functions)} | Lines: {len(lines)} | Progress: {progress:.0f}% | Speed: {actual_speed:.0f} cps | FPS: {current_fps} | Saturation: {self.saturation}%"
