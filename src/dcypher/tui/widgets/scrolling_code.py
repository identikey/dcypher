"""
Scrolling Code Widget - Simplified Implementation
Syntax highlights code once, then reveals random chunks from the top.
Right half shows normal text, left half shows mirrored text.
"""

import random
import time
import os
import pkgutil
import inspect
import importlib
import sys
from pathlib import Path
from typing import List, Tuple, Any, Optional, Dict
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

# Import profiling tools
try:
    from dcypher.lib.profiling import profile, profile_block, create_animation_profiler

    profiling_available = True
except ImportError:
    # Create no-op decorators if profiling not available
    from typing import Any
    from contextlib import nullcontext

    def profile(name: Any = None, backend: str = "cprofile"):  # type: ignore
        return lambda func: func

    def profile_block(name: Any, backend: str = "cprofile"):  # type: ignore
        return nullcontext()

    def create_animation_profiler():  # type: ignore
        return None

    profiling_available = False


# PERFORMANCE OPTIMIZATION: Module-level cache for source code discovery
# This prevents expensive module walking on every widget instantiation
_global_source_cache: Optional[List[Tuple[str, str, Any]]] = None
_cache_lock = False  # Simple flag to prevent concurrent cache population


# Character mirroring lookup table
_MIRROR_LOOKUP = {}
for src, dst in [
    ("(", ")"),
    (")", "("),
    ("[", "]"),
    ("]", "["),
    ("{", "}"),
    ("}", "{"),
    ("<", ">"),
    (">", "<"),
    ("/", "\\"),
    ("\\", "/"),
]:
    _MIRROR_LOOKUP[ord(src)] = dst


def _populate_global_source_cache() -> List[Tuple[str, str, Any]]:
    """
    PERFORMANCE OPTIMIZATION: Populate the global source cache once per process.
    This expensive operation (module discovery) now happens only once instead of
    once per widget instance.
    """
    global _global_source_cache, _cache_lock

    # Prevent concurrent cache population
    if _cache_lock:
        # If another thread is populating, wait and return existing cache
        import time

        retries = 0
        while _cache_lock and retries < 10:
            time.sleep(0.01)
            retries += 1
        return _global_source_cache or []

    if _global_source_cache is not None:
        return _global_source_cache

    _cache_lock = True
    sources = []

    try:
        import dcypher

        for importer, modname, ispkg in pkgutil.walk_packages(
            dcypher.__path__, dcypher.__name__ + "."
        ):
            try:
                module = importlib.import_module(modname)
                for name, obj in inspect.getmembers(module):
                    # FULLY INCLUSIVE approach: Get source from everything interesting
                    if (
                        hasattr(obj, "__module__")
                        and obj.__module__ == modname
                        and not name.startswith("_")  # Skip private classes/functions
                        and not name.isupper()  # Skip constants
                    ):
                        # Include everything: functions, classes, instances, TUI widgets, etc.
                        sources.append((modname, name, obj))
            except Exception:
                continue
    except Exception:
        pass

    # Add fallback if no sources found
    if not sources:
        sources = _get_fallback_sources()

    _global_source_cache = sources
    _cache_lock = False
    return sources


def _get_fallback_sources() -> List[Tuple[str, str, Any]]:
    """Get fallback source code examples"""
    fallback_code = """# dCypher - Quantum-Resistant Encryption System
import random
import time
from typing import List, Optional

class CryptoSystem:
    def __init__(self):
        self.quantum_resistant = True
        self.lattice_based = True
        
    def encrypt(self, data: bytes) -> bytes:
        '''Encrypt data using quantum-resistant algorithms'''
        return b"encrypted_" + data
        
    def decrypt(self, ciphertext: bytes) -> bytes:
        '''Decrypt ciphertext safely'''
        return ciphertext[10:]

def generate_key(length: int = 32) -> bytes:
    '''Generate cryptographically secure key'''
    return bytes(random.randint(0, 255) for _ in range(length))

class AdvancedCrypto:
    def __init__(self):
        self.algorithms = ["Kyber", "Dilithium", "SPHINCS+"]
    
    def process_data(self, data):
        # Apply multiple quantum-resistant algorithms
        for algorithm in self.algorithms:
            data = self._apply_algorithm(algorithm, data)
        return data
    
    def _apply_algorithm(self, alg, data):
        return f"{alg}({data})"

# Lattice-based cryptography implementation
class LatticeBasedCrypto:
    def __init__(self, dimension: int = 512):
        self.dimension = dimension
        self.noise_parameter = 3.2
        
    def generate_lattice(self):
        '''Generate random lattice for encryption'''
        return [[random.randint(0, 100) for _ in range(self.dimension)] 
                for _ in range(self.dimension)]
"""
    return [("fallback", "crypto_example", lambda: fallback_code)]


def clear_global_source_cache():
    """
    Clear the global source cache to force re-discovery of modules.
    Useful for development when modules are added/changed.
    """
    global _global_source_cache, _cache_lock
    _global_source_cache = None
    _cache_lock = False


class ScrollingCode:
    """
    Simplified scrolling code widget that:
    1. Syntax highlights code once at the beginning
    2. Reveals random chunks of characters from the top
    3. Displays on right half (normal) and left half (mirrored)
    4. Uses simple framebuffer matching panel dimensions
    """

    def __init__(self, width: int = 80, height: int = 20):
        self._width = width
        self._height = height
        self.enabled = True

        # Timing control
        self.last_update_time = 0.0
        self.update_interval = 0.5  # 2 FPS default - controlled by global keybindings
        self.min_chunk_size = 5
        self.max_chunk_size = 25

        # Layout
        self.center_x = width // 2

        # Saturation (for compatibility with existing code)
        self.saturation = 75

        # Performance optimization: cached objects
        self._source_switch_time = 0.0
        self._cached_empty_style = Style(color="#2a2a2a")
        self._cached_default_style = Style(color="#74b9ff")

        # RUNTIME OPTIMIZATION: Pre-compute expensive operations
        self._ord_cache = {}  # Cache ord() calls for character mirroring
        self._last_total_chars = 0  # Cache total character count
        self._display_cache_valid = False  # Track if display lines are valid
        self._cached_line_lengths = []  # Cache line lengths
        self._last_revealed_chars = 0  # Track last revealed character count

        # Framebuffer: list of rows, each row is list of (char, style) tuples
        self.framebuffer: List[List[Tuple[str, Style]]] = []
        self._initialize_framebuffer()

        # Code state - Initialize before loading sources
        self.highlighted_lines: List[
            List[Tuple[str, Style]]
        ] = []  # Pre-highlighted code lines
        self.revealed_chars = 0  # How many characters have been revealed
        self.display_lines: List[str] = []  # Currently visible lines as plain text
        self.display_lines_styled: List[
            List[Tuple[str, Style]]
        ] = []  # Rich styling preserved

        # Terminal-style scrolling state
        self.scroll_offset = 0  # Which line to start displaying from

        # Source management
        self.source_functions = []
        self.current_source_index = 0

        # Console for rendering
        self.console = Console(width=width, color_system="truecolor")

        # Character mirroring
        self.mirror_chars = [chr(i) for i in range(256)]
        for char_code, mirrored in _MIRROR_LOOKUP.items():
            if char_code < 256:
                self.mirror_chars[char_code] = mirrored

        # Initialize with first source - ensure this happens last
        self._collect_sources()
        self._load_and_highlight_source()

        # Ensure we start with a clean state
        self.revealed_chars = 0
        self._source_switch_time = 0.0

    @property
    def width(self) -> int:
        """Get the width"""
        return self._width

    @width.setter
    def width(self, value: int):
        """Set the width and resize framebuffer"""
        if value != self._width:
            self._width = value
            self.center_x = value // 2
            self._initialize_framebuffer()
            self.console = Console(width=value, color_system="truecolor")

    @property
    def height(self) -> int:
        """Get the height"""
        return self._height

    @height.setter
    def height(self, value: int):
        """Set the height and resize framebuffer"""
        if value != self._height:
            self._height = value
            self._initialize_framebuffer()

    def _initialize_framebuffer(self):
        """Initialize framebuffer with empty characters"""
        empty_style = Style(color="#2a2a2a")
        self.framebuffer = [
            [(" ", empty_style) for _ in range(self._width)]
            for _ in range(self._height)
        ]

    def _collect_sources(self):
        """PERFORMANCE OPTIMIZED: Use global source cache instead of expensive module discovery"""
        # Use the global cache - this eliminates expensive module walking
        self.source_functions = _populate_global_source_cache().copy()

    def _load_and_highlight_source(self):
        """Load source code and syntax highlight it once"""
        if not self.source_functions:
            return

        # RANDOMIZATION: Pick a random source instead of cycling
        if len(self.source_functions) > 1:
            # Avoid picking the same source twice in a row
            available_indices = [
                i
                for i in range(len(self.source_functions))
                if i != self.current_source_index
            ]
            if available_indices:
                self.current_source_index = random.choice(available_indices)
            else:
                # Fallback if somehow we only have one source
                self.current_source_index = 0

        # Get current source
        module_name, obj_name, obj = self.source_functions[self.current_source_index]

        try:
            if (
                callable(obj)
                and hasattr(obj, "__call__")
                and not hasattr(obj, "__code__")
            ):
                # It's a lambda that returns code
                source_code = obj()
            elif dill_available and dill is not None:
                # ENHANCED: Use dill's comprehensive source extraction capabilities
                source_code = self._extract_source_with_dill(obj, module_name, obj_name)
            else:
                # Enhanced fallback using inspect with multiple strategies
                source_code = self._extract_source_with_inspect(
                    obj, module_name, obj_name
                )

            source_code = f"# {module_name}.{obj_name}\n{source_code}"
        except Exception as e:
            # If all else fails, create a meaningful placeholder with object inspection
            source_code = self._create_fallback_source(obj, module_name, obj_name, e)

        # BEHAVIOR CHANGE: Append new source instead of replacing
        if self.highlighted_lines:  # If we already have content
            # Add the new source with a separator comment
            separator_line = f"\n# ═══ {module_name}.{obj_name} ═══\n{source_code}"
        else:
            # First source - no separator needed
            separator_line = source_code

        # Syntax highlight the new source
        try:
            syntax = Syntax(
                separator_line,
                "python",
                theme="monokai",
                line_numbers=False,
                word_wrap=False,
                background_color="default",
            )

            rendered_lines = self.console.render_lines(syntax, self.console.options)

            # Convert Rich segments to our format and append to existing content
            new_lines = []
            for line in rendered_lines:
                line_chars = []
                for segment in line:
                    if segment.text:
                        style = (
                            segment.style if segment.style else Style(color="#74b9ff")
                        )
                        for char in segment.text:
                            line_chars.append((char, style))
                new_lines.append(line_chars)

            # Append new lines to existing content
            self.highlighted_lines.extend(new_lines)

        except Exception as e:
            # Fallback to plain text with simple styling
            lines = separator_line.split("\n")
            default_style = Style(color="#74b9ff")
            new_lines = [[(char, default_style) for char in line] for line in lines]
            # Append fallback lines to existing content
            self.highlighted_lines.extend(new_lines)

        # Reset source switch timer to prevent immediate switching
        self._source_switch_time = 0.0

        # RUNTIME OPTIMIZATION: Invalidate caches when new content added
        self._display_cache_valid = False
        if hasattr(self, "_cached_line_lengths"):
            del self._cached_line_lengths

    def _extract_source_with_dill(self, obj, module_name: str, obj_name: str) -> str:
        """Extract source code using dill's advanced capabilities"""
        if not dill_available or dill is None:
            return self._extract_source_with_inspect(obj, module_name, obj_name)

        # Try multiple dill strategies for different object types

        # Strategy 1: Direct source extraction
        try:
            return dill.source.getsource(obj)
        except (OSError, TypeError):
            pass

        # Strategy 2: For instances, get class source + instance state
        if hasattr(obj, "__class__") and not inspect.isclass(obj):
            try:
                class_source = dill.source.getsource(obj.__class__)
                instance_repr = repr(obj)
                return f"{class_source}\n\n# Instance: {instance_repr}"
            except (OSError, TypeError):
                pass

        # Strategy 3: Use dill.source.importable for complex objects
        try:
            importable_str = dill.source.importable(obj, alias=obj_name)
            return f"# Importable representation:\n{importable_str}"
        except (OSError, TypeError):
            pass

        # Strategy 4: Get related objects and their sources
        if hasattr(dill, "detect"):
            try:
                global_vars = dill.detect.globalvars(obj) if callable(obj) else {}
                if global_vars:
                    related_code = []
                    for name, related_obj in list(global_vars.items())[
                        :3
                    ]:  # Limit to 3
                        try:
                            related_source = dill.source.getsource(related_obj)
                            related_code.append(f"# Related: {name}\n{related_source}")
                        except:
                            pass
                    if related_code:
                        return "\n\n".join(related_code)
            except:
                pass

        # Strategy 5: Create a meaningful representation
        obj_type = type(obj).__name__
        obj_module = getattr(obj, "__module__", "unknown")
        obj_repr = repr(obj)[:200] + "..." if len(repr(obj)) > 200 else repr(obj)

        return f"""# {obj_type} from {obj_module}
# Representation: {obj_repr}

# Unable to extract source directly, but this object exists in the codebase
class {obj_type}Placeholder:
    '''Placeholder representing {obj_name} of type {obj_type}'''
    def __init__(self):
        # This represents: {obj_repr}
        pass
"""

    def _extract_source_with_inspect(self, obj, module_name: str, obj_name: str) -> str:
        """Extract source code using inspect with multiple fallback strategies"""

        # Strategy 1: Direct inspect.getsource
        try:
            return inspect.getsource(obj)
        except (OSError, TypeError):
            pass

        # Strategy 2: For instances, get class source
        if hasattr(obj, "__class__") and not inspect.isclass(obj):
            try:
                class_source = inspect.getsource(obj.__class__)
                instance_info = (
                    f"# Instance of {obj.__class__.__name__}: {repr(obj)[:100]}"
                )
                return f"{instance_info}\n{class_source}"
            except (OSError, TypeError):
                pass

        # Strategy 3: For callables, try to get related info
        if callable(obj):
            try:
                if hasattr(obj, "__code__"):
                    code_info = (
                        f"# Function: {obj.__name__} in {obj.__code__.co_filename}"
                    )
                    return f"{code_info}\n# Source not directly available\ndef {obj.__name__}(): pass"
                elif hasattr(obj, "__call__"):
                    return f"# Callable object: {obj}\n# Source not directly available\nclass CallableWrapper: pass"
            except:
                pass

        # Strategy 4: Create meaningful representation based on object type
        return self._create_object_representation(obj, obj_name)

    def _create_fallback_source(
        self, obj, module_name: str, obj_name: str, error: Exception
    ) -> str:
        """Create a meaningful fallback source representation when all else fails"""
        error_msg = str(error)[:100] if str(error) else "Unknown error"
        obj_type = type(obj).__name__
        obj_repr = repr(obj)[:150] + "..." if len(repr(obj)) > 150 else repr(obj)

        # Try to extract useful information about the object
        obj_info = []

        # Get object attributes (non-private ones)
        try:
            attrs = [attr for attr in dir(obj) if not attr.startswith("_")][:5]
            if attrs:
                obj_info.append(f"# Key attributes: {', '.join(attrs)}")
        except:
            pass

        # Get docstring if available
        try:
            doc = getattr(obj, "__doc__", None)
            if doc:
                doc_preview = doc.strip().split("\n")[0][:80]
                obj_info.append(f"# Doc: {doc_preview}")
        except:
            pass

        # Get module info
        try:
            obj_module = getattr(obj, "__module__", "unknown")
            obj_info.append(f"# Module: {obj_module}")
        except:
            pass

        info_lines = (
            "\n".join(obj_info) if obj_info else "# No additional info available"
        )

        return f"""# {module_name}.{obj_name}
# Error extracting source: {error_msg}
# Object type: {obj_type}
# Representation: {obj_repr}
{info_lines}

# Placeholder for analysis
class {obj_type}Analysis:
    '''Generated analysis for {obj_name}'''
    def __init__(self):
        self.name = "{obj_name}"
        self.type = "{obj_type}"
        self.module = "{module_name}"
        # Add more analysis here
        pass
    
    def analyze(self):
        '''Analyze the original object'''
        return "Analysis of {obj_name}"
"""

    def _create_object_representation(self, obj, obj_name: str) -> str:
        """Create a code representation of an object based on its properties"""
        obj_type = type(obj).__name__

        # Handle common object types
        if inspect.ismodule(obj):
            return f"# Module: {obj.__name__}\nimport {obj.__name__}"

        elif hasattr(obj, "__dict__"):
            # Object with attributes
            attrs = {k: v for k, v in obj.__dict__.items() if not k.startswith("_")}
            attr_lines = []
            for k, v in list(attrs.items())[:5]:  # Limit to 5 attributes
                attr_lines.append(f"    self.{k} = {repr(v)[:50]}")

            attr_init = "\n".join(attr_lines) if attr_lines else "    pass"
            return f"""class {obj_type}:
    '''Reconstructed from object analysis'''
    def __init__(self):
{attr_init}
"""

        else:
            # Simple object
            return f"""# {obj_type}: {obj_name}
{obj_name} = {repr(obj)[:100]}
"""

    def update(self, current_time: Optional[float] = None):
        """Update animation - reveal random chunks of characters"""
        if not self.enabled or not self.highlighted_lines:
            return

        now = current_time if current_time is not None else time.time()
        if now - self.last_update_time < self.update_interval:
            return

        self.last_update_time = now

        # RUNTIME OPTIMIZATION: Cache total character calculation
        total_chars = self._get_cached_total_chars()

        # DEBUG: Prevent premature switching on empty/small content
        if total_chars < 10:  # Too small - might be initialization issue
            return

        if self.revealed_chars >= total_chars:
            # PERFORMANCE FIX: Don't switch sources immediately, add delay
            # Only append new source every 1 second after completion
            if self._source_switch_time == 0.0:
                self._source_switch_time = now
            elif now - self._source_switch_time > 1.0:
                # Ensure we have substantial content before switching
                if total_chars > 50:  # Only switch if we had real content
                    self._load_and_highlight_source()
                    self._source_switch_time = 0.0  # Reset for next cycle
                else:
                    # If content was too small, reset and try again
                    self._source_switch_time = 0.0
                    self.revealed_chars = 0
            return

        # Reveal a random chunk of characters
        chunk_size = random.randint(self.min_chunk_size, self.max_chunk_size)
        self.revealed_chars = min(self.revealed_chars + chunk_size, total_chars)

        # Convert revealed characters to display lines
        self._update_display_lines()

        # Render to framebuffer
        self._render_to_framebuffer()

    def _get_cached_total_chars(self) -> int:
        """RUNTIME OPTIMIZATION: Cache expensive total character calculation"""
        current_line_count = len(self.highlighted_lines)

        # Only recalculate if lines changed
        if current_line_count != len(getattr(self, "_cached_line_lengths", [])):
            self._cached_line_lengths = [len(line) for line in self.highlighted_lines]
            self._last_total_chars = sum(self._cached_line_lengths)

        return self._last_total_chars

    def _update_display_lines(self):
        """Convert revealed characters to display lines with Rich styling preserved"""
        # RUNTIME OPTIMIZATION: Skip if nothing changed
        if self._display_cache_valid and hasattr(self, "_last_revealed_chars"):
            if self._last_revealed_chars == self.revealed_chars:
                return

        chars_processed = 0
        self.display_lines = []
        self.display_lines_styled = []

        # RUNTIME OPTIMIZATION: Use cached line lengths
        line_lengths = getattr(
            self, "_cached_line_lengths", [len(line) for line in self.highlighted_lines]
        )

        for i, line_chars in enumerate(self.highlighted_lines):
            line_length = line_lengths[i] if i < len(line_lengths) else len(line_chars)

            if chars_processed + line_length <= self.revealed_chars:
                # Full line revealed - OPTIMIZED: Build string once
                line_text = "".join(char for char, style in line_chars)
                self.display_lines.append(line_text)
                self.display_lines_styled.append(line_chars)
                chars_processed += line_length
            elif chars_processed < self.revealed_chars:
                # Partial line revealed - preserve styling for revealed portion
                chars_in_line = self.revealed_chars - chars_processed
                if chars_in_line > 0:
                    line_chars_revealed = line_chars[:chars_in_line]
                    line_text = "".join(char for char, style in line_chars_revealed)
                    self.display_lines.append(line_text)
                    self.display_lines_styled.append(line_chars_revealed)
                break
            else:
                break

        # Terminal-style scrolling: adjust scroll offset when content grows
        total_display_lines = len(self.display_lines)
        if total_display_lines > self.scroll_offset + self._height:
            # New content appeared - scroll down to show it
            self.scroll_offset = total_display_lines - self._height

        # Mark cache as valid
        self._display_cache_valid = True
        self._last_revealed_chars = self.revealed_chars

    def _render_to_framebuffer(self):
        """Render display lines to framebuffer with terminal-style scrolling"""
        # PERFORMANCE FIX: Cache property access and reuse Style objects
        width = self._width  # Cache to avoid 272 property calls
        height = self._height  # Cache to avoid property calls

        # PERFORMANCE FIX: Use pre-initialized Style object
        empty_style = self._cached_empty_style

        # Clear framebuffer efficiently
        for row in self.framebuffer:
            for i in range(len(row)):
                row[i] = (" ", empty_style)

        # Terminal-style scrolling: show a window of lines starting from scroll_offset
        start_line = max(0, self.scroll_offset)
        end_line = start_line + height

        visible_lines = self.display_lines[start_line:end_line]
        visible_styled = (
            self.display_lines_styled[start_line:end_line]
            if hasattr(self, "display_lines_styled")
            else []
        )

        # Render each visible line
        for row_idx, line in enumerate(visible_lines):
            if row_idx >= height:
                break

            self._render_line_to_row(line, row_idx, width, visible_styled)

    def _render_line_to_row(self, line: str, row_idx: int, width: int, visible_styled):
        """Render a single line to a framebuffer row with mirroring"""
        row = self.framebuffer[row_idx]

        # PERFORMANCE FIX: Cache center_x calculation
        center_x = self.center_x

        # Get the styled characters for this line if available
        if visible_styled and row_idx < len(visible_styled):
            styled_chars = visible_styled[row_idx]
        else:
            # Fallback to default styling
            styled_chars = [(char, self._cached_default_style) for char in line]

        # RUNTIME OPTIMIZATION: Batch character processing to reduce function calls
        styled_chars_len = len(styled_chars)

        # Right half - normal text, truncated at framebuffer edge
        right_start = center_x
        right_chars_to_show = min(styled_chars_len, width - right_start)

        for i in range(right_chars_to_show):
            char, style = styled_chars[i]
            row[right_start + i] = (char, style)

        # Left half - mirrored text, equal and truncated at left edge
        left_chars_to_show = min(styled_chars_len, center_x)

        for i in range(left_chars_to_show):
            char, style = styled_chars[i]

            # RUNTIME OPTIMIZATION: Cache ord() calls
            char_code = ord(char)
            if char_code not in self._ord_cache:
                self._ord_cache[char_code] = (
                    self.mirror_chars[char_code] if char_code < 256 else char
                )
            mirrored_char = self._ord_cache[char_code]

            row[center_x - 1 - i] = (mirrored_char, style)

    def get_framebuffer(self):
        """Get the current framebuffer for rendering"""
        return self.framebuffer

    def resize(self, width: int, height: int):
        """Resize the widget and framebuffer"""
        self.width = width
        self.height = height

    # Control methods
    def toggle_scrolling(self):
        """Toggle scrolling on/off"""
        self.enabled = not self.enabled

    def skip_to_next_source(self):
        """Skip to next source immediately - now randomized"""
        self._load_and_highlight_source()

    def set_speed(self, interval: float):
        """Set update interval (lower = faster)"""
        self.update_interval = max(0.1, interval)

    def set_chunk_size(self, min_size: int, max_size: int):
        """Set chunk size range for character revelation"""
        self.min_chunk_size = max(1, min_size)
        self.max_chunk_size = max(self.min_chunk_size, max_size)

    def clear_and_reload(self):
        """Clear display and reload current source"""
        self._load_and_highlight_source()

    def clear_buffer(self):
        """Clear the display buffer and start fresh"""
        self.highlighted_lines = []
        self.revealed_chars = 0
        self.display_lines = []
        self.display_lines_styled = []  # Clear styled lines too
        self.scroll_offset = 0  # Reset scroll position
        self._source_switch_time = 0.0
        # Load first source to restart
        if self.enabled:
            self._load_and_highlight_source()
            # Give some time for proper initialization
            self.last_update_time = time.time()

    def set_saturation(self, saturation: int):
        """Set saturation level (0-100%) - for compatibility"""
        self.saturation = max(0, min(100, saturation))

    def increase_saturation(self):
        """Increase saturation by 10% - for compatibility"""
        self.saturation = min(100, self.saturation + 10)

    def decrease_saturation(self):
        """Decrease saturation by 10% - for compatibility"""
        self.saturation = max(0, self.saturation - 10)

    def get_stats(self):
        """Get current statistics"""
        total_chars = (
            sum(len(line) + 1 for line in self.highlighted_lines)
            if self.highlighted_lines
            else 0
        )
        progress = (self.revealed_chars / total_chars * 100) if total_chars > 0 else 0

        return (
            f"Sources: {len(self.source_functions)} | "
            f"Lines: {len(self.display_lines)} | "
            f"Progress: {progress:.0f}% | "
            f"Chunks: {self.min_chunk_size}-{self.max_chunk_size}"
        )


# Factory function for creating optimized instances
def create_scrolling_code(width: int = 80, height: int = 20) -> ScrollingCode:
    """
    Create a new ScrollingCode instance with comprehensive optimizations.

    PERFORMANCE OPTIMIZATION SUMMARY:

    1. MODULE CACHING:
       - Module discovery happens once per Python process instead of once per widget
       - Eliminates expensive pkgutil.walk_packages() calls on every instantiation
       - Reduces import overhead by reusing discovered modules
       - Expected performance gain: 50-90% faster widget creation for subsequent instances

    2. INCLUSIVE SOURCE EXTRACTION:
       - Now extracts meaningful code from ALL objects, not just classes/functions
       - Handles instances by extracting their class source + instance state
       - Uses dill's advanced capabilities (getsource, importable, globalvars)
       - Creates intelligent placeholders for objects without direct source access
       - No longer excludes objects with "mem_add" or instance types

    3. RUNTIME OPTIMIZATIONS:
       - Cached character count calculations
       - Pre-computed style objects
       - Optimized framebuffer operations
       - Batch character processing for mirroring
       - Cached line lengths and display state

    4. ENHANCED ERROR HANDLING:
       - Multiple fallback strategies for source extraction
       - Meaningful object analysis when source unavailable
       - Object introspection to create code representations
       - Preserves object information even when source can't be extracted

    RESULT: Widget now displays code from instances like KeyManager, ScrollingCode objects,
    and other runtime objects that were previously showing as "object at mem_add".
    """
    return ScrollingCode(width, height)
