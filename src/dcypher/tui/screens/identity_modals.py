import os
import json
import shutil
from pathlib import Path
from textual.containers import Container, Horizontal, Vertical, ScrollableContainer
from textual.widgets import Static, Button, Input, DataTable, Label, Select, TextArea
from textual.widget import Widget
from textual.reactive import reactive
from textual.screen import ModalScreen
from rich.panel import Panel
from rich.text import Text
from rich.table import Table
from typing import Dict, Any, List, Optional

from dcypher.lib.key_manager import KeyManager
from dcypher.lib.api_client import DCypherClient


class HexDataModal(ModalScreen[None]):
    """Base class for modals displaying large hex data with dynamic sizing"""

    def __init__(self, title: str, metadata: str, hex_data: str, **kwargs):
        super().__init__(**kwargs)
        self.title = title
        self.metadata = metadata
        self.hex_data = hex_data
        self.current_page = 0
        self.page_size = 2000  # Initial default, will be recalculated
        self.total_pages = 1
        self.border_color = "cyan"
        # Initialize formatting parameters
        self.chars_per_line = 96
        self.lines_per_page = 30

    def compose(self):
        """Compose the hex data modal"""
        with Container(id="hex-modal-container"):
            # Title bar with close button
            with Horizontal(id="title-bar"):
                yield Static(self.title or "Modal", id="modal-title")
                yield Button("✕", id="close-btn", variant="error", compact=True)

            # Metadata section (fixed at top)
            yield Static(self.metadata, id="metadata-section")

            # Hex data content area (paginated)
            yield TextArea(
                self.get_current_page_content(),
                read_only=True,
                id="hex-content-area",
            )

            # Pagination controls
            with Horizontal(id="pagination-bar"):
                yield Button("◀ Prev", id="prev-btn", compact=True)
                yield Static(
                    f"Page {self.current_page + 1} of {self.total_pages}",
                    id="page-info",
                )
                yield Button("Next ▶", id="next-btn", compact=True)

    def on_mount(self):
        """Style the modal and calculate optimal page size"""
        # Full screen modal
        container = self.query_one("#hex-modal-container")
        container.styles.width = "100%"
        container.styles.height = "100%"
        container.styles.background = "darkblue"
        container.styles.border = ("thick", self.border_color)
        container.styles.padding = (0, 1)

        # Title bar
        title_bar = self.query_one("#title-bar")
        title_bar.styles.height = "3"
        title_bar.styles.background = "darkblue"
        title_bar.styles.align = ("left", "middle")
        title_bar.styles.padding = (1, 1)

        # Title styling
        title = self.query_one("#modal-title")
        title.styles.color = self.border_color
        title.styles.text_style = "bold"
        title.styles.width = "1fr"

        # Close button
        close_btn = self.query_one("#close-btn")
        close_btn.styles.width = "5"
        close_btn.styles.height = "1"

        # Metadata section (compact at top)
        metadata_section = self.query_one("#metadata-section")
        metadata_section.styles.height = "auto"
        metadata_section.styles.width = "100%"
        metadata_section.styles.background = "darkblue"
        metadata_section.styles.color = "white"
        metadata_section.styles.padding = (1, 2)
        metadata_section.styles.border = ("solid", "gray")

        # Hex content area fills most space
        hex_content_area = self.query_one("#hex-content-area")
        hex_content_area.styles.height = "1fr"
        hex_content_area.styles.width = "100%"
        hex_content_area.styles.border = ("solid", "gray")

        # Pagination bar
        pagination_bar = self.query_one("#pagination-bar")
        pagination_bar.styles.height = "3"
        pagination_bar.styles.background = "darkblue"
        pagination_bar.styles.align = ("center", "middle")
        pagination_bar.styles.padding = (1, 1)

        # Pagination buttons
        prev_btn = self.query_one("#prev-btn", Button)
        prev_btn.styles.width = "10"

        next_btn = self.query_one("#next-btn", Button)
        next_btn.styles.width = "10"

        # Page info
        page_info = self.query_one("#page-info", Static)
        page_info.styles.color = "white"
        page_info.styles.text_align = "center"
        page_info.styles.width = "1fr"

        # Calculate optimal page size after layout is complete
        self.call_later(self.calculate_optimal_page_size)

    def calculate_optimal_page_size(self):
        """Calculate optimal page size based on actual panel dimensions"""
        try:
            # Get the hex content area widget
            hex_content_area = self.query_one("#hex-content-area", TextArea)

            # Get the actual dimensions
            content_size = hex_content_area.content_size
            width = content_size.width
            height = content_size.height

            # If dimensions aren't available yet, use app size
            if width <= 0 or height <= 0:
                app_size = self.app.size
                # Estimate content area as full app size minus UI elements
                width = max(80, int(app_size.width) - 6)  # Account for borders only
                height = max(
                    20, int(app_size.height) - 8
                )  # Account for title, metadata, pagination

            # Use the FULL available width for hex display
            # No padding - use every available character
            chars_per_line = max(
                64, width - 1
            )  # Use full width, minimum 64 for readability

            # Use ALL available height - no padding
            lines_per_page = max(10, height)  # Use every available line

            # Store formatting info
            self.chars_per_line = chars_per_line
            self.lines_per_page = lines_per_page

            # Calculate total characters per page
            calculated_page_size = chars_per_line * lines_per_page

            # Set reasonable bounds
            self.page_size = max(
                1000, min(calculated_page_size, 100000)
            )  # Increased max for large displays

            # Recalculate total pages
            if self.hex_data:
                self.total_pages = max(
                    1,
                    len(self.hex_data) // self.page_size
                    + (1 if len(self.hex_data) % self.page_size > 0 else 0),
                )
            else:
                self.total_pages = 1

            # Update the display
            self.update_content()

            self.log(
                f"Calculated optimal page size: {self.page_size} chars (area: {width}x{height}, {chars_per_line} chars/line, {lines_per_page} lines)"
            )

        except Exception as e:
            # Fallback to reasonable default
            self.chars_per_line = 120  # Increased default
            self.lines_per_page = 30
            self.page_size = 3600  # Increased for wider display
            if self.hex_data:
                self.total_pages = max(
                    1,
                    len(self.hex_data) // self.page_size
                    + (1 if len(self.hex_data) % self.page_size > 0 else 0),
                )
            else:
                self.total_pages = 1
            self.log(f"Failed to calculate optimal page size, using default: {e}")

    def format_hex_for_display(self, hex_content: str) -> str:
        """Format hex content with proper line breaks to fill available space"""
        if not hex_content:
            return "No hex data available"

        # Get formatting parameters (set during size calculation)
        chars_per_line = getattr(self, "chars_per_line", 96)
        lines_per_page = getattr(self, "lines_per_page", 30)

        # Split hex into lines of optimal width
        lines = []
        for i in range(0, len(hex_content), chars_per_line):
            line = hex_content[i : i + chars_per_line]
            lines.append(line)

        # Take only the lines that fit in the available space
        display_lines = lines[:lines_per_page]

        # If we have fewer lines than available space, pad with empty lines to fill the area
        while len(display_lines) < lines_per_page:
            display_lines.append("")

        return "\n".join(display_lines)

    def get_current_page_content(self) -> str:
        """Get hex content for current page, formatted to fill available space"""
        if not self.hex_data:
            return "No hex data available"

        start = self.current_page * self.page_size
        end = start + self.page_size
        page_content = self.hex_data[start:end]

        if not page_content:
            return "End of data"

        # Format the hex content to fill the available space
        return self.format_hex_for_display(page_content)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button presses"""
        if event.button.id == "prev-btn" and self.current_page > 0:
            self.current_page -= 1
            self.update_content()
        elif event.button.id == "next-btn" and self.current_page < self.total_pages - 1:
            self.current_page += 1
            self.update_content()
        elif event.button.id == "close-btn":
            self.dismiss()

    def update_content(self):
        """Update content and pagination controls"""
        # Update hex content
        hex_content_area = self.query_one("#hex-content-area", TextArea)
        hex_content_area.text = self.get_current_page_content()

        # Update page info
        page_info = self.query_one("#page-info", Static)
        page_info.update(f"Page {self.current_page + 1} of {self.total_pages}")

        # Update button states
        prev_btn = self.query_one("#prev-btn", Button)
        prev_btn.disabled = self.current_page == 0

        next_btn = self.query_one("#next-btn", Button)
        next_btn.disabled = self.current_page >= self.total_pages - 1


class PREKeyDetailsModal(HexDataModal):
    """Modal for viewing PRE key details with hex data pagination"""

    def __init__(self, pre_keys: Dict[str, Any], show_private: bool = False, **kwargs):
        metadata, hex_data = self._extract_data(pre_keys, show_private)
        title = "PRE Key Details" + (" (Private)" if show_private else " (Public)")
        super().__init__(title, metadata, hex_data, **kwargs)
        self.border_color = "cyan"
        self.show_private = show_private
        self.pre_keys = pre_keys

    def compose(self):
        """Compose the hex data modal with toggle button"""
        with Container(id="hex-modal-container"):
            # Title bar with close button
            with Horizontal(id="title-bar"):
                yield Static(self.title or "Modal", id="modal-title")
                yield Button("✕", id="close-btn", variant="error", compact=True)

            # Metadata section (fixed at top)
            yield Static(self.metadata, id="metadata-section")

            # Toggle view button
            with Horizontal(id="view-toggle"):
                toggle_text = "Show Public" if self.show_private else "Show Private"
                yield Button(
                    toggle_text, id="toggle-view-btn", variant="warning", compact=True
                )

            # Hex data content area (paginated)
            yield TextArea(
                self.get_current_page_content(),
                read_only=True,
                id="hex-content-area",
            )

            # Pagination controls
            with Horizontal(id="pagination-bar"):
                yield Button("◀ Prev", id="prev-btn", compact=True)
                yield Static(
                    f"Page {self.current_page + 1} of {self.total_pages}",
                    id="page-info",
                )
                yield Button("Next ▶", id="next-btn", compact=True)

    def on_mount(self):
        """Style the modal and add toggle view styling"""
        # Call parent on_mount for base styling
        super().on_mount()

        # Style the toggle view section
        view_toggle = self.query_one("#view-toggle")
        view_toggle.styles.height = "3"
        view_toggle.styles.background = "darkblue"
        view_toggle.styles.align = ("center", "middle")
        view_toggle.styles.padding = (0, 1)

        # Toggle button
        toggle_btn = self.query_one("#toggle-view-btn", Button)
        toggle_btn.styles.width = "15"

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button presses"""
        if event.button.id == "prev-btn" and self.current_page > 0:
            self.current_page -= 1
            self.update_content()
        elif event.button.id == "next-btn" and self.current_page < self.total_pages - 1:
            self.current_page += 1
            self.update_content()
        elif event.button.id == "toggle-view-btn":
            self.show_private = not self.show_private
            # Re-extract data with new view mode
            self.metadata, self.hex_data = self._extract_data(
                self.pre_keys, self.show_private
            )
            # Reset pagination for new data
            self.current_page = 0
            if self.hex_data:
                self.total_pages = max(
                    1,
                    len(self.hex_data) // self.page_size
                    + (1 if len(self.hex_data) % self.page_size > 0 else 0),
                )
            else:
                self.total_pages = 1
            self.update_content()
            self.update_toggle_button()
        elif event.button.id == "close-btn":
            self.dismiss()

    def update_toggle_button(self):
        """Update the toggle button text and modal title"""
        toggle_btn = self.query_one("#toggle-view-btn", Button)
        toggle_text = "Show Public" if self.show_private else "Show Private"
        toggle_btn.label = toggle_text

        # Update modal title
        title_widget = self.query_one("#modal-title", Static)
        title_suffix = " (Private)" if self.show_private else " (Public)"
        title_widget.update("PRE Key Details" + title_suffix)

        # Update metadata display
        metadata_widget = self.query_one("#metadata-section", Static)
        metadata_widget.update(self.metadata)

    def _extract_data(
        self, pre_keys: Dict[str, Any], show_private: bool
    ) -> tuple[str, str]:
        """Extract metadata and hex data separately"""
        if "pk_hex" in pre_keys and pre_keys["pk_hex"]:
            pk_hex = pre_keys["pk_hex"]
            sk_hex = pre_keys.get("sk_hex", "")

            # Generate ColCa fingerprints
            try:
                pk_fingerprint = KeyManager.generate_pre_key_fingerprint(
                    pk_hex, "public"
                )
                pk_fingerprint_line = f"ColCa Fingerprint (Public): {pk_fingerprint}\n"
            except Exception as e:
                pk_fingerprint_line = f"ColCa Fingerprint (Public): [Error: {e}]\n"

            sk_fingerprint_line = ""
            if sk_hex:
                try:
                    sk_fingerprint = KeyManager.generate_pre_key_fingerprint(
                        sk_hex, "private"
                    )
                    sk_fingerprint_line = (
                        f"ColCa Fingerprint (Private): {sk_fingerprint}\n"
                    )
                except Exception as e:
                    sk_fingerprint_line = f"ColCa Fingerprint (Private): [Error: {e}]\n"

            # Add ColCa security information for PRE
            colca_info_line = (
                "ColCa Properties: Context-dependent, hierarchical nesting\n"
            )

            if show_private and sk_hex:
                # Show private key data
                metadata = (
                    f"PRE Key Information (PRIVATE KEY VIEW)\n"
                    f"Status: Initialized\n"
                    f"Public Key Size: {len(pk_hex) // 2:,} bytes\n"
                    f"Private Key Size: {len(sk_hex) // 2:,} bytes\n"
                    f"Displaying: Private Key Hex Data\n"
                    f"Total Hex Length: {len(sk_hex):,} characters\n"
                    f"{pk_fingerprint_line}"
                    f"{sk_fingerprint_line}"
                    f"{colca_info_line}"
                    f"⚠️  WARNING: Private key material is displayed below!"
                )
                hex_data = sk_hex
            else:
                # Show public key data (default)
                metadata = (
                    f"PRE Key Information (PUBLIC KEY VIEW)\n"
                    f"Status: Initialized\n"
                    f"Public Key Size: {len(pk_hex) // 2:,} bytes\n"
                    f"Private Key Size: {len(sk_hex) // 2:,} bytes\n"
                    f"Displaying: Public Key Hex Data\n"
                    f"Total Hex Length: {len(pk_hex):,} characters\n"
                    f"{pk_fingerprint_line}"
                    f"{sk_fingerprint_line}"
                    f"{colca_info_line}"
                    f"Private Key: {'Available (switch view to see)' if sk_hex else 'Not available'}"
                )
                hex_data = pk_hex
        else:
            metadata = (
                f"PRE Key Information\n"
                f"Status: Not initialized\n"
                f"Use 'Init PRE' to create proxy re-encryption keys."
            )
            hex_data = ""

        return metadata, hex_data


class CryptoContextDetailsModal(HexDataModal):
    """Modal for viewing crypto context details with hex data pagination"""

    def __init__(self, crypto_context: Dict[str, Any], **kwargs):
        metadata, hex_data = self._extract_data(crypto_context)
        super().__init__("Crypto Context Details", metadata, hex_data, **kwargs)
        self.border_color = "magenta"

    def _extract_data(self, crypto_context: Dict[str, Any]) -> tuple[str, str]:
        """Extract metadata and hex data separately"""
        metadata_lines = ["Crypto Context Information"]

        if "context_source" in crypto_context:
            metadata_lines.append(f"Source: {crypto_context['context_source']}")

        if "context_size" in crypto_context:
            size_bytes = crypto_context["context_size"]
            metadata_lines.append(
                f"Size: {size_bytes:,} bytes ({size_bytes / 1024:.1f} KB)"
            )

        hex_data = ""
        if "context_bytes_hex" in crypto_context:
            context_hex = crypto_context["context_bytes_hex"]
            metadata_lines.append(f"Hex Length: {len(context_hex):,} characters")
            hex_data = context_hex

        # Add ColCa fingerprinting information
        metadata_lines.append("Fingerprinting: ColCa (Half-Split Recursive) algorithm")
        metadata_lines.append("Properties: Quantum-safe, hierarchical nesting")

        return "\n".join(metadata_lines), hex_data


class PQKeyDetailsModal(ModalScreen[None]):
    """Modal for viewing multiple PQ keys with dynamic hex sizing"""

    def __init__(
        self, pq_keys: List[Dict[str, Any]], show_private: bool = False, **kwargs
    ):
        super().__init__(**kwargs)
        self.pq_keys = pq_keys
        self.current_key_index = 0
        self.show_private = show_private

    def compose(self):
        """Compose the PQ key details modal"""
        title_suffix = " (Private)" if self.show_private else " (Public)"
        with Container(id="pq-modal-container"):
            # Title bar with close button
            with Horizontal(id="title-bar"):
                yield Static(
                    "Post-Quantum Key Details" + title_suffix, id="modal-title"
                )
                yield Button("✕", id="close-btn", variant="error", compact=True)

            # Key selection and metadata
            with Horizontal(id="key-selector"):
                yield Button("◀ Prev Key", id="prev-key-btn", compact=True)
                yield Static(self._get_key_info(), id="key-info")
                yield Button("Next Key ▶", id="next-key-btn", compact=True)

            # Toggle view button
            with Horizontal(id="view-toggle"):
                toggle_text = "Show Public" if self.show_private else "Show Private"
                yield Button(
                    toggle_text, id="toggle-view-btn", variant="warning", compact=True
                )

            # Current key hex data - fills remaining space
            yield TextArea(
                text=self._get_current_key_hex(), read_only=True, id="key-hex-content"
            )

    def on_mount(self):
        """Style the modal"""
        # Full screen modal
        container = self.query_one("#pq-modal-container")
        container.styles.width = "100%"
        container.styles.height = "100%"
        container.styles.background = "darkblue"
        container.styles.border = ("thick", "yellow")
        container.styles.padding = (0, 1)

        # Title bar
        title_bar = self.query_one("#title-bar")
        title_bar.styles.height = "3"
        title_bar.styles.background = "darkblue"
        title_bar.styles.align = ("left", "middle")
        title_bar.styles.padding = (1, 1)

        # Title styling
        title = self.query_one("#modal-title")
        title.styles.color = "yellow"
        title.styles.text_style = "bold"
        title.styles.width = "1fr"

        # Close button
        close_btn = self.query_one("#close-btn")
        close_btn.styles.width = "5"
        close_btn.styles.height = "1"

        # Key selector
        key_selector = self.query_one("#key-selector")
        key_selector.styles.height = "4"
        key_selector.styles.background = "darkblue"
        key_selector.styles.align = ("center", "middle")
        key_selector.styles.padding = (1, 1)

        # Toggle view section
        view_toggle = self.query_one("#view-toggle")
        view_toggle.styles.height = "3"
        view_toggle.styles.background = "darkblue"
        view_toggle.styles.align = ("center", "middle")
        view_toggle.styles.padding = (0, 1)

        # Toggle button
        toggle_btn = self.query_one("#toggle-view-btn", Button)
        toggle_btn.styles.width = "15"

        # Key navigation buttons
        prev_key_btn = self.query_one("#prev-key-btn", Button)
        prev_key_btn.styles.width = "12"
        prev_key_btn.disabled = len(self.pq_keys) <= 1 or self.current_key_index == 0

        next_key_btn = self.query_one("#next-key-btn", Button)
        next_key_btn.styles.width = "12"
        next_key_btn.disabled = (
            len(self.pq_keys) <= 1 or self.current_key_index >= len(self.pq_keys) - 1
        )

        # Key info
        key_info = self.query_one("#key-info", Static)
        key_info.styles.color = "white"
        key_info.styles.text_align = "center"
        key_info.styles.width = "1fr"

        # Hex content area fills remaining space
        hex_content = self.query_one("#key-hex-content")
        hex_content.styles.height = "1fr"
        hex_content.styles.width = "100%"
        hex_content.styles.border = ("solid", "gray")

    def _get_key_info(self) -> str:
        """Get info for current key"""
        if not self.pq_keys:
            return "No PQ keys available"

        if self.current_key_index >= len(self.pq_keys):
            return "Invalid key index"

        key = self.pq_keys[self.current_key_index]
        alg = key.get("alg", "unknown")
        pk_hex = key.get("pk_hex", "")
        sk_hex = key.get("sk_hex", "")

        # Generate ColCa fingerprints
        pk_fingerprint_line = ""
        sk_fingerprint_line = ""

        try:
            pk_fingerprint = KeyManager.generate_pq_key_fingerprint(
                pk_hex, alg, "public"
            )
            pk_fingerprint_line = f"\nColCa Fingerprint (Public): {pk_fingerprint}"
        except Exception as e:
            pk_fingerprint_line = f"\nColCa Fingerprint (Public): [Error: {e}]"

        if sk_hex:
            try:
                sk_fingerprint = KeyManager.generate_pq_key_fingerprint(
                    sk_hex, alg, "private"
                )
                sk_fingerprint_line = f"\nColCa Fingerprint (Private): {sk_fingerprint}"
            except Exception as e:
                sk_fingerprint_line = f"\nColCa Fingerprint (Private): [Error: {e}]"

        # Add ColCa security information
        from dcypher.lib.key_manager import calculate_colca_security_bits

        security_bits = calculate_colca_security_bits([8, 4, 4])
        security_line = f"\nColCa Security: {security_bits:.0f} bits (hierarchical nesting, progressive disclosure)"

        view_type = "Private" if self.show_private else "Public"
        displaying_size = len(sk_hex) if self.show_private and sk_hex else len(pk_hex)

        return (
            f"Key {self.current_key_index + 1} of {len(self.pq_keys)}: {alg} ({view_type} View)\n"
            f"Public Key: {len(pk_hex) // 2:,} bytes | Private Key: {len(sk_hex) // 2:,} bytes | Displaying: {displaying_size:,} chars"
            f"{pk_fingerprint_line}"
            f"{sk_fingerprint_line}"
            f"{security_line}"
        )

    def _get_current_key_hex(self) -> str:
        """Get hex data for current key"""
        if not self.pq_keys or self.current_key_index >= len(self.pq_keys):
            return "No hex data available"

        key = self.pq_keys[self.current_key_index]

        if self.show_private:
            sk_hex = key.get("sk_hex", "")
            if sk_hex:
                return f"⚠️  WARNING: Private key material below!\n\n{sk_hex}"
            else:
                return "Private key not available for this key"
        else:
            return key.get("pk_hex", "No public key data")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button presses"""
        if event.button.id == "prev-key-btn" and self.current_key_index > 0:
            self.current_key_index -= 1
            self.update_key_display()
        elif (
            event.button.id == "next-key-btn"
            and self.current_key_index < len(self.pq_keys) - 1
        ):
            self.current_key_index += 1
            self.update_key_display()
        elif event.button.id == "toggle-view-btn":
            self.show_private = not self.show_private
            self.update_key_display()
            self.update_toggle_button()
        elif event.button.id == "close-btn":
            self.dismiss()

    def update_key_display(self):
        """Update the display for current key"""
        # Update key info
        key_info = self.query_one("#key-info", Static)
        key_info.update(self._get_key_info())

        # Update hex content
        hex_content = self.query_one("#key-hex-content", TextArea)
        hex_content.text = self._get_current_key_hex()

        # Update button states
        prev_btn = self.query_one("#prev-key-btn", Button)
        prev_btn.disabled = self.current_key_index == 0

        next_btn = self.query_one("#next-key-btn", Button)
        next_btn.disabled = self.current_key_index >= len(self.pq_keys) - 1

    def update_toggle_button(self):
        """Update the toggle button text"""
        toggle_btn = self.query_one("#toggle-view-btn", Button)
        toggle_text = "Show Public" if self.show_private else "Show Private"
        toggle_btn.label = toggle_text

        # Update modal title
        title_widget = self.query_one("#modal-title", Static)
        title_suffix = " (Private)" if self.show_private else " (Public)"
        title_widget.update("Post-Quantum Key Details" + title_suffix)


class PQKeySelectionModal(ModalScreen[Optional[str]]):
    """Compact modal screen for selecting PQ algorithm to add"""

    def __init__(self, available_algorithms: List[str], **kwargs):
        super().__init__(**kwargs)
        self.available_algorithms = available_algorithms

    def compose(self):
        """Compose the PQ key selection modal"""
        with Container(id="pq-modal-container"):
            # Compact title bar
            with Horizontal(id="pq-modal-title-bar"):
                yield Static("Add Post-Quantum Key", id="pq-modal-title")
                yield Button(
                    "✕", id="pq-modal-cancel-btn", variant="error", compact=True
                )

            # Selection content
            with Vertical(id="pq-modal-content"):
                yield Static("Select algorithm:", id="pq-modal-description")

                # Algorithm selection
                algorithm_options = [(alg, alg) for alg in self.available_algorithms]
                yield Select(
                    algorithm_options,
                    id="pq-algorithm-modal-select",
                    allow_blank=False,
                    value=self.available_algorithms[0]
                    if self.available_algorithms
                    else None,
                )

                # Add button
                yield Button("Add Key", id="pq-modal-add-btn", variant="success")

    def on_mount(self):
        """Style the modal for compact space usage"""
        # Center the modal
        self.styles.align = ("center", "middle")

        # Compact modal container
        modal_container = self.query_one("#pq-modal-container")
        modal_container.styles.background = "darkblue"
        modal_container.styles.border = ("thick", "cyan")
        modal_container.styles.width = "50"
        modal_container.styles.height = "12"
        modal_container.styles.padding = (0, 1)

        # Compact title bar
        title_bar = self.query_one("#pq-modal-title-bar")
        title_bar.styles.height = "3"
        title_bar.styles.background = "darkblue"
        title_bar.styles.align = ("left", "middle")
        title_bar.styles.padding = (1, 1)

        # Title styling
        title = self.query_one("#pq-modal-title")
        title.styles.color = "cyan"
        title.styles.text_style = "bold"
        title.styles.width = "1fr"

        # Close button styling
        close_btn = self.query_one("#pq-modal-cancel-btn")
        close_btn.styles.width = "5"
        close_btn.styles.height = "1"

        # Content area styling
        content = self.query_one("#pq-modal-content")
        content.styles.height = "1fr"
        content.styles.padding = (1, 2)

        # Description styling
        desc = self.query_one("#pq-modal-description")
        desc.styles.color = "white"
        desc.styles.margin = (0, 0, 1, 0)

        # Select widget styling
        select_widget = self.query_one("#pq-algorithm-modal-select")
        select_widget.styles.margin = (0, 0, 1, 0)

        # Add button styling
        add_btn = self.query_one("#pq-modal-add-btn")
        add_btn.styles.width = "100%"

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle modal button presses"""
        if event.button.id == "pq-modal-add-btn":
            select_widget = self.query_one("#pq-algorithm-modal-select", Select)
            selected_algorithm = select_widget.value
            if selected_algorithm and selected_algorithm != Select.BLANK:
                self.dismiss(str(selected_algorithm))
            else:
                self.notify("Please select an algorithm", severity="warning")
        elif event.button.id == "pq-modal-cancel-btn":
            self.dismiss(None)
