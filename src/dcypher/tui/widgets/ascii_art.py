"""
ASCII Art Banner Widget
Cyberpunk-inspired banner with @repligate aesthetics
"""

from textual.widget import Widget
from textual.reactive import reactive
from rich.console import Console, ConsoleOptions, RenderResult
from rich.text import Text
from rich.align import Align
from rich.panel import Panel


class ASCIIBanner(Widget):
    """
    ASCII art banner for dCypher TUI
    Features cyberpunk styling with matrix-style effects
    """
    
    # Reactive properties
    show_subtitle = reactive(True)
    animation_frame = reactive(0)
    
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
    
    # Matrix-style characters for animation
    MATRIX_CHARS = "01アイウエオカキクケコサシスセソタチツテトナニヌネノハヒフヘホマミムメモヤユヨラリルレロワヲン"
    
    def __init__(self, compact=False, **kwargs):
        super().__init__(**kwargs)
        self.compact = compact
        self.ascii_art = self.DCYPHER_COMPACT if compact else self.DCYPHER_ASCII
    
    def render(self) -> RenderResult:
        """Render the ASCII banner"""
        console = Console()
        
        # Create the main ASCII art
        ascii_text = Text(self.ascii_art, style="bold green")
        
        # Add subtitle if enabled
        if self.show_subtitle:
            subtitle_text = Text(self.SUBTITLE, style="bold cyan")
            subtitle_text.stylize("dim", 0, len("QUANTUM-RESISTANT ENCRYPTION"))
            subtitle_text.stylize("bold yellow", len("QUANTUM-RESISTANT ENCRYPTION • "))
        else:
            subtitle_text = Text("")
        
        # Combine ASCII art and subtitle
        combined = Text()
        combined.append(ascii_text)
        combined.append("\n")
        combined.append(subtitle_text)
        
        # Center align the content
        aligned = Align.center(combined)
        
        # Create panel with cyberpunk border
        panel = Panel(
            aligned,
            border_style="bright_green",
            padding=(0, 1),
            title="[bold red]◢[/bold red][bold yellow]DCYPHER[/bold yellow][bold red]◣[/bold red]",
            title_align="center"
        )
        
        return panel
    
    def on_mount(self) -> None:
        """Start animation timer when mounted"""
        self.set_interval(0.5, self.animate)
    
    def animate(self) -> None:
        """Animate the banner (subtle effects)"""
        self.animation_frame = (self.animation_frame + 1) % 10
        # Could add matrix rain or other effects here
    
    def toggle_subtitle(self) -> None:
        """Toggle subtitle visibility"""
        self.show_subtitle = not self.show_subtitle


class MatrixRain(Widget):
    """
    Matrix-style digital rain effect
    For use in backgrounds or as decorative elements
    """
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.columns = []
        self.frame = 0
    
    def render(self) -> RenderResult:
        """Render matrix rain effect"""
        # This would implement the classic matrix digital rain
        # For now, return a simple placeholder
        return Text("▓▒░ MATRIX RAIN ░▒▓", style="bold green")
    
    def on_mount(self) -> None:
        """Initialize matrix rain"""
        self.set_interval(0.1, self.update_rain)
    
    def update_rain(self) -> None:
        """Update rain animation"""
        self.frame += 1
        # Update rain columns here


class CyberpunkBorder(Widget):
    """
    Decorative cyberpunk-style border widget
    Art deco inspired geometric patterns
    """
    
    BORDER_PATTERNS = {
        "simple": "─│┌┐└┘",
        "double": "═║╔╗╚╝",
        "thick": "━┃┏┓┗┛",
        "art_deco": "▬▌▛▜▙▟",
        "cyber": "▓▒░█▄▀"
    }
    
    def __init__(self, pattern="cyber", **kwargs):
        super().__init__(**kwargs)
        self.pattern = pattern
    
    def render(self) -> RenderResult:
        """Render cyberpunk border"""
        chars = self.BORDER_PATTERNS.get(self.pattern, self.BORDER_PATTERNS["cyber"])
        border_text = Text(f"[{chars}] CYBERPUNK BORDER [{chars}]", style="bold cyan")
        return Align.center(border_text)