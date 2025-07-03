#!/usr/bin/env python3

from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich import box

console = Console()

print("Testing different border styles:")
print()

# Test 1: ROUNDED
print("1. ROUNDED borders:")
cpu_panel = Panel(
    Text("CPU: 5.2% (0 children) [▁▂▃▄▅▆▇█▇▆▅▄▃▂▁]", style="bold cyan"),
    title="[bold cyan]◢dCYPHER CPU USAGE◣[/bold cyan]",
    border_style="cyan",
    box=box.ROUNDED
)
console.print(cpu_panel)

memory_panel = Panel(
    Text("Memory: 45.2 MB (2.1% of system) [██░░░░░░░░]", style="bold yellow"),
    title="[bold yellow]◢dCYPHER MEMORY USAGE◣[/bold yellow]",
    border_style="yellow",
    box=box.ROUNDED
)
console.print(memory_panel)
print()

# Test 2: DOUBLE
print("2. DOUBLE borders:")
cpu_panel2 = Panel(
    Text("CPU: 5.2% (0 children) [▁▂▃▄▅▆▇█▇▆▅▄▃▂▁]", style="bold cyan"),
    title="[bold cyan]◢dCYPHER CPU USAGE◣[/bold cyan]",
    border_style="cyan",
    box=box.DOUBLE
)
console.print(cpu_panel2)
print()

# Test 3: HEAVY
print("3. HEAVY borders:")
cpu_panel3 = Panel(
    Text("CPU: 5.2% (0 children) [▁▂▃▄▅▆▇█▇▆▅▄▃▂▁]", style="bold cyan"),
    title="[bold cyan]◢dCYPHER CPU USAGE◣[/bold cyan]",
    border_style="cyan",
    box=box.HEAVY
)
console.print(cpu_panel3)
