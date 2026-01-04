#!/usr/bin/env python3
"""
Render Demo - Shows what TUI components look like
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from rich.console import Console
from rich.panel import Panel
from rich.columns import Columns
from rich.table import Table
from rich.progress import Progress, BarColumn, TextColumn
from rich.text import Text
from rich.layout import Layout

# Import our components
from tui.widgets.ascii_art import ASCIIBanner, CyberpunkBorder
from tui.widgets.system_monitor import SystemMonitor, CryptoMonitor


def demo_ascii_banner():
    """Show ASCII banner"""
    console = Console()
    
    print("\n🎨 ASCII BANNER COMPONENT")
    print("=" * 60)
    
    banner = ASCIIBanner()
    
    # Show full banner
    console.print(Panel(
        banner.DCYPHER_ASCII + "\n\n" + banner.SUBTITLE,
        title="[bold green]dCypher TUI Banner[/bold green]",
        border_style="green",
        padding=(1, 2)
    ))
    
    print("\n📱 COMPACT BANNER")
    print("-" * 30)
    
    # Show compact banner
    banner_compact = ASCIIBanner(compact=True)
    console.print(Panel(
        banner_compact.DCYPHER_COMPACT,
        title="[bold cyan]Compact Mode[/bold cyan]",
        border_style="cyan",
        padding=(1, 2)
    ))


def demo_system_monitor():
    """Show system monitor"""
    console = Console()
    
    print("\n📊 SYSTEM MONITOR COMPONENT")
    print("=" * 60)
    
    monitor = SystemMonitor()
    
    # Simulate some data
    monitor.cpu_percent = 45.2
    monitor.memory_percent = 67.8
    monitor.disk_percent = 34.1
    monitor.network_sent = 1024 * 1024 * 150  # 150MB
    monitor.network_recv = 1024 * 1024 * 89   # 89MB
    monitor.cpu_history = [40, 42, 45, 47, 45, 43, 45, 48, 45]
    monitor.memory_history = [65, 66, 67, 68, 67, 68, 67, 69, 67]
    
    # Create CPU panel
    cpu_content = Text()
    cpu_content.append(f"CPU Usage: {monitor.cpu_percent}%\n", style="bold white")
    cpu_content.append(f"Cores: 8\n", style="dim")
    cpu_content.append(f"Frequency: 2.4GHz\n", style="dim")
    cpu_content.append("History: ", style="dim")
    cpu_content.append("▁▂▃▄▃▂▃▅▃", style="green")
    
    cpu_panel = Panel(
        cpu_content,
        title="[bold green]◢CPU◣[/bold green]",
        border_style="green"
    )
    
    # Create Memory panel
    memory_content = Text()
    memory_content.append(f"Memory: {monitor.memory_percent}%\n", style="bold white")
    memory_content.append(f"Used: {monitor.format_bytes(1024*1024*1024*6.8)}\n", style="dim")
    memory_content.append(f"Total: {monitor.format_bytes(1024*1024*1024*10)}\n", style="dim")
    memory_content.append("History: ", style="dim")
    memory_content.append("▄▅▆▇▆▇▆▇▆", style="yellow")
    
    memory_panel = Panel(
        memory_content,
        title="[bold yellow]◢MEMORY◣[/bold yellow]",
        border_style="yellow"
    )
    
    # Create Disk panel
    disk_content = Text()
    disk_content.append(f"Disk: {monitor.disk_percent}%\n", style="bold white")
    disk_content.append(f"Used: {monitor.format_bytes(1024*1024*1024*340)}\n", style="dim")
    disk_content.append(f"Free: {monitor.format_bytes(1024*1024*1024*660)}\n", style="dim")
    disk_content.append("Type: SSD", style="dim")
    
    disk_panel = Panel(
        disk_content,
        title="[bold cyan]◢DISK◣[/bold cyan]",
        border_style="cyan"
    )
    
    # Create Network panel
    network_content = Text()
    network_content.append("Network Activity\n", style="bold white")
    network_content.append(f"↑ Sent: {monitor.format_bytes(monitor.network_sent)}\n", style="green")
    network_content.append(f"↓ Recv: {monitor.format_bytes(monitor.network_recv)}\n", style="blue")
    network_content.append("Interface: eth0", style="dim")
    
    network_panel = Panel(
        network_content,
        title="[bold magenta]◢NETWORK◣[/bold magenta]",
        border_style="magenta"
    )
    
    # Display in columns
    console.print(Columns([cpu_panel, memory_panel]))
    console.print(Columns([disk_panel, network_panel]))


def demo_crypto_monitor():
    """Show crypto monitor"""
    console = Console()
    
    print("\n🔐 CRYPTO MONITOR COMPONENT")
    print("=" * 60)
    
    monitor = CryptoMonitor()
    
    # Simulate crypto activity
    monitor.active_operations = 2
    monitor.completed_operations = 156
    monitor.failed_operations = 3
    monitor.operation_history = [
        {"time": "14:32:15", "operation": "encrypt", "status": "completed"},
        {"time": "14:31:42", "operation": "decrypt", "status": "completed"},
        {"time": "14:30:18", "operation": "keygen", "status": "active"},
        {"time": "14:29:55", "operation": "sign", "status": "completed"},
        {"time": "14:29:12", "operation": "verify", "status": "failed"},
    ]
    
    # Create crypto stats
    crypto_content = Text()
    crypto_content.append("CRYPTO OPERATIONS\n\n", style="bold cyan")
    crypto_content.append(f"Active: {monitor.active_operations}\n", style="yellow")
    crypto_content.append(f"Completed: {monitor.completed_operations}\n", style="green")
    crypto_content.append(f"Failed: {monitor.failed_operations}\n", style="red")
    crypto_content.append(f"Success Rate: {(monitor.completed_operations/(monitor.completed_operations + monitor.failed_operations)*100):.1f}%\n", style="white")
    crypto_content.append("\nRecent Operations:\n", style="bold white")
    
    for op in monitor.operation_history[:3]:
        status_color = {"completed": "green", "active": "yellow", "failed": "red"}[op["status"]]
        status_icon = {"completed": "✓", "active": "⚡", "failed": "✗"}[op["status"]]
        crypto_content.append(f"{op['time']} ", style="dim")
        crypto_content.append(f"{status_icon} ", style=status_color)
        crypto_content.append(f"{op['operation']}\n", style="white")
    
    crypto_panel = Panel(
        crypto_content,
        title="[bold cyan]◢CRYPTO MONITOR◣[/bold cyan]",
        border_style="cyan"
    )
    
    console.print(crypto_panel)


def demo_dashboard_layout():
    """Show dashboard layout"""
    console = Console()
    
    print("\n📱 DASHBOARD LAYOUT")
    print("=" * 60)
    
    # Status panels
    identity_status = Panel(
        "IDENTITY STATUS\n\n✓ Loaded\nKeys: 3/3\nType: Quantum-Safe",
        title="[bold green]◢IDENTITY◣[/bold green]",
        border_style="green"
    )
    
    api_status = Panel(
        "API CONNECTION\n\n✓ Connected\nLatency: 45ms\nServer: Online",
        title="[bold green]◢API◣[/bold green]",
        border_style="green"
    )
    
    files_status = Panel(
        "FILES & SHARES\n\nFiles: 12\nShares: 5\nStorage: 2.3GB",
        title="[bold cyan]◢DATA◣[/bold cyan]",
        border_style="cyan"
    )
    
    console.print(Columns([identity_status, api_status, files_status]))
    
    # Quick actions
    print("\n🎯 QUICK ACTIONS")
    print("-" * 30)
    
    actions_table = Table(show_header=False, box=None)
    actions_table.add_column("Action", style="bold")
    actions_table.add_column("Description", style="dim")
    
    actions_table.add_row("🔑 Load Identity", "Load quantum-safe identity file")
    actions_table.add_row("📁 Upload File", "Encrypt and upload file")
    actions_table.add_row("🔗 Create Share", "Share file with recipient")
    actions_table.add_row("📋 View Logs", "Show operation history")
    
    console.print(Panel(actions_table, title="[bold yellow]Quick Actions[/bold yellow]", border_style="yellow"))


def demo_data_tables():
    """Show data tables"""
    console = Console()
    
    print("\n📊 DATA TABLES")
    print("=" * 60)
    
    # Identity table
    identity_table = Table(title="Identity History")
    identity_table.add_column("Name", style="cyan")
    identity_table.add_column("Path", style="dim")
    identity_table.add_column("Created", style="dim")
    identity_table.add_column("Status", style="bold")
    
    identity_table.add_row("default", "~/.dcypher/default.json", "2024-01-15", "[green]Active[/green]")
    identity_table.add_row("backup", "~/.dcypher/backup.json", "2024-01-10", "[dim]Inactive[/dim]")
    identity_table.add_row("test", "~/.dcypher/test.json", "2024-01-05", "[dim]Inactive[/dim]")
    
    console.print(identity_table)
    
    print()
    
    # Files table
    files_table = Table(title="Encrypted Files")
    files_table.add_column("Filename", style="white")
    files_table.add_column("Size", style="cyan")
    files_table.add_column("Encrypted", style="green")
    files_table.add_column("Shares", style="yellow")
    files_table.add_column("Modified", style="dim")
    
    files_table.add_row("document.pdf", "2.3MB", "✓", "3", "2024-01-20")
    files_table.add_row("image.jpg", "1.8MB", "✓", "1", "2024-01-19")
    files_table.add_row("data.csv", "856KB", "✓", "0", "2024-01-18")
    
    console.print(files_table)


def demo_borders():
    """Show border patterns"""
    console = Console()
    
    print("\n🔲 BORDER PATTERNS")
    print("=" * 60)
    
    border = CyberpunkBorder()
    
    patterns = ["simple", "double", "thick", "art_deco", "cyber"]
    
    for pattern in patterns:
        test_border = CyberpunkBorder(pattern=pattern)
        content = f"This is the {pattern} border pattern\nUsed throughout the TUI interface"
        
        panel = Panel(
            content,
            title=f"[bold]{pattern.upper()}[/bold]",
            border_style="cyan"
        )
        console.print(panel)
        print()


def demo_progress():
    """Show progress indicators"""
    console = Console()
    
    print("\n⚡ PROGRESS INDICATORS")
    print("=" * 60)
    
    # File upload progress
    with Progress(
        TextColumn("[bold blue]Uploading file...", justify="right"),
        BarColumn(bar_width=None),
        "[progress.percentage]{task.percentage:>3.1f}%",
        console=console
    ) as progress:
        task = progress.add_task("upload", total=100)
        progress.update(task, advance=75)
        console.print()
    
    # Encryption progress
    with Progress(
        TextColumn("[bold green]Encrypting...", justify="right"),
        BarColumn(bar_width=None),
        "[progress.percentage]{task.percentage:>3.1f}%",
        console=console
    ) as progress:
        task = progress.add_task("encrypt", total=100)
        progress.update(task, advance=45)
        console.print()
    
    # Key generation progress
    with Progress(
        TextColumn("[bold yellow]Generating keys...", justify="right"),
        BarColumn(bar_width=None),
        "[progress.percentage]{task.percentage:>3.1f}%",
        console=console
    ) as progress:
        task = progress.add_task("keygen", total=100)
        progress.update(task, advance=90)


def main():
    """Run all demos"""
    console = Console()
    
    console.print("\n🚀 [bold green]dCypher TUI - Visual Component Demo[/bold green]")
    console.print("=" * 80)
    console.print("This shows what the TUI components look like when rendered")
    console.print("=" * 80)
    
    # Run all demos
    demo_ascii_banner()
    demo_system_monitor()
    demo_crypto_monitor()
    demo_dashboard_layout()
    demo_data_tables()
    demo_borders()
    demo_progress()
    
    console.print("\n🎉 [bold green]Demo Complete![/bold green]")
    console.print("=" * 80)
    console.print("This is what the dCypher TUI looks like in action!")
    console.print("The actual TUI provides interactive navigation between these screens.")
    console.print("=" * 80)


if __name__ == "__main__":
    main()