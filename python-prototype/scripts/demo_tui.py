#!/usr/bin/env python3
"""
dCypher TUI Demo Script
Demonstrates the cyberpunk-inspired terminal user interface
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))


def demo_ascii_art():
    """Demo the ASCII art components"""
    print("🎨 ASCII Art Components Demo")
    print("=" * 50)

    from tui.widgets.ascii_art import ASCIIBanner, CyberpunkBorder

    # Show ASCII banner
    banner = ASCIIBanner()
    print("📺 dCypher ASCII Banner:")
    print(banner.DCYPHER_ASCII)
    print()
    print("📺 Subtitle:")
    print(banner.SUBTITLE)
    print()

    # Show compact version
    banner_compact = ASCIIBanner(compact=True)
    print("📺 Compact Banner:")
    print(banner_compact.DCYPHER_COMPACT)
    print()

    # Show border patterns
    border = CyberpunkBorder()
    print("🔲 Available Border Patterns:")
    for pattern_name in border.BORDER_PATTERNS:
        print(f"  • {pattern_name}")
    print()


def demo_theme():
    """Demo the cyberpunk theme"""
    print("🎨 Cyberpunk Theme Demo")
    print("=" * 50)

    from tui.theme import CYBERPUNK_THEME

    print(f"📊 Theme size: {len(CYBERPUNK_THEME)} characters")
    print()

    # Extract and show color palette
    print("🌈 Color Palette:")
    colors = [
        ("Matrix Green", "#00ff41"),
        ("Neon Orange", "#ff6b35"),
        ("Cyan Blue", "#00d4ff"),
        ("Electric Yellow", "#ffff00"),
        ("Neon Red", "#ff073a"),
        ("Bright Green", "#39ff14"),
        ("Replicant Amber", "#ffb000"),
        ("Deep Black", "#0a0a0a"),
        ("Dark Gray", "#1a1a1a"),
    ]

    for name, hex_color in colors:
        if hex_color in CYBERPUNK_THEME:
            print(f"  ✓ {name}: {hex_color}")
        else:
            print(f"  ✗ {name}: {hex_color} (missing)")
    print()

    # Show key theme sections
    print("🎯 Key Theme Sections:")
    sections = [
        "Header styling",
        "Footer styling",
        "TabbedContent styling",
        "Replicant amber styling",
        "Art deco borders",
        "Matrix rain effects",
    ]

    for section in sections:
        print(f"  • {section}")
    print()


def demo_widgets():
    """Demo the widget components"""
    print("🔧 Widget Components Demo")
    print("=" * 50)

    from tui.widgets.system_monitor import SystemMonitor, CryptoMonitor

    # System monitor demo
    print("📊 System Monitor Widget:")
    monitor = SystemMonitor()
    print(f"  • Initial CPU: {monitor.cpu_percent}%")
    print(f"  • Initial Memory: {monitor.memory_percent}%")
    print(f"  • History length: {len(monitor.cpu_history)}")
    print(f"  • Max history: {monitor.max_history}")

    # Test byte formatting
    test_sizes = [512, 1024, 1024 * 1024, 1024 * 1024 * 1024]
    print("  • Byte formatting:")
    for size in test_sizes:
        formatted = SystemMonitor.format_bytes(size)
        print(f"    {size} bytes = {formatted}")
    print()

    # Crypto monitor demo
    print("🔐 Crypto Monitor Widget:")
    crypto_monitor = CryptoMonitor()
    print(f"  • Active operations: {crypto_monitor.active_operations}")
    print(f"  • Completed operations: {crypto_monitor.completed_operations}")
    print(f"  • Failed operations: {crypto_monitor.failed_operations}")

    # Simulate some operations
    crypto_monitor.add_operation("encrypt", "active")
    crypto_monitor.add_operation("decrypt", "active")
    print(f"  • After adding 2 active: {crypto_monitor.active_operations}")

    crypto_monitor.add_operation("encrypt", "completed")
    print(
        f"  • After completing 1: active={crypto_monitor.active_operations}, completed={crypto_monitor.completed_operations}"
    )

    crypto_monitor.add_operation("decrypt", "failed")
    print(
        f"  • After failing 1: active={crypto_monitor.active_operations}, failed={crypto_monitor.failed_operations}"
    )
    print()


def demo_screens():
    """Demo the screen structure"""
    print("📱 Screen Structure Demo")
    print("=" * 50)

    # Show available screens
    screens = [
        ("Dashboard", "Main overview with system status and quick actions"),
        ("Identity", "Identity management, creation, and loading"),
        ("Crypto", "Cryptographic operations and key generation"),
        ("Accounts", "Account management and PQ key operations"),
        ("Files", "File upload, download, and management"),
        ("Sharing", "Proxy recryption sharing operations"),
    ]

    print("🖥️  Available Screens:")
    for name, description in screens:
        print(f"  • {name}: {description}")
    print()

    # Test dashboard screen
    from tui.screens.dashboard import DashboardScreen

    dashboard = DashboardScreen()
    print("📊 Dashboard Screen:")
    print(f"  • Identity loaded: {dashboard.identity_loaded}")
    print(f"  • API connected: {dashboard.api_connected}")
    print(f"  • Active files: {dashboard.active_files}")
    print(f"  • Active shares: {dashboard.active_shares}")
    print()


def demo_features():
    """Demo key features"""
    print("⭐ Key Features Demo")
    print("=" * 50)

    features = [
        "🎨 Cyberpunk/Cipherpunk aesthetic with @repligate styling",
        "🖥️  btop-inspired system monitoring",
        "🎭 Art deco design influences",
        "🔐 Full CLI feature parity",
        "📊 Real-time system and crypto monitoring",
        "🌈 Matrix rain effects and animations",
        "⚡ Quantum-resistant cryptography focus",
        "🎯 Interactive dashboard with quick actions",
        "📱 Tabbed interface for different operations",
        "🎪 Rich terminal UI with advanced widgets",
    ]

    for feature in features:
        print(f"  {feature}")
    print()


def demo_cli_integration():
    """Demo CLI integration"""
    print("🔗 CLI Integration Demo")
    print("=" * 50)

    print("💻 TUI can be launched from CLI:")
    print("  dcypher tui                    # Launch with default settings")
    print("  dcypher tui --identity-path /path/to/identity.json")
    print("  dcypher tui --api-url https://api.example.com")
    print("  dcypher tui --theme cyberpunk  # Default theme")
    print()

    print("🎯 Feature Parity:")
    cli_commands = [
        "identity (new, migrate, info, rotate, backup)",
        "crypto (gen-cc, gen-keys, encrypt, decrypt, recrypt)",
        "accounts (list, create, get, add-pq-keys, remove-pq-keys)",
        "files (upload, download, download-chunks)",
        "sharing (init-pre, create-share, list-shares, revoke-share)",
    ]

    for command in cli_commands:
        print(f"  ✓ {command}")
    print()


def main():
    """Run the complete demo"""
    print("🚀 dCypher TUI - Cyberpunk Terminal Interface")
    print("=" * 60)
    print("A quantum-resistant encryption TUI inspired by cyberpunk")
    print("aesthetics, btop monitoring, and art deco design.")
    print("=" * 60)
    print()

    demos = [
        demo_features,
        demo_theme,
        demo_ascii_art,
        demo_widgets,
        demo_screens,
        demo_cli_integration,
    ]

    for i, demo_func in enumerate(demos, 1):
        print(f"\n[{i}/{len(demos)}] ", end="")
        demo_func()

        if i < len(demos):
            print("─" * 30)
            print()

    print("🎉 Demo Complete!")
    print("=" * 60)
    print("To launch the TUI:")
    print("  uv run python -m src.tui_main")
    print("  # or")
    print("  dcypher tui")
    print("=" * 60)


if __name__ == "__main__":
    main()
