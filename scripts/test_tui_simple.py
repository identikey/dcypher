#!/usr/bin/env python3
"""
Simple TUI test script that doesn't depend on crypto libraries
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

def test_theme_import():
    """Test that we can import the cyberpunk theme"""
    try:
        from tui.theme import CYBERPUNK_THEME
        print("✓ Successfully imported cyberpunk theme")
        print(f"  Theme length: {len(CYBERPUNK_THEME)} characters")
        
        # Check for key elements
        assert "$primary: #00ff41" in CYBERPUNK_THEME, "Missing matrix green color"
        assert "Header {" in CYBERPUNK_THEME, "Missing header styling"
        assert ".replicant-amber" in CYBERPUNK_THEME, "Missing replicant styling"
        print("✓ Theme contains expected cyberpunk elements")
        return True
    except Exception as e:
        print(f"✗ Failed to import theme: {e}")
        return False

def test_ascii_banner():
    """Test ASCII banner widget"""
    try:
        from tui.widgets.ascii_art import ASCIIBanner
        
        banner = ASCIIBanner()
        print("✓ Successfully created ASCII banner")
        
        # Test properties
        assert banner.show_subtitle is True, "Subtitle should be enabled by default"
        assert banner.animation_frame == 0, "Animation frame should start at 0"
        assert len(banner.DCYPHER_ASCII) > 0, "ASCII art should not be empty"
        assert "QUANTUM-RESISTANT" in banner.SUBTITLE, "Subtitle should mention quantum resistance"
        print("✓ ASCII banner properties are correct")
        
        # Test compact mode
        banner_compact = ASCIIBanner(compact=True)
        assert banner_compact.compact is True, "Compact mode should be enabled"
        print("✓ Compact mode works correctly")
        
        return True
    except Exception as e:
        print(f"✗ Failed ASCII banner test: {e}")
        return False

def test_system_monitor():
    """Test system monitor widget"""
    try:
        from tui.widgets.system_monitor import SystemMonitor
        
        monitor = SystemMonitor()
        print("✓ Successfully created system monitor")
        
        # Test initial state
        assert monitor.cpu_percent == 0.0, "CPU percent should start at 0"
        assert monitor.memory_percent == 0.0, "Memory percent should start at 0"
        assert monitor.cpu_history == [], "CPU history should start empty"
        print("✓ System monitor initial state is correct")
        
        # Test byte formatting
        assert SystemMonitor.format_bytes(1024) == "1.0KB", "Byte formatting failed"
        assert SystemMonitor.format_bytes(1024*1024) == "1.0MB", "MB formatting failed"
        print("✓ Byte formatting works correctly")
        
        return True
    except Exception as e:
        print(f"✗ Failed system monitor test: {e}")
        return False

def test_crypto_monitor():
    """Test crypto monitor widget"""
    try:
        from tui.widgets.system_monitor import CryptoMonitor
        
        monitor = CryptoMonitor()
        print("✓ Successfully created crypto monitor")
        
        # Test initial state
        assert monitor.active_operations == 0, "Active operations should start at 0"
        assert monitor.completed_operations == 0, "Completed operations should start at 0"
        assert monitor.operation_history == [], "Operation history should start empty"
        print("✓ Crypto monitor initial state is correct")
        
        # Test operation tracking
        monitor.add_operation("encrypt", "active")
        assert monitor.active_operations == 1, "Should have 1 active operation"
        
        monitor.add_operation("encrypt", "completed")
        assert monitor.active_operations == 0, "Should have 0 active operations"
        assert monitor.completed_operations == 1, "Should have 1 completed operation"
        print("✓ Operation tracking works correctly")
        
        return True
    except Exception as e:
        print(f"✗ Failed crypto monitor test: {e}")
        return False

def test_screen_imports():
    """Test that screen classes can be imported"""
    try:
        # Test basic screen structure without importing crypto-dependent modules
        from tui.screens.dashboard import DashboardScreen
        print("✓ Successfully imported dashboard screen")
        
        # Test basic instantiation
        dashboard = DashboardScreen()
        assert dashboard.identity_loaded is False, "Dashboard should start with no identity"
        print("✓ Dashboard instantiation works correctly")
        
        # Test that other screen files exist
        import os
        screen_files = [
            'src/tui/screens/identity.py',
            'src/tui/screens/crypto.py', 
            'src/tui/screens/accounts.py',
            'src/tui/screens/files.py',
            'src/tui/screens/sharing.py'
        ]
        
        for screen_file in screen_files:
            if os.path.exists(screen_file):
                print(f"✓ Found {screen_file}")
            else:
                print(f"✗ Missing {screen_file}")
                return False
        
        print("✓ All screen files exist")
        return True
    except Exception as e:
        print(f"✗ Failed screen import test: {e}")
        return False

def test_cyberpunk_border():
    """Test cyberpunk border widget"""
    try:
        from tui.widgets.ascii_art import CyberpunkBorder
        
        border = CyberpunkBorder()
        print("✓ Successfully created cyberpunk border")
        
        # Test patterns
        assert border.pattern == "cyber", "Default pattern should be cyber"
        assert "cyber" in border.BORDER_PATTERNS, "Cyber pattern should exist"
        
        # Test different patterns
        for pattern in ["simple", "double", "thick", "art_deco", "cyber"]:
            test_border = CyberpunkBorder(pattern=pattern)
            assert test_border.pattern == pattern, f"Pattern {pattern} not set correctly"
        
        print("✓ Border patterns work correctly")
        return True
    except Exception as e:
        print(f"✗ Failed cyberpunk border test: {e}")
        return False

def main():
    """Run all tests"""
    print("🚀 Running dCypher TUI Tests")
    print("=" * 50)
    
    tests = [
        test_theme_import,
        test_ascii_banner,
        test_system_monitor,
        test_crypto_monitor,
        test_screen_imports,
        test_cyberpunk_border,
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        print(f"\n🧪 Running {test.__name__}...")
        try:
            if test():
                passed += 1
                print(f"✅ {test.__name__} PASSED")
            else:
                failed += 1
                print(f"❌ {test.__name__} FAILED")
        except Exception as e:
            failed += 1
            print(f"❌ {test.__name__} FAILED with exception: {e}")
    
    print("\n" + "=" * 50)
    print(f"📊 Test Results: {passed} passed, {failed} failed")
    
    if failed == 0:
        print("🎉 All tests passed! TUI components are working correctly.")
        return 0
    else:
        print("💥 Some tests failed. Check the output above for details.")
        return 1

if __name__ == "__main__":
    sys.exit(main())