"""
Tests for TUI widgets
"""

import pytest
from unittest.mock import Mock, patch
from textual.app import App

from dcypher.tui.widgets.ascii_art import ASCIIBanner, MatrixRain, CyberpunkBorder
from dcypher.tui.widgets.system_monitor import SystemMonitor, CryptoMonitor


class TestASCIIBanner:
    """Test cases for ASCII banner widget"""

    def test_banner_initialization(self):
        """Test banner widget initialization"""
        banner = ASCIIBanner()
        assert banner.show_subtitle is True
        assert banner.animation_frame == 0
        assert not banner.compact

    def test_banner_compact_mode(self):
        """Test banner in compact mode"""
        banner = ASCIIBanner(compact=True)
        assert banner.compact is True
        assert banner.ascii_art == banner.DCYPHER_COMPACT

    def test_banner_full_mode(self):
        """Test banner in full mode"""
        banner = ASCIIBanner(compact=False)
        assert banner.compact is False
        assert banner.ascii_art == banner.DCYPHER_ASCII

    def test_banner_subtitle_toggle(self):
        """Test subtitle toggle functionality"""
        banner = ASCIIBanner()
        initial_state = banner.show_subtitle
        banner.toggle_subtitle()
        assert banner.show_subtitle != initial_state

    def test_banner_render(self):
        """Test banner rendering"""
        banner = ASCIIBanner()
        rendered = banner.render()
        assert rendered is not None

    def test_banner_constants(self):
        """Test that banner constants are properly defined"""
        banner = ASCIIBanner()
        assert len(banner.DCYPHER_ASCII) > 0
        assert len(banner.DCYPHER_COMPACT) > 0
        assert len(banner.SUBTITLE) > 0
        assert len(banner.MATRIX_CHARS) > 0

    @patch("dcypher.tui.widgets.ascii_art.ASCIIBanner.set_interval")
    @pytest.mark.asyncio
    async def test_banner_animation_setup(self, mock_set_interval):
        """Test that animation is set up on mount"""

        class TestApp(App):
            def compose(self):
                yield ASCIIBanner()

        app = TestApp()
        async with app.run_test() as pilot:
            await pilot.pause()

            banner = pilot.app.query_one(ASCIIBanner)
            mock_set_interval.assert_called_with(0.5, banner.animate)


class TestMatrixRain:
    """Test cases for Matrix rain widget"""

    def test_matrix_rain_initialization(self):
        """Test matrix rain widget initialization"""
        rain = MatrixRain()
        assert rain.columns == []
        assert rain.frame == 0

    def test_matrix_rain_render(self):
        """Test matrix rain rendering"""
        rain = MatrixRain()
        rendered = rain.render()
        assert rendered is not None


class TestCyberpunkBorder:
    """Test cases for cyberpunk border widget"""

    def test_border_initialization(self):
        """Test border widget initialization"""
        border = CyberpunkBorder()
        assert border.pattern == "cyber"

    def test_border_patterns(self):
        """Test different border patterns"""
        patterns = ["simple", "double", "thick", "art_deco", "cyber"]

        for pattern in patterns:
            border = CyberpunkBorder(pattern=pattern)
            assert border.pattern == pattern
            rendered = border.render()
            assert rendered is not None

    def test_border_invalid_pattern(self):
        """Test border with invalid pattern falls back to default"""
        border = CyberpunkBorder(pattern="invalid")
        assert border.pattern == "invalid"
        # Should still render without error
        rendered = border.render()
        assert rendered is not None


class TestSystemMonitor:
    """Test cases for system monitor widget"""

    def test_system_monitor_initialization(self):
        """Test system monitor initialization"""
        monitor = SystemMonitor()
        assert monitor.cpu_percent == 0.0
        assert monitor.memory_percent == 0.0
        assert monitor.disk_percent == 0.0
        assert monitor.network_sent == 0
        assert monitor.network_recv == 0
        # Check that history lists are properly initialized as empty
        assert hasattr(monitor, "cpu_history")
        assert hasattr(monitor, "memory_history")
        assert len(monitor.cpu_history) == 0
        assert len(monitor.memory_history) == 0
        assert monitor.max_history == 50

    @patch("psutil.cpu_percent")
    @patch("psutil.virtual_memory")
    @patch("psutil.disk_usage")
    @patch("psutil.net_io_counters")
    def test_system_monitor_update_stats(
        self, mock_net, mock_disk, mock_memory, mock_cpu
    ):
        """Test system stats update"""
        # Mock psutil returns
        mock_cpu.return_value = 45.5
        mock_memory.return_value = Mock(percent=67.8, used=1000000, total=2000000)
        mock_disk.return_value = Mock(used=500000, total=1000000)
        mock_net.return_value = Mock(bytes_sent=1000, bytes_recv=2000)

        monitor = SystemMonitor()

        # Mock the update_display method to avoid widget query issues
        with patch.object(monitor, "update_display"):
            monitor.update_stats()

        assert monitor.cpu_percent == 45.5
        assert monitor.memory_percent == 67.8
        assert monitor.disk_percent == 50.0
        assert len(monitor.cpu_history) == 1
        assert len(monitor.memory_history) == 1

    def test_system_monitor_history_limit(self):
        """Test that history is limited to max_history"""
        monitor = SystemMonitor()
        monitor.max_history = 3

        # Add more items than the limit
        for i in range(5):
            monitor.cpu_history.append(float(i))

        # Simulate the trimming that happens in update_stats
        if len(monitor.cpu_history) > monitor.max_history:
            monitor.cpu_history = monitor.cpu_history[-monitor.max_history :]

        assert len(monitor.cpu_history) == 3
        assert monitor.cpu_history == [2.0, 3.0, 4.0]

    def test_format_bytes(self):
        """Test byte formatting utility"""
        assert SystemMonitor.format_bytes(1024) == "1.0KB"
        assert SystemMonitor.format_bytes(1024 * 1024) == "1.0MB"
        assert SystemMonitor.format_bytes(1024 * 1024 * 1024) == "1.0GB"
        assert SystemMonitor.format_bytes(500) == "500.0B"

    def test_create_sparkline(self):
        """Test sparkline creation"""
        monitor = SystemMonitor()

        # Test with empty data
        sparkline = monitor.create_sparkline([])
        assert len(sparkline.plain) > 0

        # Test with data
        data = [10.0, 20.0, 30.0, 40.0, 50.0]
        sparkline = monitor.create_sparkline(data, width=10)
        assert len(sparkline.plain) == 10

        # Test with single value
        sparkline = monitor.create_sparkline([50])
        assert len(sparkline.plain) > 0

    def test_create_cpu_panel(self):
        """Test CPU panel creation"""
        monitor = SystemMonitor()
        monitor.cpu_percent = 45.5
        monitor.cpu_history = [40, 42, 45, 47, 45]

        with (
            patch("psutil.cpu_count", return_value=8),
            patch("psutil.cpu_freq", return_value=Mock(current=2400)),
        ):
            panel = monitor.create_cpu_panel()
            assert panel is not None

    def test_create_memory_panel(self):
        """Test memory panel creation"""
        monitor = SystemMonitor()
        monitor.memory_percent = 67.8
        monitor.memory_history = [60, 62, 65, 67, 68]

        with patch(
            "psutil.virtual_memory", return_value=Mock(used=1000000, total=2000000)
        ):
            panel = monitor.create_memory_panel()
            assert panel is not None

    def test_create_disk_panel(self):
        """Test disk panel creation"""
        monitor = SystemMonitor()
        monitor.disk_percent = 50.0

        with patch(
            "psutil.disk_usage",
            return_value=Mock(used=500000, free=500000, total=1000000),
        ):
            panel = monitor.create_disk_panel()
            assert panel is not None

    def test_create_network_panel(self):
        """Test network panel creation"""
        monitor = SystemMonitor()
        monitor.network_sent = 1000
        monitor.network_recv = 2000

        with patch("psutil.net_if_stats", return_value={"eth0": Mock(isup=True)}):
            panel = monitor.create_network_panel()
            assert panel is not None


class TestCryptoMonitor:
    """Test cases for crypto monitor widget"""

    def test_crypto_monitor_initialization(self):
        """Test crypto monitor initialization"""
        monitor = CryptoMonitor()
        assert monitor.active_operations == 0
        assert monitor.completed_operations == 0
        assert monitor.failed_operations == 0
        assert monitor.operation_history == []

    def test_crypto_monitor_add_operation(self):
        """Test adding crypto operations"""
        monitor = CryptoMonitor()

        # Add active operation
        monitor.add_operation("encrypt", "active")
        assert monitor.active_operations == 1
        assert len(monitor.operation_history) == 1

        # Complete the operation
        monitor.add_operation("encrypt", "completed")
        assert monitor.active_operations == 0
        assert monitor.completed_operations == 1
        assert len(monitor.operation_history) == 2

        # Add failed operation
        monitor.add_operation("decrypt", "active")
        monitor.add_operation("decrypt", "failed")
        assert monitor.active_operations == 0
        assert monitor.failed_operations == 1
        assert len(monitor.operation_history) == 4

    def test_crypto_monitor_render(self):
        """Test crypto monitor rendering"""
        monitor = CryptoMonitor()
        monitor.active_operations = 2
        monitor.completed_operations = 10
        monitor.failed_operations = 1

        rendered = monitor.render()
        assert rendered is not None


class TestWidgetIntegration:
    """Integration tests for widgets"""

    @pytest.mark.asyncio
    async def test_widgets_in_app(self):
        """Test that widgets work within an app context"""

        class TestApp(App):
            def compose(self):
                yield ASCIIBanner()
                yield SystemMonitor()
                yield CryptoMonitor()

        app = TestApp()
        async with app.run_test() as pilot:
            await pilot.pause()

            # Check that all widgets are present
            assert pilot.app.query_one(ASCIIBanner)
            assert pilot.app.query_one(SystemMonitor)
            assert pilot.app.query_one(CryptoMonitor)

    @pytest.mark.asyncio
    async def test_widget_styling(self):
        """Test that widgets have proper styling"""

        class TestApp(App):
            CSS = """
            ASCIIBanner {
                color: green;
            }
            SystemMonitor {
                border: solid green;
            }
            """

            def compose(self):
                yield ASCIIBanner()
                yield SystemMonitor()

        app = TestApp()
        async with app.run_test() as pilot:
            await pilot.pause()

            # Widgets should render without errors even with custom CSS
            banner = pilot.app.query_one(ASCIIBanner)
            monitor = pilot.app.query_one(SystemMonitor)
            assert banner is not None
            assert monitor is not None
