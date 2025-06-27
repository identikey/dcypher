"""
Tests for the main TUI application
"""

import pytest
from unittest.mock import Mock, patch
from textual.testing import AppTest

from src.tui.app import DCypherTUI


class TestDCypherTUI:
    """Test cases for the main TUI application"""
    
    def test_app_initialization(self):
        """Test that the app initializes correctly"""
        app = DCypherTUI()
        assert app.title == "dCypher - Quantum-Resistant Encryption TUI"
        assert app.sub_title == "REPLICANT TERMINAL v2.1.0"
        assert app.current_identity is None
        assert app.api_url == "http://127.0.0.1:8000"
        assert app.connection_status == "disconnected"
    
    def test_app_initialization_with_params(self):
        """Test app initialization with custom parameters"""
        identity_path = "/test/identity.json"
        api_url = "https://api.example.com"
        
        app = DCypherTUI(identity_path=identity_path, api_url=api_url)
        assert app.current_identity == identity_path
        assert app.api_url == api_url
    
    def test_app_compose(self):
        """Test that the app composes correctly"""
        with AppTest(DCypherTUI) as pilot:
            # Check that main components are present
            assert pilot.app.query("#main-container")
            assert pilot.app.query("Header")
            assert pilot.app.query("Footer")
            assert pilot.app.query("TabbedContent")
    
    def test_app_tabs_present(self):
        """Test that all required tabs are present"""
        with AppTest(DCypherTUI) as pilot:
            tabs = pilot.app.query("TabPane")
            tab_ids = [tab.id for tab in tabs]
            
            expected_tabs = ["dashboard", "identity", "crypto", "accounts", "files", "sharing"]
            for expected_tab in expected_tabs:
                assert expected_tab in tab_ids
    
    def test_app_bindings(self):
        """Test that key bindings are properly configured"""
        app = DCypherTUI()
        binding_keys = [binding.key for binding in app.BINDINGS]
        
        expected_bindings = ["ctrl+c", "ctrl+d", "f1", "f2", "f12"]
        for expected_binding in expected_bindings:
            assert expected_binding in binding_keys
    
    def test_toggle_dark_mode(self):
        """Test dark mode toggle functionality"""
        with AppTest(DCypherTUI) as pilot:
            initial_dark = pilot.app.dark
            pilot.app.action_toggle_dark()
            assert pilot.app.dark != initial_dark
    
    def test_reactive_properties(self):
        """Test reactive property updates"""
        app = DCypherTUI()
        
        # Test identity property
        test_identity = "/test/identity.json"
        app.current_identity = test_identity
        assert app.current_identity == test_identity
        
        # Test API URL property
        test_api_url = "https://test.api.com"
        app.api_url = test_api_url
        assert app.api_url == test_api_url
        
        # Test connection status property
        app.connection_status = "connected"
        assert app.connection_status == "connected"
    
    @patch('src.tui.app.DCypherTUI.set_interval')
    def test_app_mount_intervals(self, mock_set_interval):
        """Test that intervals are set up on mount"""
        with AppTest(DCypherTUI) as pilot:
            # Check that intervals were set up
            assert mock_set_interval.call_count >= 2
            
            # Check interval calls
            calls = mock_set_interval.call_args_list
            intervals = [call[0][0] for call in calls]  # First argument (interval time)
            
            assert 1.0 in intervals  # System status update
            assert 5.0 in intervals  # API connection check
    
    def test_app_screenshot_action(self):
        """Test screenshot functionality"""
        with AppTest(DCypherTUI) as pilot:
            # This should not raise an exception
            pilot.app.action_screenshot()
    
    def test_app_css_theme_loaded(self):
        """Test that the cyberpunk theme is loaded"""
        app = DCypherTUI()
        assert app.CSS is not None
        assert len(app.CSS) > 0
        # Check for some key theme elements
        assert "$primary: #00ff41" in app.CSS or "primary" in app.CSS.lower()


class TestTUIIntegration:
    """Integration tests for TUI components"""
    
    def test_dashboard_screen_loads(self):
        """Test that dashboard screen loads without errors"""
        with AppTest(DCypherTUI) as pilot:
            # Switch to dashboard tab (should be default)
            dashboard_tab = pilot.app.query_one("#dashboard")
            assert dashboard_tab is not None
    
    def test_identity_screen_loads(self):
        """Test that identity screen loads without errors"""
        with AppTest(DCypherTUI) as pilot:
            # Switch to identity tab
            identity_tab = pilot.app.query_one("#identity")
            assert identity_tab is not None
    
    def test_all_screens_accessible(self):
        """Test that all screens can be accessed"""
        with AppTest(DCypherTUI) as pilot:
            screen_ids = ["dashboard", "identity", "crypto", "accounts", "files", "sharing"]
            
            for screen_id in screen_ids:
                screen = pilot.app.query_one(f"#{screen_id}")
                assert screen is not None, f"Screen {screen_id} not found"
    
    def test_app_state_persistence(self):
        """Test that app state persists across screen changes"""
        with AppTest(DCypherTUI) as pilot:
            # Set some state
            pilot.app.current_identity = "/test/identity.json"
            pilot.app.api_url = "https://test.api.com"
            
            # Switch tabs (simulate user interaction)
            # State should persist
            assert pilot.app.current_identity == "/test/identity.json"
            assert pilot.app.api_url == "https://test.api.com"


@pytest.fixture
def mock_identity_file(tmp_path):
    """Create a mock identity file for testing"""
    identity_data = {
        "mnemonic": "test mnemonic phrase",
        "version": "1.0",
        "derivable": True,
        "auth_keys": {
            "classic": {
                "sk_hex": "test_secret_key",
                "pk_hex": "test_public_key"
            },
            "pq": [
                {
                    "alg": "Falcon-512",
                    "sk_hex": "test_pq_secret",
                    "pk_hex": "test_pq_public",
                    "derivable": True
                }
            ]
        }
    }
    
    identity_file = tmp_path / "test_identity.json"
    import json
    with open(identity_file, 'w') as f:
        json.dump(identity_data, f)
    
    return str(identity_file)


class TestTUIWithMockData:
    """Tests using mock data"""
    
    def test_app_with_mock_identity(self, mock_identity_file):
        """Test app initialization with mock identity file"""
        app = DCypherTUI(identity_path=mock_identity_file)
        assert app.current_identity == mock_identity_file
    
    def test_identity_loading_integration(self, mock_identity_file):
        """Test identity loading in the TUI"""
        with AppTest(DCypherTUI) as pilot:
            # This would test the actual identity loading process
            # For now, just verify the app can handle the file path
            pilot.app.current_identity = mock_identity_file
            assert pilot.app.current_identity == mock_identity_file