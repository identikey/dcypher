"""
Test suite for crypto context singleton pattern and endpoints
"""

import pytest
from fastapi.testclient import TestClient
from fastapi import FastAPI

# Import our modules
from src.crypto.context_manager import CryptoContextManager, OPENFHE_AVAILABLE
from src.main import create_app


class TestCryptoContextManager:
    """Test the CryptoContextManager singleton"""

    def setup_method(self):
        """Reset singleton state before each test"""
        # Reset all process-specific singleton instances
        CryptoContextManager.reset_all_instances()
        # Create fresh instance
        self.manager: CryptoContextManager = CryptoContextManager()

    def test_singleton_pattern(self):
        """Test that CryptoContextManager follows singleton pattern"""
        manager1 = CryptoContextManager()
        manager2 = CryptoContextManager()

        assert manager1 is manager2
        assert id(manager1) == id(manager2)

    def test_openfhe_availability_check(self):
        """Test that we can check OpenFHE availability"""
        availability = self.manager.is_available()
        assert isinstance(availability, bool)
        assert availability == OPENFHE_AVAILABLE

    @pytest.mark.skipif(not OPENFHE_AVAILABLE, reason="OpenFHE not available")
    def test_context_initialization_with_openfhe(self):
        """Test context initialization with real OpenFHE library"""
        # Initialize context
        result = self.manager.initialize_context()

        # Verify context was created and stored
        assert result is not None
        assert self.manager.get_context() is not None

        # Verify parameters were stored
        params = self.manager.get_context_params()
        assert params is not None
        assert params["scheme"] == "BFV"
        assert params["plaintext_modulus"] == 65537
        assert params["multiplicative_depth"] == 2

    @pytest.mark.skipif(not OPENFHE_AVAILABLE, reason="OpenFHE not available")
    def test_context_initialization_custom_params(self):
        """Test context initialization with custom parameters"""
        # Initialize with custom parameters
        result = self.manager.initialize_context(
            scheme="BFV",
            plaintext_modulus=1024,
            multiplicative_depth=5,
            scaling_mod_size=60,
            batch_size=16,
        )

        # Verify custom parameters were stored
        params = self.manager.get_context_params()
        assert params is not None
        assert params["plaintext_modulus"] == 1024
        assert params["multiplicative_depth"] == 5
        assert params["scaling_mod_size"] == 60
        assert params["batch_size"] == 16

    @pytest.mark.skipif(not OPENFHE_AVAILABLE, reason="OpenFHE not available")
    def test_context_serialization(self):
        """Test context serialization with real OpenFHE"""
        # Initialize and serialize
        self.manager.initialize_context()
        serialized = self.manager.serialize_context()

        # Should return a non-empty string
        assert isinstance(serialized, str)
        assert len(serialized) > 0

    @pytest.mark.skipif(not OPENFHE_AVAILABLE, reason="OpenFHE not available")
    def test_context_deserialization(self):
        """Test context deserialization with real OpenFHE"""
        # First create and serialize a context
        self.manager.initialize_context()
        serialized_data = self.manager.serialize_context()

        # Reset and deserialize
        self.manager.reset()
        result = self.manager.deserialize_context_safe(serialized_data)

        assert result is not None
        assert self.manager.get_context() is not None

    def test_context_not_initialized_error(self):
        """Test error when trying to serialize uninitialized context"""
        if OPENFHE_AVAILABLE:
            with pytest.raises(RuntimeError, match="Context not initialized"):
                self.manager.serialize_context()
        else:
            with pytest.raises(RuntimeError, match="OpenFHE library is not available"):
                self.manager.serialize_context()

    @pytest.mark.skipif(not OPENFHE_AVAILABLE, reason="OpenFHE not available")
    def test_context_reset(self):
        """Test context reset functionality"""
        # Initialize context
        self.manager.initialize_context()
        assert self.manager.get_context() is not None

        # Reset context
        self.manager.reset()
        assert self.manager.get_context() is None
        assert self.manager.get_context_params() is None

    def test_unsupported_scheme_error(self):
        """Test error for unsupported scheme"""
        if OPENFHE_AVAILABLE:
            with pytest.raises(ValueError, match="Unsupported scheme: CKKS"):
                self.manager.initialize_context(scheme="CKKS")
        else:
            with pytest.raises(RuntimeError, match="OpenFHE library is not available"):
                self.manager.initialize_context(scheme="CKKS")

    @pytest.mark.skipif(
        OPENFHE_AVAILABLE, reason="Test for when OpenFHE is not available"
    )
    def test_context_operations_without_openfhe(self):
        """Test that operations fail gracefully when OpenFHE is not available"""
        with pytest.raises(RuntimeError, match="OpenFHE library is not available"):
            self.manager.initialize_context()


class TestCryptoEndpoints:
    """Test the crypto API endpoints"""

    def setup_method(self):
        """Setup test client"""
        # Reset singleton
        CryptoContextManager.reset_all_instances()

        # Create test app
        self.app: FastAPI = create_app()
        self.client: TestClient = TestClient(self.app)

    @pytest.mark.skipif(not OPENFHE_AVAILABLE, reason="OpenFHE not available")
    def test_get_crypto_context_endpoint(self):
        """Test GET /crypto/context endpoint with real OpenFHE"""
        # Make request
        response = self.client.get("/crypto/context")

        # Verify response
        assert response.status_code == 200
        data = response.json()
        assert "serialized_context" in data
        assert "context_params" in data
        assert isinstance(data["serialized_context"], str)
        assert len(data["serialized_context"]) > 0
        assert data["context_params"]["scheme"] == "BFV"

    @pytest.mark.skipif(not OPENFHE_AVAILABLE, reason="OpenFHE not available")
    def test_initialize_context_endpoint(self):
        """Test POST /crypto/initialize-context endpoint with real OpenFHE"""
        # Make request with custom parameters
        response = self.client.post(
            "/crypto/initialize-context",
            params={
                "scheme": "BFV",
                "plaintext_modulus": 2048,
                "multiplicative_depth": 3,
                "scaling_mod_size": 55,
                "batch_size": 16,  # Must be power of two for OpenFHE
            },
        )

        # Verify response
        assert response.status_code == 200
        data = response.json()
        assert data["message"] == "Crypto context initialized successfully"
        assert data["params"]["plaintext_modulus"] == 2048
        assert data["params"]["multiplicative_depth"] == 3
        assert data["params"]["batch_size"] == 16

    @pytest.mark.skipif(
        OPENFHE_AVAILABLE, reason="Test for when OpenFHE is not available"
    )
    def test_endpoints_without_openfhe(self):
        """Test that endpoints return appropriate errors when OpenFHE is not available"""
        # Test context endpoint
        response = self.client.get("/crypto/context")
        assert response.status_code == 500
        assert "OpenFHE library is not available" in response.json()["detail"]

        # Test initialize endpoint
        response = self.client.post("/crypto/initialize-context")
        assert response.status_code == 500
        assert "OpenFHE library is not available" in response.json()["detail"]


@pytest.mark.skipif(not OPENFHE_AVAILABLE, reason="OpenFHE not available")
class TestContextCompatibilityWorkflow:
    """Test the complete workflow of context sharing between client and server"""

    def setup_method(self):
        """Setup test environment"""
        CryptoContextManager.reset_all_instances()
        self.app: FastAPI = create_app()
        self.client: TestClient = TestClient(self.app)

    def test_client_server_context_synchronization(self):
        """Test that client can get server's context and use it for operations"""
        # Step 1: Server initializes context
        init_response = self.client.post("/crypto/initialize-context")
        assert init_response.status_code == 200

        # Step 2: Client requests server's context
        context_response = self.client.get("/crypto/context")
        assert context_response.status_code == 200

        context_data = context_response.json()
        serialized_context = context_data["serialized_context"]
        context_params = context_data["context_params"]

        # Step 3: Client would deserialize the same context
        # Simulate client-side context deserialization
        client_manager = CryptoContextManager()
        client_context = client_manager.deserialize_context_safe(serialized_context)

        # Verify both contexts are using the same serialized data
        assert client_manager.serialize_context() == serialized_context

    def test_deterministic_context_sharing(self):
        """Test that multiple clients get the same context"""
        # Initialize server context
        self.client.post("/crypto/initialize-context")

        # Multiple clients request context
        response1 = self.client.get("/crypto/context")
        response2 = self.client.get("/crypto/context")
        response3 = self.client.get("/crypto/context")

        # All responses should be identical
        assert response1.json() == response2.json() == response3.json()

        # All should have the same serialized context
        context1 = response1.json()["serialized_context"]
        context2 = response2.json()["serialized_context"]
        context3 = response3.json()["serialized_context"]

        assert context1 == context2 == context3


class TestContextErrorHandling:
    """Test error handling scenarios"""

    def setup_method(self):
        """Setup test environment"""
        CryptoContextManager.reset_all_instances()
        self.app: FastAPI = create_app()
        self.client: TestClient = TestClient(self.app)

    @pytest.mark.skipif(not OPENFHE_AVAILABLE, reason="OpenFHE not available")
    def test_context_initialization_with_invalid_scheme(self):
        """Test handling of invalid scheme"""
        response = self.client.post(
            "/crypto/initialize-context", params={"scheme": "INVALID_SCHEME"}
        )

        assert response.status_code == 500
        assert "Unsupported scheme" in response.json()["detail"]


if __name__ == "__main__":
    # Run tests with: python -m pytest tests/unit/test_context_singleton.py -v
    pytest.main([__file__, "-v"])
