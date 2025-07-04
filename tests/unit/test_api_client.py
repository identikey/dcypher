import pytest
import json
from pathlib import Path
from unittest.mock import Mock, patch, mock_open, MagicMock
import requests
import tempfile

from dcypher.lib.api_client import (
    DCypherClient,
    DCypherAPIError,
    AuthenticationError,
    ResourceNotFoundError,
    ValidationError,
)
from dcypher.lib.key_manager import KeyManager
from dcypher.config import ML_DSA_ALG
import secrets


def _generate_mock_context_bytes():
    """Generate valid crypto context bytes for testing purposes."""
    # Create a real crypto context and serialize it for testing
    # This ensures unit tests work with valid crypto context data
    from dcypher.lib import pre

    cc = pre.create_crypto_context()
    return pre.serialize_to_bytes(cc)


class TestDCypherClient:
    """Test cases for the DCypher API client"""

    def test_client_initialization(self):
        """Test basic client initialization"""
        client = DCypherClient("http://localhost:8000", "/path/to/identity.json")
        assert client.api_url == "http://localhost:8000"
        assert client.keys_path == "/path/to/identity.json"

        # Test URL normalization
        client = DCypherClient("http://localhost:8000/", "/path/to/identity.json")
        assert client.api_url == "http://localhost:8000"

    def test_client_initialization_with_identity(self):
        """Test client initialization with identity path"""
        client = DCypherClient("http://localhost:8000", "/path/to/identity.json")
        assert client.api_url == "http://localhost:8000"
        assert client.keys_path == "/path/to/identity.json"

    @patch("requests.get")
    def test_get_nonce_success(self, mock_get):
        """Test successful nonce retrieval"""
        mock_response = Mock()
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = {"nonce": "test_nonce_12345"}
        mock_get.return_value = mock_response

        client = DCypherClient("http://localhost:8000", "/path/to/identity.json")
        nonce = client.get_nonce()

        assert nonce == "test_nonce_12345"
        mock_get.assert_called_once_with("http://localhost:8000/nonce")

    @patch("requests.get")
    def test_get_nonce_failure(self, mock_get):
        """Test nonce retrieval failure"""
        mock_get.side_effect = requests.exceptions.RequestException("Connection error")

        client = DCypherClient("http://localhost:8000", "/path/to/identity.json")

        with pytest.raises(DCypherAPIError, match="Failed to get nonce from API"):
            client.get_nonce()

    @patch("requests.get")
    def test_get_supported_algorithms_success(self, mock_get):
        """Test successful algorithm retrieval"""
        mock_response = Mock()
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = {"algorithms": ["ML-DSA-87", "Falcon-512"]}
        mock_get.return_value = mock_response

        client = DCypherClient("http://localhost:8000", "/path/to/identity.json")
        algorithms = client.get_supported_algorithms()

        assert algorithms == ["ML-DSA-87", "Falcon-512"]
        mock_get.assert_called_once_with("http://localhost:8000/supported-pq-algs")

    @patch("requests.get")
    def test_get_health_success(self, mock_get):
        """Test successful health retrieval"""
        mock_response = Mock()
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = {
            "status": "healthy",
            "uptime_seconds": 3661,
            "server_start_time": 1609459200.0,
            "current_time": 1609462861.0,
            "version": "0.0.1",
            "service": "dCypher PQ-Lattice FHE System",
            "statistics": {"accounts": 5, "files": 12},
        }
        mock_get.return_value = mock_response

        client = DCypherClient("http://localhost:8000", "/path/to/identity.json")
        health_status = client.get_health()

        assert health_status["status"] == "healthy"
        assert health_status["service"] == "dCypher PQ-Lattice FHE System"
        assert health_status["uptime_seconds"] == 3661
        assert health_status["version"] == "0.0.1"
        assert health_status["statistics"]["accounts"] == 5
        assert health_status["statistics"]["files"] == 12
        mock_get.assert_called_once_with("http://localhost:8000/health", timeout=5)

    @patch("requests.get")
    def test_get_health_failure(self, mock_get):
        """Test health retrieval failure"""
        mock_get.side_effect = requests.exceptions.RequestException("Connection error")

        client = DCypherClient("http://localhost:8000", "/path/to/identity.json")

        with pytest.raises(DCypherAPIError, match="Failed to get server health"):
            client.get_health()

    def test_load_auth_keys_no_path(self):
        """Test loading auth keys when no path is configured"""
        client = DCypherClient("http://localhost:8000", "/path/to/identity.json")

        with pytest.raises(
            AuthenticationError, match="Failed to load authentication keys"
        ):
            client._load_auth_keys()

    def test_handle_response_success_json(self):
        """Test successful JSON response handling"""
        client = DCypherClient("http://localhost:8000", "/path/to/identity.json")
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {"content-type": "application/json"}
        mock_response.json.return_value = {"status": "success"}

        result = client._handle_response(mock_response)
        assert result == {"status": "success"}

    def test_handle_response_success_binary(self):
        """Test successful binary response handling"""
        client = DCypherClient("http://localhost:8000", "/path/to/identity.json")
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {"content-type": "application/octet-stream"}
        mock_response.content = b"binary_data"

        result = client._handle_response(mock_response)
        assert result == b"binary_data"

    def test_handle_response_validation_error(self):
        """Test validation error response handling"""
        client = DCypherClient("http://localhost:8000", "/path/to/identity.json")
        mock_response = Mock()
        mock_response.status_code = 400
        mock_response.text = "Invalid request"

        with pytest.raises(ValidationError, match="Validation error: Invalid request"):
            client._handle_response(mock_response)

    def test_handle_response_auth_error(self):
        """Test authentication error response handling"""
        client = DCypherClient("http://localhost:8000", "/path/to/identity.json")
        mock_response = Mock()
        mock_response.status_code = 401
        mock_response.text = "Unauthorized"

        with pytest.raises(
            AuthenticationError, match="Authentication error: Unauthorized"
        ):
            client._handle_response(mock_response)

    def test_handle_response_not_found_error(self):
        """Test not found error response handling"""
        client = DCypherClient("http://localhost:8000", "/path/to/identity.json")
        mock_response = Mock()
        mock_response.status_code = 404
        mock_response.text = "Not found"

        with pytest.raises(
            ResourceNotFoundError, match="Resource not found: Not found"
        ):
            client._handle_response(mock_response)

    def test_handle_response_generic_error(self):
        """Test generic error response handling"""
        client = DCypherClient("http://localhost:8000", "/path/to/identity.json")
        mock_response = Mock()
        mock_response.status_code = 500
        mock_response.text = "Internal server error"

        with pytest.raises(
            DCypherAPIError, match="API error 500: Internal server error"
        ):
            client._handle_response(mock_response)

    @patch("dcypher.lib.api_client.DCypherClient.get_nonce")
    @patch("dcypher.lib.api_client.DCypherClient._sign_message")
    @patch("requests.post")
    def test_create_account_success(self, mock_post, mock_sign, mock_nonce):
        """Test successful account creation"""
        # Setup mocks
        mock_nonce.return_value = "test_nonce"
        mock_sign.return_value = {
            "classic_signature": "classic_sig_hex",
            "pq_signatures": [{"signature": "pq_sig_hex", "alg": "ML-DSA-87"}],
        }
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {"content-type": "application/json"}
        mock_response.json.return_value = {"message": "Account created successfully"}
        mock_post.return_value = mock_response

        client = DCypherClient("http://localhost:8000", "/path/to/keys.json")
        pq_keys = [{"pk_hex": "pq_key_hex", "alg": "ML-DSA-87"}]

        result = client.create_account("classic_key_hex", pq_keys)

        # Verify the result
        assert result == {"message": "Account created successfully"}

        # Verify API calls
        mock_nonce.assert_called_once()
        mock_sign.assert_called_once_with("classic_key_hex:pq_key_hex:test_nonce")

        expected_payload = {
            "public_key": "classic_key_hex",
            "signature": "classic_sig_hex",
            "nonce": "test_nonce",
            "ml_dsa_signature": {
                "public_key": "pq_key_hex",
                "signature": "pq_sig_hex",
                "alg": "ML-DSA-87",
            },
        }
        mock_post.assert_called_once_with(
            "http://localhost:8000/accounts", json=expected_payload
        )

    @patch("requests.get")
    def test_get_account_success(self, mock_get):
        """Test successful account retrieval"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {"content-type": "application/json"}
        mock_response.json.return_value = {
            "public_key": "test_key",
            "pq_keys": [{"public_key": "pq_key", "alg": "ML-DSA-87"}],
        }
        mock_get.return_value = mock_response

        client = DCypherClient("http://localhost:8000", "/path/to/identity.json")
        result = client.get_account("test_key")

        assert result["public_key"] == "test_key"
        assert len(result["pq_keys"]) == 1
        mock_get.assert_called_once_with("http://localhost:8000/accounts/test_key")

    @patch("requests.get")
    def test_get_account_not_found(self, mock_get):
        """Test account not found error"""
        mock_response = Mock()
        mock_response.status_code = 404
        mock_response.text = "Account not found"
        mock_get.return_value = mock_response

        client = DCypherClient("http://localhost:8000", "/path/to/identity.json")

        with pytest.raises(
            ResourceNotFoundError, match="Resource not found: Account not found"
        ):
            client.get_account("nonexistent_key")

    @patch("requests.get")
    def test_list_accounts_success(self, mock_get):
        """Test successful account listing"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {"content-type": "application/json"}
        mock_response.json.return_value = {
            "accounts": ["account1", "account2", "account3"]
        }
        mock_get.return_value = mock_response

        client = DCypherClient("http://localhost:8000", "/path/to/identity.json")
        result = client.list_accounts()

        assert result == ["account1", "account2", "account3"]
        mock_get.assert_called_once_with("http://localhost:8000/accounts")

    @patch("requests.get")
    def test_get_account_graveyard_success(self, mock_get):
        """Test successful graveyard retrieval"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {"content-type": "application/json"}
        mock_response.json.return_value = {
            "graveyard": [
                {"public_key": "retired_key1", "alg": "ML-DSA-87"},
                {"public_key": "retired_key2", "alg": "Falcon-512"},
            ]
        }
        mock_get.return_value = mock_response

        client = DCypherClient("http://localhost:8000", "/path/to/identity.json")
        result = client.get_account_graveyard("test_account")

        assert len(result) == 2
        assert result[0]["public_key"] == "retired_key1"
        assert result[1]["alg"] == "Falcon-512"
        mock_get.assert_called_once_with(
            "http://localhost:8000/accounts/test_account/graveyard"
        )

    @patch("requests.get")
    def test_list_files_success(self, mock_get):
        """Test successful file listing"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {"content-type": "application/json"}
        mock_response.json.return_value = {
            "files": [
                {"hash": "file1_hash", "filename": "file1.txt", "size": 1024},
                {"hash": "file2_hash", "filename": "file2.txt", "size": 2048},
            ]
        }
        mock_get.return_value = mock_response

        client = DCypherClient("http://localhost:8000", "/path/to/identity.json")
        result = client.list_files("test_account")

        assert len(result) == 2
        assert result[0]["filename"] == "file1.txt"
        assert result[1]["size"] == 2048
        mock_get.assert_called_once_with("http://localhost:8000/storage/test_account")

    @patch("dcypher.lib.api_client.DCypherClient.get_nonce")
    @patch("dcypher.lib.api_client.DCypherClient._sign_message")
    @patch("requests.post")
    def test_register_file_success(self, mock_post, mock_sign, mock_nonce):
        """Test successful file registration"""
        # Setup mocks
        mock_nonce.return_value = "test_nonce"
        mock_sign.return_value = {
            "classic_signature": "classic_sig_hex",
            "pq_signatures": [{"signature": "pq_sig_hex", "alg": "ML-DSA-87"}],
        }
        mock_response = Mock()
        mock_response.status_code = 201
        mock_response.headers = {"content-type": "application/json"}
        mock_response.json.return_value = {"message": "File registered successfully"}
        mock_post.return_value = mock_response

        client = DCypherClient("http://localhost:8000", "/path/to/keys.json")

        result = client.register_file(
            public_key="test_pk",
            file_hash="test_hash",
            idk_part_one="test_idk_part",
            filename="test.txt",
            content_type="text/plain",
            total_size=1024,
        )

        # Verify the result
        assert result == {"message": "File registered successfully"}

        # Verify API calls
        mock_nonce.assert_called_once()
        mock_sign.assert_called_once_with("REGISTER:test_pk:test_hash:test_nonce")

        # Verify the request was made correctly
        assert mock_post.call_count == 1
        call_args = mock_post.call_args
        assert call_args[1]["files"]["idk_part_one"][0] == "test_hash.part1.idk"
        assert call_args[1]["files"]["idk_part_one"][1] == "test_idk_part"
        assert call_args[1]["data"]["filename"] == "test.txt"
        assert call_args[1]["data"]["total_size"] == "1024"

    @patch("dcypher.lib.api_client.DCypherClient.get_nonce")
    @patch("dcypher.lib.api_client.DCypherClient._sign_message")
    @patch("requests.post")
    def test_upload_chunk_success(self, mock_post, mock_sign, mock_nonce):
        """Test successful chunk upload"""
        # Setup mocks
        mock_nonce.return_value = "test_nonce"
        mock_sign.return_value = {
            "classic_signature": "classic_sig_hex",
            "pq_signatures": [{"signature": "pq_sig_hex", "alg": "ML-DSA-87"}],
        }
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {"content-type": "application/json"}
        mock_response.json.return_value = {"message": "Chunk uploaded successfully"}
        mock_post.return_value = mock_response

        client = DCypherClient("http://localhost:8000", "/path/to/keys.json")

        result = client.upload_chunk(
            public_key="test_pk",
            file_hash="test_file_hash",
            chunk_data=b"test_chunk_data",
            chunk_hash="test_chunk_hash",
            chunk_index=1,
            total_chunks=5,
            compressed=True,
        )

        # Verify the result
        assert result == {"message": "Chunk uploaded successfully"}

        # Verify API calls
        mock_nonce.assert_called_once()
        expected_message = (
            "UPLOAD-CHUNK:test_pk:test_file_hash:1:5:test_chunk_hash:test_nonce"
        )
        mock_sign.assert_called_once_with(expected_message)

    @patch("dcypher.lib.api_client.DCypherClient.get_nonce")
    @patch("dcypher.lib.api_client.DCypherClient._sign_message")
    @patch("requests.post")
    def test_download_chunks_success(self, mock_post, mock_sign, mock_nonce):
        """Test successful chunks download"""
        # Setup mocks
        mock_nonce.return_value = "test_nonce"
        mock_sign.return_value = {
            "classic_signature": "classic_sig_hex",
            "pq_signatures": [{"signature": "pq_sig_hex", "alg": "ML-DSA-87"}],
        }
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {"content-type": "application/gzip"}
        mock_response.content = b"compressed_chunk_data"
        mock_post.return_value = mock_response

        client = DCypherClient("http://localhost:8000", "/path/to/keys.json")

        result = client.download_chunks(
            public_key="test_pk", file_hash="test_file_hash"
        )

        # Verify the result
        assert result == b"compressed_chunk_data"

        # Verify API calls
        mock_nonce.assert_called_once()
        mock_sign.assert_called_once_with(
            "DOWNLOAD-CHUNKS:test_pk:test_file_hash:test_nonce"
        )

        # Verify the request payload
        call_args = mock_post.call_args
        payload = call_args[1]["json"]
        assert payload["nonce"] == "test_nonce"
        assert payload["classic_signature"] == "classic_sig_hex"

    @patch("dcypher.lib.api_client.DCypherClient.get_classic_public_key")
    @patch("dcypher.lib.api_client.DCypherClient.get_nonce")
    @patch("dcypher.lib.api_client.DCypherClient._sign_message")
    @patch("requests.post")
    def test_create_share_success(self, mock_post, mock_sign, mock_nonce, mock_get_pk):
        """Test successful share creation"""
        # Setup mocks
        mock_get_pk.return_value = "alice_pk_hex"
        mock_nonce.return_value = "test_nonce"
        mock_sign.return_value = {
            "classic_signature": "classic_sig_hex",
            "pq_signatures": [{"signature": "pq_sig_hex", "alg": "ML-DSA-87"}],
        }
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {"content-type": "application/json"}
        mock_response.json.return_value = {
            "message": "Share created successfully",
            "share_id": "test_share_id_12345",
        }
        mock_post.return_value = mock_response

        client = DCypherClient("http://localhost:8000", "/path/to/keys.json")

        result = client.create_share(
            bob_public_key="bob_pk_hex",
            file_hash="test_file_hash",
            re_encryption_key_hex="re_key_hex",
        )

        # Verify the result
        assert result == {
            "message": "Share created successfully",
            "share_id": "test_share_id_12345",
        }

        # Verify API calls
        mock_get_pk.assert_called_once()
        mock_nonce.assert_called_once()
        mock_sign.assert_called_once_with(
            "SHARE:alice_pk_hex:bob_pk_hex:test_file_hash:test_nonce"
        )

        # Verify the HTTP request
        mock_post.assert_called_once()
        call_args = mock_post.call_args
        assert call_args[0][0] == "http://localhost:8000/reencryption/share"
        form_data = call_args[1]["data"]
        assert form_data["alice_public_key"] == "alice_pk_hex"
        assert form_data["bob_public_key"] == "bob_pk_hex"
        assert form_data["file_hash"] == "test_file_hash"
        assert form_data["re_encryption_key_hex"] == "re_key_hex"
        assert form_data["nonce"] == "test_nonce"
        assert form_data["classic_signature"] == "classic_sig_hex"
        import json

        pq_sigs = json.loads(form_data["pq_signatures"])
        assert len(pq_sigs) == 1
        assert pq_sigs[0]["signature"] == "pq_sig_hex"
        assert pq_sigs[0]["alg"] == "ML-DSA-87"

    @patch("requests.get")
    def test_list_shares_success(self, mock_get):
        """Test successful shares listing"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {"content-type": "application/json"}
        mock_response.json.return_value = {
            "public_key": "test_pk",
            "shares_sent": [
                {
                    "share_id": "share_1",
                    "to": "bob_pk",
                    "file_hash": "file_hash_1",
                    "created_at": 1234567890,
                }
            ],
            "shares_received": [
                {
                    "share_id": "share_2",
                    "from": "alice_pk",
                    "file_hash": "file_hash_2",
                    "created_at": 1234567891,
                }
            ],
        }
        mock_get.return_value = mock_response

        client = DCypherClient("http://localhost:8000", "/path/to/identity.json")
        result = client.list_shares("test_pk")

        # Verify the result
        assert result["public_key"] == "test_pk"
        assert len(result["shares_sent"]) == 1
        assert len(result["shares_received"]) == 1
        assert result["shares_sent"][0]["share_id"] == "share_1"
        assert result["shares_sent"][0]["to"] == "bob_pk"
        assert result["shares_received"][0]["share_id"] == "share_2"
        assert result["shares_received"][0]["from"] == "alice_pk"

        mock_get.assert_called_once_with(
            "http://localhost:8000/reencryption/shares/test_pk"
        )

    @patch("requests.get")
    def test_list_shares_empty(self, mock_get):
        """Test listing shares when no shares exist"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {"content-type": "application/json"}
        mock_response.json.return_value = {
            "public_key": "test_pk",
            "shares_sent": [],
            "shares_received": [],
        }
        mock_get.return_value = mock_response

        client = DCypherClient("http://localhost:8000", "/path/to/identity.json")
        result = client.list_shares("test_pk")

        # Verify the result shows empty lists
        assert result["public_key"] == "test_pk"
        assert result["shares_sent"] == []
        assert result["shares_received"] == []

        mock_get.assert_called_once_with(
            "http://localhost:8000/reencryption/shares/test_pk"
        )

    @patch("requests.get")
    def test_list_shares_failure(self, mock_get):
        """Test list shares failure"""
        mock_get.side_effect = requests.exceptions.RequestException("Connection error")

        client = DCypherClient("http://localhost:8000", "/path/to/identity.json")

        with pytest.raises(DCypherAPIError, match="Failed to list shares"):
            client.list_shares("test_pk")

    @patch("dcypher.lib.api_client.DCypherClient.get_classic_public_key")
    @patch("dcypher.lib.api_client.DCypherClient.get_nonce")
    @patch("dcypher.lib.api_client.DCypherClient._sign_message")
    @patch("requests.post")
    def test_create_share_failure(self, mock_post, mock_sign, mock_nonce, mock_get_pk):
        """Test share creation failure"""
        # Setup mocks
        mock_get_pk.return_value = "alice_pk_hex"
        mock_nonce.return_value = "test_nonce"
        mock_sign.return_value = {
            "classic_signature": "classic_sig_hex",
            "pq_signatures": [{"signature": "pq_sig_hex", "alg": "ML-DSA-87"}],
        }
        mock_post.side_effect = requests.exceptions.RequestException("Connection error")

        client = DCypherClient("http://localhost:8000", "/path/to/keys.json")

        with pytest.raises(DCypherAPIError, match="Failed to create share"):
            client.create_share(
                bob_public_key="bob_pk_hex",
                file_hash="test_file_hash",
                re_encryption_key_hex="re_key_hex",
            )

    @patch("dcypher.lib.api_client.DCypherClient.get_classic_public_key")
    @patch("dcypher.lib.api_client.DCypherClient.get_nonce")
    @patch("dcypher.lib.api_client.DCypherClient._sign_message")
    @patch("requests.post")
    def test_download_shared_file_success(
        self, mock_post, mock_sign, mock_nonce, mock_get_pk
    ):
        """Test successful shared file download"""
        # Setup mocks
        mock_get_pk.return_value = "bob_pk_hex"
        mock_nonce.return_value = "test_nonce"
        mock_sign.return_value = {
            "classic_signature": "classic_sig_hex",
            "pq_signatures": [{"signature": "pq_sig_hex", "alg": "ML-DSA-87"}],
        }
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {"content-type": "application/gzip"}
        mock_response.content = b"re_encrypted_file_content"
        mock_post.return_value = mock_response

        client = DCypherClient("http://localhost:8000", "/path/to/keys.json")

        result = client.download_shared_file("test_share_id")

        # Verify the result
        assert result == b"re_encrypted_file_content"

        # Verify API calls
        mock_get_pk.assert_called_once()
        mock_nonce.assert_called_once()
        mock_sign.assert_called_once_with(
            "DOWNLOAD-SHARED:bob_pk_hex:test_share_id:test_nonce"
        )

        # Verify the HTTP request
        mock_post.assert_called_once()
        call_args = mock_post.call_args
        assert (
            call_args[0][0]
            == "http://localhost:8000/reencryption/download/test_share_id"
        )
        form_data = call_args[1]["data"]
        assert form_data["bob_public_key"] == "bob_pk_hex"
        assert form_data["nonce"] == "test_nonce"
        assert form_data["classic_signature"] == "classic_sig_hex"
        import json

        pq_sigs = json.loads(form_data["pq_signatures"])
        assert len(pq_sigs) == 1
        assert pq_sigs[0]["signature"] == "pq_sig_hex"
        assert pq_sigs[0]["alg"] == "ML-DSA-87"


def test_dcypher_client_with_auth_keys():
    """Test DCypherClient with traditional auth_keys file."""
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)

        # Create auth_keys bundle
        pk_hex, auth_keys_file = KeyManager.create_auth_keys_bundle(temp_path)

        # Create client with auth_keys
        client = DCypherClient(
            api_url="http://test.example.com", identity_path=str(auth_keys_file)
        )

        # Verify client can load keys
        with client.signing_keys() as keys:
            assert "classic_sk" in keys
            assert "pq_sigs" in keys
            assert len(keys["pq_sigs"]) >= 1

        # Verify public key extraction works
        public_key = client.get_classic_public_key()
        assert isinstance(public_key, str)
        assert len(public_key) > 0


def test_dcypher_client_with_identity():
    """Test DCypherClient with new identity file."""
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)

        # Create identity file
        mnemonic, identity_file = KeyManager.create_identity_file(
            "test_identity", temp_path, context_bytes=_generate_mock_context_bytes()
        )

        # Create client with identity file
        client = DCypherClient(
            "http://localhost:8000", identity_path=str(identity_file)
        )

        # Verify client can load keys
        with client.signing_keys() as keys:
            assert "classic_sk" in keys
            assert "pq_sigs" in keys
            assert len(keys["pq_sigs"]) >= 1

        # Verify public key extraction works
        public_key = client.get_classic_public_key()
        assert isinstance(public_key, str)
        assert len(public_key) > 0


def test_dcypher_client_identity_precedence():
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)

        # Create both auth_keys and identity files
        pk_hex_auth, auth_keys_file = KeyManager.create_auth_keys_bundle(temp_path)
        mnemonic, identity_file = KeyManager.create_identity_file(
            "test_identity", temp_path, context_bytes=_generate_mock_context_bytes()
        )

        # Create client with both paths - identity should take precedence
        client = DCypherClient(
            "http://localhost:8000",
            identity_path=str(identity_file),
        )

        # The client should be using the identity file (keys_path should point to identity)
        assert client.keys_path == str(identity_file)

        # Should be able to load keys from identity file
        with client.signing_keys() as keys:
            assert "classic_sk" in keys
            assert "pq_sigs" in keys


def test_dcypher_client_no_keys_configured():
    """Test DCypherClient error handling when no keys are configured."""
    client = DCypherClient("http://localhost:8000", "/path/to/identity.json")

    # Should raise error when trying to access keys
    with pytest.raises(AuthenticationError, match="Failed to load authentication keys"):
        with client.signing_keys():
            pass

    with pytest.raises(AuthenticationError, match="Failed to load authentication keys"):
        client.get_classic_public_key()


@patch("requests.get")
def test_dcypher_client_create_test_account_with_identity(mock_requests_get):
    """Test DCypherClient.create_test_account with identity system."""
    import tempfile
    from pathlib import Path
    from unittest.mock import patch, MagicMock

    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)

        # Mock the crypto context fetch to avoid server connection
        mock_context_bytes = _generate_mock_context_bytes()

        # Mock the requests.get call that fetches crypto context
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.content = mock_context_bytes
        mock_response.raise_for_status.return_value = None
        mock_requests_get.return_value = mock_response

        # Also create a real context object for the new API
        from dcypher.lib import pre

        mock_context_object = pre.create_crypto_context()
        pre.generate_keys(mock_context_object)  # Initialize it

        # Mock account creation to avoid the final API call
        with patch.object(DCypherClient, "create_account") as mock_create_account:
            mock_create_account.return_value = {
                "message": "Account created successfully"
            }

            # This should now work without any network calls
            client, pk_hex = DCypherClient.create_test_account(
                "http://localhost:8000", temp_path
            )

        # Verify the requests.get was called correctly
        assert mock_requests_get.call_count >= 1, (
            "Should have called requests.get at least once"
        )
        mock_requests_get.assert_any_call("http://localhost:8000/pre-crypto-context")

        # Verify identity file was created
        identity_files = list(temp_path.glob("*.json"))
        assert len(identity_files) == 1, "Should have created one identity file"

        # Verify client can load the identity
        identity_file = identity_files[0]
        assert client.keys_path == str(identity_file)

        with client.signing_keys() as keys:
            assert "classic_sk" in keys
            assert "pq_sigs" in keys

        # Verify public key was returned
        assert isinstance(pk_hex, str)
        assert len(pk_hex) > 0


def test_dcypher_client_backward_compatibility():
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)

        # Create auth_keys bundle
        pk_hex, auth_keys_file = KeyManager.create_auth_keys_bundle(temp_path)

        # Create client using legacy parameter name
        client = DCypherClient(
            api_url="http://test.example.com", identity_path=str(auth_keys_file)
        )

        # Should work exactly as before
        assert client.keys_path == str(auth_keys_file)

        with client.signing_keys() as keys:
            assert "classic_sk" in keys
            assert "pq_sigs" in keys
