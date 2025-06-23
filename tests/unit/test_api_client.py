import pytest
import json
from pathlib import Path
from unittest.mock import Mock, patch, mock_open
import requests

from src.lib.api_client import (
    DCypherClient,
    DCypherAPIError,
    AuthenticationError,
    ResourceNotFoundError,
    ValidationError,
)


class TestDCypherClient:
    """Test cases for the DCypher API client"""

    def test_client_initialization(self):
        """Test basic client initialization"""
        client = DCypherClient("http://localhost:8000")
        assert client.api_url == "http://localhost:8000"
        assert client.auth_keys_path is None

        # Test URL normalization
        client = DCypherClient("http://localhost:8000/")
        assert client.api_url == "http://localhost:8000"

    def test_client_initialization_with_auth_keys(self):
        """Test client initialization with auth keys path"""
        client = DCypherClient("http://localhost:8000", "/path/to/keys.json")
        assert client.api_url == "http://localhost:8000"
        assert client.auth_keys_path == "/path/to/keys.json"

    @patch("requests.get")
    def test_get_nonce_success(self, mock_get):
        """Test successful nonce retrieval"""
        mock_response = Mock()
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = {"nonce": "test_nonce_12345"}
        mock_get.return_value = mock_response

        client = DCypherClient("http://localhost:8000")
        nonce = client.get_nonce()

        assert nonce == "test_nonce_12345"
        mock_get.assert_called_once_with("http://localhost:8000/nonce")

    @patch("requests.get")
    def test_get_nonce_failure(self, mock_get):
        """Test nonce retrieval failure"""
        mock_get.side_effect = requests.exceptions.RequestException("Connection error")

        client = DCypherClient("http://localhost:8000")

        with pytest.raises(DCypherAPIError, match="Failed to get nonce from API"):
            client.get_nonce()

    @patch("requests.get")
    def test_get_supported_algorithms_success(self, mock_get):
        """Test successful algorithm retrieval"""
        mock_response = Mock()
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = {"algorithms": ["ML-DSA-87", "Falcon-512"]}
        mock_get.return_value = mock_response

        client = DCypherClient("http://localhost:8000")
        algorithms = client.get_supported_algorithms()

        assert algorithms == ["ML-DSA-87", "Falcon-512"]
        mock_get.assert_called_once_with("http://localhost:8000/supported-pq-algs")

    def test_load_auth_keys_no_path(self):
        """Test loading auth keys when no path is configured"""
        client = DCypherClient("http://localhost:8000")

        with pytest.raises(
            AuthenticationError, match="No authentication keys configured"
        ):
            client._load_auth_keys()

    def test_handle_response_success_json(self):
        """Test successful JSON response handling"""
        client = DCypherClient("http://localhost:8000")
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {"content-type": "application/json"}
        mock_response.json.return_value = {"status": "success"}

        result = client._handle_response(mock_response)
        assert result == {"status": "success"}

    def test_handle_response_success_binary(self):
        """Test successful binary response handling"""
        client = DCypherClient("http://localhost:8000")
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {"content-type": "application/octet-stream"}
        mock_response.content = b"binary_data"

        result = client._handle_response(mock_response)
        assert result == b"binary_data"

    def test_handle_response_validation_error(self):
        """Test validation error response handling"""
        client = DCypherClient("http://localhost:8000")
        mock_response = Mock()
        mock_response.status_code = 400
        mock_response.text = "Invalid request"

        with pytest.raises(ValidationError, match="Validation error: Invalid request"):
            client._handle_response(mock_response)

    def test_handle_response_auth_error(self):
        """Test authentication error response handling"""
        client = DCypherClient("http://localhost:8000")
        mock_response = Mock()
        mock_response.status_code = 401
        mock_response.text = "Unauthorized"

        with pytest.raises(
            AuthenticationError, match="Authentication error: Unauthorized"
        ):
            client._handle_response(mock_response)

    def test_handle_response_not_found_error(self):
        """Test not found error response handling"""
        client = DCypherClient("http://localhost:8000")
        mock_response = Mock()
        mock_response.status_code = 404
        mock_response.text = "Not found"

        with pytest.raises(
            ResourceNotFoundError, match="Resource not found: Not found"
        ):
            client._handle_response(mock_response)

    def test_handle_response_generic_error(self):
        """Test generic error response handling"""
        client = DCypherClient("http://localhost:8000")
        mock_response = Mock()
        mock_response.status_code = 500
        mock_response.text = "Internal server error"

        with pytest.raises(
            DCypherAPIError, match="API error 500: Internal server error"
        ):
            client._handle_response(mock_response)

    @patch("src.lib.api_client.DCypherClient.get_nonce")
    @patch("src.lib.api_client.DCypherClient._sign_message")
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

        client = DCypherClient("http://localhost:8000")
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

        client = DCypherClient("http://localhost:8000")

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

        client = DCypherClient("http://localhost:8000")
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

        client = DCypherClient("http://localhost:8000")
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

        client = DCypherClient("http://localhost:8000")
        result = client.list_files("test_account")

        assert len(result) == 2
        assert result[0]["filename"] == "file1.txt"
        assert result[1]["size"] == 2048
        mock_get.assert_called_once_with("http://localhost:8000/storage/test_account")

    @patch("src.lib.api_client.DCypherClient.get_nonce")
    @patch("src.lib.api_client.DCypherClient._sign_message")
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

    @patch("src.lib.api_client.DCypherClient.get_nonce")
    @patch("src.lib.api_client.DCypherClient._sign_message")
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

    @patch("src.lib.api_client.DCypherClient.get_nonce")
    @patch("src.lib.api_client.DCypherClient._sign_message")
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
