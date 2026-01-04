"""
DCypher API Client - Handles all API communications with the DCypher server
"""

import requests
import json
import tempfile
from pathlib import Path
from typing import Dict, Any, Optional, List, Tuple
from contextlib import contextmanager
from dcypher.lib.auth import sign_message_with_keys
from dcypher.lib import pre
import ecdsa
import oqs
import base64
import time

from dcypher.lib.key_manager import KeyManager


class DCypherAPIError(Exception):
    """Base exception for API errors"""

    pass


class AuthenticationError(DCypherAPIError):
    """Authentication-related errors"""

    pass


class ResourceNotFoundError(DCypherAPIError):
    """Resource not found (404) errors"""

    pass


class ValidationError(DCypherAPIError):
    """Request validation errors"""

    pass


class DCypherClient:
    """Unified client for DCypher API operations"""

    def __init__(
        self,
        api_url: str,
        identity_path: Optional[str] = None,
    ):
        """
        Initialize DCypher API client.

        Args:
            api_url: Base URL of the DCypher API server
            identity_path: Optional path to identity file for authentication
        """
        self.api_url = api_url.rstrip("/")
        self.keys_path = identity_path
        self._cached_keys = None
        self._cached_keys_timestamp = None
        self._keys_cache_ttl = 60  # Cache keys for 60 seconds
        # Private crypto context for this client instance to avoid race conditions
        self._private_context = None
        self._private_context_serialized = None

    @contextmanager
    def signing_keys(self):
        """
        Context manager for accessing signing keys with automatic cleanup.

        Now supports both auth_keys and identity files automatically.

        Usage:
            with client.signing_keys() as keys:
                sk_classic = keys["classic_sk"]
                pq_sigs = keys["pq_sigs"]
                # Use signing keys...
            # OQS signatures are automatically freed when exiting the context

        Yields:
            dict: Contains 'classic_sk' (ecdsa.SigningKey) and 'pq_sigs' (list of oqs.Signature objects)
        """
        if not self.keys_path:
            raise AuthenticationError("No authentication keys configured")

        # Import here to avoid circular import
        from dcypher.lib.key_manager import KeyManager

        # Use KeyManager's unified signing context
        assert self.keys_path is not None
        try:
            with KeyManager.signing_context(Path(self.keys_path)) as keys:
                yield keys
        except Exception as e:
            raise AuthenticationError(f"Failed to load authentication keys: {e}")

    def get_signing_keys(self) -> Dict[str, Any]:
        """
        Get direct access to signing keys for tests that need to perform
        custom signing operations.

        Returns:
            dict: Contains 'classic_sk' (ecdsa.SigningKey) and 'pq_sigs' (list of oqs.Signature objects)
        """
        auth_keys = self._load_auth_keys()

        # Create OQS signature objects for PQ keys
        pq_sigs = []
        for pq_key in auth_keys["pq_keys"]:
            sig_obj = oqs.Signature(pq_key["alg"], pq_key["sk"])
            pq_sigs.append(
                {"sig": sig_obj, "pk_hex": pq_key["pk_hex"], "alg": pq_key["alg"]}
            )

        return {"classic_sk": auth_keys["classic_sk"], "pq_sigs": pq_sigs}

    def free_signing_keys(self, signing_keys: Dict[str, Any]) -> None:
        """
        Free OQS signature objects to prevent memory leaks.

        Args:
            signing_keys: Result from get_signing_keys()
        """
        for pq_sig_info in signing_keys["pq_sigs"]:
            pq_sig_info["sig"].free()

    def sign_message_directly(self, message: str) -> Dict[str, Any]:
        """
        Sign a message directly with the loaded keys.
        Useful for tests that need to create custom signatures.

        Args:
            message: Message to sign (will be encoded to bytes)

        Returns:
            dict: Contains 'classic_signature' and 'pq_signatures' list
        """
        return self._sign_message(message)

    def create_account_with_custom_signature(
        self,
        classic_pk_hex: str,
        pq_keys: List[Dict[str, str]],
        message: str,
        classic_signature: str,
        pq_signatures: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """
        Create account with custom signatures (for testing edge cases).

        Args:
            classic_pk_hex: Classic public key hex
            pq_keys: List of PQ key info
            message: The message that was signed
            classic_signature: Custom classic signature
            pq_signatures: Custom PQ signatures

        Returns:
            API response data
        """
        # Extract nonce from message (assumes format ends with :nonce)
        nonce = message.split(":")[-1]

        # Prepare payload
        payload: Dict[str, Any] = {
            "public_key": classic_pk_hex,
            "signature": classic_signature,
            "nonce": nonce,
        }

        # Add PQ signatures
        if pq_keys and pq_signatures:
            ml_dsa_key = pq_keys[0]  # Assume first is ML-DSA
            ml_dsa_sig = pq_signatures[0]
            payload["ml_dsa_signature"] = {
                "public_key": ml_dsa_key["pk_hex"],
                "signature": ml_dsa_sig["signature"],
                "alg": ml_dsa_key["alg"],
            }

            # Additional PQ keys
            if len(pq_keys) > 1:
                additional_pq_sigs = []
                for i, pq_key in enumerate(pq_keys[1:], 1):
                    additional_pq_sigs.append(
                        {
                            "public_key": pq_key["pk_hex"],
                            "signature": pq_signatures[i]["signature"],
                            "alg": pq_key["alg"],
                        }
                    )
                payload["additional_pq_signatures"] = additional_pq_sigs

        try:
            response = requests.post(f"{self.api_url}/accounts", json=payload)
            return self._handle_response(response)
        except requests.exceptions.RequestException as e:
            raise DCypherAPIError(f"Failed to create account: {e}")

    def _load_auth_keys(self) -> Dict[str, Any]:
        """Load authentication keys from the configured path."""
        if self._cached_keys is not None and self._cached_keys_timestamp is not None:
            if time.time() - self._cached_keys_timestamp < self._keys_cache_ttl:
                return self._cached_keys

        if not self.keys_path:
            raise AuthenticationError("No authentication keys configured")

        try:
            # Use KeyManager's unified loader to support both auth_keys and identity files
            assert self.keys_path is not None
            self._cached_keys = KeyManager.load_keys_unified(Path(self.keys_path))
            self._cached_keys_timestamp = time.time()
            return self._cached_keys
        except Exception as e:
            raise AuthenticationError(f"Failed to load authentication keys: {e}")

    def get_nonce(self) -> str:
        """Get a nonce from the API server."""
        try:
            response = requests.get(f"{self.api_url}/nonce")
            response.raise_for_status()
            return response.json()["nonce"]
        except (requests.exceptions.RequestException, KeyError) as e:
            raise DCypherAPIError(f"Failed to get nonce from API: {e}")

    def get_health(self) -> Dict[str, Any]:
        """
        Get server health status and uptime information.

        This endpoint does not require authentication.

        Returns:
            Dict containing server health information including:
            - status: "healthy"
            - uptime_seconds: Server uptime in seconds
            - server_start_time: When server started (timestamp)
            - current_time: Current server time (timestamp)
            - version: Server version
            - service: Service name
            - statistics: Server statistics (accounts, files)
        """
        try:
            response = requests.get(f"{self.api_url}/health", timeout=5)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            raise DCypherAPIError(f"Failed to get server health: {e}")

    def _sign_message(self, message: str) -> Dict[str, Any]:
        """Sign a message with the loaded authentication keys."""
        auth_keys = self._load_auth_keys()
        message_bytes = message.encode("utf-8")
        return sign_message_with_keys(message_bytes, auth_keys)

    def _handle_response(self, response: requests.Response) -> Any:
        """Handle API response and convert errors to appropriate exceptions."""
        try:
            if response.status_code == 200 or response.status_code == 201:
                if response.headers.get("content-type", "").startswith(
                    "application/json"
                ):
                    return response.json()
                else:
                    return response.content
            elif response.status_code == 400:
                raise ValidationError(f"Validation error: {response.text}")
            elif response.status_code == 401:
                raise AuthenticationError(f"Authentication error: {response.text}")
            elif response.status_code == 404:
                raise ResourceNotFoundError(f"Resource not found: {response.text}")
            else:
                raise DCypherAPIError(
                    f"API error {response.status_code}: {response.text}"
                )
        except requests.exceptions.JSONDecodeError:
            raise DCypherAPIError(f"Invalid JSON response: {response.text}")

    def get_supported_algorithms(self) -> List[str]:
        """Get list of supported post-quantum algorithms."""
        try:
            response = requests.get(f"{self.api_url}/supported-pq-algs")
            response.raise_for_status()
            return response.json()["algorithms"]
        except (requests.exceptions.RequestException, KeyError) as e:
            raise DCypherAPIError(f"Failed to get supported algorithms: {e}")

    def get_crypto_context_bytes(self) -> bytes:
        """Get the serialized crypto context bytes from the API server."""
        try:
            response = requests.get(f"{self.api_url}/pre-crypto-context")
            response.raise_for_status()
            return response.content
        except requests.exceptions.RequestException as e:
            raise DCypherAPIError(f"Failed to get PRE crypto context: {e}")

    def get_pre_crypto_context(self) -> bytes:
        """
        DEPRECATED: Use get_crypto_context_bytes() instead.
        Get the serialized crypto context for PRE from the API server.
        """
        return self.get_crypto_context_bytes()

    def initialize_pre_for_identity(self) -> None:
        """
        Initializes PRE capabilities for the current identity.
        Fetches the crypto context and adds PRE keys to the identity file.
        """
        if not self.keys_path or not Path(self.keys_path).exists():
            raise AuthenticationError("Identity file not configured or does not exist.")

        # 1. Get crypto context object from server (avoids local deserialization)
        cc_object = self.get_crypto_context_object()

        # 2. Add PRE keys to identity file using the context object
        KeyManager.add_pre_keys_to_identity(Path(self.keys_path), cc_object=cc_object)

    def get_classic_public_key(self) -> str:
        """
        Get the classic public key hex from the loaded auth keys.

        Returns:
            Hex-encoded uncompressed SECP256k1 public key
        """

        auth_keys = self._load_auth_keys()
        return KeyManager.get_classic_public_key(auth_keys["classic_sk"])

    def get_dual_classical_public_keys(self) -> Dict[str, str]:
        """
        Get both classical public keys (ECDSA and ED25519) from the loaded auth keys.

        Returns:
            Dict with 'ecdsa' and 'ed25519' public keys in hex format
        """
        auth_keys = self._load_auth_keys()

        result = {"ecdsa": KeyManager.get_classic_public_key(auth_keys["classic_sk"])}

        # Include ED25519 key if present
        if "ed25519_sk" in auth_keys and auth_keys["ed25519_sk"] is not None:
            from dcypher.lib.auth import ed25519_public_key_to_hex

            ed25519_pk = auth_keys["ed25519_sk"].public_key()
            result["ed25519"] = ed25519_public_key_to_hex(ed25519_pk)

        return result

    def create_account_dual_classical(
        self, ecdsa_pk_hex: str, ed25519_pk_hex: str, pq_keys: List[Dict[str, str]]
    ) -> Dict[str, Any]:
        """
        Create a new account with dual classical keys (ECDSA + ED25519) and PQ keys.

        Args:
            ecdsa_pk_hex: Hex-encoded uncompressed SECP256k1 public key
            ed25519_pk_hex: Hex-encoded ED25519 public key
            pq_keys: List of PQ key info with 'pk_hex' and 'alg' fields

        Returns:
            API response data
        """
        # Get nonce for the operation
        nonce = self.get_nonce()

        # Construct message to sign: ecdsa_pk:ed25519_pk:pq_pk1:pq_pk2:...:nonce
        all_pks = [ecdsa_pk_hex, ed25519_pk_hex] + [key["pk_hex"] for key in pq_keys]
        message = f"{':'.join(all_pks)}:{nonce}"

        # Sign the message
        signatures = self._sign_message(message)

        # Prepare payload
        payload = {
            "ecdsa_public_key": ecdsa_pk_hex,
            "ed25519_public_key": ed25519_pk_hex,
            "ecdsa_signature": signatures["classic_signature"],
            "nonce": nonce,
        }

        # Add ED25519 signature if available
        if "ed25519_signature" in signatures:
            payload["ed25519_signature"] = signatures["ed25519_signature"]

        # Check if identity file has PRE keys and include them
        if self.keys_path and Path(self.keys_path).exists():
            try:
                with open(self.keys_path, "r") as f:
                    identity_data = json.load(f)

                # Check if this is an identity file with PRE keys
                if "auth_keys" in identity_data and "pre" in identity_data["auth_keys"]:
                    pre_keys = identity_data["auth_keys"]["pre"]
                    if "pk_hex" in pre_keys and pre_keys["pk_hex"]:
                        payload["pre_public_key_hex"] = pre_keys["pk_hex"]
            except (json.JSONDecodeError, KeyError):
                # If we can't read PRE keys, just continue without them
                pass

        # Add PQ signatures - first one is mandatory ML-DSA
        if pq_keys:
            ml_dsa_key = pq_keys[0]  # Assume first is ML-DSA
            pq_sig_for_ml_dsa = signatures["pq_signatures"][0]
            payload["ml_dsa_signature"] = {
                "public_key": ml_dsa_key["pk_hex"],
                "signature": pq_sig_for_ml_dsa["signature"],
                "alg": ml_dsa_key["alg"],
            }

            # Additional PQ keys
            if len(pq_keys) > 1:
                additional_pq_sigs = []
                for i, pq_key in enumerate(pq_keys[1:], 1):
                    additional_pq_sigs.append(
                        {
                            "public_key": pq_key["pk_hex"],
                            "signature": signatures["pq_signatures"][i]["signature"],
                            "alg": pq_key["alg"],
                        }
                    )
                payload["additional_pq_signatures"] = additional_pq_sigs

        try:
            response = requests.post(
                f"{self.api_url}/accounts", json=payload
            )
            return self._handle_response(response)
        except requests.exceptions.RequestException as e:
            raise DCypherAPIError(f"Failed to create dual classical account: {e}")

    def create_account(
        self, classic_pk_hex: str, pq_keys: List[Dict[str, str]]
    ) -> Dict[str, Any]:
        """
        Create a new account with the given classic public key and PQ keys.

        Args:
            classic_pk_hex: Hex-encoded uncompressed SECP256k1 public key
            pq_keys: List of PQ key info with 'pk_hex' and 'alg' fields

        Returns:
            API response data
        """
        # Get nonce for the operation
        nonce = self.get_nonce()

        # Construct message to sign: classic_pk:pq_pk1:pq_pk2:...:nonce
        all_pks = [classic_pk_hex] + [key["pk_hex"] for key in pq_keys]
        message = f"{':'.join(all_pks)}:{nonce}"

        # Sign the message
        signatures = self._sign_message(message)

        # Prepare payload
        payload = {
            "public_key": classic_pk_hex,
            "signature": signatures["classic_signature"],
            "nonce": nonce,
        }

        # Check if identity file has PRE keys and include them
        if self.keys_path and Path(self.keys_path).exists():
            try:
                with open(self.keys_path, "r") as f:
                    identity_data = json.load(f)

                # Check if this is an identity file with PRE keys
                if "auth_keys" in identity_data and "pre" in identity_data["auth_keys"]:
                    pre_keys = identity_data["auth_keys"]["pre"]
                    if "pk_hex" in pre_keys and pre_keys["pk_hex"]:
                        payload["pre_public_key_hex"] = pre_keys["pk_hex"]
            except (json.JSONDecodeError, KeyError):
                # If we can't read PRE keys, just continue without them
                pass

        # Add PQ signatures - first one is mandatory ML-DSA
        if pq_keys:
            ml_dsa_key = pq_keys[0]  # Assume first is ML-DSA
            pq_sig_for_ml_dsa = signatures["pq_signatures"][0]
            payload["ml_dsa_signature"] = {
                "public_key": ml_dsa_key["pk_hex"],
                "signature": pq_sig_for_ml_dsa["signature"],
                "alg": ml_dsa_key["alg"],
            }

            # Additional PQ keys
            if len(pq_keys) > 1:
                additional_pq_sigs = []
                for i, pq_key in enumerate(pq_keys[1:], 1):
                    additional_pq_sigs.append(
                        {
                            "public_key": pq_key["pk_hex"],
                            "signature": signatures["pq_signatures"][i]["signature"],
                            "alg": pq_key["alg"],
                        }
                    )
                payload["additional_pq_signatures"] = additional_pq_sigs

        try:
            response = requests.post(f"{self.api_url}/accounts", json=payload)
            return self._handle_response(response)
        except requests.exceptions.RequestException as e:
            raise DCypherAPIError(f"Failed to create account: {e}")

    def get_account(self, public_key: str) -> Dict[str, Any]:
        """
        Get account information for the given public key.

        Args:
            public_key: Hex-encoded public key

        Returns:
            Account information including PQ keys
        """
        try:
            response = requests.get(f"{self.api_url}/accounts/{public_key}")
            return self._handle_response(response)
        except requests.exceptions.RequestException as e:
            raise DCypherAPIError(f"Failed to get account: {e}")

    def list_accounts(self) -> List[str]:
        """
        List all account public keys.

        Returns:
            List of hex-encoded public keys
        """
        try:
            response = requests.get(f"{self.api_url}/accounts")
            return self._handle_response(response)["accounts"]
        except (requests.exceptions.RequestException, KeyError) as e:
            raise DCypherAPIError(f"Failed to list accounts: {e}")

    def get_account_graveyard(self, public_key: str) -> List[Dict[str, Any]]:
        """
        Get the graveyard (retired keys) for the given account.

        Args:
            public_key: Hex-encoded public key

        Returns:
            List of retired key information
        """
        try:
            response = requests.get(f"{self.api_url}/accounts/{public_key}/graveyard")
            return self._handle_response(response)["graveyard"]
        except (requests.exceptions.RequestException, KeyError) as e:
            raise DCypherAPIError(f"Failed to get account graveyard: {e}")

    def list_files(self, public_key: str) -> List[Dict[str, Any]]:
        """
        List files stored for the given account.

        Args:
            public_key: Account's classic public key

        Returns:
            List of file information
        """
        try:
            response = requests.get(f"{self.api_url}/storage/{public_key}")
            return self._handle_response(response)["files"]
        except (requests.exceptions.RequestException, KeyError) as e:
            raise DCypherAPIError(f"Failed to list files: {e}")

    def add_pq_keys(
        self, public_key: str, new_keys: List[Dict[str, str]]
    ) -> Dict[str, Any]:
        """
        Add new PQ keys to an existing account.

        Args:
            public_key: Account's classic public key
            new_keys: List of new PQ keys with 'pk_hex' and 'alg' fields

        Returns:
            API response data
        """
        # Get current account to build existing signatures
        account_info = self.get_account(public_key)
        current_pq_keys = account_info["pq_keys"]

        # Get nonce
        nonce = self.get_nonce()

        # Build message using the format the server expects: ADD-PQ:{classic_pk}:{algorithms}:{nonce}
        # For multiple algorithms, join them with ":"
        algorithms_str = ":".join(sorted([key["alg"] for key in new_keys]))
        message = f"ADD-PQ:{public_key}:{algorithms_str}:{nonce}"

        # Sign the message with all existing keys + new keys
        signatures = self._sign_message(message)

        # Prepare new PQ signatures
        new_pq_signatures = []
        for i, new_key in enumerate(new_keys):
            # The new key signatures are at the end of the signatures list
            sig_index = len(current_pq_keys) + i
            new_pq_signatures.append(
                {
                    "public_key": new_key["pk_hex"],
                    "signature": signatures["pq_signatures"][sig_index]["signature"],
                    "alg": new_key["alg"],
                }
            )

        # Prepare existing PQ signatures
        existing_pq_signatures = []
        for i, key_info in enumerate(current_pq_keys):
            existing_pq_signatures.append(
                {
                    "public_key": key_info["public_key"],
                    "signature": signatures["pq_signatures"][i]["signature"],
                    "alg": key_info["alg"],
                }
            )

        payload = {
            "new_pq_signatures": new_pq_signatures,
            "existing_pq_signatures": existing_pq_signatures,
            "classic_signature": signatures["classic_signature"],
            "nonce": nonce,
        }

        try:
            response = requests.post(
                f"{self.api_url}/accounts/{public_key}/add-pq-keys", json=payload
            )
            return self._handle_response(response)
        except requests.exceptions.RequestException as e:
            raise DCypherAPIError(f"Failed to add PQ keys: {e}")

    def remove_pq_keys(
        self, public_key: str, algs_to_remove: List[str]
    ) -> Dict[str, Any]:
        """
        Remove PQ keys from an existing account.

        Args:
            public_key: Account's classic public key
            algs_to_remove: List of algorithm names to remove

        Returns:
            API response data
        """
        # Get current account to build signatures
        account_info = self.get_account(public_key)
        current_pq_keys = account_info["pq_keys"]

        # Get nonce
        nonce = self.get_nonce()

        # Build message using the format the server expects: REMOVE-PQ:{classic_pk}:{algorithms}:{nonce}
        # For multiple algorithms, join them with ":"
        algorithms_str = ":".join(sorted(algs_to_remove))
        message = f"REMOVE-PQ:{public_key}:{algorithms_str}:{nonce}"

        # Sign the message with all existing keys
        signatures = self._sign_message(message)

        # Prepare existing PQ signatures
        pq_signatures = []
        for i, key_info in enumerate(current_pq_keys):
            pq_signatures.append(
                {
                    "public_key": key_info["public_key"],
                    "signature": signatures["pq_signatures"][i]["signature"],
                    "alg": key_info["alg"],
                }
            )

        payload = {
            "algs_to_remove": algs_to_remove,
            "classic_signature": signatures["classic_signature"],
            "pq_signatures": pq_signatures,
            "nonce": nonce,
        }

        try:
            response = requests.post(
                f"{self.api_url}/accounts/{public_key}/remove-pq-keys", json=payload
            )
            return self._handle_response(response)
        except requests.exceptions.RequestException as e:
            raise DCypherAPIError(f"Failed to remove PQ keys: {e}")

    def register_file(
        self,
        public_key: str,
        file_hash: str,
        idk_part_one: str,
        filename: str,
        content_type: str,
        total_size: int,
    ) -> Dict[str, Any]:
        """
        Register a file with the first IDK part.

        Args:
            public_key: Account's classic public key
            file_hash: Hash of the file (MerkleRoot from IDK message)
            idk_part_one: First part of the IDK message (header)
            filename: Original filename
            content_type: MIME type of the file
            total_size: Total size of the original file

        Returns:
            API response data
        """
        # Get nonce
        nonce = self.get_nonce()

        # Build message: REGISTER:public_key:file_hash:nonce
        message = f"REGISTER:{public_key}:{file_hash}:{nonce}"

        # Sign the message
        signatures = self._sign_message(message)

        # Prepare form data
        files = {
            "idk_part_one": (
                f"{file_hash}.part1.idk",
                idk_part_one,
                "application/octet-stream",
            )
        }

        data = {
            "nonce": nonce,
            "filename": filename,
            "content_type": content_type,
            "total_size": str(total_size),
            "classic_signature": signatures["classic_signature"],
            "pq_signatures": json.dumps(signatures["pq_signatures"]),
        }

        try:
            response = requests.post(
                f"{self.api_url}/storage/{public_key}/register", files=files, data=data
            )
            return self._handle_response(response)
        except requests.exceptions.RequestException as e:
            raise DCypherAPIError(f"Failed to register file: {e}")

    def upload_chunk(
        self,
        public_key: str,
        file_hash: str,
        chunk_data: bytes,
        chunk_hash: str,
        chunk_index: int,
        total_chunks: int,
        compressed: bool = True,
    ) -> Dict[str, Any]:
        """
        Upload a file chunk.

        Args:
            public_key: Account's classic public key
            file_hash: Hash of the file
            chunk_data: Raw chunk data to upload
            chunk_hash: Hash of the chunk
            chunk_index: Index of this chunk
            total_chunks: Total number of chunks
            compressed: Whether the chunk data is compressed

        Returns:
            API response data
        """
        # Get nonce
        nonce = self.get_nonce()

        # Build message: UPLOAD-CHUNK:public_key:file_hash:chunk_index:total_chunks:chunk_hash:nonce
        message = f"UPLOAD-CHUNK:{public_key}:{file_hash}:{chunk_index}:{total_chunks}:{chunk_hash}:{nonce}"

        # Sign the message
        signatures = self._sign_message(message)

        # Prepare form data
        files = {
            "file": (
                chunk_hash,
                chunk_data,
                "application/gzip" if compressed else "application/octet-stream",
            )
        }

        data = {
            "nonce": nonce,
            "chunk_hash": chunk_hash,
            "chunk_index": str(chunk_index),
            "total_chunks": str(total_chunks),
            "compressed": str(compressed).lower(),
            "classic_signature": signatures["classic_signature"],
            "pq_signatures": json.dumps(signatures["pq_signatures"]),
        }

        try:
            response = requests.post(
                f"{self.api_url}/storage/{public_key}/{file_hash}/chunks",
                files=files,
                data=data,
            )
            return self._handle_response(response)
        except requests.exceptions.RequestException as e:
            raise DCypherAPIError(f"Failed to upload chunk: {e}")

    def download_file(
        self, public_key: str, file_hash: str, compressed: bool = False
    ) -> bytes:
        """
        Download a complete file.

        Args:
            public_key: Account's classic public key
            file_hash: Hash of the file to download
            compressed: Whether to request compressed download

        Returns:
            File content as bytes
        """
        # Get nonce
        nonce = self.get_nonce()

        # Build message: DOWNLOAD:public_key:file_hash:nonce
        message = f"DOWNLOAD:{public_key}:{file_hash}:{nonce}"

        # Sign the message
        signatures = self._sign_message(message)

        payload = {
            "nonce": nonce,
            "classic_signature": signatures["classic_signature"],
            "pq_signatures": signatures["pq_signatures"],
            "compressed": compressed,
        }

        try:
            response = requests.post(
                f"{self.api_url}/storage/{public_key}/{file_hash}/download",
                json=payload,
            )
            return self._handle_response(response)
        except requests.exceptions.RequestException as e:
            raise DCypherAPIError(f"Failed to download file: {e}")

    def download_chunks(self, public_key: str, file_hash: str) -> bytes:
        """
        Download all chunks as a single concatenated gzip file.

        Args:
            public_key: Account's classic public key
            file_hash: Hash of the file to download

        Returns:
            Concatenated chunk data as bytes
        """
        # Get nonce
        nonce = self.get_nonce()

        # Build message: DOWNLOAD-CHUNKS:public_key:file_hash:nonce
        message = f"DOWNLOAD-CHUNKS:{public_key}:{file_hash}:{nonce}"

        # Sign the message
        signatures = self._sign_message(message)

        payload = {
            "nonce": nonce,
            "classic_signature": signatures["classic_signature"],
            "pq_signatures": signatures["pq_signatures"],
        }

        try:
            response = requests.post(
                f"{self.api_url}/storage/{public_key}/{file_hash}/chunks/download",
                json=payload,
            )
            return self._handle_response(response)
        except requests.exceptions.RequestException as e:
            raise DCypherAPIError(f"Failed to download chunks: {e}")

    def download_chunk(
        self, public_key: str, file_hash: str, chunk_hash: str, compressed: bool = False
    ) -> bytes:
        """
        Download a single chunk.

        Args:
            public_key: Account's classic public key
            file_hash: Hash of the file
            chunk_hash: Hash of the specific chunk
            compressed: Whether to request compressed download

        Returns:
            Chunk data as bytes
        """
        # Get nonce
        nonce = self.get_nonce()

        # Build message: DOWNLOAD-CHUNK:public_key:file_hash:chunk_hash:nonce
        message = f"DOWNLOAD-CHUNK:{public_key}:{file_hash}:{chunk_hash}:{nonce}"

        # Sign the message
        signatures = self._sign_message(message)

        payload = {
            "chunk_hash": chunk_hash,
            "nonce": nonce,
            "classic_signature": signatures["classic_signature"],
            "pq_signatures": signatures["pq_signatures"],
            "compressed": compressed,
        }

        try:
            response = requests.post(
                f"{self.api_url}/storage/{public_key}/{file_hash}/chunks/{chunk_hash}/download",
                json=payload,
            )
            return self._handle_response(response)
        except requests.exceptions.RequestException as e:
            raise DCypherAPIError(f"Failed to download chunk: {e}")

    def create_share(
        self, bob_public_key: str, file_hash: str, re_encryption_key_hex: str
    ) -> Dict[str, Any]:
        """
        Create a sharing policy to allow Bob to access Alice's file.

        Args:
            bob_public_key: Bob's classic public key
            file_hash: Hash of the file to share
            re_encryption_key_hex: Hex-encoded recryption key (Alice -> Bob)

        Returns:
            API response with share_id
        """
        alice_public_key = self.get_classic_public_key()

        # Get nonce
        nonce = self.get_nonce()

        # Build message: SHARE:alice_pk:bob_pk:file_hash:nonce
        message = f"SHARE:{alice_public_key}:{bob_public_key}:{file_hash}:{nonce}"

        # Sign the message
        signatures = self._sign_message(message)

        # Prepare form data
        data = {
            "alice_public_key": alice_public_key,
            "bob_public_key": bob_public_key,
            "file_hash": file_hash,
            "re_encryption_key_hex": re_encryption_key_hex,
            "nonce": nonce,
            "classic_signature": signatures["classic_signature"],
            "pq_signatures": json.dumps(signatures["pq_signatures"]),
        }

        try:
            response = requests.post(f"{self.api_url}/recryption/share", data=data)
            return self._handle_response(response)
        except requests.exceptions.RequestException as e:
            raise DCypherAPIError(f"Failed to create share: {e}")

    def list_shares(self, public_key: str) -> Dict[str, Any]:
        """
        List all shares involving the given public key.

        Args:
            public_key: The public key to list shares for

        Returns:
            Dict with shares_sent and shares_received lists
        """
        try:
            response = requests.get(f"{self.api_url}/recryption/shares/{public_key}")
            return self._handle_response(response)
        except requests.exceptions.RequestException as e:
            raise DCypherAPIError(f"Failed to list shares: {e}")

    def download_shared_file(self, share_id: str) -> bytes:
        """
        Download a file that has been shared with the current user.

        Args:
            share_id: ID of the share to download

        Returns:
            Recrypted file content as bytes
        """
        bob_public_key = self.get_classic_public_key()

        # Get nonce
        nonce = self.get_nonce()

        # Build message: DOWNLOAD-SHARED:bob_pk:share_id:nonce
        message = f"DOWNLOAD-SHARED:{bob_public_key}:{share_id}:{nonce}"

        # Sign the message
        signatures = self._sign_message(message)

        # Prepare form data
        data = {
            "bob_public_key": bob_public_key,
            "nonce": nonce,
            "classic_signature": signatures["classic_signature"],
            "pq_signatures": json.dumps(signatures["pq_signatures"]),
        }

        try:
            response = requests.post(
                f"{self.api_url}/recryption/download/{share_id}", data=data
            )
            return self._handle_response(response)
        except requests.exceptions.RequestException as e:
            raise DCypherAPIError(f"Failed to download shared file: {e}")

    def revoke_share(self, share_id: str) -> Dict[str, Any]:
        """
        Revoke a sharing policy.

        Args:
            share_id: ID of the share to revoke

        Returns:
            API response confirming revocation
        """
        alice_public_key = self.get_classic_public_key()

        # Get nonce
        nonce = self.get_nonce()

        # Build message: REVOKE:alice_pk:share_id:nonce
        message = f"REVOKE:{alice_public_key}:{share_id}:{nonce}"

        # Sign the message
        signatures = self._sign_message(message)

        # Prepare form data
        data = {
            "alice_public_key": alice_public_key,
            "nonce": nonce,
            "classic_signature": signatures["classic_signature"],
            "pq_signatures": json.dumps(signatures["pq_signatures"]),
        }

        try:
            response = requests.delete(
                f"{self.api_url}/recryption/share/{share_id}", data=data
            )
            return self._handle_response(response)
        except requests.exceptions.RequestException as e:
            raise DCypherAPIError(f"Failed to revoke share: {e}")

    def generate_re_encryption_key(self, bob_public_key_hex: str) -> str:
        """
        Generate a recryption key from Alice's PRE secret key to Bob's PRE public key.

        Args:
            bob_public_key_hex: Bob's PRE public key in hex format

        Returns:
            Hex-encoded recryption key
        """
        if not self.keys_path:
            raise AuthenticationError("No identity file configured")

        # Load identity file to get Alice's PRE secret key
        try:
            with open(self.keys_path, "r") as f:
                identity_data = json.load(f)

            if (
                "auth_keys" not in identity_data
                or "pre" not in identity_data["auth_keys"]
                or not identity_data["auth_keys"]["pre"]
            ):
                raise ValueError("PRE keys not found in identity file")

            alice_sk_hex = identity_data["auth_keys"]["pre"]["sk_hex"]
            alice_sk_bytes = bytes.fromhex(alice_sk_hex)

        except (FileNotFoundError, json.JSONDecodeError, KeyError) as e:
            raise AuthenticationError(f"Failed to load PRE keys: {e}")

        # Use the private context from this client instance to avoid race conditions
        # This ensures consistency with other operations on this client
        cc = self.get_crypto_context_object()

        # Deserialize Alice's secret key and Bob's public key
        alice_sk = pre.deserialize_secret_key(alice_sk_bytes)
        bob_pk_bytes = bytes.fromhex(bob_public_key_hex)
        bob_pk = pre.deserialize_public_key(bob_pk_bytes)

        # Generate the recryption key
        re_key = pre.generate_re_encryption_key(cc, alice_sk, bob_pk)

        # Serialize and return as hex
        re_key_bytes = pre.serialize_to_bytes(re_key)
        return re_key_bytes.hex()

    def get_crypto_context_object(self):
        """
        Get a properly initialized crypto context object ready for operations.

        This method maintains a private crypto context for this client instance
        to avoid race conditions in parallel test execution.

        Returns:
            Initialized crypto context object compatible with server operations
        """
        # Get server's crypto context bytes
        cc_bytes = self.get_crypto_context_bytes()
        serialized_context = base64.b64encode(cc_bytes).decode("ascii")

        # Check if we already have the correct context cached
        if (
            self._private_context is not None
            and self._private_context_serialized == serialized_context
        ):
            return self._private_context

        # Use direct PRE module deserialization
        # This creates a private context without relying on shared state
        self._private_context = pre.deserialize_cc(cc_bytes)
        self._private_context_serialized = serialized_context

        return self._private_context

    def create_identity_file(
        self,
        identity_name: str,
        key_dir: Path,
        overwrite: bool = False,
    ) -> Tuple[str, Path]:
        """
        Create a complete identity file with crypto context from this API server.

        This method handles:
        1. Fetching crypto context from the API server
        2. Creating the identity file with proper PRE keys
        3. Ensuring compatibility with this server's crypto parameters

        Args:
            identity_name: Name for the identity
            key_dir: Directory to store the identity file
            overwrite: Whether to overwrite existing identity file

        Returns:
            Tuple of (mnemonic_phrase, identity_file_path)

        Raises:
            DCypherAPIError: If unable to fetch crypto context from server
            FileExistsError: If identity already exists and overwrite=False
        """
        try:
            # Fetch crypto context from this API server
            context_bytes = self.get_crypto_context_bytes()

            # Create identity file with server's crypto context
            mnemonic, file_path = KeyManager.create_identity_file(
                identity_name,
                key_dir,
                overwrite=overwrite,
                context_bytes=context_bytes,
                context_source=self.api_url,
            )

            return mnemonic, file_path

        except DCypherAPIError:
            # Re-raise API errors as-is
            raise
        except Exception as e:
            raise DCypherAPIError(f"Failed to create identity file: {e}")

    @classmethod
    def create_test_account(
        cls,
        api_url: str,
        temp_dir: Path,
        additional_pq_algs: Optional[List[str]] = None,
    ) -> Tuple["DCypherClient", str]:
        """
        Creates a test account with complete identity file.
        Uses KeyManager for streamlined key generation and identity creation.

        Args:
            api_url: API server URL
            temp_dir: Temporary directory for identity files
            additional_pq_algs: Additional PQ algorithms beyond ML-DSA

        Returns:
            tuple: (DCypherClient, classic_public_key_hex)
        """

        # Get context bytes from server for PRE capabilities
        cc_bytes = requests.get(f"{api_url}/pre-crypto-context").content

        # ARCHITECTURAL FIX: Now that KeyManager doesn't accept api_url (to avoid circular imports),
        # we fetch the context bytes and pass them directly. This improves separation of concerns.
        mnemonic, identity_file = KeyManager.create_identity_file(
            "test_account",
            temp_dir,
            context_bytes=cc_bytes,
            context_source=f"server:{api_url}",
            # Note: api_url parameter removed to break circular import
        )

        # Add additional PQ algorithms if specified
        if additional_pq_algs:
            # Load the identity file
            with open(identity_file, "r") as f:
                identity_data = json.load(f)

            # Generate additional PQ keys
            for alg in additional_pq_algs:
                pq_pk, pq_sk = KeyManager.generate_pq_keypair(alg)
                identity_data["auth_keys"]["pq"].append(
                    {"alg": alg, "pk_hex": pq_pk.hex(), "sk_hex": pq_sk.hex()}
                )

            # Save the updated identity file
            with open(identity_file, "w") as f:
                json.dump(identity_data, f, indent=2)

        # Load identity to get public key
        keys_data = KeyManager.load_identity_file(identity_file)
        pk_classic_hex = KeyManager.get_classic_public_key(keys_data["classic_sk"])

        # Create API client with identity file
        client = cls(api_url, identity_path=str(identity_file))

        # Load the keys to get PQ key info for account creation
        if not client.keys_path:
            raise ValueError("No keys path configured for client")

        keys_data = KeyManager.load_keys_unified(Path(client.keys_path))
        pq_keys = [
            {"pk_hex": key["pk_hex"], "alg": key["alg"]} for key in keys_data["pq_keys"]
        ]
        client.create_account(pk_classic_hex, pq_keys)

        return client, pk_classic_hex

    @classmethod
    def create_test_account_dual_classical(
        cls,
        api_url: str,
        temp_dir: Path,
        additional_pq_algs: Optional[List[str]] = None,
    ) -> Tuple["DCypherClient", str, str]:
        """
        Creates a test account with dual classical keys (ECDSA + ED25519).
        Uses KeyManager for streamlined key generation and identity creation.

        Args:
            api_url: API server URL
            temp_dir: Temporary directory for identity files
            additional_pq_algs: Additional PQ algorithms beyond ML-DSA

        Returns:
            tuple: (DCypherClient, ecdsa_public_key_hex, ed25519_public_key_hex)
        """

        # Get context bytes from server for PRE capabilities
        cc_bytes = requests.get(f"{api_url}/pre-crypto-context").content

        # Create identity file with dual classical keys
        mnemonic, identity_file = KeyManager.create_identity_file(
            "test_account_dual_classical",
            temp_dir,
            context_bytes=cc_bytes,
            context_source=f"server:{api_url}",
        )

        # Add additional PQ algorithms if specified
        if additional_pq_algs:
            # Load the identity file
            with open(identity_file, "r") as f:
                identity_data = json.load(f)

            # Generate additional PQ keys
            for alg in additional_pq_algs:
                pq_pk, pq_sk = KeyManager.generate_pq_keypair(alg)
                identity_data["auth_keys"]["pq"].append(
                    {"alg": alg, "pk_hex": pq_pk.hex(), "sk_hex": pq_sk.hex()}
                )

            # Save the updated identity file
            with open(identity_file, "w") as f:
                json.dump(identity_data, f, indent=2)

        # Load identity to get both public keys
        keys_data = KeyManager.load_identity_file(identity_file)
        pk_ecdsa_hex = KeyManager.get_classic_public_key(keys_data["classic_sk"])

        # Get ED25519 public key
        if "ed25519_sk" not in keys_data:
            raise ValueError("ED25519 key not found in identity file")

        from dcypher.lib.auth import ed25519_public_key_to_hex

        ed25519_pk = keys_data["ed25519_sk"].public_key()
        pk_ed25519_hex = ed25519_public_key_to_hex(ed25519_pk)

        # Create API client with identity file
        client = cls(api_url, identity_path=str(identity_file))

        # Load the keys to get PQ key info for account creation
        if not client.keys_path:
            raise ValueError("No keys path configured for client")

        keys_data = KeyManager.load_keys_unified(Path(client.keys_path))
        pq_keys = [
            {"pk_hex": key["pk_hex"], "alg": key["alg"]} for key in keys_data["pq_keys"]
        ]

        # Create dual classical account
        client.create_account_dual_classical(pk_ecdsa_hex, pk_ed25519_hex, pq_keys)

        return client, pk_ecdsa_hex, pk_ed25519_hex
