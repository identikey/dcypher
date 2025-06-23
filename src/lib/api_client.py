import requests
import json
import tempfile
from pathlib import Path
from typing import Dict, Any, Optional, List, Tuple
from contextlib import contextmanager
from .auth import sign_message_with_keys
from .key_manager import KeyManager
import ecdsa
import oqs


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

    def __init__(self, api_url: str, auth_keys_path: Optional[str] = None):
        """
        Initialize the DCypher API client.

        Args:
            api_url: Base URL for the DCypher API
            auth_keys_path: Optional path to auth keys JSON file
        """
        self.api_url = api_url.rstrip("/")
        self.auth_keys_path = auth_keys_path
        self._auth_keys = None

    @classmethod
    def create_test_account(
        cls,
        api_url: str,
        temp_dir: Path,
        additional_pq_algs: Optional[List[str]] = None,
    ) -> Tuple["DCypherClient", str]:
        """
        Factory method to create a test account with generated keys.

        This is the preferred method for tests - it handles all key generation,
        file management, and account creation automatically.

        Args:
            api_url: Base URL for the DCypher API
            temp_dir: Directory to store temporary auth files
            additional_pq_algs: Additional PQ algorithms beyond ML-DSA

        Returns:
            tuple: (DCypherClient instance, classic_public_key_hex)
        """
        # Use KeyManager to create auth keys bundle
        pk_classic_hex, auth_keys_file = KeyManager.create_auth_keys_bundle(
            temp_dir, additional_pq_algs
        )

        # Create API client and account
        client = cls(api_url, str(auth_keys_file))

        # Load the keys to get PQ key info for account creation
        auth_keys = KeyManager.load_auth_keys_bundle(auth_keys_file)
        pq_keys = [
            {"pk_hex": key["pk_hex"], "alg": key["alg"]} for key in auth_keys["pq_keys"]
        ]
        client.create_account(pk_classic_hex, pq_keys)

        return client, pk_classic_hex

    @contextmanager
    def signing_keys(self):
        """
        Context manager for accessing signing keys with automatic cleanup.

        Usage:
            with client.signing_keys() as keys:
                sk_classic = keys["classic_sk"]
                pq_sigs = keys["pq_sigs"]
                # Use signing keys...
            # OQS signatures are automatically freed when exiting the context

        Yields:
            dict: Contains 'classic_sk' (ecdsa.SigningKey) and 'pq_sigs' (list of oqs.Signature objects)
        """
        if not self.auth_keys_path:
            raise AuthenticationError("No authentication keys configured")

        # Use KeyManager's signing context
        with KeyManager.signing_context(Path(self.auth_keys_path)) as keys:
            yield keys

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
        if self._auth_keys is not None:
            return self._auth_keys

        if not self.auth_keys_path:
            raise AuthenticationError("No authentication keys configured")

        try:
            # Use KeyManager to load auth keys
            self._auth_keys = KeyManager.load_auth_keys_bundle(
                Path(self.auth_keys_path)
            )
            return self._auth_keys
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

    def get_classic_public_key(self) -> str:
        """
        Get the classic public key hex from the loaded auth keys.

        Returns:
            Hex-encoded uncompressed SECP256k1 public key
        """
        auth_keys = self._load_auth_keys()
        return KeyManager.get_classic_public_key(auth_keys["classic_sk"])

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
