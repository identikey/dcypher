import requests
import json
from pathlib import Path
from typing import Dict, Any, Optional, List
from .auth import sign_message_with_keys
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

    def _load_auth_keys(self) -> Dict[str, Any]:
        """Load authentication keys from the configured path."""
        if self._auth_keys is not None:
            return self._auth_keys

        if not self.auth_keys_path:
            raise AuthenticationError("No authentication keys configured")

        try:
            with open(self.auth_keys_path, "r") as f:
                auth_keys_data = json.load(f)

            # Load classic signing key
            classic_sk_path = auth_keys_data["classic_sk_path"]
            with open(classic_sk_path, "r") as f:
                sk_hex = f.read().strip()
                classic_sk = ecdsa.SigningKey.from_string(
                    bytes.fromhex(sk_hex), curve=ecdsa.SECP256k1
                )

            # Load PQ keys
            pq_keys = []
            for pq_key_info in auth_keys_data["pq_keys"]:
                pq_sk_path = pq_key_info["sk_path"]
                with open(pq_sk_path, "rb") as f:
                    pq_sk = f.read()
                pq_keys.append(
                    {
                        "sk": pq_sk,
                        "pk_hex": pq_key_info["pk_hex"],
                        "alg": pq_key_info["alg"],
                    }
                )

            self._auth_keys = {"classic_sk": classic_sk, "pq_keys": pq_keys}

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
        # Get current account to build message
        account_info = self.get_account(public_key)
        current_pq_keys = [key["public_key"] for key in account_info["pq_keys"]]

        # Get nonce
        nonce = self.get_nonce()

        # Build message: classic_pk:existing_pq1:existing_pq2:...:new_pq1:new_pq2:...:nonce
        all_pks = [public_key] + current_pq_keys + [key["pk_hex"] for key in new_keys]
        message = f"{':'.join(all_pks)}:{nonce}"

        # Sign the message
        signatures = self._sign_message(message)

        # Prepare payload
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

        existing_pq_signatures = []
        for i, current_pk_hex in enumerate(current_pq_keys):
            existing_pq_signatures.append(
                {
                    "public_key": current_pk_hex,
                    "signature": signatures["pq_signatures"][i]["signature"],
                    "alg": next(
                        key["alg"]
                        for key in account_info["pq_keys"]
                        if key["public_key"] == current_pk_hex
                    ),
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

        # Build message: classic_pk:existing_pq1:existing_pq2:...:nonce
        all_pks = [public_key] + [key["public_key"] for key in current_pq_keys]
        message = f"{':'.join(all_pks)}:{nonce}"

        # Sign the message
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
