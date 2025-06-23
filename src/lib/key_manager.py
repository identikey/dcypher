"""
Unified key management for DCypher applications.

This module provides centralized key generation, loading, and management
functionality that can be used by both the API client and CLI tools.
"""

import ecdsa
import json
import tempfile
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
from contextlib import contextmanager
import oqs
from lib.pq_auth import generate_pq_keys
from config import ML_DSA_ALG
from bip_utils import Bip39MnemonicGenerator, Bip39WordsNum


class KeyManager:
    """Unified key management for DCypher operations."""

    @staticmethod
    def generate_classic_keypair() -> Tuple[ecdsa.SigningKey, str]:
        """
        Generate a classic ECDSA key pair.

        Returns:
            tuple: (SigningKey object, hex-encoded public key)
        """
        sk_classic = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
        vk_classic = sk_classic.get_verifying_key()
        assert vk_classic is not None
        pk_classic_hex = vk_classic.to_string("uncompressed").hex()
        return sk_classic, pk_classic_hex

    @staticmethod
    def generate_pq_keypair(algorithm: str) -> Tuple[bytes, bytes]:
        """
        Generate a post-quantum key pair.

        Args:
            algorithm: PQ algorithm name (e.g., 'ML-DSA-87')

        Returns:
            tuple: (public_key_bytes, secret_key_bytes)
        """
        return generate_pq_keys(algorithm)

    @staticmethod
    def save_classic_key(sk_classic: ecdsa.SigningKey, file_path: Path) -> None:
        """Save classic signing key to file."""
        with open(file_path, "w") as f:
            f.write(sk_classic.to_string().hex())

    @staticmethod
    def save_pq_key(pq_sk: bytes, file_path: Path) -> None:
        """Save PQ secret key to file."""
        with open(file_path, "wb") as f:
            f.write(pq_sk)

    @staticmethod
    def load_classic_key(file_path: Path) -> ecdsa.SigningKey:
        """Load classic signing key from file."""
        with open(file_path, "r") as f:
            sk_hex = f.read().strip()
            return ecdsa.SigningKey.from_string(
                bytes.fromhex(sk_hex), curve=ecdsa.SECP256k1
            )

    @staticmethod
    def load_pq_key(file_path: Path) -> bytes:
        """Load PQ secret key from file."""
        with open(file_path, "rb") as f:
            return f.read()

    @classmethod
    def create_auth_keys_bundle(
        cls,
        key_dir: Path,
        additional_pq_algs: Optional[List[str]] = None,
    ) -> Tuple[str, Path]:
        """
        Create a complete auth keys bundle with all necessary keys.

        This is the preferred method for creating authentication keys
        for both testing and production use.

        Args:
            key_dir: Directory to store key files
            additional_pq_algs: Additional PQ algorithms beyond ML-DSA

        Returns:
            tuple: (classic_public_key_hex, auth_keys_file_path)
        """
        if additional_pq_algs is None:
            additional_pq_algs = []

        # Ensure temp directory exists
        key_dir.mkdir(parents=True, exist_ok=True)

        # Generate and save classic key
        sk_classic, pk_classic_hex = cls.generate_classic_keypair()
        classic_sk_path = key_dir / "classic.sk"
        cls.save_classic_key(sk_classic, classic_sk_path)

        # Generate and save PQ keys
        pq_keys_data = []
        all_algs = [ML_DSA_ALG] + additional_pq_algs

        for i, alg in enumerate(all_algs):
            pq_pk, pq_sk = cls.generate_pq_keypair(alg)
            pq_sk_path = key_dir / f"pq_{i}.sk"
            cls.save_pq_key(pq_sk, pq_sk_path)
            pq_keys_data.append(
                {"sk_path": str(pq_sk_path), "pk_hex": pq_pk.hex(), "alg": alg}
            )

        # Create auth keys file
        auth_keys_data = {
            "classic_sk_path": str(classic_sk_path),
            "pq_keys": pq_keys_data,
        }
        auth_keys_file = key_dir / "auth_keys.json"
        with open(auth_keys_file, "w") as f:
            json.dump(auth_keys_data, f)

        return pk_classic_hex, auth_keys_file

    @classmethod
    def load_auth_keys_bundle(cls, auth_keys_file: Path) -> Dict[str, Any]:
        """
        Load a complete auth keys bundle from file.

        Args:
            auth_keys_file: Path to auth keys JSON file

        Returns:
            dict: Contains 'classic_sk' and 'pq_keys' list
        """
        with open(auth_keys_file, "r") as f:
            auth_keys_data = json.load(f)

        # Load classic signing key
        classic_sk_path = auth_keys_data["classic_sk_path"]
        classic_sk = cls.load_classic_key(Path(classic_sk_path))

        # Load PQ keys
        pq_keys = []
        for pq_key_info in auth_keys_data["pq_keys"]:
            pq_sk_path = pq_key_info["sk_path"]
            pq_sk = cls.load_pq_key(Path(pq_sk_path))
            pq_keys.append(
                {
                    "sk": pq_sk,
                    "pk_hex": pq_key_info["pk_hex"],
                    "alg": pq_key_info["alg"],
                }
            )

        return {"classic_sk": classic_sk, "pq_keys": pq_keys}

    @classmethod
    @contextmanager
    def signing_context(cls, auth_keys_file: Path):
        """
        Context manager for signing operations with automatic cleanup.

        Usage:
            with KeyManager.signing_context(auth_keys_file) as keys:
                classic_sk = keys["classic_sk"]
                pq_sigs = keys["pq_sigs"]
                # Use signing keys...
            # OQS signatures are automatically freed

        Args:
            auth_keys_file: Path to auth keys JSON file

        Yields:
            dict: Contains 'classic_sk' and 'pq_sigs' with OQS objects
        """
        auth_keys = cls.load_auth_keys_bundle(auth_keys_file)

        # Create OQS signature objects for PQ keys
        pq_sigs = []
        oqs_objects = []  # Keep track for cleanup

        try:
            for pq_key in auth_keys["pq_keys"]:
                sig_obj = oqs.Signature(pq_key["alg"], pq_key["sk"])
                oqs_objects.append(sig_obj)
                pq_sigs.append(
                    {"sig": sig_obj, "pk_hex": pq_key["pk_hex"], "alg": pq_key["alg"]}
                )

            yield {"classic_sk": auth_keys["classic_sk"], "pq_sigs": pq_sigs}
        finally:
            # Automatically free all OQS signature objects
            for sig_obj in oqs_objects:
                sig_obj.free()

    @staticmethod
    def get_classic_public_key(classic_sk: ecdsa.SigningKey) -> str:
        """
        Get hex-encoded public key from classic signing key.

        Args:
            classic_sk: Classic signing key

        Returns:
            Hex-encoded uncompressed public key
        """
        classic_vk = classic_sk.get_verifying_key()
        assert classic_vk is not None
        return classic_vk.to_string("uncompressed").hex()

    @staticmethod
    def create_identity_file(
        identity_name: str, key_dir: Path, overwrite: bool = False
    ) -> Tuple[str, Path]:
        identity_path = key_dir / f"{identity_name}.json"
        if identity_path.exists() and not overwrite:
            raise FileExistsError(
                f"Identity '{identity_name}' already exists at {identity_path}. Use --overwrite to replace it."
            )

        # 1. Generate mnemonic
        mnemonic = Bip39MnemonicGenerator().FromWordsNumber(Bip39WordsNum.WORDS_NUM_24)

        # 2. Generate auth keys
        sk_classic, pk_classic_hex = KeyManager.generate_classic_keypair()
        pq_pk, pq_sk = KeyManager.generate_pq_keypair(ML_DSA_ALG)

        # 3. Create identity data structure
        identity_data = {
            "mnemonic": str(mnemonic),
            "auth_keys": {
                "classic": {
                    "sk_hex": sk_classic.to_string().hex(),
                    "pk_hex": pk_classic_hex,
                },
                "pq": [
                    {
                        "alg": ML_DSA_ALG,
                        "sk_hex": pq_sk.hex(),
                        "pk_hex": pq_pk.hex(),
                    }
                ],
            },
        }

        # 4. Save to file
        key_dir.mkdir(parents=True, exist_ok=True)
        with open(identity_path, "w") as f:
            json.dump(identity_data, f, indent=4)

        return str(mnemonic), identity_path
