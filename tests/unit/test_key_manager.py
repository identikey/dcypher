"""Unit tests for the KeyManager class."""

import pytest
import tempfile
from pathlib import Path
import ecdsa
import oqs
from src.lib.key_manager import KeyManager
from src.config import ML_DSA_ALG


def test_generate_classic_keypair():
    """Test classic key pair generation."""
    sk, pk_hex = KeyManager.generate_classic_keypair()

    # Verify types
    assert isinstance(sk, ecdsa.SigningKey)
    assert isinstance(pk_hex, str)

    # Verify public key can be reconstructed
    vk = sk.get_verifying_key()
    assert vk is not None
    assert vk.to_string("uncompressed").hex() == pk_hex


def test_generate_pq_keypair():
    """Test PQ key pair generation."""
    pk_bytes, sk_bytes = KeyManager.generate_pq_keypair(ML_DSA_ALG)

    # Verify types
    assert isinstance(pk_bytes, bytes)
    assert isinstance(sk_bytes, bytes)

    # Verify keys can be used with OQS
    with oqs.Signature(ML_DSA_ALG, sk_bytes) as sig:
        message = b"test message"
        signature = sig.sign(message)
        assert isinstance(signature, bytes)
        assert len(signature) > 0


def test_save_and_load_classic_key():
    """Test saving and loading classic keys."""
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)

        # Generate and save key
        sk_original, pk_hex = KeyManager.generate_classic_keypair()
        key_file = temp_path / "test.sk"
        KeyManager.save_classic_key(sk_original, key_file)

        # Verify file exists
        assert key_file.exists()

        # Load key and verify it matches
        sk_loaded = KeyManager.load_classic_key(key_file)
        vk_loaded = sk_loaded.get_verifying_key()
        assert vk_loaded is not None
        assert vk_loaded.to_string("uncompressed").hex() == pk_hex


def test_save_and_load_pq_key():
    """Test saving and loading PQ keys."""
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)

        # Generate and save key
        pk_bytes, sk_bytes_original = KeyManager.generate_pq_keypair(ML_DSA_ALG)
        key_file = temp_path / "test.pqsk"
        KeyManager.save_pq_key(sk_bytes_original, key_file)

        # Verify file exists
        assert key_file.exists()

        # Load key and verify it matches
        sk_bytes_loaded = KeyManager.load_pq_key(key_file)
        assert sk_bytes_loaded == sk_bytes_original


def test_create_auth_keys_bundle():
    """Test creating a complete auth keys bundle."""
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)

        # Create bundle with additional PQ algorithms
        additional_algs = ["Falcon-512", "Falcon-1024"]
        pk_hex, auth_keys_file = KeyManager.create_auth_keys_bundle(
            temp_path, additional_algs
        )

        # Verify return values
        assert isinstance(pk_hex, str)
        assert isinstance(auth_keys_file, Path)
        assert auth_keys_file.exists()

        # Verify files were created
        assert (temp_path / "classic.sk").exists()
        assert (temp_path / "pq_0.sk").exists()  # ML-DSA
        assert (temp_path / "pq_1.sk").exists()  # Falcon-512
        assert (temp_path / "pq_2.sk").exists()  # Falcon-1024

        # Load and verify the bundle
        auth_keys = KeyManager.load_auth_keys_bundle(auth_keys_file)
        assert "classic_sk" in auth_keys
        assert "pq_keys" in auth_keys
        assert len(auth_keys["pq_keys"]) == 3  # ML-DSA + 2 additional

        # Verify classic key matches
        classic_sk = auth_keys["classic_sk"]
        vk = classic_sk.get_verifying_key()
        assert vk is not None
        assert vk.to_string("uncompressed").hex() == pk_hex

        # Verify PQ keys
        expected_algs = [ML_DSA_ALG] + additional_algs
        actual_algs = [key["alg"] for key in auth_keys["pq_keys"]]
        assert actual_algs == expected_algs


def test_load_auth_keys_bundle():
    """Test loading an auth keys bundle."""
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)

        # Create bundle
        pk_hex, auth_keys_file = KeyManager.create_auth_keys_bundle(temp_path)

        # Load bundle
        auth_keys = KeyManager.load_auth_keys_bundle(auth_keys_file)

        # Verify structure
        assert isinstance(auth_keys, dict)
        assert "classic_sk" in auth_keys
        assert "pq_keys" in auth_keys
        assert isinstance(auth_keys["classic_sk"], ecdsa.SigningKey)
        assert isinstance(auth_keys["pq_keys"], list)
        assert len(auth_keys["pq_keys"]) == 1  # Just ML-DSA by default

        # Verify PQ key structure
        pq_key = auth_keys["pq_keys"][0]
        assert "sk" in pq_key
        assert "pk_hex" in pq_key
        assert "alg" in pq_key
        assert pq_key["alg"] == ML_DSA_ALG


def test_signing_context():
    """Test the signing context manager."""
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)

        # Create bundle
        pk_hex, auth_keys_file = KeyManager.create_auth_keys_bundle(temp_path)

        # Test signing context
        with KeyManager.signing_context(auth_keys_file) as keys:
            assert "classic_sk" in keys
            assert "pq_sigs" in keys
            assert isinstance(keys["classic_sk"], ecdsa.SigningKey)
            assert isinstance(keys["pq_sigs"], list)
            assert len(keys["pq_sigs"]) == 1

            # Verify PQ signature object
            pq_sig_info = keys["pq_sigs"][0]
            assert "sig" in pq_sig_info
            assert "pk_hex" in pq_sig_info
            assert "alg" in pq_sig_info
            assert isinstance(pq_sig_info["sig"], oqs.Signature)

            # Test signing
            message = b"test message"
            classic_sig = keys["classic_sk"].sign(message)
            pq_sig = pq_sig_info["sig"].sign(message)

            assert isinstance(classic_sig, bytes)
            assert isinstance(pq_sig, bytes)
            assert len(classic_sig) > 0
            assert len(pq_sig) > 0


def test_get_classic_public_key():
    """Test getting public key from classic signing key."""
    sk, expected_pk_hex = KeyManager.generate_classic_keypair()
    actual_pk_hex = KeyManager.get_classic_public_key(sk)
    assert actual_pk_hex == expected_pk_hex


def test_multiple_pq_algorithms():
    """Test creating bundle with multiple PQ algorithms."""
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)

        # Create bundle with multiple algorithms
        additional_algs = ["Falcon-512", "Falcon-1024"]
        pk_hex, auth_keys_file = KeyManager.create_auth_keys_bundle(
            temp_path, additional_algs
        )

        # Test signing context with multiple algorithms
        with KeyManager.signing_context(auth_keys_file) as keys:
            assert len(keys["pq_sigs"]) == 3  # ML-DSA + 2 additional

            # Verify all algorithms are present
            algorithms = [sig_info["alg"] for sig_info in keys["pq_sigs"]]
            expected_algs = [ML_DSA_ALG] + additional_algs
            assert algorithms == expected_algs

            # Test signing with all algorithms
            message = b"test message"
            for sig_info in keys["pq_sigs"]:
                signature = sig_info["sig"].sign(message)
                assert isinstance(signature, bytes)
                assert len(signature) > 0
