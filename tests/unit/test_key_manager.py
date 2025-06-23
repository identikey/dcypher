"""Unit tests for the KeyManager class."""

import pytest
import tempfile
from pathlib import Path
import ecdsa
import oqs
import json
from src.lib.key_manager import KeyManager
from src.config import ML_DSA_ALG
from .util.util import get_enabled_sigs, get_sigs_with_ctx_support


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


def test_create_auth_keys_bundle():
    """Test creating a complete auth keys bundle."""
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)

        # Get enabled algorithms and use a subset for testing
        enabled_algs = get_enabled_sigs()
        # Use up to 3 additional algorithms beyond ML-DSA for testing (to keep test reasonable)
        additional_algs = [alg for alg in enabled_algs if alg != ML_DSA_ALG][:3]

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

        # Verify additional algorithm files exist
        for i in range(len(additional_algs)):
            assert (temp_path / f"pq_{i + 1}.sk").exists()

        # Load and verify the bundle
        auth_keys = KeyManager.load_auth_keys_bundle(auth_keys_file)
        assert "classic_sk" in auth_keys
        assert "pq_keys" in auth_keys
        expected_count = 1 + len(additional_algs)  # ML-DSA + additional
        assert len(auth_keys["pq_keys"]) == expected_count

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


def test_algorithm_availability():
    """Test that OQS signature algorithms are available."""
    enabled_algorithms = get_enabled_sigs()

    # Should have at least one enabled algorithm
    assert len(enabled_algorithms) > 0, (
        "Should have at least one enabled signature algorithm"
    )

    # ML-DSA should be available (from config)
    assert ML_DSA_ALG in enabled_algorithms, (
        f"{ML_DSA_ALG} should be in enabled algorithms"
    )


def test_identity_file_deterministic():
    """Test that identity file creation always uses seeded key generation."""
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)

        # Create an identity file
        mnemonic, identity_file = KeyManager.create_identity_file(
            "test_identity", temp_path
        )

        # Verify the file was created
        assert identity_file.exists(), "Identity file should be created"

        # Load and verify structure
        with open(identity_file) as f:
            data = json.load(f)

        # Verify basic structure
        assert "mnemonic" in data, "Identity should contain mnemonic"
        assert "auth_keys" in data, "Identity should contain auth_keys"
        assert "classic" in data["auth_keys"], "Should have classic keys"
        assert "pq" in data["auth_keys"], "Should have PQ keys"
        assert len(data["auth_keys"]["pq"]) > 0, "Should have at least one PQ algorithm"

        # Verify mnemonic is valid (should be 24 words)
        words = mnemonic.split()
        assert len(words) == 24, "Should have 24 word mnemonic"

        # Verify version and derivability fields (no fallbacks)
        assert "version" in data, "Should have version field"
        assert data["version"] == "seeded", (
            "Should always be seeded version (no fallbacks)"
        )
        assert "derivable" in data, "Should have derivability info"
        assert data["derivable"] == True, "Should always be derivable (no fallbacks)"

        # Verify PQ keys are also marked as derivable
        pq_key = data["auth_keys"]["pq"][0]
        assert "derivable" in pq_key, "PQ key should have derivability info"
        assert pq_key["derivable"] == True, (
            "PQ key should always be derivable (no fallbacks)"
        )


def test_load_identity_file():
    """Test loading an identity file and converting to auth_keys format."""
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)

        # Create an identity file
        mnemonic, identity_file = KeyManager.create_identity_file(
            "test_identity", temp_path
        )

        # Load the identity file
        auth_keys = KeyManager.load_identity_file(identity_file)

        # Verify structure matches auth_keys format
        assert isinstance(auth_keys, dict)
        assert "classic_sk" in auth_keys
        assert "pq_keys" in auth_keys
        assert isinstance(auth_keys["classic_sk"], ecdsa.SigningKey)
        assert isinstance(auth_keys["pq_keys"], list)
        assert len(auth_keys["pq_keys"]) >= 1

        # Verify PQ key structure
        pq_key = auth_keys["pq_keys"][0]
        assert "sk" in pq_key
        assert "pk_hex" in pq_key
        assert "alg" in pq_key
        assert isinstance(pq_key["sk"], bytes)
        assert isinstance(pq_key["pk_hex"], str)
        assert pq_key["alg"] == ML_DSA_ALG

        # Verify classic key can be used for signing
        test_message = b"test message"
        signature = auth_keys["classic_sk"].sign(test_message)
        assert len(signature) > 0

        # Verify PQ key can be used with OQS
        with oqs.Signature(pq_key["alg"], pq_key["sk"]) as sig:
            pq_signature = sig.sign(test_message)
            assert len(pq_signature) > 0


def test_load_keys_unified_with_auth_keys():
    """Test unified loader with auth_keys file."""
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)

        # Create auth_keys bundle
        pk_hex, auth_keys_file = KeyManager.create_auth_keys_bundle(temp_path)

        # Load using unified loader
        auth_keys = KeyManager.load_keys_unified(auth_keys_file)

        # Verify structure
        assert isinstance(auth_keys, dict)
        assert "classic_sk" in auth_keys
        assert "pq_keys" in auth_keys


def test_load_keys_unified_with_identity():
    """Test unified loader with identity file."""
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)

        # Create identity file
        mnemonic, identity_file = KeyManager.create_identity_file(
            "test_identity", temp_path
        )

        # Load using unified loader
        auth_keys = KeyManager.load_keys_unified(identity_file)

        # Verify structure
        assert isinstance(auth_keys, dict)
        assert "classic_sk" in auth_keys
        assert "pq_keys" in auth_keys


def test_load_keys_unified_invalid_file():
    """Test unified loader with invalid file format."""
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)

        # Create invalid JSON file
        invalid_file = temp_path / "invalid.json"
        with open(invalid_file, "w") as f:
            json.dump({"invalid": "structure"}, f)

        # Should raise ValueError
        with pytest.raises(ValueError, match="Unrecognized key file format"):
            KeyManager.load_keys_unified(invalid_file)


def test_signing_context_with_identity():
    """Test signing context with identity file."""
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)

        # Create identity file
        mnemonic, identity_file = KeyManager.create_identity_file(
            "test_identity", temp_path
        )

        # Test signing context with identity file
        with KeyManager.signing_context(identity_file) as keys:
            assert "classic_sk" in keys
            assert "pq_sigs" in keys
            assert isinstance(keys["classic_sk"], ecdsa.SigningKey)
            assert isinstance(keys["pq_sigs"], list)
            assert len(keys["pq_sigs"]) >= 1

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
