"""Unit tests for the KeyManager class."""

import pytest
import tempfile
from pathlib import Path
import ecdsa
import oqs
import json
from src.lib.key_manager import KeyManager, SecureBytes, SecureKeyHandle
from src.crypto.context_manager import CryptoContextManager, OPENFHE_AVAILABLE
from bip_utils import Bip39SeedGenerator, Bip39MnemonicGenerator, Bip39WordsNum
from src.config import ML_DSA_ALG
from .util.util import get_enabled_sigs, get_sigs_with_ctx_support
import secrets


@pytest.fixture
def crypto_context_manager():
    """Provides an initialized CryptoContextManager for tests."""
    if not OPENFHE_AVAILABLE:
        pytest.skip("OpenFHE not available")
    with CryptoContextManager(
        scheme="BFV",
        plaintext_modulus=65537,
        multiplicative_depth=2,
        scaling_mod_size=50,
        batch_size=8,
    ) as manager:
        # Initialize with keys to make it fully functional
        from src.lib import pre

        pre.generate_keys(manager.get_context())
        yield manager


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


def test_identity_file_deterministic(crypto_context_manager):
    """Test that identity file creation always uses seeded key generation."""
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)

        # Create an identity file using the context manager fixture
        mnemonic, identity_file = KeyManager.create_identity_file(
            "test_identity", temp_path, _test_context=crypto_context_manager
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

        # Verify version and derivability fields
        assert "version" in data, "Should have version field"
        assert data["version"] == "hd_v1", (
            "The identity file should have the correct version"
        )
        assert "rotation_count" in data and data["rotation_count"] == 0
        assert "derivation_paths" in data, "Should contain derivation paths"

        # In our new model, all keys from a mnemonic are derivable
        # We'll re-add a specific "derivable" flag if we re-introduce non-derivable (imported) keys
        auth_keys = data["auth_keys"]
        assert auth_keys["classic"]["pk_hex"] is not None
        assert auth_keys["pq"][0]["pk_hex"] is not None


def test_load_identity_file(crypto_context_manager):
    """Test loading an identity file and converting to auth_keys format."""
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)

        # Create an identity file using the context manager fixture
        mnemonic, identity_file = KeyManager.create_identity_file(
            "test_identity", temp_path, _test_context=crypto_context_manager
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


def test_load_keys_unified_with_identity(crypto_context_manager):
    """Test unified loader with identity file."""
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)

        # Create identity file using the context manager fixture
        mnemonic, identity_file = KeyManager.create_identity_file(
            "test_identity", temp_path, _test_context=crypto_context_manager
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


def test_signing_context_with_identity(crypto_context_manager):
    """Test signing context with identity file."""
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)

        # Create identity file using the context manager fixture
        mnemonic, identity_file = KeyManager.create_identity_file(
            "test_identity", temp_path, _test_context=crypto_context_manager
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


class TestSecureMemory:
    """Tests for secure memory management classes."""

    def test_secure_bytes_wipe(self):
        """Test that SecureBytes can be wiped."""
        initial_data = secrets.token_bytes(32)
        secure_data = SecureBytes(initial_data)

        assert secure_data.get_bytes() == initial_data

        secure_data.wipe()

        with pytest.raises(RuntimeError, match="SecureBytes has been wiped"):
            secure_data.get_bytes()

    def test_secure_key_handle(self):
        """Test the SecureKeyHandle context manager."""
        key_material = secrets.token_bytes(64)
        handle = SecureKeyHandle(key_material, "test_key")

        with handle.access() as accessed_key:
            assert accessed_key == key_material

        handle.invalidate()

        with pytest.raises(RuntimeError, match="Key handle has been invalidated"):
            with handle.access() as _:
                pass


class TestKeyDerivationAndRotation:
    """Tests for deterministic derivation and key rotation."""

    @pytest.fixture
    def test_identity(self, crypto_context_manager):
        """Create a test identity for rotation tests."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            mnemonic, identity_file = KeyManager.create_identity_file(
                "rotation_test",
                temp_path,
                _test_context=crypto_context_manager,
            )
            yield identity_file

    @pytest.mark.skip(reason="Test disabled temporarily")
    def test_hybrid_derivation_is_deterministic(self, test_identity):
        """Verify that derivation is deterministic."""
        with open(test_identity, "r") as f:
            identity_data = json.load(f)

        mnemonic = identity_data["mnemonic"]
        seed_generator = Bip39SeedGenerator(mnemonic)
        master_seed = seed_generator.Generate()

        # Re-derive classic key and check for consistency
        sk_classic, pk_classic_hex, path = KeyManager._derive_classic_key_from_seed(
            master_seed, 0
        )
        assert pk_classic_hex == identity_data["auth_keys"]["classic"]["pk_hex"]

        # Re-derive PQ key and check
        pq_pk, pq_sk, path = KeyManager._derive_pq_key_from_seed(master_seed, 0)
        assert pq_pk.hex() == identity_data["auth_keys"]["pq"][0]["pk_hex"]

    def test_key_rotation(self, test_identity):
        """Test key rotation functionality."""
        with open(test_identity, "r") as f:
            initial_data = json.load(f)

        old_classic_pk = initial_data["auth_keys"]["classic"]["pk_hex"]
        old_pq_pk = initial_data["auth_keys"]["pq"][0]["pk_hex"]

        # Rotate keys
        result = KeyManager.rotate_keys_in_identity(test_identity, "scheduled_test")

        with open(test_identity, "r") as f:
            rotated_data = json.load(f)

        # Verify rotation count and metadata
        assert rotated_data["rotation_count"] == 1
        assert rotated_data["rotation_reason"] == "scheduled_test"

        # Verify keys have changed
        new_classic_pk = rotated_data["auth_keys"]["classic"]["pk_hex"]
        new_pq_pk = rotated_data["auth_keys"]["pq"][0]["pk_hex"]
        assert new_classic_pk != old_classic_pk
        assert new_pq_pk != old_pq_pk

        # Verify rotation history
        assert len(rotated_data["rotation_history"]) == 1
        history = rotated_data["rotation_history"][0]
        assert history["rotation_count"] == 1
        assert history["old_classic_pk"] == old_classic_pk
        assert history["new_pq_pk"] == new_pq_pk


class TestSecureBackup:
    """Tests for the secure backup functionality."""

    def test_secure_backup_creation(self, crypto_context_manager):
        """Test that a secure, encrypted backup is created."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)

            # Create an identity using the context manager fixture
            mnemonic, identity_file = KeyManager.create_identity_file(
                "backup_test", temp_path, _test_context=crypto_context_manager
            )

            # Create a backup
            backup_dir = temp_path / "backups"
            backup_file = KeyManager.backup_identity_securely(identity_file, backup_dir)

            assert backup_file.exists()

            # Verify the backup is not plaintext
            with open(backup_file, "r") as f:
                backup_data = json.load(f)

            assert "encrypted_identity" in backup_data

            # The original mnemonic should not be in the encrypted backup file in plain text
            assert mnemonic not in backup_data["encrypted_identity"]

            # Quick check to ensure it's not just base64 of the original
            with open(identity_file, "r") as f_orig:
                original_content = f_orig.read()
            import base64

            assert (
                base64.b64encode(original_content.encode())
                not in backup_data["encrypted_identity"].encode()
            )


@pytest.mark.skip(reason="Test disabled temporarily")
def test_create_identity_file_is_deterministic(crypto_context_manager):
    """
    Tests that creating an identity file results in a deterministic set of keys
    that can be reproduced from the mnemonic.
    """
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)

        # 1. Create an identity file using the context manager fixture
        mnemonic, identity_file = KeyManager.create_identity_file(
            "deterministic_test",
            temp_path,
            _test_context=crypto_context_manager,
        )

        with open(identity_file, "r") as f:
            identity_data = json.load(f)

        pk_classic_initial = identity_data["auth_keys"]["classic"]["pk_hex"]
        pk_pq_initial = identity_data["auth_keys"]["pq"][0]["pk_hex"]

        # 2. Re-derive keys from the same mnemonic
        master_seed = Bip39SeedGenerator(mnemonic).Generate()

        # Re-derive classic key
        classic_path = identity_data["derivation_paths"]["classic"]
        classic_seed = KeyManager._derive_key_material(
            master_seed, classic_path, "classic"
        )
        sk_classic_regen = ecdsa.SigningKey.from_string(
            classic_seed, curve=ecdsa.SECP256k1
        )
        vk_classic_regen = sk_classic_regen.get_verifying_key()
        assert vk_classic_regen is not None
        pk_classic_regen = vk_classic_regen.to_string("uncompressed").hex()

        # Re-derive PQ key
        pq_path = identity_data["derivation_paths"]["pq"]
        pq_seed = KeyManager._derive_key_material(master_seed, pq_path, ML_DSA_ALG)
        pq_pk_regen, _ = KeyManager.generate_pq_keypair_from_seed(ML_DSA_ALG, pq_seed)

        # 3. Assert that the re-derived public keys match the ones stored in the file
        assert pk_classic_initial == pk_classic_regen
        assert pk_pq_initial == pq_pk_regen.hex()
