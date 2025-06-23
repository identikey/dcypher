"""Unit tests for KeyManager PQ key save/load across all algorithms."""

import pytest
import tempfile
from pathlib import Path
from src.lib.key_manager import KeyManager
from .util.util import get_enabled_sigs


@pytest.mark.parametrize("algorithm", get_enabled_sigs())
def test_save_and_load_pq_key(algorithm):
    """Test saving and loading PQ keys for all enabled algorithms."""
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)

        # Generate and save key
        pk_bytes, sk_bytes_original = KeyManager.generate_pq_keypair(algorithm)
        key_file = temp_path / f"test_{algorithm.replace('-', '_')}.pqsk"
        KeyManager.save_pq_key(sk_bytes_original, key_file)

        # Verify file exists
        assert key_file.exists()

        # Load key and verify it matches
        sk_bytes_loaded = KeyManager.load_pq_key(key_file)
        assert sk_bytes_loaded == sk_bytes_original
