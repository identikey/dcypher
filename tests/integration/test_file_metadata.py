"""
File metadata and listing API tests.

This module contains tests for file listing and metadata operations
including retrieving file lists and handling non-existent resources.
"""

import pytest
from fastapi.testclient import TestClient
from main import app

from tests.integration.test_api import (
    storage_paths,
    cleanup,
    _create_test_account,
)

client = TestClient(app)


def test_list_files_nonexistent_account():
    """
    Tests that listing files for a non-existent account returns 404.
    """
    response = client.get("/storage/nonexistent-public-key")
    assert response.status_code == 404
    assert "Account not found" in response.json()["detail"]


def test_get_file_metadata_nonexistent_file():
    """
    Tests that getting metadata for a non-existent file hash returns 404.
    """
    # 1. Create a real account
    sk_classic, pk_classic_hex, all_pq_sks, oqs_sigs_to_free = _create_test_account()
    try:
        # 2. Attempt to get metadata for a hash that does not exist
        response = client.get(f"/storage/{pk_classic_hex}/nonexistent-file-hash")
        assert response.status_code == 404
        assert "File not found" in response.json()["detail"]
    finally:
        # Clean up oqs signatures
        for sig in oqs_sigs_to_free:
            sig.free()
