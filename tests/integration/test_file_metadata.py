"""
File metadata and listing API tests.

This module contains tests for file listing and metadata operations
including retrieving file lists and handling non-existent resources.
"""

import pytest
import requests
from main import app

from tests.integration.test_api import (
    _create_test_account,
    setup_test_account_with_client,
)


def test_list_files_nonexistent_account(api_base_url: str):
    """
    Tests that listing files for a non-existent account returns 404.
    """
    response = requests.get(f"{api_base_url}/storage/nonexistent-public-key")
    assert response.status_code == 404
    assert "Account not found" in response.json()["detail"]


def test_get_file_metadata_nonexistent_file(api_base_url: str, tmp_path):
    """
    Tests that getting metadata for a non-existent file hash returns 404.
    This test demonstrates the new API client pattern.
    """
    # 1. Create a real account using the new helper
    client, pk_classic_hex, auth_keys_file = setup_test_account_with_client(
        tmp_path, api_base_url
    )

    # 2. Attempt to get metadata for a hash that does not exist
    response = requests.get(
        f"{api_base_url}/storage/{pk_classic_hex}/nonexistent-file-hash"
    )
    assert response.status_code == 404
    assert "File not found" in response.json()["detail"]

    # Note: No manual cleanup needed - the new helper manages resources properly
