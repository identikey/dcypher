import pytest
from fastapi import HTTPException

from src.app_state import ServerState, find_account, get_app_state


def test_get_app_state():
    """Tests that get_app_state returns the singleton instance."""
    state1 = get_app_state()
    state2 = get_app_state()
    assert state1 is state2
    assert isinstance(state1, ServerState)


@pytest.fixture
def clean_state():
    """Fixture to reset the app state for a test."""
    original_state = get_app_state()
    # Replace the global state with a fresh instance
    new_state = ServerState()
    # This is a bit of a hack, but it's the simplest way to replace the singleton
    # for testing purposes. We'll manually set the global `state` variable.
    import src.app_state

    src.app_state.state = new_state
    yield new_state
    # Restore the original state
    src.app_state.state = original_state


def test_find_account_success(clean_state):
    """Tests that find_account returns the correct account."""
    clean_state.accounts["test_pk"] = {"alg": "test_alg"}
    account = find_account("test_pk")
    assert account == {"alg": "test_alg"}


def test_find_account_not_found(clean_state):
    """Tests that find_account raises HTTPException for a non-existent account."""
    with pytest.raises(HTTPException) as excinfo:
        find_account("non_existent_pk")
    assert excinfo.value.status_code == 404


def test_server_state_initialization():
    """Tests that a new ServerState instance is initialized with empty stores."""
    state = ServerState()
    assert state.accounts == {}
    assert state.graveyard == {}
    assert state.used_nonces == set()
    assert state.block_store == {}
    assert state.chunk_store == {}


def test_add_to_block_store(clean_state):
    """Tests adding file metadata to the block_store."""
    # Add first file for a user
    clean_state.block_store["user1"] = {"file1_hash": {"filename": "test1.txt"}}
    assert "user1" in clean_state.block_store
    assert clean_state.block_store["user1"]["file1_hash"] == {"filename": "test1.txt"}

    # Add second file for the same user
    clean_state.block_store["user1"]["file2_hash"] = {"filename": "test2.txt"}
    assert len(clean_state.block_store["user1"]) == 2
    assert clean_state.block_store["user1"]["file2_hash"] == {"filename": "test2.txt"}

    # Add file for a second user
    clean_state.block_store["user2"] = {"file3_hash": {"filename": "test3.txt"}}
    assert "user2" in clean_state.block_store
    assert len(clean_state.block_store) == 2


def test_add_to_chunk_store(clean_state):
    """Tests adding chunk metadata to the chunk_store."""
    # Add first chunk for a file
    clean_state.chunk_store["file1_hash"] = {"chunk1_hash": {"index": 0}}
    assert "file1_hash" in clean_state.chunk_store
    assert clean_state.chunk_store["file1_hash"]["chunk1_hash"] == {"index": 0}

    # Add second chunk for the same file
    clean_state.chunk_store["file1_hash"]["chunk2_hash"] = {"index": 1}
    assert len(clean_state.chunk_store["file1_hash"]) == 2

    # Add chunk for a different file
    clean_state.chunk_store["file2_hash"] = {"chunkA_hash": {"index": 0}}
    assert "file2_hash" in clean_state.chunk_store
    assert len(clean_state.chunk_store) == 2


def test_add_to_graveyard(clean_state):
    """Tests adding retired keys to the graveyard."""
    # Add a retired key for a new user
    clean_state.graveyard["user1"] = [{"public_key": "old_pk_1", "alg": "alg1"}]
    assert "user1" in clean_state.graveyard
    assert len(clean_state.graveyard["user1"]) == 1

    # Add another retired key for the same user
    clean_state.graveyard["user1"].append({"public_key": "old_pk_2", "alg": "alg2"})
    assert len(clean_state.graveyard["user1"]) == 2


def test_add_used_nonce(clean_state):
    """Tests adding a nonce to the used_nonces set."""
    nonce1 = "nonce_123"
    nonce2 = "nonce_456"
    assert nonce1 not in clean_state.used_nonces

    clean_state.used_nonces.add(nonce1)
    assert nonce1 in clean_state.used_nonces
    assert nonce2 not in clean_state.used_nonces

    clean_state.used_nonces.add(nonce2)
    assert nonce2 in clean_state.used_nonces
    assert len(clean_state.used_nonces) == 2


def test_check_and_add_nonce(clean_state):
    """Tests the atomic check_and_add_nonce method."""
    nonce = "atomic_nonce_123"

    # First time should be successful
    try:
        clean_state.check_and_add_nonce(nonce)
    except HTTPException:
        pytest.fail("check_and_add_nonce() raised HTTPException unexpectedly!")

    assert nonce in clean_state.used_nonces

    # Second time should raise an exception
    with pytest.raises(HTTPException) as excinfo:
        clean_state.check_and_add_nonce(nonce)
    assert excinfo.value.status_code == 400
    assert "Replay attack detected" in excinfo.value.detail


def test_remove_account(clean_state):
    """Tests removing an account."""
    clean_state.accounts["test_pk"] = {"alg": "test_alg"}
    assert "test_pk" in clean_state.accounts

    del clean_state.accounts["test_pk"]
    assert "test_pk" not in clean_state.accounts


def test_remove_from_block_store(clean_state):
    """Tests removing file metadata from the block_store."""
    clean_state.block_store["user1"] = {
        "file1_hash": {"filename": "test1.txt"},
        "file2_hash": {"filename": "test2.txt"},
    }
    # Remove one file for a user
    del clean_state.block_store["user1"]["file1_hash"]
    assert "file1_hash" not in clean_state.block_store["user1"]
    assert len(clean_state.block_store["user1"]) == 1

    # Remove the user completely
    del clean_state.block_store["user1"]
    assert "user1" not in clean_state.block_store


def test_remove_from_chunk_store(clean_state):
    """Tests removing chunk metadata from the chunk_store."""
    clean_state.chunk_store["file1_hash"] = {
        "chunk1_hash": {"index": 0},
        "chunk2_hash": {"index": 1},
    }
    # Remove a chunk from a file
    del clean_state.chunk_store["file1_hash"]["chunk1_hash"]
    assert "chunk1_hash" not in clean_state.chunk_store["file1_hash"]
    assert len(clean_state.chunk_store["file1_hash"]) == 1

    # Remove the file entry completely
    del clean_state.chunk_store["file1_hash"]
    assert "file1_hash" not in clean_state.chunk_store


# NEW COMPREHENSIVE API METHOD TESTS

import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed


class TestAddAccountMethod:
    """Test the add_account method comprehensively."""

    def test_add_account_basic(self, clean_state):
        """Test basic add_account functionality."""
        public_key = "test_account_pk"
        account_data = {"ML-DSA-65": "ml_dsa_key", "Falcon-512": "falcon_key"}

        clean_state.add_account(public_key, account_data)

        assert public_key in clean_state.accounts
        assert clean_state.accounts[public_key] == account_data

    def test_add_account_overwrite_existing(self, clean_state):
        """Test that add_account overwrites existing accounts."""
        public_key = "test_account_pk"
        original_data = {"ML-DSA-65": "original_key"}
        updated_data = {"ML-DSA-65": "updated_key", "Falcon-512": "new_key"}

        # Add original account
        clean_state.add_account(public_key, original_data)
        assert clean_state.accounts[public_key] == original_data

        # Update account
        clean_state.add_account(public_key, updated_data)
        assert clean_state.accounts[public_key] == updated_data

        # Verify only one account exists
        assert len(clean_state.accounts) == 1

    def test_add_account_empty_data(self, clean_state):
        """Test add_account with empty account data."""
        public_key = "empty_account"
        empty_data = {}

        clean_state.add_account(public_key, empty_data)

        assert public_key in clean_state.accounts
        assert clean_state.accounts[public_key] == empty_data

    def test_add_account_unicode_data(self, clean_state):
        """Test add_account with unicode characters."""
        public_key = "unicode_account_测试_🔑"
        unicode_data = {
            "алгоритм_中文": "公钥_🔐_データ",
            "clé_française": "données_spéciales_🗝️",
        }

        clean_state.add_account(public_key, unicode_data)

        assert public_key in clean_state.accounts
        assert clean_state.accounts[public_key] == unicode_data

    def test_add_account_thread_safety(self, clean_state):
        """Test add_account thread safety."""
        num_threads = 5
        accounts_per_thread = 20

        def add_accounts(thread_id):
            for i in range(accounts_per_thread):
                pk = f"thread_{thread_id}_account_{i}"
                account_data = {
                    "ML-DSA-65": f"ml_dsa_key_{thread_id}_{i}",
                    "thread_id": thread_id,
                    "account_id": i,
                }
                clean_state.add_account(pk, account_data)

        with ThreadPoolExecutor(max_workers=num_threads) as executor:
            futures = [executor.submit(add_accounts, i) for i in range(num_threads)]
            for future in as_completed(futures):
                future.result()

        # Verify all accounts were created
        assert len(clean_state.accounts) == num_threads * accounts_per_thread


class TestRemoveAccountMethod:
    """Test the remove_account method comprehensively."""

    def test_remove_account_basic(self, clean_state):
        """Test basic remove_account functionality."""
        public_key = "test_account"
        account_data = {"ML-DSA-65": "test_key"}

        # Add account first
        clean_state.add_account(public_key, account_data)
        assert public_key in clean_state.accounts

        # Remove account
        clean_state.remove_account(public_key)
        assert public_key not in clean_state.accounts

    def test_remove_nonexistent_account(self, clean_state):
        """Test removing a non-existent account doesn't raise an error."""
        # Should not raise any exception
        clean_state.remove_account("nonexistent_account")
        assert len(clean_state.accounts) == 0

    def test_remove_account_multiple_times(self, clean_state):
        """Test removing the same account multiple times."""
        public_key = "test_account"
        account_data = {"ML-DSA-65": "test_key"}

        # Add account
        clean_state.add_account(public_key, account_data)
        assert public_key in clean_state.accounts

        # Remove first time
        clean_state.remove_account(public_key)
        assert public_key not in clean_state.accounts

        # Remove second time (should not raise error)
        clean_state.remove_account(public_key)
        assert public_key not in clean_state.accounts


class TestAddFileToBlockStoreMethod:
    """Test the add_file_to_block_store method comprehensively."""

    def test_add_file_to_block_store_basic(self, clean_state):
        """Test basic add_file_to_block_store functionality."""
        user_pk = "user123"
        file_hash = "file_hash_abc"
        file_metadata = {
            "filename": "document.pdf",
            "size": 1024,
            "content_type": "application/pdf",
            "created_at": time.time(),
        }

        clean_state.add_file_to_block_store(user_pk, file_hash, file_metadata)

        assert user_pk in clean_state.block_store
        assert file_hash in clean_state.block_store[user_pk]
        assert clean_state.block_store[user_pk][file_hash] == file_metadata

    def test_add_file_to_block_store_new_user(self, clean_state):
        """Test adding file for a new user creates user entry."""
        user_pk = "new_user"
        file_hash = "file_123"
        file_metadata = {"filename": "test.txt"}

        # Initially no users
        assert len(clean_state.block_store) == 0

        clean_state.add_file_to_block_store(user_pk, file_hash, file_metadata)

        # User should be created
        assert user_pk in clean_state.block_store
        assert len(clean_state.block_store) == 1
        assert len(clean_state.block_store[user_pk]) == 1

    def test_add_file_to_block_store_overwrite_file(self, clean_state):
        """Test overwriting existing file metadata."""
        user_pk = "user123"
        file_hash = "file_abc"
        original_metadata = {"filename": "original.txt", "size": 100}
        updated_metadata = {"filename": "updated.txt", "size": 200, "updated": True}

        # Add original file
        clean_state.add_file_to_block_store(user_pk, file_hash, original_metadata)
        assert clean_state.block_store[user_pk][file_hash] == original_metadata

        # Update file metadata
        clean_state.add_file_to_block_store(user_pk, file_hash, updated_metadata)
        assert clean_state.block_store[user_pk][file_hash] == updated_metadata

        # Should still be only one file
        assert len(clean_state.block_store[user_pk]) == 1

    def test_add_file_to_block_store_thread_safety(self, clean_state):
        """Test thread safety of add_file_to_block_store."""
        num_threads = 5
        files_per_thread = 10

        def add_files(thread_id):
            user_pk = f"user_{thread_id}"
            for i in range(files_per_thread):
                file_hash = f"file_{thread_id}_{i}"
                file_metadata = {
                    "filename": f"file_{i}.txt",
                    "thread_id": thread_id,
                    "file_id": i,
                }
                clean_state.add_file_to_block_store(user_pk, file_hash, file_metadata)

        with ThreadPoolExecutor(max_workers=num_threads) as executor:
            futures = [executor.submit(add_files, i) for i in range(num_threads)]
            for future in as_completed(futures):
                future.result()

        # Verify all files were added
        assert len(clean_state.block_store) == num_threads


class TestAddChunkToChunkStoreMethod:
    """Test the add_chunk_to_chunk_store method comprehensively."""

    def test_add_chunk_to_chunk_store_basic(self, clean_state):
        """Test basic add_chunk_to_chunk_store functionality."""
        file_hash = "file_abc"
        chunk_hash = "chunk_123"
        chunk_metadata = {"index": 0, "size": 1024, "stored_at": time.time()}

        clean_state.add_chunk_to_chunk_store(file_hash, chunk_hash, chunk_metadata)

        assert file_hash in clean_state.chunk_store
        assert chunk_hash in clean_state.chunk_store[file_hash]
        assert clean_state.chunk_store[file_hash][chunk_hash] == chunk_metadata

    def test_add_chunk_to_chunk_store_new_file(self, clean_state):
        """Test adding chunk for a new file creates file entry."""
        file_hash = "new_file"
        chunk_hash = "chunk_1"
        chunk_metadata = {"index": 0, "size": 512}

        # Initially no files
        assert len(clean_state.chunk_store) == 0

        clean_state.add_chunk_to_chunk_store(file_hash, chunk_hash, chunk_metadata)

        # File should be created
        assert file_hash in clean_state.chunk_store
        assert len(clean_state.chunk_store) == 1
        assert len(clean_state.chunk_store[file_hash]) == 1

    def test_add_chunk_to_chunk_store_overwrite_chunk(self, clean_state):
        """Test overwriting existing chunk metadata."""
        file_hash = "file_abc"
        chunk_hash = "chunk_123"
        original_metadata = {"index": 0, "size": 1024}
        updated_metadata = {"index": 0, "size": 2048, "updated": True}

        # Add original chunk
        clean_state.add_chunk_to_chunk_store(file_hash, chunk_hash, original_metadata)
        assert clean_state.chunk_store[file_hash][chunk_hash] == original_metadata

        # Update chunk metadata
        clean_state.add_chunk_to_chunk_store(file_hash, chunk_hash, updated_metadata)
        assert clean_state.chunk_store[file_hash][chunk_hash] == updated_metadata

        # Should still be only one chunk
        assert len(clean_state.chunk_store[file_hash]) == 1


class TestAddToGraveyardMethod:
    """Test the add_to_graveyard method comprehensively."""

    def test_add_to_graveyard_basic(self, clean_state):
        """Test basic add_to_graveyard functionality."""
        user_pk = "user123"
        retired_key_data = {
            "public_key": "old_ml_dsa_key",
            "alg": "ML-DSA-65",
            "retired_at": time.time(),
        }

        clean_state.add_to_graveyard(user_pk, retired_key_data)

        assert user_pk in clean_state.graveyard
        assert len(clean_state.graveyard[user_pk]) == 1
        assert clean_state.graveyard[user_pk][0] == retired_key_data

    def test_add_to_graveyard_new_user(self, clean_state):
        """Test adding retired key for a new user creates user entry."""
        user_pk = "new_user"
        retired_key_data = {
            "public_key": "retired_key",
            "alg": "Falcon-512",
            "retired_at": time.time(),
        }

        # Initially no users in graveyard
        assert len(clean_state.graveyard) == 0

        clean_state.add_to_graveyard(user_pk, retired_key_data)

        # User should be created in graveyard
        assert user_pk in clean_state.graveyard
        assert len(clean_state.graveyard) == 1
        assert len(clean_state.graveyard[user_pk]) == 1

    def test_add_to_graveyard_multiple_keys(self, clean_state):
        """Test adding multiple retired keys for the same user."""
        user_pk = "user123"
        retired_keys = [
            {
                "public_key": "old_ml_dsa_key",
                "alg": "ML-DSA-65",
                "retired_at": time.time() - 3600,
            },
            {
                "public_key": "old_falcon_key",
                "alg": "Falcon-512",
                "retired_at": time.time() - 1800,
            },
        ]

        for retired_key_data in retired_keys:
            clean_state.add_to_graveyard(user_pk, retired_key_data)

        assert len(clean_state.graveyard[user_pk]) == 2
        for i, retired_key_data in enumerate(retired_keys):
            assert clean_state.graveyard[user_pk][i] == retired_key_data

    def test_add_to_graveyard_preserves_order(self, clean_state):
        """Test that retired keys are added in order."""
        user_pk = "user123"

        # Add keys with timestamps to verify order
        for i in range(5):
            retired_key_data = {
                "public_key": f"key_{i}",
                "alg": f"alg_{i}",
                "retired_at": time.time() + i,
                "order": i,
            }
            clean_state.add_to_graveyard(user_pk, retired_key_data)

        # Verify order is preserved
        assert len(clean_state.graveyard[user_pk]) == 5
        for i in range(5):
            assert clean_state.graveyard[user_pk][i]["order"] == i
            assert clean_state.graveyard[user_pk][i]["public_key"] == f"key_{i}"


class TestEdgeCasesAndErrorConditions:
    """Test edge cases and error conditions for all methods."""

    def test_nonce_replay_protection_edge_cases(self, clean_state):
        """Tests nonce replay protection edge cases."""
        nonce = "test_nonce_123"

        # First use should succeed
        clean_state.check_and_add_nonce(nonce)
        assert nonce in clean_state.used_nonces

        # Second use should fail
        with pytest.raises(HTTPException) as exc_info:
            clean_state.check_and_add_nonce(nonce)
        assert exc_info.value.status_code == 400
        assert "Replay attack detected" in exc_info.value.detail

        # Test with empty nonce
        clean_state.check_and_add_nonce("")
        assert "" in clean_state.used_nonces

        # Test with very long nonce
        long_nonce = "a" * 1000
        clean_state.check_and_add_nonce(long_nonce)
        assert long_nonce in clean_state.used_nonces

    def test_large_data_handling(self, clean_state):
        """Tests handling of large data structures."""
        # Test large account data
        large_account_data = {
            f"alg_{i}": f"very_long_public_key_{'x' * 100}_{i}" for i in range(20)
        }
        clean_state.add_account("large_account", large_account_data)

        retrieved = find_account("large_account")
        assert retrieved == large_account_data

        # Test large file metadata
        large_file_metadata = {
            "filename": "large_file.txt",
            "description": "x" * 1000,
            "tags": [f"tag_{i}" for i in range(100)],
        }
        clean_state.add_file_to_block_store(
            "user1", "large_file_hash", large_file_metadata
        )

        assert (
            clean_state.block_store["user1"]["large_file_hash"] == large_file_metadata
        )

    def test_unicode_and_special_characters(self, clean_state):
        """Tests handling of unicode and special characters."""
        # Test unicode in account keys and data
        unicode_pk = "测试用户_🔑_公钥"
        unicode_data = {
            "алгоритм": "公钥_🔐_データ",
            "clé_publique": "données_spéciales_🗝️",
        }
        clean_state.add_account(unicode_pk, unicode_data)

        retrieved = find_account(unicode_pk)
        assert retrieved == unicode_data

        # Test special characters in nonces
        special_nonce = "nonce_with_special_chars_!@#$%^&*()_+-="
        clean_state.check_and_add_nonce(special_nonce)
        assert special_nonce in clean_state.used_nonces


class TestIntegrationScenarios:
    """Test integration scenarios that mirror real application usage."""

    def test_complete_account_lifecycle(self, clean_state):
        """Tests complete account lifecycle with all operations."""
        pk = "lifecycle_account"

        # 1. Create account
        initial_data = {"ML-DSA-65": "ml_dsa_key", "Falcon-512": "falcon_key"}
        clean_state.add_account(pk, initial_data)

        # 2. Verify account exists
        account = find_account(pk)
        assert account == initial_data

        # 3. Add files to account
        for i in range(3):
            file_hash = f"file_{i}_hash"
            file_metadata = {
                "filename": f"document_{i}.pdf",
                "size": 1024 * (i + 1),
                "created_at": time.time(),
            }
            clean_state.add_file_to_block_store(pk, file_hash, file_metadata)

        # 4. Add chunks for files
        for i in range(3):
            file_hash = f"file_{i}_hash"
            for j in range(2):  # 2 chunks per file
                chunk_hash = f"chunk_{i}_{j}_hash"
                chunk_metadata = {"index": j, "size": 512, "stored_at": time.time()}
                clean_state.add_chunk_to_chunk_store(
                    file_hash, chunk_hash, chunk_metadata
                )

        # 5. Update account (retire old key)
        old_falcon_key = initial_data["Falcon-512"]
        clean_state.add_to_graveyard(
            pk,
            {
                "public_key": old_falcon_key,
                "alg": "Falcon-512",
                "retired_at": time.time(),
            },
        )

        updated_data = {"ML-DSA-65": "ml_dsa_key", "Falcon-512": "new_falcon_key"}
        clean_state.add_account(pk, updated_data)

        # 6. Verify final state
        final_account = find_account(pk)
        assert final_account == updated_data
        assert len(clean_state.block_store[pk]) == 3
        assert len(clean_state.chunk_store) == 3
        assert len(clean_state.graveyard[pk]) == 1
        assert clean_state.graveyard[pk][0]["public_key"] == old_falcon_key
