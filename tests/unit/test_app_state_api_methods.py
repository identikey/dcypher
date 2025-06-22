"""
Comprehensive tests for ServerState API methods that are used by routers
but not directly tested in the basic test_app_state.py.

These tests focus on:
1. add_account() method
2. remove_account() method
3. add_file_to_block_store() method
4. add_chunk_to_chunk_store() method
5. add_to_graveyard() method

Each method is tested for:
- Normal operation
- Edge cases
- Error conditions
- Thread safety
- Data validation
"""

import pytest
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from fastapi import HTTPException

from app_state import ServerState, find_account, get_app_state


@pytest.fixture
def clean_state():
    """Fixture to reset the app state for a test."""
    original_state = get_app_state()
    new_state = ServerState()
    import app_state

    app_state.state = new_state
    yield new_state
    app_state.state = original_state


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

    def test_add_account_large_data(self, clean_state):
        """Test add_account with large account data."""
        public_key = "large_account"
        large_data = {
            f"alg_{i}": f"very_long_public_key_{'x' * 1000}_{i}" for i in range(50)
        }

        clean_state.add_account(public_key, large_data)

        assert public_key in clean_state.accounts
        assert clean_state.accounts[public_key] == large_data
        assert len(clean_state.accounts[public_key]) == 50

    def test_add_account_unicode_data(self, clean_state):
        """Test add_account with unicode characters."""
        public_key = "unicode_account_测试_🔑"
        unicode_data = {
            "алгоритм_中文": "公钥_🔐_データ",
            "clé_française": "données_spéciales_🗝️",
            "العربية": "المفتاح_العام",
        }

        clean_state.add_account(public_key, unicode_data)

        assert public_key in clean_state.accounts
        assert clean_state.accounts[public_key] == unicode_data

    def test_add_account_special_characters(self, clean_state):
        """Test add_account with special characters."""
        public_key = "special!@#$%^&*()_+-={}[]|\\:;\"'<>?,./"
        special_data = {
            "alg!@#": "key$%^&*()",
            "alg+={}": "key[]|\\:;",
            "alg\"'<>": "key?,./",
        }

        clean_state.add_account(public_key, special_data)

        assert public_key in clean_state.accounts
        assert clean_state.accounts[public_key] == special_data

    def test_add_account_thread_safety(self, clean_state):
        """Test add_account thread safety."""
        num_threads = 10
        accounts_per_thread = 50

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

        # Verify data integrity
        for thread_id in range(num_threads):
            for i in range(accounts_per_thread):
                pk = f"thread_{thread_id}_account_{i}"
                assert pk in clean_state.accounts
                assert clean_state.accounts[pk]["thread_id"] == thread_id
                assert clean_state.accounts[pk]["account_id"] == i

    def test_add_account_concurrent_updates(self, clean_state):
        """Test concurrent updates to the same account."""
        public_key = "concurrent_account"
        num_threads = 10

        def update_account(thread_id):
            account_data = {
                "ML-DSA-65": f"key_from_thread_{thread_id}",
                "last_update": time.time(),
                "thread_id": thread_id,
            }
            clean_state.add_account(public_key, account_data)

        with ThreadPoolExecutor(max_workers=num_threads) as executor:
            futures = [executor.submit(update_account, i) for i in range(num_threads)]
            for future in as_completed(futures):
                future.result()

        # Account should exist and contain data from one of the threads
        assert public_key in clean_state.accounts
        account_data = clean_state.accounts[public_key]
        assert "thread_id" in account_data
        assert 0 <= account_data["thread_id"] < num_threads


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

    def test_remove_account_preserves_other_accounts(self, clean_state):
        """Test that removing one account doesn't affect others."""
        accounts = {
            "account1": {"ML-DSA-65": "key1"},
            "account2": {"ML-DSA-65": "key2"},
            "account3": {"ML-DSA-65": "key3"},
        }

        # Add all accounts
        for pk, data in accounts.items():
            clean_state.add_account(pk, data)

        assert len(clean_state.accounts) == 3

        # Remove middle account
        clean_state.remove_account("account2")

        assert len(clean_state.accounts) == 2
        assert "account1" in clean_state.accounts
        assert "account2" not in clean_state.accounts
        assert "account3" in clean_state.accounts
        assert clean_state.accounts["account1"] == accounts["account1"]
        assert clean_state.accounts["account3"] == accounts["account3"]

    def test_remove_account_thread_safety(self, clean_state):
        """Test remove_account thread safety."""
        num_accounts = 100
        num_threads = 10

        # Add accounts first
        for i in range(num_accounts):
            pk = f"account_{i}"
            clean_state.add_account(pk, {"ML-DSA-65": f"key_{i}"})

        assert len(clean_state.accounts) == num_accounts

        def remove_accounts(thread_id):
            # Each thread removes its assigned accounts
            start = thread_id * (num_accounts // num_threads)
            end = (thread_id + 1) * (num_accounts // num_threads)
            for i in range(start, end):
                pk = f"account_{i}"
                clean_state.remove_account(pk)

        with ThreadPoolExecutor(max_workers=num_threads) as executor:
            futures = [executor.submit(remove_accounts, i) for i in range(num_threads)]
            for future in as_completed(futures):
                future.result()

        # All accounts should be removed
        assert len(clean_state.accounts) == 0

    def test_remove_account_concurrent_same_account(self, clean_state):
        """Test concurrent removal of the same account."""
        public_key = "concurrent_remove_account"
        account_data = {"ML-DSA-65": "test_key"}

        clean_state.add_account(public_key, account_data)
        assert public_key in clean_state.accounts

        num_threads = 10

        def remove_account():
            clean_state.remove_account(public_key)

        with ThreadPoolExecutor(max_workers=num_threads) as executor:
            futures = [executor.submit(remove_account) for _ in range(num_threads)]
            for future in as_completed(futures):
                future.result()  # Should not raise any exceptions

        # Account should be removed
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

    def test_add_file_to_block_store_multiple_files(self, clean_state):
        """Test adding multiple files for the same user."""
        user_pk = "user123"
        files = {
            "file1": {"filename": "doc1.pdf", "size": 1024},
            "file2": {"filename": "doc2.pdf", "size": 2048},
            "file3": {"filename": "doc3.pdf", "size": 3072},
        }

        for file_hash, metadata in files.items():
            clean_state.add_file_to_block_store(user_pk, file_hash, metadata)

        assert len(clean_state.block_store[user_pk]) == 3
        for file_hash, metadata in files.items():
            assert clean_state.block_store[user_pk][file_hash] == metadata

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

    def test_add_file_to_block_store_empty_metadata(self, clean_state):
        """Test adding file with empty metadata."""
        user_pk = "user123"
        file_hash = "empty_file"
        empty_metadata = {}

        clean_state.add_file_to_block_store(user_pk, file_hash, empty_metadata)

        assert clean_state.block_store[user_pk][file_hash] == empty_metadata

    def test_add_file_to_block_store_large_metadata(self, clean_state):
        """Test adding file with large metadata."""
        user_pk = "user123"
        file_hash = "large_file"
        large_metadata = {
            "filename": "large_file.bin",
            "description": "x" * 10000,  # 10KB description
            "tags": [f"tag_{i}" for i in range(1000)],  # 1000 tags
            "custom_fields": {
                f"field_{i}": f"value_{i}" for i in range(500)
            },  # 500 custom fields
        }

        clean_state.add_file_to_block_store(user_pk, file_hash, large_metadata)

        assert clean_state.block_store[user_pk][file_hash] == large_metadata
        assert len(clean_state.block_store[user_pk][file_hash]["tags"]) == 1000
        assert len(clean_state.block_store[user_pk][file_hash]["custom_fields"]) == 500

    def test_add_file_to_block_store_unicode(self, clean_state):
        """Test adding file with unicode characters."""
        user_pk = "用户_🔑"
        file_hash = "文件_📄_hash"
        unicode_metadata = {
            "filename": "文档_测试_🗎.pdf",
            "description": "这是一个测试文件_🔍",
            "tags": ["标签1", "タグ2", "علامة3"],
            "العربية": "قيمة_عربية",
            "中文": "中文值",
            "日本語": "日本語の値",
        }

        clean_state.add_file_to_block_store(user_pk, file_hash, unicode_metadata)

        assert clean_state.block_store[user_pk][file_hash] == unicode_metadata

    def test_add_file_to_block_store_thread_safety(self, clean_state):
        """Test thread safety of add_file_to_block_store."""
        num_threads = 10
        files_per_thread = 20

        def add_files(thread_id):
            user_pk = f"user_{thread_id}"
            for i in range(files_per_thread):
                file_hash = f"file_{thread_id}_{i}"
                file_metadata = {
                    "filename": f"file_{i}.txt",
                    "thread_id": thread_id,
                    "file_id": i,
                    "created_at": time.time(),
                }
                clean_state.add_file_to_block_store(user_pk, file_hash, file_metadata)

        with ThreadPoolExecutor(max_workers=num_threads) as executor:
            futures = [executor.submit(add_files, i) for i in range(num_threads)]
            for future in as_completed(futures):
                future.result()

        # Verify all files were added
        assert len(clean_state.block_store) == num_threads
        for thread_id in range(num_threads):
            user_pk = f"user_{thread_id}"
            assert len(clean_state.block_store[user_pk]) == files_per_thread

            # Verify data integrity
            for i in range(files_per_thread):
                file_hash = f"file_{thread_id}_{i}"
                metadata = clean_state.block_store[user_pk][file_hash]
                assert metadata["thread_id"] == thread_id
                assert metadata["file_id"] == i

    def test_add_file_to_block_store_same_user_concurrent(self, clean_state):
        """Test concurrent file additions for the same user."""
        user_pk = "concurrent_user"
        num_threads = 10
        files_per_thread = 10

        def add_files(thread_id):
            for i in range(files_per_thread):
                file_hash = f"thread_{thread_id}_file_{i}"
                file_metadata = {
                    "filename": f"concurrent_file_{thread_id}_{i}.txt",
                    "thread_id": thread_id,
                    "file_id": i,
                }
                clean_state.add_file_to_block_store(user_pk, file_hash, file_metadata)

        with ThreadPoolExecutor(max_workers=num_threads) as executor:
            futures = [executor.submit(add_files, i) for i in range(num_threads)]
            for future in as_completed(futures):
                future.result()

        # All files should be added for the single user
        assert len(clean_state.block_store) == 1
        assert len(clean_state.block_store[user_pk]) == num_threads * files_per_thread


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

    def test_add_chunk_to_chunk_store_multiple_chunks(self, clean_state):
        """Test adding multiple chunks for the same file."""
        file_hash = "file_abc"
        chunks = {
            "chunk_0": {"index": 0, "size": 1024},
            "chunk_1": {"index": 1, "size": 1024},
            "chunk_2": {"index": 2, "size": 512},
        }

        for chunk_hash, metadata in chunks.items():
            clean_state.add_chunk_to_chunk_store(file_hash, chunk_hash, metadata)

        assert len(clean_state.chunk_store[file_hash]) == 3
        for chunk_hash, metadata in chunks.items():
            assert clean_state.chunk_store[file_hash][chunk_hash] == metadata

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

    def test_add_chunk_to_chunk_store_thread_safety(self, clean_state):
        """Test thread safety of add_chunk_to_chunk_store."""
        num_threads = 10
        chunks_per_thread = 20

        def add_chunks(thread_id):
            file_hash = f"file_{thread_id}"
            for i in range(chunks_per_thread):
                chunk_hash = f"chunk_{thread_id}_{i}"
                chunk_metadata = {
                    "index": i,
                    "size": 1024 + i,
                    "thread_id": thread_id,
                    "chunk_id": i,
                }
                clean_state.add_chunk_to_chunk_store(
                    file_hash, chunk_hash, chunk_metadata
                )

        with ThreadPoolExecutor(max_workers=num_threads) as executor:
            futures = [executor.submit(add_chunks, i) for i in range(num_threads)]
            for future in as_completed(futures):
                future.result()

        # Verify all chunks were added
        assert len(clean_state.chunk_store) == num_threads
        for thread_id in range(num_threads):
            file_hash = f"file_{thread_id}"
            assert len(clean_state.chunk_store[file_hash]) == chunks_per_thread

            # Verify data integrity
            for i in range(chunks_per_thread):
                chunk_hash = f"chunk_{thread_id}_{i}"
                metadata = clean_state.chunk_store[file_hash][chunk_hash]
                assert metadata["thread_id"] == thread_id
                assert metadata["chunk_id"] == i
                assert metadata["index"] == i


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
            {
                "public_key": "old_dilithium_key",
                "alg": "Dilithium2",
                "retired_at": time.time(),
            },
        ]

        for retired_key_data in retired_keys:
            clean_state.add_to_graveyard(user_pk, retired_key_data)

        assert len(clean_state.graveyard[user_pk]) == 3
        for i, retired_key_data in enumerate(retired_keys):
            assert clean_state.graveyard[user_pk][i] == retired_key_data

    def test_add_to_graveyard_preserves_order(self, clean_state):
        """Test that retired keys are added in order."""
        user_pk = "user123"

        # Add keys with timestamps to verify order
        for i in range(10):
            retired_key_data = {
                "public_key": f"key_{i}",
                "alg": f"alg_{i}",
                "retired_at": time.time() + i,  # Incrementing timestamps
                "order": i,
            }
            clean_state.add_to_graveyard(user_pk, retired_key_data)

        # Verify order is preserved
        assert len(clean_state.graveyard[user_pk]) == 10
        for i in range(10):
            assert clean_state.graveyard[user_pk][i]["order"] == i
            assert clean_state.graveyard[user_pk][i]["public_key"] == f"key_{i}"

    def test_add_to_graveyard_unicode_data(self, clean_state):
        """Test adding retired key with unicode data."""
        user_pk = "用户_🔑"
        retired_key_data = {
            "public_key": "退休密钥_🗝️",
            "alg": "算法_ML-DSA",
            "retired_at": time.time(),
            "reason": "密钥轮换_🔄",
        }

        clean_state.add_to_graveyard(user_pk, retired_key_data)

        assert clean_state.graveyard[user_pk][0] == retired_key_data

    def test_add_to_graveyard_thread_safety(self, clean_state):
        """Test thread safety of add_to_graveyard."""
        num_threads = 10
        keys_per_thread = 20

        def add_retired_keys(thread_id):
            user_pk = f"user_{thread_id}"
            for i in range(keys_per_thread):
                retired_key_data = {
                    "public_key": f"retired_key_{thread_id}_{i}",
                    "alg": f"alg_{thread_id}_{i}",
                    "retired_at": time.time(),
                    "thread_id": thread_id,
                    "key_id": i,
                }
                clean_state.add_to_graveyard(user_pk, retired_key_data)

        with ThreadPoolExecutor(max_workers=num_threads) as executor:
            futures = [executor.submit(add_retired_keys, i) for i in range(num_threads)]
            for future in as_completed(futures):
                future.result()

        # Verify all retired keys were added
        assert len(clean_state.graveyard) == num_threads
        for thread_id in range(num_threads):
            user_pk = f"user_{thread_id}"
            assert len(clean_state.graveyard[user_pk]) == keys_per_thread

            # Verify data integrity and order
            for i in range(keys_per_thread):
                retired_key = clean_state.graveyard[user_pk][i]
                assert retired_key["thread_id"] == thread_id
                assert retired_key["key_id"] == i

    def test_add_to_graveyard_same_user_concurrent(self, clean_state):
        """Test concurrent additions to graveyard for the same user."""
        user_pk = "concurrent_user"
        num_threads = 10
        keys_per_thread = 5

        def add_retired_keys(thread_id):
            for i in range(keys_per_thread):
                retired_key_data = {
                    "public_key": f"key_{thread_id}_{i}",
                    "alg": f"alg_{thread_id}",
                    "retired_at": time.time(),
                    "thread_id": thread_id,
                    "key_id": i,
                }
                clean_state.add_to_graveyard(user_pk, retired_key_data)

        with ThreadPoolExecutor(max_workers=num_threads) as executor:
            futures = [executor.submit(add_retired_keys, i) for i in range(num_threads)]
            for future in as_completed(futures):
                future.result()

        # All retired keys should be added for the single user
        assert len(clean_state.graveyard) == 1
        assert len(clean_state.graveyard[user_pk]) == num_threads * keys_per_thread

        # Verify all keys are present (order may vary due to concurrency)
        all_keys = clean_state.graveyard[user_pk]
        thread_ids = [key["thread_id"] for key in all_keys]
        assert set(thread_ids) == set(range(num_threads))

        # Verify each thread contributed the right number of keys
        for thread_id in range(num_threads):
            thread_keys = [key for key in all_keys if key["thread_id"] == thread_id]
            assert len(thread_keys) == keys_per_thread
