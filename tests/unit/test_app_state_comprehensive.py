"""
Comprehensive tests for app state covering edge cases, thread safety,
and real-world usage patterns required for public audit.

These tests complement the basic tests in test_app_state.py by focusing on:
1. Thread safety and concurrent access
2. API method coverage (add_account, add_file_to_block_store, etc.)
3. State consistency under stress
4. Edge cases and error conditions
5. Memory management and cleanup
6. Integration scenarios
"""

import pytest
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from fastapi import HTTPException

from src.app_state import ServerState, find_account, get_app_state


@pytest.fixture
def clean_state():
    """Fixture to reset the app state for a test."""
    original_state = get_app_state()
    new_state = ServerState()
    import src.app_state

    src.app_state.state = new_state
    yield new_state
    src.app_state.state = original_state


class TestThreadSafety:
    """Test thread safety of all app state operations."""

    def test_concurrent_nonce_operations(self, clean_state):
        """Tests that concurrent nonce operations are thread-safe."""
        num_threads = 10
        num_nonces_per_thread = 100
        results = []

        def add_nonces(thread_id):
            thread_results = []
            for i in range(num_nonces_per_thread):
                nonce = f"thread_{thread_id}_nonce_{i}"
                try:
                    clean_state.check_and_add_nonce(nonce)
                    thread_results.append(("success", nonce))
                except HTTPException:
                    thread_results.append(("replay", nonce))
            return thread_results

        with ThreadPoolExecutor(max_workers=num_threads) as executor:
            futures = [executor.submit(add_nonces, i) for i in range(num_threads)]
            for future in as_completed(futures):
                results.extend(future.result())

        # All nonces should be successful (no duplicates)
        success_count = sum(1 for status, _ in results if status == "success")
        assert success_count == num_threads * num_nonces_per_thread

        # Verify all nonces are in the set
        assert len(clean_state.used_nonces) == num_threads * num_nonces_per_thread

    def test_concurrent_account_operations(self, clean_state):
        """Tests concurrent account add/remove operations."""
        num_threads = 5
        accounts_per_thread = 20

        def account_operations(thread_id):
            for i in range(accounts_per_thread):
                pk = f"thread_{thread_id}_account_{i}"
                account_data = {"alg": f"test_alg_{thread_id}_{i}"}
                clean_state.add_account(pk, account_data)

                # Verify account exists
                try:
                    retrieved = find_account(pk)
                    assert retrieved == account_data
                except HTTPException:
                    pytest.fail(f"Account {pk} not found after creation")

        with ThreadPoolExecutor(max_workers=num_threads) as executor:
            futures = [
                executor.submit(account_operations, i) for i in range(num_threads)
            ]
            for future in as_completed(futures):
                future.result()  # This will raise any exceptions

        # Verify all accounts were created
        assert len(clean_state.accounts) == num_threads * accounts_per_thread

    def test_concurrent_block_store_operations(self, clean_state):
        """Tests concurrent block store operations."""
        num_threads = 5
        files_per_thread = 10

        def block_store_operations(thread_id):
            for i in range(files_per_thread):
                user_pk = f"user_{thread_id}"
                file_hash = f"file_{thread_id}_{i}"
                file_metadata = {
                    "filename": f"test_{thread_id}_{i}.txt",
                    "size": i * 100,
                    "thread_id": thread_id,
                }
                clean_state.add_file_to_block_store(user_pk, file_hash, file_metadata)

        with ThreadPoolExecutor(max_workers=num_threads) as executor:
            futures = [
                executor.submit(block_store_operations, i) for i in range(num_threads)
            ]
            for future in as_completed(futures):
                future.result()

        # Verify all files were stored correctly
        assert len(clean_state.block_store) == num_threads
        for thread_id in range(num_threads):
            user_pk = f"user_{thread_id}"
            assert len(clean_state.block_store[user_pk]) == files_per_thread

    def test_concurrent_chunk_store_operations(self, clean_state):
        """Tests concurrent chunk store operations."""
        num_threads = 5
        chunks_per_thread = 10

        def chunk_store_operations(thread_id):
            for i in range(chunks_per_thread):
                file_hash = f"file_{thread_id}"
                chunk_hash = f"chunk_{thread_id}_{i}"
                chunk_metadata = {"index": i, "size": i * 50, "thread_id": thread_id}
                clean_state.add_chunk_to_chunk_store(
                    file_hash, chunk_hash, chunk_metadata
                )

        with ThreadPoolExecutor(max_workers=num_threads) as executor:
            futures = [
                executor.submit(chunk_store_operations, i) for i in range(num_threads)
            ]
            for future in as_completed(futures):
                future.result()

        # Verify all chunks were stored correctly
        assert len(clean_state.chunk_store) == num_threads
        for thread_id in range(num_threads):
            file_hash = f"file_{thread_id}"
            assert len(clean_state.chunk_store[file_hash]) == chunks_per_thread

    def test_concurrent_graveyard_operations(self, clean_state):
        """Tests concurrent graveyard operations."""
        num_threads = 5
        keys_per_thread = 10

        def graveyard_operations(thread_id):
            for i in range(keys_per_thread):
                user_pk = f"user_{thread_id}"
                retired_key_data = {
                    "public_key": f"old_key_{thread_id}_{i}",
                    "alg": f"alg_{thread_id}_{i}",
                    "retired_at": time.time(),
                    "thread_id": thread_id,
                }
                clean_state.add_to_graveyard(user_pk, retired_key_data)

        with ThreadPoolExecutor(max_workers=num_threads) as executor:
            futures = [
                executor.submit(graveyard_operations, i) for i in range(num_threads)
            ]
            for future in as_completed(futures):
                future.result()

        # Verify all retired keys were stored correctly
        assert len(clean_state.graveyard) == num_threads
        for thread_id in range(num_threads):
            user_pk = f"user_{thread_id}"
            assert len(clean_state.graveyard[user_pk]) == keys_per_thread


class TestAPIMethodCoverage:
    """Test all API methods defined in ServerState class."""

    def test_add_account_method(self, clean_state):
        """Tests the add_account method thoroughly."""
        # Test adding new account
        pk = "test_account_pk"
        account_data = {"alg1": "pk1", "alg2": "pk2"}
        clean_state.add_account(pk, account_data)

        assert pk in clean_state.accounts
        assert clean_state.accounts[pk] == account_data

        # Test updating existing account
        updated_data = {"alg1": "new_pk1", "alg3": "pk3"}
        clean_state.add_account(pk, updated_data)

        assert clean_state.accounts[pk] == updated_data
        assert len(clean_state.accounts) == 1

    def test_remove_account_method(self, clean_state):
        """Tests the remove_account method thoroughly."""
        # Add account first
        pk = "test_account_pk"
        account_data = {"alg": "test_alg"}
        clean_state.add_account(pk, account_data)
        assert pk in clean_state.accounts

        # Remove account
        clean_state.remove_account(pk)
        assert pk not in clean_state.accounts

        # Test removing non-existent account (should not raise error)
        clean_state.remove_account("non_existent_pk")
        assert len(clean_state.accounts) == 0

    def test_add_file_to_block_store_method(self, clean_state):
        """Tests the add_file_to_block_store method thoroughly."""
        user_pk = "user123"
        file_hash = "file_hash_123"
        file_metadata = {
            "filename": "test.txt",
            "size": 1024,
            "content_type": "text/plain",
            "created_at": time.time(),
        }

        # Test adding first file for user
        clean_state.add_file_to_block_store(user_pk, file_hash, file_metadata)

        assert user_pk in clean_state.block_store
        assert file_hash in clean_state.block_store[user_pk]
        assert clean_state.block_store[user_pk][file_hash] == file_metadata

        # Test adding second file for same user
        file_hash2 = "file_hash_456"
        file_metadata2 = {"filename": "test2.txt", "size": 2048}
        clean_state.add_file_to_block_store(user_pk, file_hash2, file_metadata2)

        assert len(clean_state.block_store[user_pk]) == 2
        assert clean_state.block_store[user_pk][file_hash2] == file_metadata2

        # Test overwriting existing file
        new_metadata = {"filename": "updated.txt", "size": 512}
        clean_state.add_file_to_block_store(user_pk, file_hash, new_metadata)

        assert clean_state.block_store[user_pk][file_hash] == new_metadata
        assert len(clean_state.block_store[user_pk]) == 2

    def test_add_chunk_to_chunk_store_method(self, clean_state):
        """Tests the add_chunk_to_chunk_store method thoroughly."""
        file_hash = "file_abc"
        chunk_hash = "chunk_123"
        chunk_metadata = {"index": 0, "size": 1024, "stored_at": time.time()}

        # Test adding first chunk for file
        clean_state.add_chunk_to_chunk_store(file_hash, chunk_hash, chunk_metadata)

        assert file_hash in clean_state.chunk_store
        assert chunk_hash in clean_state.chunk_store[file_hash]
        assert clean_state.chunk_store[file_hash][chunk_hash] == chunk_metadata

        # Test adding second chunk for same file
        chunk_hash2 = "chunk_456"
        chunk_metadata2 = {"index": 1, "size": 2048}
        clean_state.add_chunk_to_chunk_store(file_hash, chunk_hash2, chunk_metadata2)

        assert len(clean_state.chunk_store[file_hash]) == 2
        assert clean_state.chunk_store[file_hash][chunk_hash2] == chunk_metadata2

        # Test overwriting existing chunk
        new_metadata = {"index": 0, "size": 512, "updated": True}
        clean_state.add_chunk_to_chunk_store(file_hash, chunk_hash, new_metadata)

        assert clean_state.chunk_store[file_hash][chunk_hash] == new_metadata
        assert len(clean_state.chunk_store[file_hash]) == 2

    def test_add_to_graveyard_method(self, clean_state):
        """Tests the add_to_graveyard method thoroughly."""
        user_pk = "user123"
        retired_key_data = {
            "public_key": "old_pk_1",
            "alg": "Dilithium2",
            "retired_at": time.time(),
        }

        # Test adding first retired key
        clean_state.add_to_graveyard(user_pk, retired_key_data)

        assert user_pk in clean_state.graveyard
        assert len(clean_state.graveyard[user_pk]) == 1
        assert clean_state.graveyard[user_pk][0] == retired_key_data

        # Test adding second retired key for same user
        retired_key_data2 = {
            "public_key": "old_pk_2",
            "alg": "Falcon-512",
            "retired_at": time.time(),
        }
        clean_state.add_to_graveyard(user_pk, retired_key_data2)

        assert len(clean_state.graveyard[user_pk]) == 2
        assert clean_state.graveyard[user_pk][1] == retired_key_data2


class TestEdgeCasesAndErrorConditions:
    """Test edge cases and error conditions."""

    def test_find_account_with_threading_edge_cases(self, clean_state):
        """Tests find_account under various threading scenarios."""
        pk = "test_pk"
        account_data = {"alg": "test_alg"}

        # Test account creation and immediate lookup
        clean_state.add_account(pk, account_data)

        def concurrent_lookup():
            try:
                account = find_account(pk)
                return account
            except HTTPException as e:
                return e.status_code

        # Run multiple concurrent lookups
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(concurrent_lookup) for _ in range(50)]
            results = [future.result() for future in as_completed(futures)]

        # All lookups should be successful
        for result in results:
            assert result == account_data

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
        long_nonce = "a" * 10000
        clean_state.check_and_add_nonce(long_nonce)
        assert long_nonce in clean_state.used_nonces

    def test_large_data_handling(self, clean_state):
        """Tests handling of large data structures."""
        # Test large account data
        large_account_data = {
            f"alg_{i}": f"very_long_public_key_{'x' * 1000}_{i}" for i in range(100)
        }
        clean_state.add_account("large_account", large_account_data)

        retrieved = find_account("large_account")
        assert retrieved == large_account_data

        # Test large file metadata
        large_file_metadata = {
            "filename": "large_file.txt",
            "description": "x" * 10000,
            "tags": [f"tag_{i}" for i in range(1000)],
            "custom_fields": {
                f"field_{i}": f"value_{'y' * 100}_{i}" for i in range(100)
            },
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
        special_nonce = "nonce_with_special_chars_!@#$%^&*()_+-={}[]|\\:;\"'<>?,./"
        clean_state.check_and_add_nonce(special_nonce)
        assert special_nonce in clean_state.used_nonces


class TestStateConsistency:
    """Test state consistency under various conditions."""

    def test_state_consistency_during_concurrent_modifications(self, clean_state):
        """Tests that state remains consistent during concurrent modifications."""
        num_operations = 100

        def mixed_operations(thread_id):
            for i in range(num_operations):
                # Account operations
                pk = f"account_{thread_id}_{i}"
                clean_state.add_account(pk, {"alg": f"alg_{thread_id}_{i}"})

                # Block store operations
                clean_state.add_file_to_block_store(
                    f"user_{thread_id}",
                    f"file_{thread_id}_{i}",
                    {"filename": f"file_{i}.txt"},
                )

                # Chunk store operations
                clean_state.add_chunk_to_chunk_store(
                    f"file_{thread_id}", f"chunk_{thread_id}_{i}", {"index": i}
                )

                # Graveyard operations
                clean_state.add_to_graveyard(
                    f"user_{thread_id}",
                    {"public_key": f"old_key_{i}", "alg": f"alg_{i}"},
                )

                # Nonce operations
                clean_state.check_and_add_nonce(f"nonce_{thread_id}_{i}")

        # Run concurrent operations
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(mixed_operations, i) for i in range(5)]
            for future in as_completed(futures):
                future.result()

        # Verify state consistency
        assert len(clean_state.accounts) == 5 * num_operations
        assert len(clean_state.block_store) == 5  # 5 users
        assert len(clean_state.chunk_store) == 5  # 5 files
        assert len(clean_state.graveyard) == 5  # 5 users
        assert len(clean_state.used_nonces) == 5 * num_operations

        # Verify individual stores are consistent
        for user_id in range(5):
            user_pk = f"user_{user_id}"
            assert len(clean_state.block_store[user_pk]) == num_operations
            assert len(clean_state.graveyard[user_pk]) == num_operations

            file_hash = f"file_{user_id}"
            assert len(clean_state.chunk_store[file_hash]) == num_operations

    def test_memory_cleanup_patterns(self, clean_state):
        """Tests that memory usage remains reasonable with typical usage patterns."""
        # Simulate a usage pattern with account churn
        for cycle in range(10):
            # Add accounts
            for i in range(100):
                pk = f"cycle_{cycle}_account_{i}"
                clean_state.add_account(pk, {"alg": "test_alg"})

            # Add files for each account
            for i in range(100):
                user_pk = f"cycle_{cycle}_account_{i}"
                for j in range(5):  # 5 files per account
                    file_hash = f"cycle_{cycle}_file_{i}_{j}"
                    clean_state.add_file_to_block_store(
                        user_pk, file_hash, {"filename": f"file_{j}.txt"}
                    )

            # Remove half the accounts (simulating account deletion)
            for i in range(50):
                pk = f"cycle_{cycle}_account_{i}"
                clean_state.remove_account(pk)
                # Also remove from block store
                if pk in clean_state.block_store:
                    del clean_state.block_store[pk]

        # After cleanup, we should have reasonable memory usage
        # 10 cycles * 50 remaining accounts per cycle = 500 accounts
        assert len(clean_state.accounts) == 500
        assert len(clean_state.block_store) == 500

        # Verify we can still operate normally
        test_pk = "final_test_account"
        clean_state.add_account(test_pk, {"alg": "final_test"})
        retrieved = find_account(test_pk)
        assert retrieved == {"alg": "final_test"}


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
        for i in range(5):
            file_hash = f"file_{i}_hash"
            file_metadata = {
                "filename": f"document_{i}.pdf",
                "size": 1024 * (i + 1),
                "created_at": time.time(),
            }
            clean_state.add_file_to_block_store(pk, file_hash, file_metadata)

        # 4. Add chunks for files
        for i in range(5):
            file_hash = f"file_{i}_hash"
            for j in range(3):  # 3 chunks per file
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
        assert len(clean_state.block_store[pk]) == 5
        assert len(clean_state.chunk_store) == 5
        assert len(clean_state.graveyard[pk]) == 1
        assert clean_state.graveyard[pk][0]["public_key"] == old_falcon_key

    def test_high_throughput_nonce_usage(self, clean_state):
        """Tests high-throughput nonce usage pattern."""
        # Simulate high-frequency API calls
        nonce_count = 10000
        nonces = [f"api_call_{i}_{time.time()}_{i % 100}" for i in range(nonce_count)]

        # Process nonces in batches to simulate real API usage
        batch_size = 100
        for i in range(0, nonce_count, batch_size):
            batch = nonces[i : i + batch_size]

            def process_nonce(nonce):
                try:
                    clean_state.check_and_add_nonce(nonce)
                    return True
                except HTTPException:
                    return False

            with ThreadPoolExecutor(max_workers=10) as executor:
                results = list(executor.map(process_nonce, batch))

            # All nonces should be successfully processed
            assert all(results)

        # Verify all nonces are stored
        assert len(clean_state.used_nonces) == nonce_count

        # Verify replay protection still works
        with pytest.raises(HTTPException):
            clean_state.check_and_add_nonce(nonces[0])
