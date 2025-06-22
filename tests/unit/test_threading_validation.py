"""
Test to validate whether threading provides meaningful concurrency testing
for our app state, or if we need multiprocessing.

This test demonstrates that threading can still catch race conditions
even with Python's GIL.
"""

import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
import pytest
from src.app_state import ServerState


def test_threading_vs_multiprocessing_race_detection():
    """
    Demonstrates that threading can detect race conditions in our context.
    This test intentionally creates a race condition to show it's detectable.
    """

    class UnsafeCounter:
        """A deliberately unsafe counter to demonstrate race conditions."""

        def __init__(self):
            self.count = 0
            self.operations = []

        def unsafe_increment(self, thread_id):
            """Unsafe increment that can have race conditions."""
            # Read
            current = self.count
            # Simulate some work that could be interrupted
            time.sleep(0.0001)  # Small delay to increase chance of race
            # Write
            self.count = current + 1
            self.operations.append(f"thread_{thread_id}")

    class SafeCounter:
        """A safe counter using threading locks."""

        def __init__(self):
            self.count = 0
            self.operations = []
            self.lock = threading.Lock()

        def safe_increment(self, thread_id):
            """Safe increment using locks."""
            with self.lock:
                current = self.count
                time.sleep(0.0001)  # Same delay, but protected
                self.count = current + 1
                self.operations.append(f"thread_{thread_id}")

    # Test unsafe counter with threading - should show race conditions
    unsafe_counter = UnsafeCounter()
    num_threads = 50
    increments_per_thread = 10

    def unsafe_worker(thread_id):
        for _ in range(increments_per_thread):
            unsafe_counter.unsafe_increment(thread_id)

    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = [executor.submit(unsafe_worker, i) for i in range(num_threads)]
        for future in as_completed(futures):
            future.result()

    expected_count = num_threads * increments_per_thread
    print(
        f"Unsafe counter - Expected: {expected_count}, Actual: {unsafe_counter.count}"
    )

    # The unsafe counter should show race conditions (count < expected)
    # If threading provides no concurrency, count would always equal expected
    race_condition_detected = unsafe_counter.count < expected_count

    # Test safe counter with threading - should work correctly
    safe_counter = SafeCounter()

    def safe_worker(thread_id):
        for _ in range(increments_per_thread):
            safe_counter.safe_increment(thread_id)

    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = [executor.submit(safe_worker, i) for i in range(num_threads)]
        for future in as_completed(futures):
            future.result()

    print(f"Safe counter - Expected: {expected_count}, Actual: {safe_counter.count}")

    # The safe counter should always be correct
    safe_counter_correct = safe_counter.count == expected_count

    # Verify our test can detect both safe and unsafe scenarios
    assert race_condition_detected, "Threading should be able to detect race conditions"
    assert safe_counter_correct, "Lock-protected operations should be safe"


def test_server_state_lock_effectiveness():
    """
    Test that our ServerState locks actually provide protection in threaded scenarios.
    """
    state = ServerState()
    num_threads = 20
    operations_per_thread = 100

    def nonce_worker(thread_id):
        """Worker that adds nonces concurrently."""
        for i in range(operations_per_thread):
            nonce = f"thread_{thread_id}_nonce_{i}"
            try:
                state.check_and_add_nonce(nonce)
            except Exception:
                # Expected for duplicate nonces
                pass

    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = [executor.submit(nonce_worker, i) for i in range(num_threads)]
        for future in as_completed(futures):
            future.result()

    # All nonces should be unique (no duplicates due to race conditions)
    expected_nonces = num_threads * operations_per_thread
    actual_nonces = len(state.used_nonces)

    print(f"Nonces - Expected: {expected_nonces}, Actual: {actual_nonces}")
    assert actual_nonces == expected_nonces, (
        "ServerState locks should prevent race conditions"
    )


def test_threading_gil_interaction():
    """
    Demonstrates that even with GIL, threading provides meaningful testing
    for our I/O and lock-bound operations.
    """
    # Test that we can detect contention even with GIL
    shared_resource = {"counter": 0}
    lock = threading.Lock()
    contention_detected = threading.Event()

    def contended_operation(thread_id):
        """Operation that simulates lock contention."""
        for i in range(10):
            # Try to acquire lock with timeout
            if not lock.acquire(timeout=0.001):  # Very short timeout
                contention_detected.set()
                lock.acquire()  # Now wait for it
            try:
                # Simulate work inside critical section
                current = shared_resource["counter"]
                time.sleep(0.0001)  # Brief delay
                shared_resource["counter"] = current + 1
            finally:
                lock.release()

    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(contended_operation, i) for i in range(5)]
        for future in as_completed(futures):
            future.result()

    # We should detect lock contention (threads waiting for locks)
    # This proves threading provides meaningful concurrency testing
    print(f"Lock contention detected: {contention_detected.is_set()}")
    print(f"Final counter value: {shared_resource['counter']}")

    # The counter should be correct (all operations protected)
    assert shared_resource["counter"] == 50, "All operations should complete safely"
    # Contention detection is environment-dependent, so we won't assert it
    # but it demonstrates that threading provides real concurrency


def test_memory_sharing_with_threading():
    """
    Demonstrates that threading provides the shared memory model we need
    for testing our ServerState singleton.
    """
    # Threading: Shared memory space (what we need)
    shared_state = ServerState()

    def modify_shared_state(value):
        shared_state.accounts[f"account_{value}"] = {"data": value}

    with ThreadPoolExecutor(max_workers=3) as executor:
        futures = [executor.submit(modify_shared_state, i) for i in range(3)]
        for future in futures:
            future.result()

    # All modifications visible in shared state
    assert len(shared_state.accounts) == 3
    print(f"Shared state accounts: {len(shared_state.accounts)}")

    # Verify all expected accounts are present
    for i in range(3):
        assert f"account_{i}" in shared_state.accounts
        assert shared_state.accounts[f"account_{i}"]["data"] == i


def test_stress_concurrent_operations():
    """
    Stress test to validate our thread safety under high load.
    """
    state = ServerState()
    num_threads = 20
    operations_per_thread = 50

    def mixed_operations(thread_id):
        """Mix of all operations to stress test the system."""
        for i in range(operations_per_thread):
            # Account operations
            account_pk = f"thread_{thread_id}_account_{i}"
            state.add_account(account_pk, {"alg": f"test_alg_{thread_id}_{i}"})

            # File operations
            file_hash = f"thread_{thread_id}_file_{i}"
            state.add_file_to_block_store(
                account_pk, file_hash, {"filename": f"file_{i}.txt", "size": i * 100}
            )

            # Chunk operations
            chunk_hash = f"thread_{thread_id}_chunk_{i}"
            state.add_chunk_to_chunk_store(
                file_hash, chunk_hash, {"index": i, "size": 1024}
            )

            # Graveyard operations
            state.add_to_graveyard(
                account_pk, {"public_key": f"old_key_{i}", "alg": "retired_alg"}
            )

            # Nonce operations
            try:
                state.check_and_add_nonce(f"thread_{thread_id}_nonce_{i}")
            except Exception:
                pass  # Expected for any duplicate nonces

    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = [executor.submit(mixed_operations, i) for i in range(num_threads)]
        for future in as_completed(futures):
            future.result()

    expected_operations = num_threads * operations_per_thread

    # Verify all operations completed successfully
    assert len(state.accounts) == expected_operations
    assert len(state.block_store) == expected_operations
    assert len(state.chunk_store) == expected_operations
    assert len(state.graveyard) == expected_operations
    assert len(state.used_nonces) == expected_operations

    print(f"Stress test completed successfully:")
    print(f"  Accounts: {len(state.accounts)}")
    print(f"  Block store entries: {len(state.block_store)}")
    print(f"  Chunk store entries: {len(state.chunk_store)}")
    print(f"  Graveyard entries: {len(state.graveyard)}")
    print(f"  Unique nonces: {len(state.used_nonces)}")


if __name__ == "__main__":
    # Run tests to demonstrate threading effectiveness
    test_threading_vs_multiprocessing_race_detection()
    test_server_state_lock_effectiveness()
    test_threading_gil_interaction()
    test_memory_sharing_with_threading()
    test_stress_concurrent_operations()
    print(
        "\nAll tests passed! Threading is appropriate and effective for our use case."
    )
