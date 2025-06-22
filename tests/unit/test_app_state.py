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
