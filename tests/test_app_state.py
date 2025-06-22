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
