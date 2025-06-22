from typing import Any
import threading
from fastapi import HTTPException


class ServerState:
    """A simple in-memory store for application state."""

    def __init__(self):
        # accounts: { classic_pk: { alg: pq_pk, ... }, ... }
        self.accounts = {}
        # graveyard: { classic_pk: [ { "public_key": pk, "alg": alg, "retired_at": ts }, ... ] }
        self.graveyard = {}
        self.used_nonces = set()
        # block_store: { classic_pk: { file_hash: file_metadata } }
        self.block_store = {}
        # chunk_store: { file_hash: { chunk_hash: chunk_metadata } }
        self.chunk_store = {}
        self._nonce_lock = threading.Lock()
        self._accounts_lock = threading.Lock()
        self._graveyard_lock = threading.Lock()
        self._block_store_lock = threading.Lock()
        self._chunk_store_lock = threading.Lock()

    def check_and_add_nonce(self, nonce: str):
        """
        Atomically checks for a nonce and adds it to the used set.

        Raises:
            HTTPException: If the nonce has already been used, to prevent replay attacks.
        """
        with self._nonce_lock:
            if nonce in self.used_nonces:
                raise HTTPException(
                    status_code=400,
                    detail="Replay attack detected: nonce has already been used.",
                )
            self.used_nonces.add(nonce)

    def add_account(self, public_key: str, account_data: dict[str, Any]):
        """Adds or updates an account in the state."""
        with self._accounts_lock:
            self.accounts[public_key] = account_data

    def remove_account(self, public_key: str):
        """Removes an account from the state if it exists."""
        with self._accounts_lock:
            if public_key in self.accounts:
                del self.accounts[public_key]

    def add_to_graveyard(self, public_key: str, retired_key_data: dict[str, Any]):
        """Adds a retired key to the graveyard for a given user."""
        with self._graveyard_lock:
            if public_key not in self.graveyard:
                self.graveyard[public_key] = []
            self.graveyard[public_key].append(retired_key_data)

    def add_file_to_block_store(
        self, user_pk: str, file_hash: str, file_metadata: dict[str, Any]
    ):
        """Atomically adds file metadata to the block_store."""
        with self._block_store_lock:
            if user_pk not in self.block_store:
                self.block_store[user_pk] = {}
            self.block_store[user_pk][file_hash] = file_metadata

    def add_chunk_to_chunk_store(
        self, file_hash: str, chunk_hash: str, chunk_metadata: dict[str, Any]
    ):
        """Atomically adds chunk metadata to the chunk_store."""
        with self._chunk_store_lock:
            if file_hash not in self.chunk_store:
                self.chunk_store[file_hash] = {}
            self.chunk_store[file_hash][chunk_hash] = chunk_metadata


# Global state instance. In a real app, this might be managed differently.
state = ServerState()


def get_app_state():
    """Returns the global app state instance."""
    return state


def find_account(public_key: str):
    """Finds an account by its classic public key or raises HTTPException."""
    # Read operations on dicts are generally atomic in Python (GIL),
    # but locking ensures consistency during complex multi-step updates,
    # which might be introduced later.
    with get_app_state()._accounts_lock:
        account = get_app_state().accounts.get(public_key)
    if not account:
        raise HTTPException(status_code=404, detail="Account not found.")
    return account
