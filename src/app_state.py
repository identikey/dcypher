from typing import Any
import threading
from fastapi import HTTPException
from lib import pre


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

        # PRE-related state
        self.pre_crypto_context = pre.create_crypto_context()
        # We need to generate keys to fully initialize the context before serialization
        pre.generate_keys(self.pre_crypto_context)
        self.pre_cc_serialized = pre.serialize_to_bytes(self.pre_crypto_context)
        # { classic_pk: pre_public_key_bytes }
        self.pre_keys = {}
        # { share_id: {from: classic_pk, to: classic_pk, file_hash: str, re_key: bytes} }
        self.shares = {}

        self._nonce_lock = threading.Lock()
        self._accounts_lock = threading.Lock()
        self._graveyard_lock = threading.Lock()
        self._block_store_lock = threading.Lock()
        self._chunk_store_lock = threading.Lock()
        self._pre_keys_lock = threading.Lock()
        self._shares_lock = threading.Lock()

    def add_pre_key(self, public_key: str, pre_public_key: bytes):
        """Adds a PRE public key for a given user."""
        with self._pre_keys_lock:
            self.pre_keys[public_key] = pre_public_key

    def get_pre_key(self, public_key: str):
        """Retrieves a PRE public key for a given user."""
        with self._pre_keys_lock:
            return self.pre_keys.get(public_key)

    def add_share(self, share_id: str, share_data: dict[str, Any]):
        """Adds a sharing policy."""
        with self._shares_lock:
            self.shares[share_id] = share_data

    def get_share(self, share_id: str):
        """Retrieves a sharing policy."""
        with self._shares_lock:
            return self.shares.get(share_id)

    def remove_share(self, share_id: str):
        """Removes a sharing policy."""
        with self._shares_lock:
            if share_id in self.shares:
                del self.shares[share_id]

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

    def find_account(self, public_key: str):
        """Finds an account by its classic public key or raises HTTPException."""
        with self._accounts_lock:
            account = self.accounts.get(public_key)
        if not account:
            raise HTTPException(status_code=404, detail="Account not found.")
        return account


# Global state instance. In a real app, this might be managed differently.
state = ServerState()


def get_app_state():
    """Returns the global app state instance."""
    return state


def find_account(public_key: str):
    """
    DEPRECATED: Use state.find_account() instead.
    Finds an account by its classic public key or raises HTTPException.
    """
    return state.find_account(public_key)
