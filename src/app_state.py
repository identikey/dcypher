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


# Global state instance. In a real app, this might be managed differently.
state = ServerState()


def get_app_state():
    """Returns the global app state instance."""
    return state


def find_account(public_key: str):
    """Finds an account by its classic public key or raises HTTPException."""
    account = get_app_state().accounts.get(public_key)
    if not account:
        raise HTTPException(status_code=404, detail="Account not found.")
    return account
