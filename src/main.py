import secrets
import time
import hmac
import hashlib
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

# To run this with uvicorn:
# uvicorn src.main:app --reload
# Ensure your PYTHONPATH is set up correctly if you have issues with the import.
# For example: export PYTHONPATH=.
from lib.auth import verify_signature
from lib.pq_auth import SUPPORTED_SIG_ALGS, verify_pq_signature

# In a real application, this should be loaded from a secure configuration manager
# or environment variable, and it should be a long, random string.
SERVER_SECRET = "a-very-secret-key-that-should-be-changed"

app = FastAPI()

# A simple in-memory store for accounts and nonces.
# In a real application, you would use a persistent database.
accounts = set()
used_nonces = set()


class CreateAccountRequest(BaseModel):
    public_key: str  # hex-encoded uncompressed SECP256k1 public key
    signature: str  # hex-encoded DER signature
    pq_public_key: str  # hex-encoded post-quantum public key
    pq_signature: str  # hex-encoded post-quantum signature
    pq_alg: str  # post-quantum algorithm used
    nonce: str  # time-based nonce provided by the server


@app.get("/supported-pq-algs")
def get_supported_pq_algs():
    """Returns a list of supported post-quantum signature algorithms."""
    return {"algorithms": SUPPORTED_SIG_ALGS}


@app.get("/nonce")
def get_nonce():
    """
    Generates a time-based, HMAC-signed nonce for the client to sign.
    Nonces are valid for 5 minutes.
    """
    timestamp = str(time.time())
    mac = hmac.new(
        SERVER_SECRET.encode(), timestamp.encode(), hashlib.sha256
    ).hexdigest()
    nonce = f"{timestamp}:{mac}"
    return {"nonce": nonce}


def verify_nonce(nonce: str) -> bool:
    """Verifies the integrity and expiration of a nonce."""
    try:
        timestamp_str, mac = nonce.split(":")
        timestamp = float(timestamp_str)
    except ValueError:
        return False  # Malformed nonce

    # 1. Check if expired (5-minute validity)
    if time.time() - timestamp > 300:
        return False

    # 2. Check HMAC signature
    expected_mac = hmac.new(
        SERVER_SECRET.encode(), timestamp_str.encode(), hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(expected_mac, mac):
        return False

    return True


@app.post("/accounts")
def create_account(request: CreateAccountRequest):
    """
    Creates a new account, identified by a public key.
    The request must be signed to prove ownership of the public key.

    To create an account, the client must first request a nonce from the `/nonce`
    endpoint. Then, it must sign a message with the format:
    f"{public_key_hex}:{pq_public_key_hex}:{nonce}"

    The signature should be created over the bytes of this UTF-8 encoded string,
    using SHA256 as the hash function for the classic signature, and the
    appropriate hash function for the post-quantum signature.
    """
    if not verify_nonce(request.nonce):
        raise HTTPException(status_code=400, detail="Invalid or expired nonce.")

    if request.nonce in used_nonces:
        raise HTTPException(status_code=400, detail="Nonce has already been used.")

    if request.pq_alg not in SUPPORTED_SIG_ALGS:
        raise HTTPException(status_code=400, detail="Unsupported PQ algorithm.")

    # The message that is expected to be signed is the public key concatenated with the nonce.
    message_to_verify = (
        f"{request.public_key}:{request.pq_public_key}:{request.nonce}".encode("utf-8")
    )

    is_valid_classic = verify_signature(
        public_key_hex=request.public_key,
        signature_hex=request.signature,
        message=message_to_verify,
    )
    if not is_valid_classic:
        raise HTTPException(status_code=401, detail="Invalid classic signature.")

    is_valid_pq = verify_pq_signature(
        public_key_hex=request.pq_public_key,
        signature_hex=request.pq_signature,
        message=message_to_verify,
        alg=request.pq_alg,
    )

    if not is_valid_pq:
        raise HTTPException(status_code=401, detail="Invalid post-quantum signature.")

    account_id = (request.public_key, request.pq_public_key, request.pq_alg)
    if any(acc[0] == request.public_key for acc in accounts):
        raise HTTPException(
            status_code=409,
            detail="Account with this classic public key already exists.",
        )

    accounts.add(account_id)
    used_nonces.add(request.nonce)

    return {"message": "Account created successfully", "public_key": request.public_key}


@app.get("/accounts")
def get_accounts():
    """Returns a list of all created accounts."""
    return {"accounts": [acc[0] for acc in accounts]}


@app.get("/accounts/{public_key}")
def get_account(public_key: str):
    """Retrieves a single account by public key."""
    account = next((acc for acc in accounts if acc[0] == public_key), None)
    if not account:
        raise HTTPException(status_code=404, detail="Account not found.")
    return {
        "public_key": account[0],
        "pq_public_key": account[1],
        "pq_alg": account[2],
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
