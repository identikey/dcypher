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
ML_DSA_ALG = "ML-DSA-87"

app = FastAPI()

# A simple in-memory store for accounts and nonces.
# In a real application, you would use a persistent database.
accounts = set()
used_nonces = set()


class PqSignature(BaseModel):
    """Represents a post-quantum signature."""

    public_key: str  # hex-encoded post-quantum public key
    signature: str  # hex-encoded post-quantum signature
    alg: str  # post-quantum algorithm used


class CreateAccountRequest(BaseModel):
    public_key: str  # hex-encoded uncompressed SECP256k1 public key
    signature: str  # hex-encoded DER signature for the classic key
    ml_dsa_signature: PqSignature  # Mandatory ML-DSA-87 signature
    additional_pq_signatures: list[PqSignature] = []  # Optional additional PQ sigs
    nonce: str  # time-based nonce provided by the server


class AddPqKeysRequest(BaseModel):
    """Request to add new PQ keys to an account."""

    new_pq_signatures: list[PqSignature]  # New PQ keys and their signatures
    classic_signature: str  # Signature from the classic key
    existing_pq_signatures: list[PqSignature]  # Signatures from existing PQ keys
    nonce: str


class RemovePqKeysRequest(BaseModel):
    """Request to remove PQ keys from an account."""

    public_keys_to_remove: list[str]  # Public keys of the PQ keys to remove
    classic_signature: str  # Signature from the classic key
    pq_signatures: list[PqSignature]  # Signatures from all existing PQ keys
    nonce: str


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
    The request must be signed with a classic ECDSA key, a mandatory ML-DSA key,
    and any number of optional additional post-quantum keys.

    All signatures must be valid for the account to be created.

    To create an account, the client must first request a nonce from the `/nonce`
    endpoint. Then, it must sign a message with the format:
    f"{classic_pk_hex}:{ml_dsa_pk_hex}:{other_pk_1_hex}:...:{nonce}"

    The signature should be created over the bytes of this UTF-8 encoded string.
    """
    if not verify_nonce(request.nonce):
        raise HTTPException(status_code=400, detail="Invalid or expired nonce.")

    if request.nonce in used_nonces:
        raise HTTPException(status_code=400, detail="Nonce has already been used.")

    if request.ml_dsa_signature.alg != ML_DSA_ALG:
        raise HTTPException(
            status_code=400,
            detail=f"Incorrect mandatory PQ algorithm. Expected {ML_DSA_ALG}, got {request.ml_dsa_signature.alg}",
        )

    all_pq_signatures = [request.ml_dsa_signature] + request.additional_pq_signatures
    for pq_sig in all_pq_signatures:
        if pq_sig.alg not in SUPPORTED_SIG_ALGS:
            raise HTTPException(
                status_code=400, detail=f"Unsupported PQ algorithm: {pq_sig.alg}."
            )

    # Construct the message from all public keys and the nonce.
    all_pq_public_keys = [sig.public_key for sig in all_pq_signatures]
    all_public_keys_str = ":".join([request.public_key] + all_pq_public_keys)
    message_to_verify = f"{all_public_keys_str}:{request.nonce}".encode("utf-8")

    # 1. Verify classic signature
    is_valid_classic = verify_signature(
        public_key_hex=request.public_key,
        signature_hex=request.signature,
        message=message_to_verify,
    )
    if not is_valid_classic:
        raise HTTPException(status_code=401, detail="Invalid classic signature.")

    # 2. Verify all post-quantum signatures
    for pq_sig in all_pq_signatures:
        is_valid_pq = verify_pq_signature(
            public_key_hex=pq_sig.public_key,
            signature_hex=pq_sig.signature,
            message=message_to_verify,
            alg=pq_sig.alg,
        )
        if not is_valid_pq:
            raise HTTPException(
                status_code=401,
                detail=f"Invalid post-quantum signature for algorithm {pq_sig.alg}.",
            )

    # Check for account existence based on the classic public key
    if any(acc[0] == request.public_key for acc in accounts):
        raise HTTPException(
            status_code=409,
            detail="Account with this classic public key already exists.",
        )

    # Store the account with all its public keys
    pq_keys_info = tuple((sig.public_key, sig.alg) for sig in all_pq_signatures)
    account_id = (request.public_key, pq_keys_info)
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

    pq_keys_list = [{"public_key": pk, "alg": alg} for pk, alg in account[1]]
    return {
        "public_key": account[0],
        "pq_keys": pq_keys_list,
    }


def find_account(public_key: str):
    """Finds an account by its classic public key or raises HTTPException."""
    account = next((acc for acc in accounts if acc[0] == public_key), None)
    if not account:
        raise HTTPException(status_code=404, detail="Account not found.")
    return account


@app.post("/accounts/{public_key}/add-pq-keys")
def add_pq_keys(public_key: str, request: AddPqKeysRequest):
    """
    Adds one or more new post-quantum keys to an existing account.
    This action must be authorized by signing the request with the classic key
    and all existing post-quantum keys for the account. The new keys must also
    provide a signature to prove ownership.

    The message to sign is:
    f"ADD-PQ:{classic_pk}:{new_pk_1}:{new_pk_2}:...:{nonce}"
    """
    account = find_account(public_key)

    if not verify_nonce(request.nonce):
        raise HTTPException(status_code=400, detail="Invalid or expired nonce.")

    if request.nonce in used_nonces:
        raise HTTPException(status_code=400, detail="Nonce has already been used.")

    # Validate new keys
    for new_sig in request.new_pq_signatures:
        if new_sig.alg not in SUPPORTED_SIG_ALGS:
            raise HTTPException(
                status_code=400, detail=f"Unsupported PQ algorithm: {new_sig.alg}."
            )

    classic_pk, existing_pq_keys_tuple = account
    existing_pq_keys_map = dict(existing_pq_keys_tuple)

    new_pks_to_add = {s.public_key for s in request.new_pq_signatures}
    if any(pk in existing_pq_keys_map for pk in new_pks_to_add):
        raise HTTPException(
            status_code=409, detail="One or more PQ keys already exist on the account."
        )

    if len(new_pks_to_add) != len(request.new_pq_signatures):
        raise HTTPException(
            status_code=400, detail="Duplicate public keys in new signatures list."
        )

    # Construct message and verify all signatures
    new_pks_str = ":".join(sorted(list(new_pks_to_add)))
    message_to_verify = f"ADD-PQ:{public_key}:{new_pks_str}:{request.nonce}".encode(
        "utf-8"
    )

    # 1. Verify classic signature
    if not verify_signature(public_key, request.classic_signature, message_to_verify):
        raise HTTPException(status_code=401, detail="Invalid classic signature.")

    # 2. Verify signatures from all existing PQ keys
    existing_pks_in_req = {s.public_key for s in request.existing_pq_signatures}
    if existing_pks_in_req != set(existing_pq_keys_map.keys()):
        raise HTTPException(
            status_code=401, detail="Signatures from all existing PQ keys are required."
        )

    for pq_sig in request.existing_pq_signatures:
        if not verify_pq_signature(
            pq_sig.public_key, pq_sig.signature, message_to_verify, pq_sig.alg
        ):
            raise HTTPException(
                status_code=401,
                detail=f"Invalid signature for existing PQ key {pq_sig.public_key}",
            )

    # 3. Verify signatures from all new PQ keys (proves ownership)
    for new_sig in request.new_pq_signatures:
        if not verify_pq_signature(
            new_sig.public_key, new_sig.signature, message_to_verify, new_sig.alg
        ):
            raise HTTPException(
                status_code=401,
                detail=f"Invalid signature for new PQ key {new_sig.public_key}",
            )

    # All checks passed, update the account
    accounts.remove(account)
    new_pq_keys_info = tuple((s.public_key, s.alg) for s in request.new_pq_signatures)
    updated_pq_keys = existing_pq_keys_tuple + new_pq_keys_info
    new_account_tuple = (classic_pk, updated_pq_keys)
    accounts.add(new_account_tuple)
    used_nonces.add(request.nonce)

    return {"message": f"Successfully added {len(new_pq_keys_info)} PQ key(s)."}


@app.post("/accounts/{public_key}/remove-pq-keys")
def remove_pq_keys(public_key: str, request: RemovePqKeysRequest):
    """
    Removes one or more post-quantum keys from an existing account.
    This action must be authorized by signing the request with the classic key
    and all existing post-quantum keys for the account. The mandatory ML-DSA
    key cannot be removed.

    The message to sign is:
    f"REMOVE-PQ:{classic_pk}:{removed_pk_1}:{removed_pk_2}:...:{nonce}"
    """
    account = find_account(public_key)

    if not verify_nonce(request.nonce):
        raise HTTPException(status_code=400, detail="Invalid or expired nonce.")

    if request.nonce in used_nonces:
        raise HTTPException(status_code=400, detail="Nonce has already been used.")

    classic_pk, existing_pq_keys_tuple = account
    existing_pq_keys_map = dict(existing_pq_keys_tuple)

    # Validate keys to remove
    for pk_to_remove in request.public_keys_to_remove:
        if pk_to_remove not in existing_pq_keys_map:
            raise HTTPException(
                status_code=404,
                detail=f"PQ key {pk_to_remove} not found on account.",
            )
        if existing_pq_keys_map[pk_to_remove] == ML_DSA_ALG:
            raise HTTPException(
                status_code=400,
                detail=f"Cannot remove the mandatory PQ key ({ML_DSA_ALG}).",
            )

    # Construct message and verify all signatures
    remove_pks_str = ":".join(sorted(request.public_keys_to_remove))
    message_to_verify = (
        f"REMOVE-PQ:{public_key}:{remove_pks_str}:{request.nonce}".encode("utf-8")
    )

    # 1. Verify classic signature
    if not verify_signature(public_key, request.classic_signature, message_to_verify):
        raise HTTPException(status_code=401, detail="Invalid classic signature.")

    # 2. Verify signatures from ALL existing PQ keys
    pks_in_req = {s.public_key for s in request.pq_signatures}
    if pks_in_req != set(existing_pq_keys_map.keys()):
        raise HTTPException(
            status_code=401,
            detail="Signatures from all existing PQ keys are required for removal.",
        )

    for pq_sig in request.pq_signatures:
        if not verify_pq_signature(
            pq_sig.public_key, pq_sig.signature, message_to_verify, pq_sig.alg
        ):
            raise HTTPException(
                status_code=401,
                detail=f"Invalid signature for existing PQ key {pq_sig.public_key}",
            )

    # All checks passed, update the account
    accounts.remove(account)
    updated_pq_keys_tuple = tuple(
        key_info
        for key_info in existing_pq_keys_tuple
        if key_info[0] not in request.public_keys_to_remove
    )
    new_account_tuple = (classic_pk, updated_pq_keys_tuple)
    accounts.add(new_account_tuple)
    used_nonces.add(request.nonce)

    return {"message": "Successfully removed PQ key(s)."}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
