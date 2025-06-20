import secrets
import time
import hmac
import hashlib
import os
import json
from fastapi import FastAPI, HTTPException, UploadFile, File, Form
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from typing import List

# To run this with uvicorn:
# uvicorn src.main:app --reload
# Ensure your PYTHONPATH is set up correctly if you have issues with the import.
# For example: export PYTHONPATH=.
from lib.auth import verify_signature
from lib.pq_auth import SUPPORTED_SIG_ALGS, verify_pq_signature
from lib import idk_message

# In a real application, this should be loaded from a secure configuration manager
# or environment variable, and it should be a long, random string.
SERVER_SECRET = "a-very-secret-key-that-should-be-changed"
ML_DSA_ALG = "ML-DSA-87"

# --- Storage Configuration ---
# These paths can be monkeypatched in tests to redirect storage.
BLOCK_STORE_ROOT = "block_store"
CHUNK_STORE_ROOT = "chunk_store"
# ---

app = FastAPI()

# A simple in-memory store for accounts and nonces.
# In a real application, you would use a persistent database.
# accounts: { classic_pk: { alg: pq_pk, ... }, ... }
accounts = {}
# graveyard: { classic_pk: [ { "public_key": pk, "alg": alg, "retired_at": ts }, ... ] }
graveyard = {}
used_nonces = set()
# block_store: { classic_pk: { file_hash: file_metadata } }
block_store = {}
# chunk_store: { file_hash: { chunk_hash: chunk_metadata } }
chunk_store = {}


class PqSignature(BaseModel):
    """Represents a post-quantum signature."""

    public_key: str  # hex-encoded post-quantum public key
    signature: str  # hex-encoded post-quantum signature
    alg: str  # post-quantum algorithm used


class CreateAccountRequest(BaseModel):
    public_key: str = Field(
        ..., description="Hex-encoded uncompressed SECP256k1 public key."
    )
    signature: str = Field(
        ..., description="Hex-encoded DER signature from the classic key."
    )
    ml_dsa_signature: PqSignature = Field(
        ..., description="Mandatory ML-DSA-87 signature."
    )
    additional_pq_signatures: list[PqSignature] = Field(
        [], description="Optional list of additional PQ signatures."
    )
    nonce: str = Field(..., description="Time-based nonce provided by the server.")


class AddPqKeysRequest(BaseModel):
    """Request to add new PQ keys to an account."""

    new_pq_signatures: list[PqSignature] = Field(
        ..., description="New PQ keys and their corresponding authorization signatures."
    )
    classic_signature: str = Field(
        ...,
        description="Signature from the root classic key authorizing the operation.",
    )
    existing_pq_signatures: list[PqSignature] = Field(
        ..., description="Signatures from all existing PQ keys on the account."
    )
    nonce: str = Field(..., description="Time-based nonce provided by the server.")


class RemovePqKeysRequest(BaseModel):
    """Request to remove PQ keys from an account."""

    algs_to_remove: list[str] = Field(
        ..., description="A list of the algorithm names for the PQ keys to be removed."
    )
    classic_signature: str = Field(
        ...,
        description="Signature from the root classic key authorizing the operation.",
    )
    pq_signatures: list[PqSignature] = Field(
        ..., description="Signatures from all existing PQ keys on the account."
    )
    nonce: str = Field(..., description="Time-based nonce provided by the server.")


class DownloadFileRequest(BaseModel):
    """Request to download a file from the block store."""

    classic_signature: str = Field(
        ..., description="Signature from the root classic key authorizing the download."
    )
    pq_signatures: list[PqSignature] = Field(
        ..., description="Signatures from all existing PQ keys on the account."
    )
    nonce: str = Field(..., description="Time-based nonce provided by the server.")


class UploadFileRequest(BaseModel):
    """Request to upload a file to the block store."""

    file_hash: str = Field(..., description="SHA256 hash of the entire file content.")
    classic_signature: str = Field(
        ..., description="Signature from the root classic key authorizing the upload."
    )
    pq_signatures: list[PqSignature] = Field(
        ..., description="Signatures from all existing PQ keys on the account."
    )
    nonce: str = Field(..., description="Time-based nonce provided by the server.")


class UploadChunkRequest(BaseModel):
    """Request to upload a single file chunk."""

    chunk_hash: str = Field(..., description="SHA256 hash of the chunk's content.")
    chunk_index: int = Field(..., description="The zero-based index of this chunk.")
    total_chunks: int = Field(
        ..., description="The total number of chunks for the file."
    )
    classic_signature: str = Field(
        ...,
        description="Signature from the root classic key authorizing the chunk upload.",
    )
    pq_signatures: list[PqSignature] = Field(
        ..., description="Signatures from all existing PQ keys on the account."
    )
    nonce: str = Field(..., description="Time-based nonce provided by the server.")


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

    # Prevent creating an account with duplicate algorithm types
    all_pq_algs = [request.ml_dsa_signature.alg] + [
        sig.alg for sig in request.additional_pq_signatures
    ]
    if len(all_pq_algs) != len(set(all_pq_algs)):
        raise HTTPException(
            status_code=400, detail="Duplicate algorithm types are not allowed."
        )

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
    if request.public_key in accounts:
        raise HTTPException(
            status_code=409,
            detail="Account with this classic public key already exists.",
        )

    # Store the account with all its public keys, indexed by algorithm
    active_pq_keys = {sig.alg: sig.public_key for sig in all_pq_signatures}
    accounts[request.public_key] = active_pq_keys
    used_nonces.add(request.nonce)

    return {"message": "Account created successfully", "public_key": request.public_key}


@app.get("/accounts")
def get_accounts():
    """Returns a list of all created accounts."""
    return {"accounts": list(accounts.keys())}


@app.get("/accounts/{public_key}")
def get_account(public_key: str):
    """Retrieves a single account by public key."""
    account_pq_keys = find_account(public_key)
    pq_keys_list = [
        {"public_key": pk, "alg": alg} for alg, pk in account_pq_keys.items()
    ]
    return {
        "public_key": public_key,
        "pq_keys": pq_keys_list,
    }


def find_account(public_key: str):
    """Finds an account by its classic public key or raises HTTPException."""
    account = accounts.get(public_key)
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
    f"ADD-PQ:{classic_pk}:{new_alg_1}:{new_alg_2}:...:{nonce}"
    """
    account_pq_keys = find_account(public_key)

    if not verify_nonce(request.nonce):
        raise HTTPException(status_code=400, detail="Invalid or expired nonce.")

    if request.nonce in used_nonces:
        raise HTTPException(status_code=400, detail="Nonce has already been used.")

    # Validate new keys
    new_algs_to_add = {s.alg for s in request.new_pq_signatures}
    if len(new_algs_to_add) != len(request.new_pq_signatures):
        raise HTTPException(
            status_code=400, detail="Duplicate algorithm types in new signatures list."
        )

    for new_sig in request.new_pq_signatures:
        if new_sig.alg not in SUPPORTED_SIG_ALGS:
            raise HTTPException(
                status_code=400, detail=f"Unsupported PQ algorithm: {new_sig.alg}."
            )
        if new_sig.alg == ML_DSA_ALG:
            raise HTTPException(
                status_code=400,
                detail=f"Cannot add another key for the mandatory algorithm {ML_DSA_ALG}.",
            )

    new_pks_to_add = {s.public_key for s in request.new_pq_signatures}
    if len(new_pks_to_add) != len(request.new_pq_signatures):
        raise HTTPException(
            status_code=400, detail="Duplicate public keys in new signatures list."
        )

    # Construct message and verify all signatures
    # Message includes algs now, not pks, as they are the identifiers
    new_algs_str = ":".join(sorted(list(new_algs_to_add)))
    message_to_verify = f"ADD-PQ:{public_key}:{new_algs_str}:{request.nonce}".encode(
        "utf-8"
    )

    # 1. Verify classic signature
    if not verify_signature(public_key, request.classic_signature, message_to_verify):
        raise HTTPException(status_code=401, detail="Invalid classic signature.")

    # 2. Verify signatures from all existing PQ keys
    existing_pks_in_req = {s.public_key for s in request.existing_pq_signatures}
    if existing_pks_in_req != set(account_pq_keys.values()):
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
    # Move any replaced keys to the graveyard
    if public_key not in graveyard:
        graveyard[public_key] = []

    for new_sig in request.new_pq_signatures:
        if new_sig.alg in account_pq_keys:
            old_pk = account_pq_keys[new_sig.alg]
            graveyard[public_key].append(
                {
                    "public_key": old_pk,
                    "alg": new_sig.alg,
                    "retired_at": time.time(),
                }
            )
        account_pq_keys[new_sig.alg] = new_sig.public_key

    used_nonces.add(request.nonce)

    return {
        "message": f"Successfully added {len(request.new_pq_signatures)} PQ key(s)."
    }


@app.post("/accounts/{public_key}/remove-pq-keys")
def remove_pq_keys(public_key: str, request: RemovePqKeysRequest):
    """
    Removes one or more post-quantum keys from an existing account.
    This action must be authorized by signing the request with the classic key
    and all existing post-quantum keys for the account. The mandatory ML-DSA
    key cannot be removed.

    The message to sign is:
    f"REMOVE-PQ:{classic_pk}:{removed_alg_1}:{removed_alg_2}:...:{nonce}"
    """
    account_pq_keys = find_account(public_key)

    if not verify_nonce(request.nonce):
        raise HTTPException(status_code=400, detail="Invalid or expired nonce.")

    if request.nonce in used_nonces:
        raise HTTPException(status_code=400, detail="Nonce has already been used.")

    # Validate keys to remove
    for alg_to_remove in request.algs_to_remove:
        if alg_to_remove not in account_pq_keys:
            raise HTTPException(
                status_code=404,
                detail=f"PQ key for algorithm {alg_to_remove} not found on account.",
            )
        if alg_to_remove == ML_DSA_ALG:
            raise HTTPException(
                status_code=400,
                detail=f"Cannot remove the mandatory PQ key ({ML_DSA_ALG}).",
            )

    # Construct message and verify all signatures
    remove_algs_str = ":".join(sorted(request.algs_to_remove))
    message_to_verify = (
        f"REMOVE-PQ:{public_key}:{remove_algs_str}:{request.nonce}".encode("utf-8")
    )

    # 1. Verify classic signature
    if not verify_signature(public_key, request.classic_signature, message_to_verify):
        raise HTTPException(status_code=401, detail="Invalid classic signature.")

    # 2. Verify signatures from ALL existing PQ keys
    pks_in_req = {s.public_key for s in request.pq_signatures}
    if pks_in_req != set(account_pq_keys.values()):
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
    # Move any replaced keys to the graveyard
    if public_key not in graveyard:
        graveyard[public_key] = []

    for alg_to_remove in request.algs_to_remove:
        removed_pk = account_pq_keys.pop(alg_to_remove)
        graveyard[public_key].append(
            {
                "public_key": removed_pk,
                "alg": alg_to_remove,
                "retired_at": time.time(),
            }
        )
    used_nonces.add(request.nonce)

    return {"message": "Successfully removed PQ key(s)."}


@app.get("/accounts/{public_key}/graveyard")
def get_graveyard(public_key: str):
    """Retrieves the graveyard of retired PQ keys for a given account."""
    find_account(public_key)  # Ensure account exists
    return {"public_key": public_key, "graveyard": graveyard.get(public_key, [])}


@app.post("/storage/{public_key}", status_code=201)
async def upload_file(
    public_key: str,
    nonce: str = Form(...),
    file_hash: str = Form(...),
    classic_signature: str = Form(...),
    pq_signatures: str = Form(...),  # This will be a JSON string
    file: UploadFile = File(...),
):
    """
    Uploads a file to the account's block store.
    The action must be authorized by all keys on the account.
    The message to sign is:
    f"UPLOAD:{classic_pk}:{file_hash}:{nonce}"

    Because of limitations with multipart/form-data, pq_signatures must be
    a JSON-encoded string representing a list of PqSignature objects.
    """
    account_pq_keys = find_account(public_key)

    if not verify_nonce(nonce):
        raise HTTPException(status_code=400, detail="Invalid or expired nonce.")

    if nonce in used_nonces:
        raise HTTPException(status_code=400, detail="Nonce has already been used.")

    # Manually parse pq_signatures from JSON string
    try:
        pq_signatures_list = json.loads(pq_signatures)
        parsed_pq_sigs = [PqSignature(**p) for p in pq_signatures_list]
    except (json.JSONDecodeError, TypeError):
        raise HTTPException(status_code=400, detail="Invalid format for pq_signatures.")

    # Verify file hash by parsing the IDK message
    file_content = await file.read()
    try:
        parsed_part = idk_message.parse_idk_message_part(file_content.decode("utf-8"))
        computed_hash = parsed_part["headers"]["MerkleRoot"]
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Could not parse IDK message: {e}")

    if computed_hash != file_hash:
        raise HTTPException(
            status_code=400, detail="File hash does not match MerkleRoot."
        )

    # Construct message and verify signatures
    message_to_verify = f"UPLOAD:{public_key}:{file_hash}:{nonce}".encode("utf-8")

    # 1. Verify classic signature
    if not verify_signature(public_key, classic_signature, message_to_verify):
        raise HTTPException(status_code=401, detail="Invalid classic signature.")

    # 2. Verify signatures from all existing PQ keys
    pks_in_req = {s.public_key for s in parsed_pq_sigs}
    if pks_in_req != set(account_pq_keys.values()):
        raise HTTPException(
            status_code=401,
            detail="Signatures from all existing PQ keys are required for upload.",
        )

    for pq_sig in parsed_pq_sigs:
        if not verify_pq_signature(
            pq_sig.public_key, pq_sig.signature, message_to_verify, pq_sig.alg
        ):
            raise HTTPException(
                status_code=401,
                detail=f"Invalid signature for existing PQ key {pq_sig.public_key}",
            )

    # Store the file and its metadata
    os.makedirs(BLOCK_STORE_ROOT, exist_ok=True)
    file_path = os.path.join(BLOCK_STORE_ROOT, file_hash)
    with open(file_path, "wb") as f:
        f.write(file_content)

    if public_key not in block_store:
        block_store[public_key] = {}

    block_store[public_key][file_hash] = {
        "filename": file.filename,
        "content_type": file.content_type,
        "size": len(file_content),
        "created_at": time.time(),
    }

    used_nonces.add(nonce)

    return {"message": "File uploaded successfully", "file_hash": file_hash}


@app.get("/storage/{public_key}")
def list_files(public_key: str):
    """Lists all files in the user's block store."""
    find_account(public_key)  # Ensure account exists
    user_files = block_store.get(public_key, {})
    return {"files": list(user_files.keys())}


@app.get("/storage/{public_key}/{file_hash}")
def get_file_metadata(public_key: str, file_hash: str):
    """Gets metadata for a specific file in the user's block store."""
    find_account(public_key)
    user_files = block_store.get(public_key, {})
    file_metadata = user_files.get(file_hash)
    if not file_metadata:
        raise HTTPException(status_code=404, detail="File not found.")
    return file_metadata


@app.post("/storage/{public_key}/{file_hash}/download")
async def download_file(public_key: str, file_hash: str, request: DownloadFileRequest):
    """
    Downloads a file from the block store.
    Must be authorized by all keys on the account.
    Message to sign: f"DOWNLOAD:{public_key}:{file_hash}:{nonce}"
    """
    account_pq_keys = find_account(public_key)
    user_files = block_store.get(public_key, {})
    file_metadata = user_files.get(file_hash)
    if not file_metadata:
        raise HTTPException(status_code=404, detail="File not found.")

    if not verify_nonce(request.nonce):
        raise HTTPException(status_code=400, detail="Invalid or expired nonce.")

    if request.nonce in used_nonces:
        raise HTTPException(status_code=400, detail="Nonce has already been used.")

    message_to_verify = f"DOWNLOAD:{public_key}:{file_hash}:{request.nonce}".encode(
        "utf-8"
    )

    # 1. Verify classic signature
    if not verify_signature(public_key, request.classic_signature, message_to_verify):
        raise HTTPException(status_code=401, detail="Invalid classic signature.")

    # 2. Verify signatures from all existing PQ keys
    pks_in_req = {s.public_key for s in request.pq_signatures}
    if pks_in_req != set(account_pq_keys.values()):
        raise HTTPException(
            status_code=401,
            detail="Signatures from all existing PQ keys are required for download.",
        )

    for pq_sig in request.pq_signatures:
        if not verify_pq_signature(
            pq_sig.public_key, pq_sig.signature, message_to_verify, pq_sig.alg
        ):
            raise HTTPException(
                status_code=401,
                detail=f"Invalid signature for existing PQ key {pq_sig.public_key}",
            )

    file_path = os.path.join(BLOCK_STORE_ROOT, file_hash)
    if not os.path.exists(file_path):
        # This case should be rare if metadata exists, but good to have
        raise HTTPException(status_code=404, detail="File content not found on server.")

    used_nonces.add(request.nonce)
    return FileResponse(
        path=file_path,
        filename=file_metadata["filename"],
        media_type=file_metadata.get("content_type", "application/octet-stream"),
    )


@app.post("/storage/{public_key}/{file_hash}/chunks")
async def upload_chunk(
    public_key: str,
    file_hash: str,
    nonce: str = Form(...),
    chunk_hash: str = Form(...),
    chunk_index: int = Form(...),
    total_chunks: int = Form(...),
    classic_signature: str = Form(...),
    pq_signatures: str = Form(...),  # JSON string
    file: UploadFile = File(...),
):
    """
    Uploads a single encrypted chunk for a file.
    Must be authorized by all keys.
    Message to sign: f"UPLOAD-CHUNK:{pk}:{file_hash}:{chunk_index}:{total_chunks}:{chunk_hash}:{nonce}"
    """
    account_pq_keys = find_account(public_key)

    # Simplified file existence check for now
    if public_key not in block_store or file_hash not in block_store[public_key]:
        raise HTTPException(
            status_code=404,
            detail="File record not found. Upload file metadata first.",
        )

    if not verify_nonce(nonce):
        raise HTTPException(status_code=400, detail="Invalid or expired nonce.")

    if nonce in used_nonces:
        raise HTTPException(status_code=400, detail="Nonce has already been used.")

    # Manually parse pq_signatures from JSON string
    try:
        pq_signatures_list = json.loads(pq_signatures)
        parsed_pq_sigs = [PqSignature(**p) for p in pq_signatures_list]
    except (json.JSONDecodeError, TypeError):
        raise HTTPException(status_code=400, detail="Invalid format for pq_signatures.")

    # Verify chunk hash
    chunk_content = await file.read()
    computed_hash = hashlib.sha256(chunk_content).hexdigest()
    if computed_hash != chunk_hash:
        raise HTTPException(status_code=400, detail="Chunk hash does not match.")

    # Construct message for signature verification
    message_to_verify = (
        f"UPLOAD-CHUNK:{public_key}:{file_hash}:"
        f"{chunk_index}:{total_chunks}:{chunk_hash}:{nonce}"
    ).encode("utf-8")

    # Verify signatures (classic and all PQ)
    if not verify_signature(public_key, classic_signature, message_to_verify):
        raise HTTPException(status_code=401, detail="Invalid classic signature.")

    pks_in_req = {s.public_key for s in parsed_pq_sigs}
    if pks_in_req != set(account_pq_keys.values()):
        raise HTTPException(
            status_code=401,
            detail="Signatures from all existing PQ keys are required for upload.",
        )

    for pq_sig in parsed_pq_sigs:
        if not verify_pq_signature(
            pq_sig.public_key, pq_sig.signature, message_to_verify, pq_sig.alg
        ):
            raise HTTPException(
                status_code=401,
                detail=f"Invalid signature for existing PQ key {pq_sig.public_key}",
            )

    # Store the chunk
    os.makedirs(CHUNK_STORE_ROOT, exist_ok=True)
    chunk_path = os.path.join(CHUNK_STORE_ROOT, chunk_hash)
    with open(chunk_path, "wb") as f:
        f.write(chunk_content)

    if file_hash not in chunk_store:
        chunk_store[file_hash] = {}

    chunk_store[file_hash][chunk_hash] = {
        "index": chunk_index,
        "size": len(chunk_content),
        "stored_at": time.time(),
    }
    used_nonces.add(nonce)

    return {"message": f"Chunk {chunk_index}/{total_chunks} uploaded successfully."}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
