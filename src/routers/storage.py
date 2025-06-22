import os
import json
import time
import hashlib
from fastapi import APIRouter, HTTPException, UploadFile, File, Form
from fastapi.responses import FileResponse
from typing import List

from lib.auth import verify_signature
from lib.pq_auth import verify_pq_signature
from lib import idk_message
from security import verify_nonce
from models import (
    PqSignature,
    DownloadFileRequest,
)
from app_state import state, find_account
import config

router = APIRouter()


@router.post("/storage/{public_key}", status_code=201)
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

    if nonce in state.used_nonces:
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
    os.makedirs(config.BLOCK_STORE_ROOT, exist_ok=True)
    file_path = os.path.join(config.BLOCK_STORE_ROOT, file_hash)
    with open(file_path, "wb") as f:
        f.write(file_content)

    if public_key not in state.block_store:
        state.block_store[public_key] = {}

    state.block_store[public_key][file_hash] = {
        "filename": file.filename,
        "content_type": file.content_type,
        "size": len(file_content),
        "created_at": time.time(),
    }

    state.used_nonces.add(nonce)

    return {"message": "File uploaded successfully", "file_hash": file_hash}


@router.get("/storage/{public_key}")
def list_files(public_key: str):
    """Lists all files in the user's block store."""
    find_account(public_key)  # Ensure account exists
    user_files = state.block_store.get(public_key, {})
    return {"files": list(user_files.keys())}


@router.get("/storage/{public_key}/{file_hash}")
def get_file_metadata(public_key: str, file_hash: str):
    """Gets metadata for a specific file in the user's block store."""
    find_account(public_key)
    user_files = state.block_store.get(public_key, {})
    file_metadata = user_files.get(file_hash)
    if not file_metadata:
        raise HTTPException(status_code=404, detail="File not found.")
    return file_metadata


@router.post("/storage/{public_key}/{file_hash}/download")
async def download_file(public_key: str, file_hash: str, request: DownloadFileRequest):
    """
    Downloads a file from the block store.
    Must be authorized by all keys on the account.
    Message to sign: f"DOWNLOAD:{public_key}:{file_hash}:{nonce}"
    """
    account_pq_keys = find_account(public_key)
    user_files = state.block_store.get(public_key, {})
    file_metadata = user_files.get(file_hash)
    if not file_metadata:
        raise HTTPException(status_code=404, detail="File not found.")

    if not verify_nonce(request.nonce):
        raise HTTPException(status_code=400, detail="Invalid or expired nonce.")

    if request.nonce in state.used_nonces:
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

    file_path = os.path.join(config.BLOCK_STORE_ROOT, file_hash)
    if not os.path.exists(file_path):
        # This case should be rare if metadata exists, but good to have
        raise HTTPException(status_code=404, detail="File content not found on server.")

    state.used_nonces.add(request.nonce)
    return FileResponse(
        path=file_path,
        filename=file_metadata["filename"],
        media_type=file_metadata.get("content_type", "application/octet-stream"),
    )


@router.post("/storage/{public_key}/{file_hash}/chunks")
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
    if (
        public_key not in state.block_store
        or file_hash not in state.block_store[public_key]
    ):
        raise HTTPException(
            status_code=404,
            detail="File record not found. Upload file metadata first.",
        )

    if not verify_nonce(nonce):
        raise HTTPException(status_code=400, detail="Invalid or expired nonce.")

    if nonce in state.used_nonces:
        raise HTTPException(status_code=400, detail="Nonce has already been used.")

    # Manually parse pq_signatures from JSON string
    try:
        pq_signatures_list = json.loads(pq_signatures)
        parsed_pq_sigs = [PqSignature(**p) for p in pq_signatures_list]
    except (json.JSONDecodeError, TypeError):
        raise HTTPException(status_code=400, detail="Invalid format for pq_signatures.")

    # Verify chunk hash
    chunk_content = await file.read()
    computed_hash = hashlib.blake2b(chunk_content).hexdigest()
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
    os.makedirs(config.CHUNK_STORE_ROOT, exist_ok=True)
    chunk_path = os.path.join(config.CHUNK_STORE_ROOT, chunk_hash)
    with open(chunk_path, "wb") as f:
        f.write(chunk_content)

    if file_hash not in state.chunk_store:
        state.chunk_store[file_hash] = {}

    state.chunk_store[file_hash][chunk_hash] = {
        "index": chunk_index,
        "size": len(chunk_content),
        "stored_at": time.time(),
    }
    state.used_nonces.add(nonce)

    return {"message": f"Chunk {chunk_index}/{total_chunks} uploaded successfully."}
