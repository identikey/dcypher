import os
import json
import time
import hashlib
import gzip
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
    DownloadChunkRequest,
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

    # Handle compression if requested
    if request.compressed:
        # Read file content and compress it
        with open(file_path, "rb") as f:
            file_content = f.read()

        compressed_content = gzip.compress(file_content, compresslevel=9)

        from fastapi.responses import Response

        return Response(
            content=compressed_content,
            media_type="application/gzip",
            headers={
                "Content-Disposition": f'attachment; filename="{file_metadata["filename"]}.gz"',
                "X-Original-Size": str(len(file_content)),
                "X-Compressed-Size": str(len(compressed_content)),
            },
        )
    else:
        # Return uncompressed file as before
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
    compressed: bool = Form(False),  # New parameter to indicate if chunk is compressed
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

    # Read chunk content
    chunk_content = await file.read()

    # If chunk is compressed, decompress it for hash verification
    if compressed:
        try:
            original_chunk_content = gzip.decompress(chunk_content)
        except Exception as e:
            raise HTTPException(
                status_code=400, detail=f"Failed to decompress chunk: {e}"
            )
    else:
        original_chunk_content = chunk_content

    # Verify chunk hash against original (decompressed) content
    computed_hash = hashlib.blake2b(original_chunk_content).hexdigest()
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

    # Store the chunk (keep compressed if it was compressed)
    os.makedirs(config.CHUNK_STORE_ROOT, exist_ok=True)
    chunk_path = os.path.join(config.CHUNK_STORE_ROOT, chunk_hash)
    with open(chunk_path, "wb") as f:
        f.write(chunk_content)  # Store as received (compressed or not)

    if file_hash not in state.chunk_store:
        state.chunk_store[file_hash] = {}

    state.chunk_store[file_hash][chunk_hash] = {
        "index": chunk_index,
        "size": len(original_chunk_content),  # Original size
        "compressed_size": len(chunk_content)
        if compressed
        else len(original_chunk_content),
        "compressed": compressed,
        "stored_at": time.time(),
    }
    state.used_nonces.add(nonce)

    compression_info = (
        f" (compressed {len(chunk_content)} bytes from {len(original_chunk_content)} bytes)"
        if compressed
        else ""
    )
    return {
        "message": f"Chunk {chunk_index}/{total_chunks} uploaded successfully{compression_info}."
    }


@router.post("/storage/{public_key}/{file_hash}/chunks/{chunk_hash}/download")
async def download_chunk(
    public_key: str, file_hash: str, chunk_hash: str, request: DownloadChunkRequest
):
    """
    Downloads a single chunk from the chunk store.
    Must be authorized by all keys on the account.
    Message to sign: f"DOWNLOAD-CHUNK:{public_key}:{file_hash}:{chunk_hash}:{nonce}"
    """
    account_pq_keys = find_account(public_key)

    # Verify the parent file exists
    user_files = state.block_store.get(public_key, {})
    if file_hash not in user_files:
        raise HTTPException(status_code=404, detail="Parent file not found.")

    # Verify the chunk exists
    if (
        file_hash not in state.chunk_store
        or chunk_hash not in state.chunk_store[file_hash]
    ):
        raise HTTPException(status_code=404, detail="Chunk not found.")

    chunk_metadata = state.chunk_store[file_hash][chunk_hash]

    if not verify_nonce(request.nonce):
        raise HTTPException(status_code=400, detail="Invalid or expired nonce.")

    if request.nonce in state.used_nonces:
        raise HTTPException(status_code=400, detail="Nonce has already been used.")

    # Construct and verify signature message
    message_to_verify = (
        f"DOWNLOAD-CHUNK:{public_key}:{file_hash}:{chunk_hash}:{request.nonce}".encode(
            "utf-8"
        )
    )

    # Verify classic signature
    if not verify_signature(public_key, request.classic_signature, message_to_verify):
        raise HTTPException(status_code=401, detail="Invalid classic signature.")

    # Verify PQ signatures
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

    # Read the chunk from storage
    chunk_path = os.path.join(config.CHUNK_STORE_ROOT, chunk_hash)
    if not os.path.exists(chunk_path):
        raise HTTPException(
            status_code=404, detail="Chunk content not found on server."
        )

    state.used_nonces.add(request.nonce)

    # Handle compression based on client request and storage state
    with open(chunk_path, "rb") as f:
        chunk_data = f.read()

    is_stored_compressed = chunk_metadata.get("compressed", False)
    client_wants_compressed = request.compressed

    if is_stored_compressed and not client_wants_compressed:
        # Stored compressed, client wants uncompressed
        try:
            chunk_data = gzip.decompress(chunk_data)
            media_type = "application/octet-stream"
        except Exception as e:
            raise HTTPException(
                status_code=500, detail=f"Failed to decompress chunk: {e}"
            )
    elif not is_stored_compressed and client_wants_compressed:
        # Stored uncompressed, client wants compressed
        chunk_data = gzip.compress(chunk_data, compresslevel=9)
        media_type = "application/gzip"
    else:
        # Return as stored (compressed->compressed or uncompressed->uncompressed)
        media_type = (
            "application/gzip" if is_stored_compressed else "application/octet-stream"
        )

    from fastapi.responses import Response

    return Response(
        content=chunk_data,
        media_type=media_type,
        headers={
            "Content-Disposition": f'attachment; filename="{chunk_hash}.chunk"',
            "X-Chunk-Index": str(chunk_metadata["index"]),
            "X-Original-Size": str(chunk_metadata["size"]),
            "X-Compressed": str(is_stored_compressed).lower(),
        },
    )
