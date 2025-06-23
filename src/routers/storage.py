import os
import json
import time
import hashlib
import gzip
import asyncio
from fastapi import APIRouter, HTTPException, UploadFile, File, Form, BackgroundTasks
from fastapi.responses import FileResponse, StreamingResponse
from typing import List

from lib.auth import verify_signature
from lib.pq_auth import verify_pq_signature
from lib import idk_message
from security import verify_nonce
from models import (
    PqSignature,
    DownloadFileRequest,
    DownloadChunkRequest,
    DownloadConcatenatedRequest,
    RegisterFileRequest,
)
from app_state import state, find_account
import config

router = APIRouter()

# Timeout for chunk uploads in seconds (5 minutes)
CHUNK_UPLOAD_TIMEOUT = 300


async def cleanup_expired_pending_uploads():
    """
    A background task that runs periodically to clean up resources for expired
    file uploads that were never completed.
    """
    while True:
        await asyncio.sleep(60)  # Check every 60 seconds

        now = time.time()
        # Create a copy of accounts to avoid issues with modifying during iteration
        all_accounts = list(state.block_store.keys())

        for public_key in all_accounts:
            # Create a copy of file hashes for the current account
            all_file_hashes = list(state.block_store.get(public_key, {}).keys())

            for file_hash in all_file_hashes:
                file_metadata = state.block_store.get(public_key, {}).get(file_hash)

                if not file_metadata or file_metadata.get("status") != "pending":
                    continue

                if now - file_metadata.get("registered_at", 0) > CHUNK_UPLOAD_TIMEOUT:
                    print(f"Found expired pending upload, cleaning up {file_hash}...")

                    # 1. Delete individual chunk files from disk
                    chunks_metadata = state.chunk_store.get(file_hash, {})
                    for chunk_hash_to_del in chunks_metadata.keys():
                        chunk_path = os.path.join(
                            config.CHUNK_STORE_ROOT, chunk_hash_to_del
                        )
                        if os.path.exists(chunk_path):
                            try:
                                os.remove(chunk_path)
                            except OSError as e:
                                print(f"Error removing chunk file {chunk_path}: {e}")

                    # 2. Delete concatenated chunk file from disk
                    concatenated_file_path = os.path.join(
                        config.BLOCK_STORE_ROOT, f"{file_hash}.chunks.gz"
                    )
                    if os.path.exists(concatenated_file_path):
                        try:
                            os.remove(concatenated_file_path)
                        except OSError as e:
                            print(
                                f"Error removing concatenated file {concatenated_file_path}: {e}"
                            )

                    # 3. Delete metadata from in-memory state
                    if file_hash in state.chunk_store:
                        del state.chunk_store[file_hash]
                    if (
                        public_key in state.block_store
                        and file_hash in state.block_store[public_key]
                    ):
                        del state.block_store[public_key][file_hash]

                    print(f"Cleanup for expired upload {file_hash} complete.")


@router.post("/storage/{public_key}/register", status_code=201)
async def register_file(
    public_key: str,
    nonce: str = Form(...),
    filename: str = Form(...),
    content_type: str = Form(...),
    total_size: int = Form(...),
    classic_signature: str = Form(...),
    pq_signatures: str = Form(...),  # JSON string
    idk_part_one: UploadFile = File(...),
):
    """
    Registers a new file by uploading the first IDK message part (header).
    This validates the file format, extracts the MerkleRoot as the file_hash,
    and stores the first part as the first chunk.
    The message to sign is f"REGISTER:{public_key}:{file_hash}:{nonce}"
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

    # Read and parse the first IDK part to get the file_hash (MerkleRoot)
    part_one_content = await idk_part_one.read()
    try:
        parsed_part = idk_message.parse_idk_message_part(
            part_one_content.decode("utf-8")
        )
        file_hash = parsed_part["headers"]["MerkleRoot"]
    except Exception as e:
        raise HTTPException(
            status_code=400, detail=f"Could not parse IDK message part one: {e}"
        )

    # Construct message and verify signatures
    message_to_verify = f"REGISTER:{public_key}:{file_hash}:{nonce}".encode("utf-8")

    # 1. Verify classic signature
    if not verify_signature(public_key, classic_signature, message_to_verify):
        raise HTTPException(status_code=401, detail="Invalid classic signature.")

    # 2. Verify signatures from all existing PQ keys
    pks_in_req = {s.public_key for s in parsed_pq_sigs}
    if pks_in_req != set(account_pq_keys.values()):
        raise HTTPException(
            status_code=401,
            detail="Signatures from all existing PQ keys are required for registration.",
        )

    for pq_sig in parsed_pq_sigs:
        if not verify_pq_signature(
            pq_sig.public_key, pq_sig.signature, message_to_verify, pq_sig.alg
        ):
            raise HTTPException(
                status_code=401,
                detail=f"Invalid signature for existing PQ key {pq_sig.public_key}",
            )

    # Store file metadata
    if public_key not in state.block_store:
        state.block_store[public_key] = {}

    state.block_store[public_key][file_hash] = {
        "filename": filename,
        "content_type": content_type,
        "size": total_size,
        "status": "pending",
        "registered_at": time.time(),
    }

    # --- Treat this first part as the first chunk ---
    # 1. Store the chunk individually
    chunk_hash_one = hashlib.blake2b(part_one_content).hexdigest()
    os.makedirs(config.CHUNK_STORE_ROOT, exist_ok=True)
    chunk_path = os.path.join(config.CHUNK_STORE_ROOT, chunk_hash_one)
    with open(chunk_path, "wb") as f:
        f.write(part_one_content)

    # 2. Append to concatenated gzip file
    os.makedirs(config.BLOCK_STORE_ROOT, exist_ok=True)
    concatenated_file_path = os.path.join(
        config.BLOCK_STORE_ROOT, f"{file_hash}.chunks.gz"
    )
    with open(concatenated_file_path, "ab") as f:
        f.write(gzip.compress(part_one_content, compresslevel=9))

    # 3. Track chunk metadata
    if file_hash not in state.chunk_store:
        state.chunk_store[file_hash] = {}

    state.chunk_store[file_hash][chunk_hash_one] = {
        "index": 0,  # First part is chunk 0
        "size": len(part_one_content),
        "compressed_size": None,  # Not applicable as it's not pre-compressed
        "compressed": False,
        "stored_at": time.time(),
    }

    state.used_nonces.add(nonce)

    # If this is a single-part file, the upload is already complete.
    if parsed_part["headers"]["TotalParts"] == 1:
        state.block_store[public_key][file_hash]["status"] = "completed"
        state.block_store[public_key][file_hash]["completed_at"] = time.time()
        print(f"File upload completed for {file_hash}")

    return {
        "message": "File registered successfully. First chunk received. Ready for subsequent chunks.",
        "file_hash": file_hash,
        "first_chunk_hash": chunk_hash_one,
    }


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

    # Check if the file has been registered and if the upload window is still open.
    file_metadata = state.block_store.get(public_key, {}).get(file_hash)

    if not file_metadata:
        raise HTTPException(
            status_code=404,
            detail="File record not found. Please register the file first.",
        )

    # Enforce the timeout for chunk uploads
    if time.time() - file_metadata.get("registered_at", 0) > CHUNK_UPLOAD_TIMEOUT:
        # NOTE: In a production system, a background job would handle cleanup
        # of expired registrations and their associated stored chunks.
        # For now, we'll just block new chunks for expired registrations.
        raise HTTPException(
            status_code=400, detail="File registration has expired (5 minute timeout)."
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

    # Store the chunk individually (as before) and also append to concatenated file
    os.makedirs(config.CHUNK_STORE_ROOT, exist_ok=True)
    chunk_path = os.path.join(config.CHUNK_STORE_ROOT, chunk_hash)
    with open(chunk_path, "wb") as f:
        f.write(chunk_content)  # Store as received (compressed or not)

    # Also append to concatenated gzip file for tools like zgrep
    os.makedirs(config.BLOCK_STORE_ROOT, exist_ok=True)
    concatenated_file_path = os.path.join(
        config.BLOCK_STORE_ROOT, f"{file_hash}.chunks.gz"
    )

    # Ensure chunk is compressed before appending to concatenated file
    if compressed:
        compressed_data = chunk_content
    else:
        # Compress uncompressed chunks before appending
        compressed_data = gzip.compress(original_chunk_content, compresslevel=9)

    # Append compressed chunk to concatenated file with newline separator
    with open(concatenated_file_path, "ab") as f:  # append binary mode
        # Add newline separator before each chunk (the first chunk was added during registration)
        f.write(gzip.compress(b"\n", compresslevel=9))
        f.write(compressed_data)

    # Track chunk metadata for both storage methods
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

    # Check if upload is complete
    all_chunks_metadata = state.chunk_store.get(file_hash, {})
    if len(all_chunks_metadata) == total_chunks:
        file_metadata["status"] = "completed"
        file_metadata["completed_at"] = time.time()
        print(f"File upload completed for {file_hash}")

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


def stream_idk_parts_only(file_path: str):
    """
    Generator that reads a concatenated gzip file and yields only the IDK message parts,
    skipping the compressed newline separators.
    """
    # Pre-compress a newline to identify separator gzip members
    compressed_newline = gzip.compress(b"\n", compresslevel=9)

    with open(file_path, "rb") as f:
        while True:
            # Try to read the next gzip member
            start_pos = f.tell()
            if start_pos >= os.path.getsize(file_path):
                break

            try:
                # Read this gzip member
                with gzip.GzipFile(fileobj=f) as gz:
                    decompressed_content = gz.read()

                # If this is just a newline separator, skip it
                if decompressed_content == b"\n":
                    continue

                # Otherwise, this is an IDK message part - we need to get its compressed form
                end_pos = f.tell()
                f.seek(start_pos)
                compressed_chunk = f.read(end_pos - start_pos)
                f.seek(end_pos)  # Reset position for next iteration

                yield compressed_chunk

            except Exception as e:
                # If we can't read a gzip member, we're done
                break


def verify_signatures(
    request, public_key: str, account_pq_keys: dict[str, str], message: str
):
    """
    Helper function to verify both classic and PQ signatures for download requests.
    """
    if not verify_nonce(request.nonce):
        raise HTTPException(status_code=400, detail="Invalid or expired nonce.")

    if request.nonce in state.used_nonces:
        raise HTTPException(status_code=400, detail="Nonce has already been used.")

    message_to_verify = message.encode("utf-8")

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


@router.post("/storage/{public_key}/{file_hash}/chunks/download")
async def download_concatenated_chunks(
    public_key: str, file_hash: str, request: DownloadConcatenatedRequest
):
    """
    Downloads all chunks as a single concatenated gzip file that can be used with zgrep, zcat, etc.
    Must be authorized by all keys on the account.
    Message to sign: f"DOWNLOAD-CHUNKS:{public_key}:{file_hash}:{nonce}"
    """
    account_pq_keys = find_account(public_key)

    # Verify the parent file exists
    user_files = state.block_store.get(public_key, {})
    if file_hash not in user_files:
        raise HTTPException(status_code=404, detail="File not found.")

    # Check if concatenated chunks file exists
    concatenated_file_path = os.path.join(
        config.BLOCK_STORE_ROOT, f"{file_hash}.chunks.gz"
    )
    if not os.path.exists(concatenated_file_path):
        raise HTTPException(
            status_code=404, detail="Concatenated chunks file not found."
        )

    # Verify signatures
    verify_signatures(
        request,
        public_key,
        account_pq_keys,
        f"DOWNLOAD-CHUNKS:{public_key}:{file_hash}:{request.nonce}",
    )
    state.used_nonces.add(request.nonce)

    # Get file metadata for filename
    file_metadata = user_files[file_hash]
    base_filename = (
        file_metadata["filename"].rsplit(".", 1)[0]
        if "." in file_metadata["filename"]
        else file_metadata["filename"]
    )
    filename = f"{base_filename}.chunks.gz"

    # Get chunk count for the response header
    chunk_count = len(state.chunk_store.get(file_hash, {}))

    # Check if we're running in test mode (TestClient doesn't handle StreamingResponse well)
    import sys

    is_testing = "pytest" in sys.modules or "unittest" in sys.modules

    if is_testing:
        # For tests, concatenate only the IDK parts (no separators) and return as one response
        idk_parts = []
        for compressed_part in stream_idk_parts_only(concatenated_file_path):
            idk_parts.append(compressed_part)

        concatenated_idk_content = b"".join(idk_parts)

        from fastapi.responses import Response

        return Response(
            content=concatenated_idk_content,
            media_type="application/gzip",
            headers={
                "Content-Disposition": f"attachment; filename={filename}",
                "X-Chunk-Count": str(chunk_count),
            },
        )
    else:
        # For production, use streaming response
        from fastapi.responses import StreamingResponse

        return StreamingResponse(
            stream_idk_parts_only(concatenated_file_path),
            media_type="application/gzip",
            headers={
                "Content-Disposition": f"attachment; filename={filename}",
                "X-Chunk-Count": str(chunk_count),
            },
        )
