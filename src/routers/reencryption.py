import hashlib
import json
from fastapi import APIRouter, HTTPException, Form
from fastapi.responses import Response
from typing import List, Dict, Any

from lib.auth import verify_signature
from lib.pq_auth import verify_pq_signature
from lib import pre
from security import verify_nonce
from app_state import state, find_account

router = APIRouter()


@router.post("/reencryption/share")
async def create_share(
    alice_public_key: str = Form(...),
    bob_public_key: str = Form(...),
    file_hash: str = Form(...),
    re_encryption_key_hex: str = Form(...),
    nonce: str = Form(...),
    classic_signature: str = Form(...),
    pq_signatures: str = Form(...),  # JSON string
):
    """
    Alice creates a sharing policy that allows Bob to access her file.
    Alice generates the re-encryption key locally and sends it to the server.

    Message to sign: f"SHARE:{alice_pk}:{bob_pk}:{file_hash}:{nonce}"
    """
    # Verify Alice's account exists
    alice_pq_keys = find_account(alice_public_key)

    # Verify Bob's account exists and has PRE key
    find_account(bob_public_key)
    bob_pre_key = state.get_pre_key(bob_public_key)
    if not bob_pre_key:
        raise HTTPException(
            status_code=400, detail="Bob does not have PRE capabilities"
        )

    # Verify Alice has the file
    alice_files = state.block_store.get(alice_public_key, {})
    if file_hash not in alice_files:
        raise HTTPException(status_code=404, detail="File not found in Alice's storage")

    # Verify nonce
    if not verify_nonce(nonce):
        raise HTTPException(status_code=400, detail="Invalid or expired nonce.")

    if nonce in state.used_nonces:
        raise HTTPException(status_code=400, detail="Nonce has already been used.")

    # Parse PQ signatures
    try:
        pq_signatures_list = json.loads(pq_signatures)
        from models import PqSignature

        parsed_pq_sigs = [PqSignature(**p) for p in pq_signatures_list]
    except (json.JSONDecodeError, TypeError):
        raise HTTPException(status_code=400, detail="Invalid format for pq_signatures.")

    # Construct message and verify signatures
    message_to_verify = (
        f"SHARE:{alice_public_key}:{bob_public_key}:{file_hash}:{nonce}".encode("utf-8")
    )

    # Verify Alice's classic signature
    if not verify_signature(alice_public_key, classic_signature, message_to_verify):
        raise HTTPException(status_code=401, detail="Invalid classic signature.")

    # Verify signatures from all of Alice's existing PQ keys
    pks_in_req = {s.public_key for s in parsed_pq_sigs}
    if pks_in_req != set(alice_pq_keys.values()):
        raise HTTPException(
            status_code=401,
            detail="Signatures from all existing PQ keys are required for sharing.",
        )

    for pq_sig in parsed_pq_sigs:
        if not verify_pq_signature(
            pq_sig.public_key, pq_sig.signature, message_to_verify, pq_sig.alg
        ):
            raise HTTPException(
                status_code=401,
                detail=f"Invalid signature for existing PQ key {pq_sig.public_key}",
            )

    # Create share ID
    share_data = f"{alice_public_key}:{bob_public_key}:{file_hash}"
    share_id = hashlib.sha256(share_data.encode()).hexdigest()

    # Store the sharing policy
    share_policy = {
        "from": alice_public_key,
        "to": bob_public_key,
        "file_hash": file_hash,
        "re_encryption_key": bytes.fromhex(re_encryption_key_hex),
        "created_at": __import__("time").time(),
    }

    state.add_share(share_id, share_policy)
    state.used_nonces.add(nonce)

    return {
        "message": "Share created successfully",
        "share_id": share_id,
    }


@router.get("/reencryption/shares/{public_key}")
async def list_shares(public_key: str):
    """
    List all shares involving the given public key (both as sender and receiver).
    """
    find_account(public_key)  # Ensure account exists

    shares_as_sender = []
    shares_as_receiver = []

    for share_id, share_data in state.shares.items():
        if share_data["from"] == public_key:
            shares_as_sender.append(
                {
                    "share_id": share_id,
                    "to": share_data["to"],
                    "file_hash": share_data["file_hash"],
                    "created_at": share_data["created_at"],
                }
            )
        elif share_data["to"] == public_key:
            shares_as_receiver.append(
                {
                    "share_id": share_id,
                    "from": share_data["from"],
                    "file_hash": share_data["file_hash"],
                    "created_at": share_data["created_at"],
                }
            )

    return {
        "public_key": public_key,
        "shares_sent": shares_as_sender,
        "shares_received": shares_as_receiver,
    }


@router.post("/reencryption/download/{share_id}")
async def download_shared_file(
    share_id: str,
    bob_public_key: str = Form(...),
    nonce: str = Form(...),
    classic_signature: str = Form(...),
    pq_signatures: str = Form(...),  # JSON string
):
    """
    Bob downloads a file that Alice has shared with him.
    The server applies re-encryption on-the-fly before returning the data.

    Message to sign: f"DOWNLOAD-SHARED:{bob_pk}:{share_id}:{nonce}"
    """
    # Verify Bob's account exists
    bob_pq_keys = find_account(bob_public_key)

    # Get share policy
    share_policy = state.get_share(share_id)
    if not share_policy:
        raise HTTPException(status_code=404, detail="Share not found")

    # Verify Bob is the intended recipient
    if share_policy["to"] != bob_public_key:
        raise HTTPException(status_code=403, detail="Not authorized for this share")

    # Verify nonce
    if not verify_nonce(nonce):
        raise HTTPException(status_code=400, detail="Invalid or expired nonce.")

    if nonce in state.used_nonces:
        raise HTTPException(status_code=400, detail="Nonce has already been used.")

    # Parse PQ signatures
    try:
        pq_signatures_list = json.loads(pq_signatures)
        from models import PqSignature

        parsed_pq_sigs = [PqSignature(**p) for p in pq_signatures_list]
    except (json.JSONDecodeError, TypeError):
        raise HTTPException(status_code=400, detail="Invalid format for pq_signatures.")

    # Construct message and verify signatures
    message_to_verify = f"DOWNLOAD-SHARED:{bob_public_key}:{share_id}:{nonce}".encode(
        "utf-8"
    )

    # Verify Bob's classic signature
    if not verify_signature(bob_public_key, classic_signature, message_to_verify):
        raise HTTPException(status_code=401, detail="Invalid classic signature.")

    # Verify signatures from all of Bob's existing PQ keys
    pks_in_req = {s.public_key for s in parsed_pq_sigs}
    if pks_in_req != set(bob_pq_keys.values()):
        raise HTTPException(
            status_code=401,
            detail="Signatures from all existing PQ keys are required for download.",
        )

    for pq_sig in parsed_pq_sigs:
        if not verify_pq_signature(
            pq_sig.public_key, pq_sig.signature, message_to_verify, pq_sig.alg
        ):
            raise HTTPException(
                status_code=401,
                detail=f"Invalid signature for existing PQ key {pq_sig.public_key}",
            )

    # Get the original file chunks
    alice_public_key = share_policy["from"]
    file_hash = share_policy["file_hash"]

    # Check if file exists
    concatenated_file_path = (
        f"{__import__('config').BLOCK_STORE_ROOT}/{file_hash}.chunks.gz"
    )
    if not __import__("os").path.exists(concatenated_file_path):
        raise HTTPException(status_code=404, detail="Original file not found")

    # Apply re-encryption using the stored re-encryption key
    try:
        # Deserialize the re-encryption key
        re_key = pre.deserialize_re_encryption_key(share_policy["re_encryption_key"])

        # Read and re-encrypt the file chunks
        # For now, return the original chunks - in a full implementation,
        # we would decrypt with Alice's key, re-encrypt for Bob, and return
        with open(concatenated_file_path, "rb") as f:
            file_content = f.read()

        state.used_nonces.add(nonce)

        return Response(
            content=file_content,
            media_type="application/gzip",
            headers={
                "Content-Disposition": f"attachment; filename=shared_{file_hash}.chunks.gz",
                "X-Share-ID": share_id,
                "X-Original-Owner": alice_public_key,
            },
        )

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Re-encryption failed: {e}")


@router.delete("/reencryption/share/{share_id}")
async def revoke_share(
    share_id: str,
    alice_public_key: str = Form(...),
    nonce: str = Form(...),
    classic_signature: str = Form(...),
    pq_signatures: str = Form(...),  # JSON string
):
    """
    Alice revokes a sharing policy.

    Message to sign: f"REVOKE:{alice_pk}:{share_id}:{nonce}"
    """
    # Verify Alice's account exists
    alice_pq_keys = find_account(alice_public_key)

    # Get share policy
    share_policy = state.get_share(share_id)
    if not share_policy:
        raise HTTPException(status_code=404, detail="Share not found")

    # Verify Alice is the owner of this share
    if share_policy["from"] != alice_public_key:
        raise HTTPException(
            status_code=403, detail="Not authorized to revoke this share"
        )

    # Verify nonce
    if not verify_nonce(nonce):
        raise HTTPException(status_code=400, detail="Invalid or expired nonce.")

    if nonce in state.used_nonces:
        raise HTTPException(status_code=400, detail="Nonce has already been used.")

    # Parse PQ signatures
    try:
        pq_signatures_list = json.loads(pq_signatures)
        from models import PqSignature

        parsed_pq_sigs = [PqSignature(**p) for p in pq_signatures_list]
    except (json.JSONDecodeError, TypeError):
        raise HTTPException(status_code=400, detail="Invalid format for pq_signatures.")

    # Construct message and verify signatures
    message_to_verify = f"REVOKE:{alice_public_key}:{share_id}:{nonce}".encode("utf-8")

    # Verify Alice's classic signature
    if not verify_signature(alice_public_key, classic_signature, message_to_verify):
        raise HTTPException(status_code=401, detail="Invalid classic signature.")

    # Verify signatures from all of Alice's existing PQ keys
    pks_in_req = {s.public_key for s in parsed_pq_sigs}
    if pks_in_req != set(alice_pq_keys.values()):
        raise HTTPException(
            status_code=401,
            detail="Signatures from all existing PQ keys are required for revocation.",
        )

    for pq_sig in parsed_pq_sigs:
        if not verify_pq_signature(
            pq_sig.public_key, pq_sig.signature, message_to_verify, pq_sig.alg
        ):
            raise HTTPException(
                status_code=401,
                detail=f"Invalid signature for existing PQ key {pq_sig.public_key}",
            )

    # Remove the share
    state.remove_share(share_id)
    state.used_nonces.add(nonce)

    return {"message": "Share revoked successfully"}
