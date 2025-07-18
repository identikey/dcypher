import hashlib
import json
import base64
from fastapi import APIRouter, HTTPException, Form
from fastapi.responses import Response
from typing import List, Dict, Any
from datetime import datetime

from dcypher.lib.auth import verify_signature
from dcypher.lib.pq_auth import verify_pq_signature
from dcypher.lib import pre
from dcypher.security import verify_nonce
from dcypher.app_state import state
from dcypher.crypto.context_manager import CryptoContextManager
from dcypher import config
import ecdsa

# Generate a signing key for the server (for re-signed IDK messages)
SERVER_SK: ecdsa.SigningKey = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
_server_vk = SERVER_SK.get_verifying_key()
assert _server_vk is not None, "Failed to generate server verifying key"
SERVER_VK: ecdsa.VerifyingKey = _server_vk
SERVER_PUBLIC_KEY: str = SERVER_VK.to_string("uncompressed").hex()

router = APIRouter()


@router.post("/recryption/share")
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
    Alice generates the recryption key locally and sends it to the server.

    Message to sign: f"SHARE:{alice_pk}:{bob_pk}:{file_hash}:{nonce}"
    """
    # Verify Alice's account exists
    alice_pq_keys = state.find_account(alice_public_key)

    # Verify Bob's account exists and has PRE key
    state.find_account(bob_public_key)
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
        from dcypher.models import PqSignature

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


@router.get("/recryption/shares/{public_key}")
async def list_shares(public_key: str):
    """
    List all shares involving the given public key (both as sender and receiver).
    """
    state.find_account(public_key)  # Ensure account exists

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


@router.post("/recryption/download/{share_id}")
async def download_shared_file(
    share_id: str,
    bob_public_key: str = Form(...),
    nonce: str = Form(...),
    classic_signature: str = Form(...),
    pq_signatures: str = Form(...),  # JSON string
):
    """
    Bob downloads a file that Alice has shared with him.
    The server applies recryption on-the-fly before returning the data.

    Message to sign: f"DOWNLOAD-SHARED:{bob_pk}:{share_id}:{nonce}"
    """
    # Verify Bob's account exists
    bob_pq_keys = state.find_account(bob_public_key)

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
        from dcypher.models import PqSignature

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
    concatenated_file_path = f"{config.BLOCK_STORE_ROOT}/{file_hash}.chunks.gz"
    if not __import__("os").path.exists(concatenated_file_path):
        raise HTTPException(status_code=404, detail="Original file not found")

    # Apply recryption using the stored recryption key
    try:
        # Import here to avoid circular imports
        from dcypher.lib import pre

        # CRITICAL FIX: Use the server's pre-initialized context from app startup
        # The server's context is initialized once at startup and stored in the singleton
        # We should NEVER call deserialize_context() on the server side as it can destroy the context

        # Get the server's singleton context - this was initialized at startup
        context_manager = CryptoContextManager()
        server_context = context_manager.get_context()

        if server_context is None:
            # Context was destroyed (likely by fhe.ReleaseAllContexts() during parallel test execution)
            # Try to recover by reinitializing the server's context
            try:
                # Reinitialize the server's context with default parameters
                # This should match the parameters used during server startup
                fresh_context = pre.create_crypto_context()
                pre.generate_keys(fresh_context)  # Initialize it

                # Store it in the singleton
                context_manager._context = fresh_context
                server_context = fresh_context

                # Log the recovery for debugging
                import logging

                logger = logging.getLogger(__name__)
                logger.warning(
                    "Server crypto context was destroyed and has been recovered. This may indicate parallel test execution issues."
                )

            except Exception as recovery_error:
                # Recovery failed, this is a serious problem
                raise RuntimeError(
                    f"Server crypto context not initialized and recovery failed: {recovery_error}. This indicates a server startup issue."
                ) from recovery_error

        # CRITICAL: All operations must use the SAME context instance from the singleton
        # This includes deserialization of keys and ciphertexts

        # Deserialize the recryption key using the server's context
        re_key_bytes = share_policy["re_encryption_key"]
        re_key = pre.deserialize_re_encryption_key(re_key_bytes)

        # Read the original file chunks (these are IDK message parts)
        with open(concatenated_file_path, "rb") as f:
            file_content = f.read()

        # Decompress the gzip file content
        import gzip

        decompressed_content = gzip.decompress(file_content)

        # Parse the IDK message parts to extract Alice's ciphertexts
        idk_message_str = decompressed_content.decode("utf-8")

        # Split into individual IDK parts and extract ciphertexts
        import re
        from dcypher.lib import idk_message

        # Parse IDK message parts
        parts_with_empties = re.split(
            r"(----- BEGIN IDK MESSAGE PART)", idk_message_str
        )
        message_parts = []
        for i in range(1, len(parts_with_empties), 2):
            if i + 1 < len(parts_with_empties):
                full_part = parts_with_empties[i] + parts_with_empties[i + 1]
                message_parts.append(full_part.strip())

        # Extract Alice's ciphertexts and apply recryption
        import base64

        re_encrypted_parts = []

        for part_str in message_parts:
            # Parse each IDK part
            parsed_part = idk_message.parse_idk_message_part(part_str)

            # Extract the ciphertext payload
            payload_bytes = base64.b64decode(parsed_part["payload_b64"])

            # CRITICAL: Deserialize Alice's ciphertext using the SAME context instance
            # This ensures context consistency across all operations
            alice_ciphertext = pre.deserialize_ciphertext(payload_bytes)

            # Apply recryption transformation using the same context instance
            # All objects (ciphertext, re-key, context) are now consistent
            bob_ciphertexts = pre.re_encrypt(server_context, re_key, [alice_ciphertext])
            bob_ciphertext = bob_ciphertexts[0]

            # Serialize the recrypted ciphertext
            bob_payload_bytes = pre.serialize_to_bytes(bob_ciphertext)
            bob_payload_b64 = base64.b64encode(bob_payload_bytes).decode("ascii")

            # Create new headers following the recryption specification
            new_headers = parsed_part["headers"].copy()

            # Update required headers for recrypted messages
            new_headers["ChunkHash"] = hashlib.blake2b(bob_payload_bytes).hexdigest()
            new_headers["Recrypted"] = "true"
            new_headers["OriginalSender"] = alice_public_key
            new_headers["RecryptedBy"] = SERVER_PUBLIC_KEY
            new_headers["RecryptedFor"] = bob_public_key
            new_headers["RecryptionTimestamp"] = datetime.utcnow().isoformat() + "Z"
            new_headers["ProxyPublicKey"] = SERVER_PUBLIC_KEY  # Required by new spec

            # Remove headers that are invalidated by recryption
            new_headers.pop("Signature", None)  # Original signature no longer valid
            new_headers.pop(
                "SignerPublicKey", None
            )  # Original signer no longer relevant
            new_headers.pop("AuthPath", None)  # Merkle verification impossible
            new_headers.pop("MerkleRoot", None)  # Original Merkle tree invalidated

            # Create canonical header string for proxy signature (matching idk_message.py format)
            canonical_header_str = ""
            for key in sorted(new_headers.keys()):
                if (
                    key != "ProxySignature"
                ):  # Don't include the signature we're about to create
                    value = new_headers[key]
                    if key in ["PartSlotsTotal", "PartSlotsUsed", "BytesTotal"]:
                        canonical_header_str += f"{key}: {value}\n"
                    else:
                        canonical_header_str += f'{key}: "{value}"\n'

            canonical_hash = hashlib.sha256(
                canonical_header_str.encode("utf-8")
            ).digest()

            # Sign with server's private key
            proxy_signature = SERVER_SK.sign_digest(canonical_hash)
            new_headers["ProxySignature"] = proxy_signature.hex()

            # Reconstruct the IDK part with recrypted payload and new headers
            header_block = ""
            for key in sorted(new_headers.keys()):
                if key in ["PartNum", "TotalParts"]:
                    continue  # Skip derived keys
                value = new_headers[key]
                if key in ["PartSlotsTotal", "PartSlotsUsed", "BytesTotal"]:
                    header_block += f"{key}: {value}\n"
                else:
                    header_block += f'{key}: "{value}"\n'

            part_num = new_headers.get("PartNum", parsed_part["headers"]["PartNum"])
            total_parts = new_headers.get(
                "TotalParts", parsed_part["headers"]["TotalParts"]
            )

            re_encrypted_part = (
                f"----- BEGIN IDK MESSAGE PART {part_num}/{total_parts} -----\n"
                f"{header_block}\n"
                f"{bob_payload_b64}\n"
                f"----- END IDK MESSAGE PART {part_num}/{total_parts} -----"
            )

            re_encrypted_parts.append(re_encrypted_part)

        # Combine all recrypted parts
        re_encrypted_message = "\n".join(re_encrypted_parts)

        # Compress the recrypted content
        import gzip

        re_encrypted_bytes = gzip.compress(re_encrypted_message.encode("utf-8"))

        state.used_nonces.add(nonce)

        return Response(
            content=re_encrypted_bytes,
            media_type="application/gzip",
            headers={
                "Content-Disposition": f"attachment; filename=shared_{file_hash}.chunks.gz",
                "X-Share-ID": share_id,
                "X-Original-Owner": alice_public_key,
                "X-Recrypted": "true",  # Indicate this content has been recrypted
            },
        )

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Recryption failed: {e}")


@router.delete("/recryption/share/{share_id}")
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
    alice_pq_keys = state.find_account(alice_public_key)

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
        from dcypher.models import PqSignature

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
