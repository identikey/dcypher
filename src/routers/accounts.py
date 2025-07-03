import time
from fastapi import APIRouter, HTTPException
from app_state import state
from models import CreateAccountRequest, AddPqKeysRequest, RemovePqKeysRequest
from lib.auth import verify_signature
from lib.pq_auth import verify_pq_signature, SUPPORTED_SIG_ALGS
from security import verify_nonce
from config import ML_DSA_ALG


router = APIRouter()


@router.post("/accounts")
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

    if request.nonce in state.used_nonces:
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
    if request.public_key in state.accounts:
        raise HTTPException(
            status_code=409,
            detail="Account with this classic public key already exists.",
        )

    # Store the account with all its public keys, indexed by algorithm
    active_pq_keys = {sig.alg: sig.public_key for sig in all_pq_signatures}
    state.accounts[request.public_key] = active_pq_keys
    state.used_nonces.add(request.nonce)

    # If a PRE public key is provided, store it
    if request.pre_public_key_hex:
        state.add_pre_key(request.public_key, bytes.fromhex(request.pre_public_key_hex))

    return {"message": "Account created successfully", "public_key": request.public_key}


@router.get("/accounts")
def get_accounts():
    """Returns a list of all created accounts."""
    return {"accounts": list(state.accounts.keys())}


@router.get("/accounts/{public_key}")
def get_account(public_key: str):
    """Retrieves a single account by public key."""
    account_pq_keys = state.find_account(public_key)
    pq_keys_list = [
        {"public_key": pk, "alg": alg} for alg, pk in account_pq_keys.items()
    ]

    # Build the response with PQ keys
    response = {
        "public_key": public_key,
        "pq_keys": pq_keys_list,
    }

    # Include PRE public key if it exists
    pre_public_key_bytes = state.get_pre_key(public_key)
    if pre_public_key_bytes:
        response["pre_public_key_hex"] = pre_public_key_bytes.hex()

    return response


@router.post("/accounts/{public_key}/add-pq-keys")
def add_pq_keys(public_key: str, request: AddPqKeysRequest):
    """
    Adds one or more new post-quantum keys to an existing account.
    This action must be authorized by signing the request with the classic key
    and all existing post-quantum keys for the account. The new keys must also
    provide a signature to prove ownership.

    The message to sign is:
    f"ADD-PQ:{classic_pk}:{new_alg_1}:{new_alg_2}:...:{nonce}"
    """
    account_pq_keys = state.find_account(public_key)

    if not verify_nonce(request.nonce):
        raise HTTPException(status_code=400, detail="Invalid or expired nonce.")

    if request.nonce in state.used_nonces:
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
    if public_key not in state.graveyard:
        state.graveyard[public_key] = []

    for new_sig in request.new_pq_signatures:
        if new_sig.alg in account_pq_keys:
            old_pk = account_pq_keys[new_sig.alg]
            state.graveyard[public_key].append(
                {
                    "public_key": old_pk,
                    "alg": new_sig.alg,
                    "retired_at": time.time(),
                    "reason": "replaced",
                }
            )
        account_pq_keys[new_sig.alg] = new_sig.public_key

    state.used_nonces.add(request.nonce)

    return {
        "message": f"Successfully added {len(request.new_pq_signatures)} PQ key(s)."
    }


@router.post("/accounts/{public_key}/remove-pq-keys")
def remove_pq_keys(public_key: str, request: RemovePqKeysRequest):
    """
    Removes one or more post-quantum keys from an existing account.
    This action must be authorized by signing the request with the classic key
    and all existing post-quantum keys for the account. The mandatory ML-DSA
    key cannot be removed.

    The message to sign is:
    f"REMOVE-PQ:{classic_pk}:{removed_alg_1}:{removed_alg_2}:...:{nonce}"
    """
    account_pq_keys = state.find_account(public_key)

    if not verify_nonce(request.nonce):
        raise HTTPException(status_code=400, detail="Invalid or expired nonce.")

    if request.nonce in state.used_nonces:
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
    if public_key not in state.graveyard:
        state.graveyard[public_key] = []

    for alg_to_remove in request.algs_to_remove:
        removed_pk = account_pq_keys.pop(alg_to_remove)
        state.graveyard[public_key].append(
            {
                "public_key": removed_pk,
                "alg": alg_to_remove,
                "retired_at": time.time(),
                "reason": "removed",
            }
        )
    state.used_nonces.add(request.nonce)

    return {"message": "Successfully removed PQ key(s)."}


@router.get("/accounts/{public_key}/graveyard")
def get_graveyard(public_key: str):
    """Retrieves the graveyard of retired PQ keys for a given account."""
    state.find_account(public_key)  # Ensure account exists
    return {"public_key": public_key, "graveyard": state.graveyard.get(public_key, [])}
