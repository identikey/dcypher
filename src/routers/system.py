from fastapi import APIRouter
from fastapi.responses import Response

from lib.pq_auth import SUPPORTED_SIG_ALGS
from security import generate_nonce
from app_state import get_app_state

router = APIRouter()


@router.get("/pre-crypto-context")
def get_pre_crypto_context():
    """
    Returns the serialized crypto context for the PRE scheme.
    Clients must use this context for all PRE operations.
    """
    cc_bytes = get_app_state().pre_cc_serialized
    return Response(content=cc_bytes, media_type="application/octet-stream")


@router.get("/supported-pq-algs")
def get_supported_pq_algs():
    """Returns a list of supported post-quantum signature algorithms."""
    return {"algorithms": SUPPORTED_SIG_ALGS}


@router.get("/nonce")
def get_nonce():
    """
    Generates a time-based, HMAC-signed nonce for the client to sign.
    Nonces are valid for 5 minutes.
    """
    nonce = generate_nonce()
    return {"nonce": nonce}
