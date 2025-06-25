from fastapi import APIRouter
from fastapi.responses import Response
import base64

from lib.pq_auth import SUPPORTED_SIG_ALGS
from security import generate_nonce
from app_state import get_app_state
from src.crypto.context_manager import CryptoContextManager

router = APIRouter()


@router.get("/pre-crypto-context")
def get_pre_crypto_context():
    """
    Returns the serialized crypto context for the PRE scheme.
    Clients must use this context for all PRE operations.

    Updated to use the context singleton pattern for consistency.
    """
    # Get the context from the singleton manager
    context_manager = CryptoContextManager()

    # If the singleton doesn't have a context yet, initialize it from app state
    if context_manager.get_context() is None:
        # Initialize from the app state's stored context
        app_state = get_app_state()
        if hasattr(app_state, "pre_cc_serialized") and app_state.pre_cc_serialized:
            # Deserialize the context into the singleton
            serialized_context = base64.b64encode(app_state.pre_cc_serialized).decode(
                "ascii"
            )
            context_manager.deserialize_context(serialized_context)
        else:
            # Initialize a new context if none exists
            context_manager.initialize_context()

    # Get the serialized context from the singleton
    serialized_context = context_manager.serialize_context()

    # Convert back to bytes for the response
    cc_bytes = base64.b64decode(serialized_context.encode("ascii"))

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
