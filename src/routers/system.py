from fastapi import APIRouter
from fastapi.responses import Response
import base64

from src.lib.pq_auth import SUPPORTED_SIG_ALGS
from ..security import generate_nonce
from ..app_state import get_app_state
from ..crypto.context_manager import CryptoContextManager

router = APIRouter()


@router.get("/pre-crypto-context")
def get_pre_crypto_context():
    """
    Returns the serialized crypto context for the PRE scheme.
    Clients must use this context for all PRE operations.

    Always returns the same context that was created at server startup.

    NOTE: This endpoint is deprecated and should be replaced with /pre-crypto-params
    for proper client-server architecture. Keeping for backward compatibility.
    """
    # Use the same context manager that the crypto router and re-encryption use
    # This ensures complete consistency across all server operations
    context_manager = CryptoContextManager()

    # Ensure context is initialized
    if context_manager.get_context() is None:
        # Initialize with default parameters (same as crypto router)
        context_manager.initialize_context()

    # Return the serialized context from the singleton
    try:
        serialized_context = context_manager.serialize_context()
        # Convert from base64 string to raw bytes for consistency with old API
        context_bytes = base64.b64decode(serialized_context.encode("ascii"))

        return Response(content=context_bytes, media_type="application/octet-stream")
    except Exception as e:
        raise RuntimeError(f"Failed to get server crypto context: {e}")


@router.get("/pre-crypto-params")
def get_pre_crypto_params():
    """
    Returns the crypto context parameters for the PRE scheme.
    Clients should use these parameters to create compatible contexts.

    This is the proper API design - clients create their own contexts
    with the same parameters, rather than sharing context state.
    """
    # Return the standard parameters used by the server
    # These match the parameters used in pre.create_crypto_context()
    return {
        "scheme": "BFV",
        "plaintext_modulus": 65537,
        "multiplicative_depth": 2,
        "scaling_mod_size": 50,
        "batch_size": 8192,
        "security_level": 128,
        "ring_dimension": 16384,
        "description": "Standard DCypher PRE context parameters - create your own context with these parameters for compatibility",
    }


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
