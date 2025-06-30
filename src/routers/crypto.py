"""
Crypto-related API endpoints
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Dict, Any, Optional

from crypto.context_manager import context_manager

router = APIRouter(prefix="/crypto", tags=["crypto"])


class CryptoContextResponse(BaseModel):
    """Response model for crypto context"""

    serialized_context: str
    context_params: Dict[str, Any]


@router.get("/context", response_model=CryptoContextResponse)
async def get_crypto_context():
    """
    Get the server's crypto context for client synchronization.

    This endpoint allows clients to obtain the same crypto context
    that the server is using, ensuring compatibility for all
    cryptographic operations.
    """
    try:
        # Ensure context is initialized
        if context_manager.get_context() is None:
            # Initialize with default parameters
            context_manager.initialize_context()

        # Get serialized context and parameters
        serialized_context = context_manager.serialize_context()
        context_params = context_manager.get_context_params()

        return CryptoContextResponse(
            serialized_context=serialized_context, context_params=context_params or {}
        )

    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Failed to get crypto context: {str(e)}"
        )


@router.post("/initialize-context")
async def initialize_crypto_context(
    scheme: str = "BFV",
    plaintext_modulus: int = 65537,
    multiplicative_depth: int = 2,
    scaling_mod_size: int = 50,
    batch_size: int = 8,
):
    """
    Initialize the server's crypto context with custom parameters.

    This is typically called once during server startup or configuration.
    Once initialized, all clients should use the same context via /context endpoint.
    """
    try:
        # Check if context is already initialized with compatible parameters
        existing_context = context_manager.get_context()
        existing_params = context_manager.get_context_params()

        requested_params = {
            "scheme": scheme,
            "plaintext_modulus": plaintext_modulus,
            "multiplicative_depth": multiplicative_depth,
            "scaling_mod_size": scaling_mod_size,
            "batch_size": batch_size,
        }

        if existing_context is not None and existing_params == requested_params:
            # Context already exists with the same parameters, no need to reset
            return {
                "message": "Crypto context already initialized with these parameters",
                "params": existing_params,
            }

        # Only reset if we need different parameters or no context exists
        if existing_context is not None:
            # Reset context if already initialized with different parameters
            context_manager.reset()

        # Initialize with new parameters
        context_manager.initialize_context(
            scheme=scheme,
            plaintext_modulus=plaintext_modulus,
            multiplicative_depth=multiplicative_depth,
            scaling_mod_size=scaling_mod_size,
            batch_size=batch_size,
        )

        return {
            "message": "Crypto context initialized successfully",
            "params": context_manager.get_context_params(),
        }

    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Failed to initialize crypto context: {str(e)}"
        )
