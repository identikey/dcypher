"""
Crypto-related API endpoints
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Dict, Any, Optional

from ..crypto.context_manager import CryptoContextManager

router = APIRouter(prefix="/crypto", tags=["crypto"])


class CryptoContextResponse(BaseModel):
    """Response model for crypto context"""

    serialized_context: str
    context_params: Dict[str, Any]


@router.get("/context", response_model=CryptoContextResponse)
async def get_crypto_context():
    """
    Get a new, default crypto context for client use.

    This endpoint generates a new crypto context with default parameters
    and returns its serialized representation. Clients can use this to
    synchronize with a valid context for cryptographic operations.
    """
    try:
        # Create a new context manager with default parameters
        with CryptoContextManager() as manager:
            # Get serialized context and parameters
            serialized_context = manager.serialize_context()
            context_params = manager.get_context_params()

            return CryptoContextResponse(
                serialized_context=serialized_context,
                context_params=context_params or {},
            )

    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Failed to get crypto context: {str(e)}"
        )
