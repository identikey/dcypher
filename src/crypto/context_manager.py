"""
Crypto Context Manager - Singleton pattern for OpenFHE context management
"""

import threading
import base64
from typing import Optional, Dict, Any

# Try to import OpenFHE, but handle gracefully if not available
try:
    import openfhe

    OPENFHE_AVAILABLE = True
except ImportError:
    OPENFHE_AVAILABLE = False
    openfhe = None

# Import our PRE module for serialization functions
try:
    from lib import pre

    PRE_MODULE_AVAILABLE = True
except ImportError:
    PRE_MODULE_AVAILABLE = False
    pre = None


class CryptoContextManager:
    """Singleton manager for OpenFHE crypto context"""

    _instance: Optional["CryptoContextManager"] = None
    _lock = threading.Lock()

    def __new__(cls) -> "CryptoContextManager":
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance

    def __init__(self) -> None:
        if not getattr(self, "_initialized", False):
            self._context: Optional[Any] = None
            self._context_params: Optional[Dict[str, Any]] = None
            self._serialized_context: Optional[str] = None
            self._initialized = True

    def initialize_context(
        self,
        scheme: str = "BFV",
        plaintext_modulus: int = 65537,
        multiplicative_depth: int = 2,
        scaling_mod_size: int = 50,
        batch_size: int = 8,
    ) -> Any:
        """Initialize the crypto context with specified parameters"""
        if not OPENFHE_AVAILABLE:
            raise RuntimeError(
                "OpenFHE library is not available. Please install openfhe-python."
            )

        with self._lock:
            if self._context is not None:
                return self._context

            # Store parameters for later reference
            self._context_params = {
                "scheme": scheme,
                "plaintext_modulus": plaintext_modulus,
                "multiplicative_depth": multiplicative_depth,
                "scaling_mod_size": scaling_mod_size,
                "batch_size": batch_size,
            }

            # Create context based on scheme
            if scheme == "BFV":
                parameters = openfhe.CCParamsBFVRNS()
                parameters.SetPlaintextModulus(plaintext_modulus)
                parameters.SetMultiplicativeDepth(multiplicative_depth)
                parameters.SetScalingModSize(scaling_mod_size)
                parameters.SetBatchSize(batch_size)

                self._context = openfhe.GenCryptoContext(parameters)
            else:
                raise ValueError(f"Unsupported scheme: {scheme}")

            # Enable required features based on OpenFHE Python API
            self._context.Enable(openfhe.PKE)
            self._context.Enable(openfhe.KEYSWITCH)
            self._context.Enable(openfhe.LEVELEDSHE)
            self._context.Enable(openfhe.ADVANCEDSHE)
            self._context.Enable(openfhe.PRE)

            return self._context

    def get_context(self) -> Optional[Any]:
        """Get the current crypto context"""
        return self._context

    def get_context_params(self) -> Optional[Dict[str, Any]]:
        """Get the context parameters"""
        return self._context_params.copy() if self._context_params else None

    def serialize_context(self) -> str:
        """Serialize the context to string using our pre.py serialization functions"""
        if not OPENFHE_AVAILABLE:
            raise RuntimeError("OpenFHE library is not available")

        if not PRE_MODULE_AVAILABLE:
            raise RuntimeError("PRE module is not available")

        with self._lock:
            if self._context is None:
                raise RuntimeError("Context not initialized")

            if self._serialized_context is None:
                # Use our pre.py serialization functions
                context_bytes = pre.serialize_to_bytes(self._context)
                self._serialized_context = base64.b64encode(context_bytes).decode(
                    "ascii"
                )

            return self._serialized_context

    def deserialize_context(self, serialized_data: str) -> Any:
        """Deserialize context from string using our pre.py serialization functions"""
        if not OPENFHE_AVAILABLE:
            raise RuntimeError("OpenFHE library is not available")

        if not PRE_MODULE_AVAILABLE:
            raise RuntimeError("PRE module is not available")

        with self._lock:
            # CRITICAL: Check if we already have the same context to avoid unnecessary deserialization
            # OpenFHE's ReleaseAllContexts() in deserialize_cc() can break existing context objects
            if (
                self._serialized_context == serialized_data
                and self._context is not None
            ):
                # We already have this exact context - return it to maintain object consistency
                return self._context

            # Clear any existing context
            if self._context is not None:
                # Note: In production, we might need to call context factory cleanup
                pass

            # Use our pre.py deserialization functions
            context_bytes = base64.b64decode(serialized_data.encode("ascii"))
            self._context = pre.deserialize_cc(context_bytes)
            self._serialized_context = serialized_data

            return self._context

    def reset(self) -> None:
        """Reset the singleton (mainly for testing)"""
        with self._lock:
            self._context = None
            self._context_params = None
            self._serialized_context = None

    def is_available(self) -> bool:
        """Check if OpenFHE library and PRE module are available"""
        return OPENFHE_AVAILABLE and PRE_MODULE_AVAILABLE


# Global instance
context_manager = CryptoContextManager()
