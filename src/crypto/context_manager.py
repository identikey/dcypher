"""
Crypto Context Manager - Manages OpenFHE contexts for cryptographic operations.
"""

import threading
import base64
import os
from typing import Optional, Any, Dict

# Import guards for OpenFHE availability
_pre_module = None
_pre_module_available = False
try:
    from ..lib import pre

    _pre_module = pre
    _pre_module_available = True
except ImportError:
    # Fallback for when running from CLI or different contexts
    try:
        import sys
        import os

        # Add the parent directory to the path to find lib module
        parent_dir = os.path.dirname(os.path.dirname(__file__))
        if parent_dir not in sys.path:
            sys.path.insert(0, parent_dir)
        from lib import pre

        _pre_module = pre
        _pre_module_available = True
    except ImportError:
        _pre_module_available = False

_fhe_module = None
_openfhe_available = False
try:
    import openfhe as fhe  # type: ignore

    _fhe_module = fhe
    _openfhe_available = True
except ImportError:
    _openfhe_available = False

# Backward compatibility exports
OPENFHE_AVAILABLE = _openfhe_available
PRE_MODULE_AVAILABLE = _pre_module_available


class CryptoContextManager:
    """Manages OpenFHE crypto contexts using a context manager pattern.

    This class provides a thread-safe way to initialize, serialize, and
    manage OpenFHE crypto contexts. It is designed to be used within a
    `with` statement to ensure proper cleanup of cryptographic resources.

    Example:
        with CryptoContextManager(scheme="BFV") as manager:
            context = manager.get_context()
            # ... use context for cryptographic operations
    """

    def __init__(
        self,
        scheme: str = "BFV",
        plaintext_modulus: int = 65537,
        multiplicative_depth: int = 2,
        scaling_mod_size: int = 50,
        batch_size: int = 8,
        serialized_data: Optional[str] = None,
        deserialize_safe: bool = False,
    ) -> None:
        """Initialize the crypto context manager.

        The context can be initialized either by providing cryptographic
        parameters or by deserializing an existing context from a string.

        Args:
            scheme (str): The FHE scheme to use (e.g., "BFV").
            plaintext_modulus (int): The plaintext modulus.
            multiplicative_depth (int): The multiplicative depth for the scheme.
            scaling_mod_size (int): The scaling modulus size.
            batch_size (int): The batch size for vector operations.
            serialized_data (Optional[str]): A base64-encoded string of a
                                             serialized context. If provided,
                                             other parameters are ignored.
            deserialize_safe (bool): If true, use process-safe deserialization.
        """
        self._context_lock = threading.RLock()
        self._serialization_lock = threading.RLock()
        self._initialization_lock = threading.RLock()

        self._context: Optional[Any] = None
        self._serialized_context: Optional[str] = None
        self._context_params: Optional[Dict[str, Any]] = None
        self._initialized: bool = False

        if serialized_data:
            if deserialize_safe:
                self.deserialize_context_safe(serialized_data)
            else:
                self.deserialize_context(serialized_data)
        else:
            self.initialize_context(
                scheme=scheme,
                plaintext_modulus=plaintext_modulus,
                multiplicative_depth=multiplicative_depth,
                scaling_mod_size=scaling_mod_size,
                batch_size=batch_size,
            )

    def __enter__(self) -> "CryptoContextManager":
        """Enter the context manager.

        Returns:
            The instance of the context manager.
        """
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """Exit the context manager and clean up resources."""
        with self._initialization_lock, self._context_lock, self._serialization_lock:
            self._context = None
            self._serialized_context = None
            self._context_params = None
            self._initialized = False

    def get_context(self) -> Optional[Any]:
        """Get the current crypto context with thread safety."""
        with self._context_lock:
            return self._context

    def get_context_params(self) -> Optional[Dict[str, Any]]:
        """Get the current context parameters with thread safety."""
        with self._context_lock:
            return self._context_params.copy() if self._context_params else None

    def set_context_params(self, params: Dict[str, Any]) -> None:
        """Set context parameters - backward compatibility for tests only.

        Note: This should only be used in tests. In production, parameters
        are set during initialization or deserialization.
        """
        with self._context_lock:
            with self._initialization_lock:
                if self._initialized:
                    raise RuntimeError(
                        "Cannot modify context parameters after initialization"
                    )
                self._context_params = params.copy() if params else None

    def is_initialized(self) -> bool:
        """Check if the context is initialized."""
        with self._initialization_lock:
            return self._initialized

    def deserialize_context(self, serialized_data: str) -> Any:
        """Deserialize context from string with maximum thread safety."""
        if not _openfhe_available:
            raise RuntimeError("OpenFHE library is not available")

        if not _pre_module_available or _pre_module is None:
            raise RuntimeError("PRE module is not available")

        # Use locks for thread safety
        with self._serialization_lock:
            with self._context_lock:
                with self._initialization_lock:
                    if self._initialized:
                        raise RuntimeError("Context is already initialized.")

                    # Deserialize with maximum safety
                    try:
                        context_bytes = base64.b64decode(
                            serialized_data.encode("ascii")
                        )
                        if os.environ.get("PYTEST_XDIST_WORKER") or os.environ.get(
                            "PARALLEL_EXECUTION"
                        ):
                            self._context = _pre_module.deserialize_cc_safe(
                                context_bytes
                            )
                        else:
                            self._context = _pre_module.deserialize_cc(context_bytes)

                        self._serialized_context = serialized_data
                        self._initialized = True

                        return self._context
                    except Exception as e:
                        # Reset state on failure
                        self._context = None
                        self._serialized_context = None
                        self._initialized = False
                        raise RuntimeError(f"Failed to deserialize context: {e}")

    def deserialize_context_safe(self, serialized_data: str) -> Any:
        """Process-safe deserialization with maximum thread safety."""
        if not _openfhe_available:
            raise RuntimeError("OpenFHE library is not available")

        if not _pre_module_available or _pre_module is None:
            raise RuntimeError("PRE module is not available")

        # Use locks for thread safety
        with self._serialization_lock:
            with self._context_lock:
                with self._initialization_lock:
                    if self._initialized:
                        raise RuntimeError("Context is already initialized.")

                    # Use safe deserialization with maximum safety
                    try:
                        context_bytes = base64.b64decode(
                            serialized_data.encode("ascii")
                        )
                        self._context = _pre_module.deserialize_cc_safe(context_bytes)
                        self._serialized_context = serialized_data
                        self._initialized = True

                        return self._context
                    except Exception as e:
                        # Reset state on failure
                        self._context = None
                        self._serialized_context = None
                        self._initialized = False
                        raise RuntimeError(f"Failed to safely deserialize context: {e}")

    def serialize_context(self) -> str:
        """Serialize the current context with maximum thread safety."""
        if not _openfhe_available:
            raise RuntimeError("OpenFHE library is not available")

        if not _pre_module_available or _pre_module is None:
            raise RuntimeError("PRE module is not available")

        with self._serialization_lock:
            with self._context_lock:
                if self._context is None:
                    raise RuntimeError("Context not initialized")

                if self._serialized_context is not None:
                    return self._serialized_context

                try:
                    # Serialize with maximum safety
                    context_bytes = _pre_module.serialize_to_bytes(self._context)
                    self._serialized_context = base64.b64encode(context_bytes).decode(
                        "ascii"
                    )
                    return self._serialized_context
                except Exception as e:
                    raise RuntimeError(f"Failed to serialize context: {e}")

    def initialize_context(
        self,
        scheme: str = "BFV",
        plaintext_modulus: int = 65537,
        multiplicative_depth: int = 2,
        scaling_mod_size: int = 50,
        batch_size: int = 8,
    ) -> Any:
        """Initialize the crypto context with maximum thread safety."""
        if not _openfhe_available or _fhe_module is None:
            raise RuntimeError(
                "OpenFHE library is not available. Please install openfhe-python."
            )

        # Use locks for thread safety
        with self._initialization_lock:
            with self._context_lock:
                with self._serialization_lock:
                    if self._initialized:
                        raise RuntimeError("Context is already initialized.")

                    try:
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
                            parameters = _fhe_module.CCParamsBFVRNS()
                            parameters.SetPlaintextModulus(plaintext_modulus)
                            parameters.SetMultiplicativeDepth(multiplicative_depth)
                            parameters.SetScalingModSize(scaling_mod_size)
                            parameters.SetBatchSize(batch_size)

                            self._context = _fhe_module.GenCryptoContext(parameters)
                        else:
                            raise ValueError(f"Unsupported scheme: {scheme}")

                        # Enable required features
                        if self._context is not None:
                            self._context.Enable(_fhe_module.PKE)
                            self._context.Enable(_fhe_module.KEYSWITCH)
                            self._context.Enable(_fhe_module.LEVELEDSHE)
                            self._context.Enable(_fhe_module.ADVANCEDSHE)
                            self._context.Enable(_fhe_module.PRE)

                        self._initialized = True
                        return self._context

                    except Exception as e:
                        # Reset state on failure
                        self._context = None
                        self._context_params = None
                        self._initialized = False
                        raise RuntimeError(f"Failed to initialize context: {e}")

    def is_available(self) -> bool:
        """Check if OpenFHE library and PRE module are available."""
        return _openfhe_available and _pre_module_available
