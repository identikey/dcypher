"""
Crypto Context Manager - Global singleton pattern for OpenFHE context management
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
    """Global thread-safe singleton manager for OpenFHE crypto context.

    This class implements a global singleton pattern with maximum thread safety
    for C bindings. All operations are heavily locked to prevent race conditions
    in multi-threaded environments.
    """

    # Global singleton instance
    _instance: Optional["CryptoContextManager"] = None
    # Multiple locks for different operations
    _creation_lock = threading.RLock()  # Reentrant lock for instance creation
    _context_lock = threading.RLock()  # Reentrant lock for context operations
    _serialization_lock = threading.RLock()  # Reentrant lock for serialization
    _initialization_lock = threading.RLock()  # Reentrant lock for initialization

    # Instance variables that will be initialized in __new__
    _context: Optional[Any] = None
    _serialized_context: Optional[str] = None
    _context_params: Optional[Dict[str, Any]] = None
    _initialized: bool = False

    def __new__(cls) -> "CryptoContextManager":
        """Create or return the global singleton instance with maximum thread safety."""
        # Double-checked locking with maximum safety
        if cls._instance is not None:
            return cls._instance

        with cls._creation_lock:
            if cls._instance is not None:
                return cls._instance

            # Create new instance with all locks
            instance = super().__new__(cls)

            # Initialize all instance variables under lock
            with cls._context_lock:
                instance._context = None
                instance._serialized_context = None
                instance._context_params = None
                instance._initialized = False

            cls._instance = instance
            return cls._instance

    def __init__(self) -> None:
        """Initialize instance - called every time but only acts once."""
        # No-op since everything is done in __new__
        pass

    @classmethod
    def get_instance(cls) -> "CryptoContextManager":
        """Get the global singleton instance."""
        if cls._instance is None:
            with cls._creation_lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance

    @classmethod
    def reset_instance(cls) -> None:
        """Reset the global singleton instance. Use with extreme caution."""
        with cls._creation_lock:
            with cls._context_lock:
                with cls._serialization_lock:
                    with cls._initialization_lock:
                        if cls._instance is not None:
                            try:
                                cls._instance._context = None
                                cls._instance._serialized_context = None
                                cls._instance._context_params = None
                                cls._instance._initialized = False
                            except Exception:
                                pass  # Ignore cleanup errors
                        cls._instance = None

    @classmethod
    def reset_all_instances(cls) -> None:
        """Reset all instances - backward compatibility."""
        # cls.reset_instance()
        pass

    def reset(self) -> None:
        """Reset the current instance - backward compatibility."""
        # self.reset_instance()
        pass

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

        # Triple-checked locking for maximum safety
        with self._serialization_lock:
            with self._context_lock:
                with self._initialization_lock:
                    # Check if we already have this exact context
                    if (
                        self._serialized_context == serialized_data
                        and self._context is not None
                        and self._initialized
                    ):
                        return self._context

                    if self._initialized:
                        raise RuntimeError("Cannot modify context after initialization")

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

        # Triple-checked locking for maximum safety
        with self._serialization_lock:
            with self._context_lock:
                with self._initialization_lock:
                    # Check if we already have this exact context
                    if (
                        self._serialized_context == serialized_data
                        and self._context is not None
                        and self._initialized
                    ):
                        return self._context

                    if self._initialized:
                        raise RuntimeError("Cannot modify context after initialization")

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

        # Triple-checked locking for maximum safety
        with self._initialization_lock:
            with self._context_lock:
                with self._serialization_lock:
                    # Check if already initialized
                    if self._context is not None and self._initialized:
                        return self._context

                    if self._initialized:
                        raise RuntimeError("Cannot modify context after initialization")

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


class CryptoClientContextManager(CryptoContextManager):
    """Client-side crypto context manager with separate singleton instance.

    This class provides the same thread-safe functionality as CryptoContextManager
    but maintains a separate singleton instance for client-side operations.
    This prevents conflicts when client and server run in the same process (e.g., tests).
    """

    # Separate singleton instance for client operations
    _client_instance: Optional["CryptoClientContextManager"] = None

    def __new__(cls) -> "CryptoClientContextManager":
        """Create or return the client-side singleton instance."""
        # Double-checked locking with maximum safety for client instance
        if cls._client_instance is not None:
            return cls._client_instance

        with cls._creation_lock:
            if cls._client_instance is not None:
                return cls._client_instance

            # Create new client instance with all locks
            instance = super(CryptoContextManager, cls).__new__(cls)

            # Initialize all instance variables under lock
            with cls._context_lock:
                instance._context = None
                instance._serialized_context = None
                instance._context_params = None
                instance._initialized = False

            cls._client_instance = instance
            return cls._client_instance

    @classmethod
    def get_client_instance(cls) -> "CryptoClientContextManager":
        """Get the client-side singleton instance."""
        if cls._client_instance is None:
            with cls._creation_lock:
                if cls._client_instance is None:
                    cls._client_instance = cls()
        return cls._client_instance

    @classmethod
    def reset_client_instance(cls) -> None:
        """Reset the client-side singleton instance."""
        with cls._creation_lock:
            with cls._context_lock:
                with cls._serialization_lock:
                    with cls._initialization_lock:
                        if cls._client_instance is not None:
                            try:
                                cls._client_instance._context = None
                                cls._client_instance._serialized_context = None
                                cls._client_instance._context_params = None
                                cls._client_instance._initialized = False
                            except Exception:
                                pass  # Ignore cleanup errors
                        cls._client_instance = None


# Global client-side singleton instance - thread-safe access
def get_client_context_manager() -> CryptoClientContextManager:
    """Get the global thread-safe client-side singleton context manager."""
    return CryptoClientContextManager.get_client_instance()


# Global singleton instance - thread-safe access
def get_context_manager() -> CryptoContextManager:
    """Get the global thread-safe singleton context manager."""
    return CryptoContextManager.get_instance()


# Backward compatibility
context_manager = get_context_manager()
