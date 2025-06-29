"""
Crypto Context Manager - Singleton pattern for OpenFHE context management
"""

import threading
import base64
import os
from typing import Optional, Any, Dict

# Import guards for OpenFHE availability
try:
    from lib import pre

    PRE_MODULE_AVAILABLE = True
except ImportError:
    PRE_MODULE_AVAILABLE = False

try:
    import openfhe as fhe  # type: ignore

    OPENFHE_AVAILABLE = True
except ImportError:
    OPENFHE_AVAILABLE = False
    fhe = None  # type: ignore


class CryptoContextManager:
    """Thread-safe singleton manager for OpenFHE crypto context.

    Ensures all crypto operations use the same context instance to avoid
    OpenFHE's 'Key was not generated with the same crypto context' errors.

    This class implements a process-specific singleton pattern to handle
    parallel test execution properly - each process gets its own singleton.
    """

    # Use process ID in the class variable to make it process-specific
    _instances: Dict[int, "CryptoContextManager"] = {}
    _lock = threading.Lock()

    def __init__(self) -> None:
        """Initialize instance variables."""
        # These will be set in __new__ but define them for type checking
        if not hasattr(self, "_context"):
            self._context: Optional[Any] = None
        if not hasattr(self, "_serialized_context"):
            self._serialized_context: Optional[str] = None
        if not hasattr(self, "_context_params"):
            self._context_params: Optional[Dict[str, Any]] = None
        if not hasattr(self, "_instance_lock"):
            self._instance_lock = threading.Lock()

    def __new__(cls) -> "CryptoContextManager":
        """Create or return the singleton instance for the current process."""
        process_id = os.getpid()

        with cls._lock:
            if process_id not in cls._instances:
                instance = super().__new__(cls)
                cls._instances[process_id] = instance
                # Initialize the instance attributes before __init__ is called
                instance._context = None
                instance._serialized_context = None
                instance._context_params = None
                instance._instance_lock = threading.Lock()
                instance._initialized = True
            return cls._instances[process_id]

    @classmethod
    def reset_all_instances(cls) -> None:
        """Reset all process instances. Used for testing."""
        with cls._lock:
            for instance in cls._instances.values():
                try:
                    instance.reset()
                except Exception:
                    pass  # Ignore cleanup errors
            cls._instances.clear()

    def reset(self) -> None:
        """Reset the context manager state."""
        with self._instance_lock:
            self._context = None
            self._serialized_context = None
            self._context_params = None

    def get_context(self) -> Optional[Any]:
        """Get the current crypto context."""
        with self._instance_lock:
            return self._context

    def get_context_params(self) -> Optional[Dict[str, Any]]:
        """Get the current context parameters."""
        with self._instance_lock:
            return self._context_params

    def set_context_params(self, params: Dict[str, Any]) -> None:
        """Set the context parameters."""
        with self._instance_lock:
            self._context_params = params

    def deserialize_context(self, serialized_data: str) -> Any:
        """Deserialize context from string using our pre.py serialization functions"""
        if not OPENFHE_AVAILABLE:
            raise RuntimeError("OpenFHE library is not available")

        if not PRE_MODULE_AVAILABLE:
            raise RuntimeError("PRE module is not available")

        with self._instance_lock:
            # CRITICAL: Check if we already have the same context to avoid unnecessary deserialization
            # OpenFHE's ReleaseAllContexts() in deserialize_cc() can break existing context objects
            if (
                self._serialized_context == serialized_data
                and self._context is not None
            ):
                # We already have this exact context - return it without deserializing again
                return self._context

            # Use our pre.py deserialization functions
            context_bytes = base64.b64decode(serialized_data.encode("ascii"))
            self._context = pre.deserialize_cc(context_bytes)
            self._serialized_context = serialized_data

            return self._context

    def serialize_context(self) -> str:
        """Serialize the current context to string using our pre.py serialization functions"""
        if not OPENFHE_AVAILABLE:
            raise RuntimeError("OpenFHE library is not available")

        if not PRE_MODULE_AVAILABLE:
            raise RuntimeError("PRE module is not available")

        with self._instance_lock:
            if self._context is None:
                raise RuntimeError("Context not initialized")

            if self._serialized_context is not None:
                # We already have the serialized version
                return self._serialized_context

            # Serialize using our pre.py functions
            context_bytes = pre.serialize_to_bytes(self._context)
            self._serialized_context = base64.b64encode(context_bytes).decode("ascii")

            return self._serialized_context

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

        with self._instance_lock:
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
                parameters = fhe.CCParamsBFVRNS()
                parameters.SetPlaintextModulus(plaintext_modulus)
                parameters.SetMultiplicativeDepth(multiplicative_depth)
                parameters.SetScalingModSize(scaling_mod_size)
                parameters.SetBatchSize(batch_size)

                self._context = fhe.GenCryptoContext(parameters)
            else:
                raise ValueError(f"Unsupported scheme: {scheme}")

            # Enable required features based on OpenFHE Python API
            self._context.Enable(fhe.PKE)
            self._context.Enable(fhe.KEYSWITCH)
            self._context.Enable(fhe.LEVELEDSHE)
            self._context.Enable(fhe.ADVANCEDSHE)
            self._context.Enable(fhe.PRE)

            return self._context

    def is_available(self) -> bool:
        """Check if OpenFHE library and PRE module are available"""
        return OPENFHE_AVAILABLE and PRE_MODULE_AVAILABLE


# Global instance
context_manager = CryptoContextManager()
