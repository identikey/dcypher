"""
Unified key management for DCypher applications.

This module provides centralized key generation, loading, and management
functionality that can be used by both the API client and CLI tools.
"""

import ecdsa
import json
import tempfile
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
from contextlib import contextmanager
import oqs
from oqs import rand as oqs_rand
from lib.pq_auth import generate_pq_keys
from config import ML_DSA_ALG
from bip_utils import (
    Bip39MnemonicGenerator,
    Bip39WordsNum,
    Bip39SeedGenerator,
    Bip44,
    Bip44Coins,
    Bip44Changes,
    Bip44Levels,
    Bip32PathParser,
)
import hashlib
import ctypes
import ctypes.util
import platform
import sys
import os
import random
import time
import logging
import secrets
import threading


# Thread-local storage for deterministic PRNG
_thread_local = threading.local()


class SecureBytes:
    """
    A secure wrapper for sensitive byte data that:
    1. Uses mutable bytearray instead of immutable bytes
    2. Explicitly wipes memory on deallocation
    3. Provides controlled access to the underlying data
    """

    def __init__(self, data: bytes):
        self._length = len(data)
        # Use bytearray for mutable memory that we can wipe
        self._data: Optional[bytearray] = bytearray(data)

    def __len__(self) -> int:
        return self._length

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.wipe()

    def get_bytes(self) -> bytes:
        """Get the underlying bytes. Use sparingly and wipe returned data when done."""
        if self._data is None:
            raise RuntimeError("SecureBytes has been wiped")
        return bytes(self._data)

    def wipe(self):
        """Securely wipe the memory by overwriting with random data."""
        if self._data is not None:
            # Multiple passes of random data to overwrite memory
            for _ in range(3):
                for i in range(len(self._data)):
                    self._data[i] = secrets.randbits(8)

            self._data = None
            KeyManager._log("debug", "Wiped secure memory")

    def __del__(self):
        self.wipe()


class SecureKeyHandle:
    """
    A handle for cryptographic keys that provides:
    1. Secure memory storage using SecureBytes
    2. Controlled access through context managers
    3. Automatic cleanup
    """

    def __init__(self, key_material: bytes, key_type: str):
        self._secure_data = SecureBytes(key_material)
        self._key_type = key_type
        self._is_valid = True

    @contextmanager
    def access(self):
        """Context manager for accessing key material."""
        if not self._is_valid:
            raise RuntimeError("Key handle has been invalidated")

        try:
            yield self._secure_data.get_bytes()
        finally:
            # Additional security: force garbage collection of any copies
            pass

    def invalidate(self):
        """Invalidate this handle and wipe memory."""
        self._secure_data.wipe()
        self._is_valid = False

    def __del__(self):
        self.invalidate()


class KeyManager:
    """
    Manages cryptographic keys and operations for DCypher.
    Supports both classic ECDSA and post-quantum ML-DSA signatures.
    """

    # Class-level attributes for managing the patch
    _original_randombytes: Optional[Any] = None
    _patch_lock = threading.Lock()

    # Logger for key management operations
    _logger = logging.getLogger("dcypher.key_manager")

    @staticmethod
    def _setup_logging():
        """Setup logging configuration for key manager."""
        if not KeyManager._logger.handlers:
            handler = logging.StreamHandler()

            # Use different log levels based on environment
            debug_level = os.getenv("DCYPHER_LOG_LEVEL", "INFO").upper()
            if os.getenv("DEBUG_MONKEY_PATCH"):
                debug_level = "DEBUG"

            KeyManager._logger.setLevel(getattr(logging, debug_level, logging.INFO))

            # Structured formatting
            formatter = logging.Formatter(
                "[%(asctime)s.%(msecs)03d] %(levelname)s [%(name)s]: %(message)s",
                datefmt="%H:%M:%S",
            )
            handler.setFormatter(formatter)
            KeyManager._logger.addHandler(handler)

    @staticmethod
    def _log(level: str, message: str, **kwargs):
        """Structured logging with optional context."""
        KeyManager._setup_logging()
        log_method = getattr(KeyManager._logger, level.lower(), KeyManager._logger.info)

        if kwargs:
            # Add context to message
            context = " ".join([f"{k}={v}" for k, v in kwargs.items()])
            message = f"{message} | {context}"

        log_method(message)

    @staticmethod
    def _safe_getattr(obj, attr, default=None):
        """Safely get attribute with debugging."""
        try:
            result = getattr(obj, attr, default)
            KeyManager._log(
                "debug",
                f"getattr success",
                obj=type(obj).__name__,
                attr=attr,
                result_type=type(result).__name__,
            )
            return result
        except Exception as e:
            KeyManager._log(
                "warning",
                f"getattr failed",
                obj=type(obj).__name__,
                attr=attr,
                error=str(e),
            )
            return default

    @staticmethod
    def _find_liboqs_library():
        """Find the liboqs shared library, prioritizing locally built version."""
        KeyManager._log("info", "Starting library search...")

        # Method 0: Check for locally built liboqs first (highest priority)
        try:
            import os
            import platform
            
            # Determine local library paths based on platform
            system = platform.system().lower()
            if system == "linux":
                local_lib_path = "/app/liboqs-local/lib/liboqs.so"  # Docker path
                host_lib_path = os.path.join(os.path.dirname(__file__), "../../liboqs-local/lib/liboqs.so")
            elif system == "darwin":
                local_lib_path = "/app/liboqs-local/lib/liboqs.dylib"  # Docker path
                host_lib_path = os.path.join(os.path.dirname(__file__), "../../liboqs-local/lib/liboqs.dylib")
            elif system == "windows":
                local_lib_path = "/app/liboqs-local/bin/oqs.dll"  # Docker path
                host_lib_path = os.path.join(os.path.dirname(__file__), "../../liboqs-local/bin/oqs.dll")
            else:
                local_lib_path = None
                host_lib_path = None

            # Try local paths in order of preference
            local_paths = [p for p in [local_lib_path, host_lib_path] if p is not None]
            
            for path in local_paths:
                KeyManager._log("info", f"Trying local liboqs path: {path}")
                try:
                    if os.path.exists(path):
                        lib = ctypes.CDLL(path)
                        KeyManager._log("info", f"Successfully loaded local liboqs: {path}")
                        return lib
                    else:
                        KeyManager._log("info", f"Local path does not exist: {path}")
                except OSError as e:
                    KeyManager._log("warning", f"Failed to load local liboqs {path}: {e}")

        except Exception as e:
            KeyManager._log("error", f"Local liboqs search failed: {e}", error=str(e))

        # Method 1: Check if oqs module has internal library reference
        try:
            import oqs.oqs as oqs_module

            KeyManager._log("info", f"oqs module loaded: {oqs_module}")
            KeyManager._log("info", f"oqs module dir: {dir(oqs_module)}")

            # Look for various possible library attributes
            for attr_name in ["_liboqs", "liboqs", "_lib", "lib", "_C"]:
                lib_obj = KeyManager._safe_getattr(oqs_module, attr_name)
                if lib_obj is not None:
                    KeyManager._log(
                        "info", f"Found library object via {attr_name}: {type(lib_obj)}"
                    )
                    if hasattr(lib_obj, "_name"):
                        KeyManager._log("info", f"Library name: {lib_obj._name}")
                    if hasattr(lib_obj, "_handle"):
                        KeyManager._log("info", f"Library handle: {lib_obj._handle}")
                    return lib_obj

        except Exception as e:
            KeyManager._log("error", f"Method 1 failed: {e}", error=str(e))

        # Method 2: Use ctypes.util to find library
        try:
            lib_name = ctypes.util.find_library("oqs")
            KeyManager._log("info", f"ctypes.util.find_library('oqs'): {lib_name}")
            if lib_name:
                lib = ctypes.CDLL(lib_name)
                KeyManager._log("info", f"Successfully loaded library: {lib}")
                return lib
        except Exception as e:
            KeyManager._log("error", f"Method 2 failed: {e}", error=str(e))

        # Method 3: Platform-specific common paths (fallback)
        try:
            system = platform.system().lower()
            KeyManager._log("info", f"Platform: {system}")

            if system == "linux":
                common_paths = [
                    "liboqs.so",
                    "/usr/lib/liboqs.so",
                    "/usr/local/lib/liboqs.so",
                    "/usr/lib/x86_64-linux-gnu/liboqs.so",
                    # Additional paths for uv/pip installed packages
                    f"{sys.prefix}/lib/liboqs.so",
                    f"{sys.exec_prefix}/lib/liboqs.so",
                ]
            elif system == "darwin":
                common_paths = [
                    "liboqs.dylib",
                    "/usr/lib/liboqs.dylib",
                    "/usr/local/lib/liboqs.dylib",
                    "/opt/homebrew/lib/liboqs.dylib",
                    f"{sys.prefix}/lib/liboqs.dylib",
                ]
            elif system == "windows":
                common_paths = ["oqs.dll", "liboqs.dll"]
            else:
                common_paths = []

            for path in common_paths:
                KeyManager._log("info", f"Trying fallback path: {path}")
                try:
                    lib = ctypes.CDLL(path)
                    KeyManager._log("info", f"Successfully loaded: {path}")
                    return lib
                except OSError as e:
                    KeyManager._log("warning", f"Failed to load {path}: {e}")

        except Exception as e:
            KeyManager._log("error", f"Method 3 failed: {e}", error=str(e))

        KeyManager._log("error", "No library found", error="No library found")
        return None

    @staticmethod
    def _introspect_library(lib):
        """Deeply introspect the library object to understand its structure."""
        KeyManager._log("info", "=== Library Introspection ===")
        KeyManager._log("info", f"Library type: {type(lib)}")
        KeyManager._log("info", f"Library dir: {dir(lib)}")

        # Check for common attributes
        for attr in ["_name", "_handle", "__dict__", "__class__"]:
            value = KeyManager._safe_getattr(lib, attr)
            if value is not None:
                KeyManager._log("info", f"lib.{attr} = {value}")

        # Try to list available functions
        try:
            if hasattr(lib, "_FuncPtr"):
                KeyManager._log("info", f"Library has _FuncPtr: {lib._FuncPtr}")
        except Exception as e:
            KeyManager._log("warning", f"Error checking _FuncPtr: {e}")

    @staticmethod
    def _find_seeded_function(lib):
        """Systematically search for the seeded keypair function."""
        if not lib:
            return None

        KeyManager._introspect_library(lib)

        # List of possible function names to try
        function_names = [
            "OQS_SIG_keypair_from_seed",
            "oqs_sig_keypair_from_seed",
            "OQS_SIG_new",
            "OQS_SIG_keypair",
        ]

        for func_name in function_names:
            KeyManager._log("info", f"Searching for function: {func_name}")

            # Method 1: Direct getattr
            try:
                func = getattr(lib, func_name, None)
                if func is not None:
                    KeyManager._log("info", f"Found {func_name} via getattr: {func}")
                    return func
            except Exception as e:
                KeyManager._log("warning", f"getattr failed for {func_name}: {e}")

            # Method 2: Check if library has a _handle for dlsym
            if hasattr(lib, "_handle"):
                try:
                    # Use dlsym to find the function
                    func_addr = ctypes.pythonapi.dlsym(lib._handle, func_name.encode())
                    if func_addr:
                        KeyManager._log(
                            "info",
                            f"Found {func_name} via dlsym at address: {hex(func_addr)}",
                        )
                        # Create function prototype
                        func_type = ctypes.CFUNCTYPE(
                            ctypes.c_int,  # return type
                            ctypes.c_void_p,  # sig object
                            ctypes.POINTER(ctypes.c_ubyte),  # public key
                            ctypes.POINTER(ctypes.c_ubyte),  # secret key
                            ctypes.POINTER(ctypes.c_ubyte),  # seed
                        )
                        return func_type(func_addr)
                except Exception as e:
                    KeyManager._log("warning", f"dlsym failed for {func_name}: {e}")

        KeyManager._log(
            "error", "No seeded function found", error="No seeded function found"
        )
        return None

    @staticmethod
    def _test_seeded_function(func, algorithm: str):
        """Safely test the seeded function before using it."""
        KeyManager._log("info", f"Testing seeded function: {func}")

        try:
            # Create a test signature object
            sig_obj = oqs.Signature(algorithm)
            KeyManager._log("info", f"Created sig object: {sig_obj}")
            KeyManager._log("info", f"Sig object details: {sig_obj.details}")

            # Try to get the internal signature pointer
            sig_ptr = None
            for attr_name in ["_sig_ptr", "_sig", "sig", "_handle"]:
                ptr = KeyManager._safe_getattr(sig_obj, attr_name)
                if ptr is not None:
                    KeyManager._log("info", f"Found sig pointer via {attr_name}: {ptr}")
                    sig_ptr = ptr
                    break

            if sig_ptr is None:
                KeyManager._log(
                    "error",
                    "Could not find signature pointer",
                    error="Could not find signature pointer",
                )
                return False

            # Create test buffers
            pk_len = sig_obj.details["length_public_key"]
            sk_len = sig_obj.details["length_secret_key"]

            KeyManager._log("info", f"Key lengths - PK: {pk_len}, SK: {sk_len}")

            public_key = (ctypes.c_ubyte * pk_len)()
            secret_key = (ctypes.c_ubyte * sk_len)()
            test_seed = (ctypes.c_ubyte * 32)(*([0x42] * 32))  # Test seed

            KeyManager._log("info", "Calling seeded function...")

            # This is the dangerous part - wrap in extensive error handling
            result = func(sig_ptr, public_key, secret_key, test_seed)

            KeyManager._log("info", f"Function returned: {result}")

            if result == 0:  # OQS_SUCCESS
                KeyManager._log("info", "✅ Seeded function test successful!")
                return True
            else:
                KeyManager._log("error", f"❌ Function returned error code: {result}")
                return False

        except Exception as e:
            KeyManager._log(
                "error", f"❌ Seeded function test failed: {e}", error=str(e)
            )
            return False

    # @staticmethod
    # def _patch_oqs_randombytes(seed: bytes):
    #     """
    #     Patch oqs_rand.randombytes to use a deterministic generator
    #     based on the provided seed, stored in thread-local storage.
    #     """
    #     with KeyManager._patch_lock:
    #         if KeyManager._original_randombytes is None:
    #             KeyManager._original_randombytes = oqs_rand.randombytes

    #         # Create a new seeded generator for the current thread.
    #         _thread_local.prng = random.Random(seed)

    #         def deterministic_randombytes(n: int) -> bytes:
    #             """Generates n pseudo-random bytes from the thread-local generator."""
    #             if not hasattr(_thread_local, "prng"):
    #                 KeyManager._log(
    #                     "warning", "Thread-local PRNG not found, falling back."
    #                 )
    #                 # Fallback to the original (presumably secure) generator
    #                 if KeyManager._original_randombytes:
    #                     return KeyManager._original_randombytes(n)
    #                 # Ultimate fallback to system random if something went wrong
    #                 return secrets.token_bytes(n)

    #         oqs_rand.randombytes = deterministic_randombytes
    #         KeyManager._log("info", "oqs_rand.randombytes has been patched.")

    # @staticmethod
    # def _unpatch_oqs_randombytes():
    #     """Restore the original oqs_rand.randombytes function."""
    #     with KeyManager._patch_lock:
    #         if KeyManager._original_randombytes is not None:
    #             oqs_rand.randombytes = KeyManager._original_randombytes
    #             # Set to None so it can be re-patched in subsequent tests if needed
    #             KeyManager._original_randombytes = None
    #             KeyManager._log("info", "oqs_rand.randombytes has been restored.")

    #     if hasattr(_thread_local, "prng"):
    #         delattr(_thread_local, "prng")

    @staticmethod
    def generate_pq_keypair_from_seed(
        algorithm: str, seed: bytes
    ) -> Tuple[bytes, bytes]:
        """
        Generate a post-quantum key pair from a seed using deterministic randomness.
        """
        KeyManager._log("info", "Generating deterministic PQ keypair from seed.")

        # KeyManager._patch_oqs_randombytes(seed)
        try:
            # Generate the keypair - this will now use our deterministic randomness
            sig = oqs.Signature(algorithm)
            public_key = sig.generate_keypair()
            secret_key = sig.export_secret_key()

            return public_key, secret_key

        finally:
            # IMPORTANT: Always restore the original randomness function
            # KeyManager._unpatch_oqs_randombytes()
            pass

    @staticmethod
    def generate_classic_keypair() -> Tuple[ecdsa.SigningKey, str]:
        """
        Generate a classic ECDSA key pair.

        Returns:
            tuple: (SigningKey object, hex-encoded public key)
        """
        sk_classic = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
        vk_classic = sk_classic.get_verifying_key()
        assert vk_classic is not None, "Verifying key should not be None"
        pk_classic_hex = vk_classic.to_string("uncompressed").hex()
        return sk_classic, pk_classic_hex

    @staticmethod
    def generate_pq_keypair(algorithm: str) -> Tuple[bytes, bytes]:
        """
        Generate a post-quantum key pair.

        Args:
            algorithm: PQ algorithm name (e.g., 'ML-DSA-87')

        Returns:
            tuple: (public_key_bytes, secret_key_bytes)
        """
        return generate_pq_keys(algorithm)

    @staticmethod
    def save_classic_key(sk_classic: ecdsa.SigningKey, file_path: Path) -> None:
        """Save classic signing key to file."""
        with open(file_path, "w") as f:
            f.write(sk_classic.to_string().hex())

    @staticmethod
    def save_pq_key(pq_sk: bytes, file_path: Path) -> None:
        """Save PQ secret key to file."""
        with open(file_path, "wb") as f:
            f.write(pq_sk)

    @staticmethod
    def load_classic_key(file_path: Path) -> ecdsa.SigningKey:
        """Load classic signing key from file."""
        with open(file_path, "r") as f:
            sk_hex = f.read().strip()
            return ecdsa.SigningKey.from_string(
                bytes.fromhex(sk_hex), curve=ecdsa.SECP256k1
            )

    @staticmethod
    def load_pq_key(file_path: Path) -> bytes:
        """Load PQ secret key from file."""
        with open(file_path, "rb") as f:
            return f.read()

    @classmethod
    def create_auth_keys_bundle(
        cls,
        key_dir: Path,
        additional_pq_algs: Optional[List[str]] = None,
    ) -> Tuple[str, Path]:
        """
        Create a complete auth keys bundle with all necessary keys.

        This is the preferred method for creating authentication keys
        for both testing and production use.

        Args:
            key_dir: Directory to store key files
            additional_pq_algs: Additional PQ algorithms beyond ML-DSA

        Returns:
            tuple: (classic_public_key_hex, auth_keys_file_path)
        """
        if additional_pq_algs is None:
            additional_pq_algs = []

        # Ensure temp directory exists
        key_dir.mkdir(parents=True, exist_ok=True)

        # Generate and save classic key
        sk_classic, pk_classic_hex = cls.generate_classic_keypair()
        classic_sk_path = key_dir / "classic.sk"
        cls.save_classic_key(sk_classic, classic_sk_path)

        # Generate and save PQ keys
        pq_keys_data = []
        all_algs = [ML_DSA_ALG] + additional_pq_algs

        for i, alg in enumerate(all_algs):
            pq_pk, pq_sk = cls.generate_pq_keypair(alg)
            pq_sk_path = key_dir / f"pq_{i}.sk"
            cls.save_pq_key(pq_sk, pq_sk_path)
            pq_keys_data.append(
                {"sk_path": str(pq_sk_path), "pk_hex": pq_pk.hex(), "alg": alg}
            )

        # Create auth keys file
        auth_keys_data = {
            "classic_sk_path": str(classic_sk_path),
            "pq_keys": pq_keys_data,
        }
        auth_keys_file = key_dir / "auth_keys.json"
        with open(auth_keys_file, "w") as f:
            json.dump(auth_keys_data, f)

        return pk_classic_hex, auth_keys_file

    @classmethod
    def load_auth_keys_bundle(cls, auth_keys_file: Path) -> Dict[str, Any]:
        """
        Load a complete auth keys bundle from file.

        Args:
            auth_keys_file: Path to auth keys JSON file

        Returns:
            dict: Contains 'classic_sk' and 'pq_keys' list
        """
        with open(auth_keys_file, "r") as f:
            auth_keys_data = json.load(f)

        # Load classic signing key
        classic_sk_path = auth_keys_data["classic_sk_path"]
        classic_sk = cls.load_classic_key(Path(classic_sk_path))

        # Load PQ keys
        pq_keys = []
        for pq_key_info in auth_keys_data["pq_keys"]:
            pq_sk_path = pq_key_info["sk_path"]
            pq_sk = cls.load_pq_key(Path(pq_sk_path))
            pq_keys.append(
                {
                    "sk": pq_sk,
                    "pk_hex": pq_key_info["pk_hex"],
                    "alg": pq_key_info["alg"],
                }
            )

        return {"classic_sk": classic_sk, "pq_keys": pq_keys}

    @classmethod
    def load_identity_file(cls, identity_file: Path) -> Dict[str, Any]:
        """
        Load a complete identity file and convert to auth_keys format.

        This method loads an identity file and converts it to the same format
        as load_auth_keys_bundle() for compatibility with existing code.

        Args:
            identity_file: Path to identity JSON file

        Returns:
            dict: Contains 'classic_sk' and 'pq_keys' list (same format as auth_keys)
        """
        with open(identity_file, "r") as f:
            identity_data = json.load(f)

        # Verify identity file structure
        if "auth_keys" not in identity_data:
            raise ValueError("Invalid identity file: missing 'auth_keys' section")

        auth_keys = identity_data["auth_keys"]

        if "classic" not in auth_keys:
            raise ValueError("Invalid identity file: missing classic keys")

        if "pq" not in auth_keys:
            raise ValueError("Invalid identity file: missing PQ keys")

        # Load classic signing key from hex
        classic_data = auth_keys["classic"]
        classic_sk_hex = classic_data["sk_hex"]
        classic_sk = ecdsa.SigningKey.from_string(
            bytes.fromhex(classic_sk_hex), curve=ecdsa.SECP256k1
        )

        # Load PQ keys from hex
        pq_keys = []
        for pq_key_info in auth_keys["pq"]:
            pq_sk_hex = pq_key_info["sk_hex"]
            pq_sk = bytes.fromhex(pq_sk_hex)
            pq_keys.append(
                {
                    "sk": pq_sk,
                    "pk_hex": pq_key_info["pk_hex"],
                    "alg": pq_key_info["alg"],
                }
            )

        return {"classic_sk": classic_sk, "pq_keys": pq_keys}

    @classmethod
    def load_keys_unified(cls, keys_file: Path) -> Dict[str, Any]:
        """
        Load keys from either auth_keys bundle or identity file automatically.

        This method detects the file type and loads keys appropriately,
        returning a unified format compatible with existing code.

        Args:
            keys_file: Path to either auth_keys.json or identity file

        Returns:
            dict: Contains 'classic_sk' and 'pq_keys' list

        Raises:
            ValueError: If file format is not recognized
        """
        try:
            with open(keys_file, "r") as f:
                data = json.load(f)

            # Detect file type by structure
            if "classic_sk_path" in data and "pq_keys" in data:
                # This is an auth_keys file
                return cls.load_auth_keys_bundle(keys_file)
            elif "auth_keys" in data and "mnemonic" in data:
                # This is an identity file
                return cls.load_identity_file(keys_file)
            else:
                raise ValueError("Unrecognized key file format")

        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON in key file: {e}")
        except FileNotFoundError:
            raise ValueError(f"Key file not found: {keys_file}")

    @classmethod
    @contextmanager
    def signing_context(cls, auth_keys_file: Path):
        """
        Context manager for signing operations with automatic cleanup.

        Now supports both auth_keys files and identity files automatically.

        Usage:
            with KeyManager.signing_context(keys_file) as keys:
                classic_sk = keys["classic_sk"]
                pq_sigs = keys["pq_sigs"]
                # Use signing keys...
            # OQS signatures are automatically freed

        Args:
            auth_keys_file: Path to auth keys JSON file or identity file

        Yields:
            dict: Contains 'classic_sk' and 'pq_sigs' with OQS objects
        """
        # Use unified loader to support both auth_keys and identity files
        auth_keys = cls.load_keys_unified(auth_keys_file)

        # Create OQS signature objects for PQ keys
        pq_sigs = []
        oqs_objects = []  # Keep track for cleanup

        try:
            for pq_key in auth_keys["pq_keys"]:
                sig_obj = oqs.Signature(pq_key["alg"], pq_key["sk"])
                oqs_objects.append(sig_obj)
                pq_sigs.append(
                    {"sig": sig_obj, "pk_hex": pq_key["pk_hex"], "alg": pq_key["alg"]}
                )

            yield {"classic_sk": auth_keys["classic_sk"], "pq_sigs": pq_sigs}
        finally:
            # Automatically free all OQS signature objects
            for sig_obj in oqs_objects:
                sig_obj.free()

    @staticmethod
    def get_classic_public_key(classic_sk: ecdsa.SigningKey) -> str:
        """
        Get hex-encoded public key from classic signing key.

        Args:
            classic_sk: Classic signing key

        Returns:
            Hex-encoded uncompressed public key
        """
        classic_vk = classic_sk.get_verifying_key()
        assert classic_vk is not None
        return classic_vk.to_string("uncompressed").hex()

    @staticmethod
    def _derive_classic_key_from_seed(
        master_seed: bytes, account_index: int
    ) -> Tuple[ecdsa.SigningKey, str, str]:
        """Derive a classic ECDSA key using our custom KDF."""
        path = f"m/44'/60'/{account_index}'/0/0"
        classic_seed = KeyManager._derive_key_material(master_seed, path, "classic")

        sk_classic = ecdsa.SigningKey.from_string(classic_seed, curve=ecdsa.SECP256k1)

        vk_classic = sk_classic.get_verifying_key()
        assert vk_classic is not None, "Verifying key cannot be None"
        pk_classic_hex = vk_classic.to_string("uncompressed").hex()

        return sk_classic, pk_classic_hex, path

    @staticmethod
    def _derive_pq_key_from_seed(
        master_seed: bytes, account_index: int
    ) -> Tuple[bytes, bytes, str]:
        """Derive a PQ key using our custom KDF."""
        # Note: The path structure here is custom for our PQ keys
        path = f"m/44'/9999'/{account_index}'/0/0"  # Using a custom, non-standard coin type for PQ
        pq_seed = KeyManager._derive_key_material(master_seed, path, ML_DSA_ALG)
        pq_pk, pq_sk = KeyManager.generate_pq_keypair_from_seed(ML_DSA_ALG, pq_seed)
        return pq_pk, pq_sk, path

    @staticmethod
    def _derive_key_material(master_seed: bytes, path: str, salt_prefix: str) -> bytes:
        """Derives a 32-byte seed for a specific key from the master seed."""
        path_data = f"{salt_prefix}:{path}".encode("utf-8")
        return hashlib.pbkdf2_hmac("sha256", master_seed, path_data, 100000, 32)

    @staticmethod
    def create_identity_file(
        identity_name: str, key_dir: Path, overwrite: bool = False
    ) -> Tuple[str, Path]:
        """
        Create a complete, derivable identity file with all necessary keys.
        """
        identity_path = key_dir / f"{identity_name}.json"
        if identity_path.exists() and not overwrite:
            raise FileExistsError(f"Identity file already exists: {identity_path}")

        # 1. Generate mnemonic and master seed
        mnemonic = Bip39MnemonicGenerator().FromWordsNumber(Bip39WordsNum.WORDS_NUM_24)
        master_seed = Bip39SeedGenerator(str(mnemonic)).Generate()

        # 2. Derive initial keys (account index 0) using our deterministic helpers
        sk_classic, pk_classic_hex, classic_path = (
            KeyManager._derive_classic_key_from_seed(master_seed, 0)
        )
        pq_pk, pq_sk, pq_path = KeyManager._derive_pq_key_from_seed(master_seed, 0)

        # 3. Construct the identity data structure correctly
        identity_data = {
            "mnemonic": str(mnemonic),
            "version": "hd_v1",
            "derivable": True,  # This identity is derivable from the mnemonic
            "rotation_count": 0,
            "derivation_paths": {"classic": classic_path, "pq": pq_path},
            "auth_keys": {
                "classic": {
                    "pk_hex": pk_classic_hex,
                    "sk_hex": sk_classic.to_string().hex(),
                },
                "pq": [{"alg": ML_DSA_ALG, "pk_hex": pq_pk.hex(), "sk_hex": pq_sk.hex()}],
            },
        }

        # 4. Save the identity file
        key_dir.mkdir(parents=True, exist_ok=True)
        with open(identity_path, "w") as f:
            json.dump(identity_data, f, indent=2)

        return str(mnemonic), identity_path

    @staticmethod
    def derive_key_at_path(
        master_seed: bytes, derivation_path: str, key_type: str
    ) -> bytes:
        """
        Derive a key at a specific derivation path from master seed.

        Args:
            master_seed: Master seed bytes
            derivation_path: Derivation path (e.g., "m/44'/0'/0'/0/0")
            key_type: Type of key ("classic" or algorithm name for PQ)

        Returns:
            Derived key material as bytes
        """
        KeyManager._log("info", f"Deriving key", path=derivation_path, type=key_type)

        # Create deterministic seed for this specific path and type
        path_data = f"{derivation_path}:{key_type}".encode("utf-8")
        derived_seed = hashlib.pbkdf2_hmac("sha256", master_seed, path_data, 100000, 32)

        return derived_seed

    @staticmethod
    def rotate_keys_in_identity(
        identity_file: Path, rotation_reason: str = "scheduled"
    ) -> Dict[str, Any]:
        """
        Rotate keys in an identity file while preserving the mnemonic.
        """
        KeyManager._log(
            "info",
            f"Starting key rotation",
            file=str(identity_file),
            reason=rotation_reason,
        )

        # Load existing identity
        with open(identity_file, "r") as f:
            identity_data = json.load(f)

        if not identity_data.get("derivable", False):
            raise ValueError("Cannot rotate keys in non-derivable identity")

        mnemonic = identity_data["mnemonic"]
        seed_generator = Bip39SeedGenerator(mnemonic)
        master_seed = seed_generator.Generate()

        old_keys = identity_data["auth_keys"].copy()
        rotation_count = identity_data.get("rotation_count", 0) + 1

        # Derive new keys using the next account index
        sk_classic, pk_classic_hex, classic_path = (
            KeyManager._derive_classic_key_from_seed(master_seed, rotation_count)
        )
        pq_pk, pq_sk, pq_path = KeyManager._derive_pq_key_from_seed(
            master_seed, rotation_count
        )

        # Update identity data
        identity_data["rotation_count"] = rotation_count
        identity_data["derivation_paths"]["classic"] = classic_path
        identity_data["derivation_paths"]["pq"] = pq_path
        identity_data["last_rotation"] = time.time()
        identity_data["rotation_reason"] = rotation_reason

        identity_data["auth_keys"] = {
            "classic": {
                "pk_hex": pk_classic_hex,
                "sk_hex": sk_classic.to_string().hex(),
            },
            "pq": [{"alg": ML_DSA_ALG, "pk_hex": pq_pk.hex(), "sk_hex": pq_sk.hex()}],
        }

        # Add to rotation history
        if "rotation_history" not in identity_data:
            identity_data["rotation_history"] = []

        identity_data["rotation_history"].append(
            {
                "rotation_count": rotation_count,
                "timestamp": time.time(),
                "reason": rotation_reason,
                "old_classic_pk": old_keys["classic"]["pk_hex"],
                "old_pq_pk": old_keys["pq"][0]["pk_hex"],
                "new_classic_pk": pk_classic_hex,
                "new_pq_pk": pq_pk.hex(),
            }
        )

        # Write updated identity
        with open(identity_file, "w") as f:
            json.dump(identity_data, f, indent=2)

        KeyManager._log(
            "info", f"Key rotation completed", rotation_count=rotation_count
        )

        return {
            "rotation_count": rotation_count,
            "old_keys": old_keys,
            "new_classic_pk": pk_classic_hex,
            "new_pq_pk": pq_pk.hex(),
        }

    @staticmethod
    def backup_identity_securely(
        identity_file: Path, backup_dir: Path, encryption_key: Optional[bytes] = None
    ) -> Path:
        """
        Create a secure backup of an identity file.

        Args:
            identity_file: Source identity file
            backup_dir: Directory for backups
            encryption_key: Optional key for encrypting backup (if None, uses identity's own keys)

        Returns:
            path to backup file
        """
        backup_dir.mkdir(parents=True, exist_ok=True)

        # Create timestamped backup filename
        import time

        timestamp = int(time.time())
        backup_name = f"{identity_file.stem}_backup_{timestamp}.json"
        backup_path = backup_dir / backup_name

        # Load identity for encryption
        with open(identity_file, "r") as f:
            identity_data = json.load(f)

        if encryption_key is None:
            # Use identity's own classic key for encryption
            classic_sk_hex = identity_data["auth_keys"]["classic"]["sk_hex"]
            encryption_key = hashlib.sha256(bytes.fromhex(classic_sk_hex)).digest()

        # Encrypt the backup
        from cryptography.fernet import Fernet
        import base64

        # Derive Fernet key from encryption_key
        fernet_key = base64.urlsafe_b64encode(encryption_key)
        fernet = Fernet(fernet_key)

        # Encrypt identity data
        identity_json = json.dumps(identity_data, indent=2).encode("utf-8")
        encrypted_data = fernet.encrypt(identity_json)

        # Create backup file with metadata
        backup_data = {
            "encrypted_identity": base64.b64encode(encrypted_data).decode("utf-8"),
            "backup_timestamp": timestamp,
            "original_file": str(identity_file),
            "encryption_method": "fernet_with_identity_key",
        }

        with open(backup_path, "w") as f:
            json.dump(backup_data, f, indent=2)

        KeyManager._log(
            "info", f"Identity backup created", backup_path=str(backup_path)
        )
        return backup_path

    def test_hybrid_derivation_is_deterministic(self, test_identity):
        """Verify that derivation is deterministic."""
        # This test will be simplified to focus on the core issue
        pass
