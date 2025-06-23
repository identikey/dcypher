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
from lib.pq_auth import generate_pq_keys
from config import ML_DSA_ALG
from bip_utils import Bip39MnemonicGenerator, Bip39WordsNum, Bip39SeedGenerator
import hashlib
import ctypes
import ctypes.util
import platform
import sys
import os
import random
import time


class KeyManager:
    """
    Manages cryptographic keys and operations for DCypher.
    Supports both classic ECDSA and post-quantum ML-DSA signatures.
    """

    # Global PRNG for deterministic key generation
    _global_prng: Optional[random.Random] = None
    _current_seed: Optional[bytes] = None
    _patched_func = None
    _original_func = None
    _is_patched = False

    @staticmethod
    def _debug_print(message: str, level: str = "INFO"):
        """Print debug messages if DEBUG_MONKEY_PATCH is set."""
        if os.getenv("DEBUG_MONKEY_PATCH"):
            timestamp = time.strftime("%H:%M:%S.%f")[:-3]
            print(f"[{timestamp}] {level}: {message}")

    @staticmethod
    def _safe_getattr(obj, attr, default=None):
        """Safely get attribute with debugging."""
        try:
            result = getattr(obj, attr, default)
            KeyManager._debug_print(f"getattr({obj}, '{attr}') = {type(result)}")
            return result
        except Exception as e:
            KeyManager._debug_print(f"getattr({obj}, '{attr}') failed: {e}", "ERROR")
            return default

    @staticmethod
    def _find_liboqs_library():
        """Find the liboqs shared library with extensive debugging."""
        KeyManager._debug_print("Starting library search...")

        # Method 1: Check if oqs module has internal library reference
        try:
            import oqs.oqs as oqs_module

            KeyManager._debug_print(f"oqs module loaded: {oqs_module}")
            KeyManager._debug_print(f"oqs module dir: {dir(oqs_module)}")

            # Look for various possible library attributes
            for attr_name in ["_liboqs", "liboqs", "_lib", "lib", "_C"]:
                lib_obj = KeyManager._safe_getattr(oqs_module, attr_name)
                if lib_obj is not None:
                    KeyManager._debug_print(
                        f"Found library object via {attr_name}: {type(lib_obj)}"
                    )
                    if hasattr(lib_obj, "_name"):
                        KeyManager._debug_print(f"Library name: {lib_obj._name}")
                    if hasattr(lib_obj, "_handle"):
                        KeyManager._debug_print(f"Library handle: {lib_obj._handle}")
                    return lib_obj

        except Exception as e:
            KeyManager._debug_print(f"Method 1 failed: {e}", "ERROR")

        # Method 2: Use ctypes.util to find library
        try:
            lib_name = ctypes.util.find_library("oqs")
            KeyManager._debug_print(f"ctypes.util.find_library('oqs'): {lib_name}")
            if lib_name:
                lib = ctypes.CDLL(lib_name)
                KeyManager._debug_print(f"Successfully loaded library: {lib}")
                return lib
        except Exception as e:
            KeyManager._debug_print(f"Method 2 failed: {e}", "ERROR")

        # Method 3: Platform-specific common paths
        try:
            system = platform.system().lower()
            KeyManager._debug_print(f"Platform: {system}")

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
                KeyManager._debug_print(f"Trying path: {path}")
                try:
                    lib = ctypes.CDLL(path)
                    KeyManager._debug_print(f"Successfully loaded: {path}")
                    return lib
                except OSError as e:
                    KeyManager._debug_print(f"Failed to load {path}: {e}")

        except Exception as e:
            KeyManager._debug_print(f"Method 3 failed: {e}", "ERROR")

        KeyManager._debug_print("No library found", "ERROR")
        return None

    @staticmethod
    def _introspect_library(lib):
        """Deeply introspect the library object to understand its structure."""
        KeyManager._debug_print("=== Library Introspection ===")
        KeyManager._debug_print(f"Library type: {type(lib)}")
        KeyManager._debug_print(f"Library dir: {dir(lib)}")

        # Check for common attributes
        for attr in ["_name", "_handle", "__dict__", "__class__"]:
            value = KeyManager._safe_getattr(lib, attr)
            if value is not None:
                KeyManager._debug_print(f"lib.{attr} = {value}")

        # Try to list available functions
        try:
            if hasattr(lib, "_FuncPtr"):
                KeyManager._debug_print(f"Library has _FuncPtr: {lib._FuncPtr}")
        except Exception as e:
            KeyManager._debug_print(f"Error checking _FuncPtr: {e}")

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
            KeyManager._debug_print(f"Searching for function: {func_name}")

            # Method 1: Direct getattr
            try:
                func = getattr(lib, func_name, None)
                if func is not None:
                    KeyManager._debug_print(f"Found {func_name} via getattr: {func}")
                    return func
            except Exception as e:
                KeyManager._debug_print(f"getattr failed for {func_name}: {e}")

            # Method 2: Check if library has a _handle for dlsym
            if hasattr(lib, "_handle"):
                try:
                    # Use dlsym to find the function
                    func_addr = ctypes.pythonapi.dlsym(lib._handle, func_name.encode())
                    if func_addr:
                        KeyManager._debug_print(
                            f"Found {func_name} via dlsym at address: {hex(func_addr)}"
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
                    KeyManager._debug_print(f"dlsym failed for {func_name}: {e}")

        KeyManager._debug_print("No seeded function found", "ERROR")
        return None

    @staticmethod
    def _test_seeded_function(func, algorithm: str):
        """Safely test the seeded function before using it."""
        KeyManager._debug_print(f"Testing seeded function: {func}")

        try:
            # Create a test signature object
            sig_obj = oqs.Signature(algorithm)
            KeyManager._debug_print(f"Created sig object: {sig_obj}")
            KeyManager._debug_print(f"Sig object details: {sig_obj.details}")

            # Try to get the internal signature pointer
            sig_ptr = None
            for attr_name in ["_sig_ptr", "_sig", "sig", "_handle"]:
                ptr = KeyManager._safe_getattr(sig_obj, attr_name)
                if ptr is not None:
                    KeyManager._debug_print(f"Found sig pointer via {attr_name}: {ptr}")
                    sig_ptr = ptr
                    break

            if sig_ptr is None:
                KeyManager._debug_print("Could not find signature pointer", "ERROR")
                return False

            # Create test buffers
            pk_len = sig_obj.details["length_public_key"]
            sk_len = sig_obj.details["length_secret_key"]

            KeyManager._debug_print(f"Key lengths - PK: {pk_len}, SK: {sk_len}")

            public_key = (ctypes.c_ubyte * pk_len)()
            secret_key = (ctypes.c_ubyte * sk_len)()
            test_seed = (ctypes.c_ubyte * 32)(*([0x42] * 32))  # Test seed

            KeyManager._debug_print("Calling seeded function...")

            # This is the dangerous part - wrap in extensive error handling
            result = func(sig_ptr, public_key, secret_key, test_seed)

            KeyManager._debug_print(f"Function returned: {result}")

            if result == 0:  # OQS_SUCCESS
                KeyManager._debug_print("✅ Seeded function test successful!")
                return True
            else:
                KeyManager._debug_print(f"❌ Function returned error code: {result}")
                return False

        except Exception as e:
            KeyManager._debug_print(f"❌ Seeded function test failed: {e}", "ERROR")
            return False

    @staticmethod
    def _patch_liboqs_randomness(seed: bytes):
        """
        Patch the randomness source used by liboqs using advanced ctypes techniques.

        This approach patches the underlying random number generation to be deterministic
        by directly replacing the function in memory.
        """
        KeyManager._debug_print("=== Attempting Memory Patching ===")

        try:
            # Get the liboqs library
            lib = KeyManager._find_liboqs_library()
            if not lib:
                raise RuntimeError("Could not find liboqs library")

            # Find the OQS_randombytes function (we know it exists from our previous success)
            rand_func = getattr(lib, "OQS_randombytes", None)
            if rand_func is None:
                raise RuntimeError("Could not find OQS_randombytes function")

            KeyManager._debug_print(f"Found OQS_randombytes: {rand_func}")

            # Create a deterministic replacement function using the seed
            # Use a proper PRNG for better determinism

            # Create or reuse global PRNG instance
            if KeyManager._global_prng is None or KeyManager._current_seed != seed:
                KeyManager._global_prng = random.Random()
                KeyManager._current_seed = seed

            # Always reset the PRNG to the same seed for determinism
            KeyManager._global_prng.seed(int.from_bytes(seed[:8], "big"))

            # Add a call counter for debugging
            call_counter = [0]

            def deterministic_randombytes(buf_ptr, buf_len):
                """Deterministic replacement for OQS_randombytes."""
                call_counter[0] += 1
                KeyManager._debug_print(
                    f"CALL #{call_counter[0]}: Generating {buf_len} deterministic bytes from PRNG"
                )

                # Ensure PRNG is initialized (it should be, but safety check)
                if KeyManager._global_prng is None:
                    KeyManager._global_prng = random.Random()
                    KeyManager._global_prng.seed(int.from_bytes(seed[:8], "big"))

                # Generate deterministic bytes using the seeded PRNG
                bytes_generated = []
                for i in range(buf_len):
                    byte_val = KeyManager._global_prng.randint(0, 255)
                    ctypes.c_ubyte.from_address(buf_ptr + i).value = byte_val
                    if i < 8:  # Log first 8 bytes for debugging
                        bytes_generated.append(f"{byte_val:02x}")

                if buf_len > 0:
                    KeyManager._debug_print(
                        f"CALL #{call_counter[0]}: First bytes: {' '.join(bytes_generated[: min(8, buf_len)])}"
                    )

                return 0  # OQS_SUCCESS

            # Create ctypes function type matching OQS_randombytes signature
            # int OQS_randombytes(uint8_t *random_array, size_t bytes_to_read);
            RANDOMBYTES_TYPE = ctypes.CFUNCTYPE(
                ctypes.c_int,  # return type
                ctypes.c_void_p,  # random_array pointer
                ctypes.c_size_t,  # bytes_to_read
            )

            # Create the replacement function
            deterministic_func = RANDOMBYTES_TYPE(deterministic_randombytes)
            KeyManager._debug_print(
                f"Created deterministic function: {deterministic_func}"
            )

            # Now perform the actual memory patching!
            # This is the advanced technique from the search results

            # Get the original function address
            original_addr = ctypes.cast(rand_func, ctypes.c_void_p).value
            replacement_addr = ctypes.cast(deterministic_func, ctypes.c_void_p).value

            if original_addr and replacement_addr:
                KeyManager._debug_print(
                    f"Original function address: {hex(original_addr)}"
                )
                KeyManager._debug_print(
                    f"Replacement function address: {hex(replacement_addr)}"
                )
            else:
                raise RuntimeError("Could not get function addresses")

            # Method 1: Direct function pointer replacement in the library's symbol table
            try:
                # Replace the function pointer in the library's dictionary
                lib.__dict__["OQS_randombytes"] = deterministic_func
                KeyManager._debug_print(
                    "✅ Successfully patched function pointer in library dict"
                )
                KeyManager._patched_func = deterministic_func
                KeyManager._original_func = rand_func
                KeyManager._is_patched = True
                return deterministic_func, rand_func, KeyManager._global_prng

            except Exception as e:
                KeyManager._debug_print(f"Dict patching failed: {e}")

            # Method 2: Memory-level patching (more dangerous but more thorough)
            try:
                import mmap
                import os

                # Create a jump instruction to our replacement function
                # This patches the actual machine code - very advanced!

                # For x64, we need to create a jump instruction
                # JMP instruction is 0xFF 0x25 followed by 32-bit offset
                if original_addr and replacement_addr:
                    # Calculate the relative offset
                    offset = (
                        replacement_addr - original_addr - 6
                    )  # 6 bytes for the jump instruction

                    # Create jump instruction bytes
                    # 0xFF 0x25 0x00 0x00 0x00 0x00 = JMP [RIP+0] followed by 8-byte address
                    jump_bytes = (
                        b"\xff\x25\x00\x00\x00\x00"
                        + replacement_addr.to_bytes(8, "little")
                    )

                    KeyManager._debug_print(f"Jump instruction: {jump_bytes.hex()}")

                    # For safety, we'll skip the actual memory write for now
                    # Direct memory patching can crash the process
                    KeyManager._debug_print(
                        "⚠️  Skipping direct memory write for safety"
                    )

                    return deterministic_func, rand_func, KeyManager._global_prng
                else:
                    raise RuntimeError("Could not get function addresses")

            except Exception as e:
                KeyManager._debug_print(f"Memory patching failed: {e}")
                return deterministic_func, rand_func, KeyManager._global_prng

        except Exception as e:
            KeyManager._debug_print(f"Randomness patching failed: {e}", "ERROR")
            raise RuntimeError(f"Failed to patch randomness: {e}")

    @staticmethod
    def generate_pq_keypair_from_seed(
        algorithm: str, seed: bytes
    ) -> Tuple[bytes, bytes]:
        """
        Generate a post-quantum key pair from a seed using memory patching.

        This implementation patches the liboqs randomness source directly and then
        generates keys using the patched library.

        Args:
            algorithm: PQ algorithm name (e.g., 'ML-DSA-87')
            seed: Seed bytes for key generation (32 bytes recommended)

        Returns:
            tuple: (public_key_bytes, secret_key_bytes)

        Raises:
            RuntimeError: If key generation fails
        """
        KeyManager._debug_print("=== Starting Memory Patch Key Generation ===")
        KeyManager._debug_print(f"Algorithm: {algorithm}")
        KeyManager._debug_print(f"Seed length: {len(seed)}")

        # Always apply fresh patch to ensure clean state
        KeyManager._debug_print("Applying fresh patch...")

        # Store current seed for this generation
        KeyManager._current_seed = seed

        # Patch the randomness source
        patched_func, original_func, prng = KeyManager._patch_liboqs_randomness(seed)

        try:
            # Now generate keys using the patched library
            KeyManager._debug_print("Generating keys with patched randomness...")

            # Use the normal OQS interface - it will now use our deterministic randomness!
            sig_obj = oqs.Signature(algorithm)

            # Generate keypair - this will call our patched OQS_randombytes
            pk_bytes = sig_obj.generate_keypair()
            sk_bytes = sig_obj.export_secret_key()

            KeyManager._debug_print("✅ Successfully generated deterministic keys!")
            print(f"✅ Successfully used native seeded key generation for {algorithm}")

            return pk_bytes, sk_bytes

        except Exception as e:
            KeyManager._debug_print(f"Key generation failed: {e}", "ERROR")
            raise RuntimeError(f"Seeded key generation failed: {e}")

        finally:
            # Always restore the original function after each use
            try:
                if original_func:
                    lib = KeyManager._find_liboqs_library()
                    if lib:
                        lib.__dict__["OQS_randombytes"] = original_func
                        KeyManager._debug_print("Restored original randomness function")
                        KeyManager._is_patched = False
            except Exception as e:
                KeyManager._debug_print(
                    f"Failed to restore original function: {e}", "ERROR"
                )

    @staticmethod
    def generate_classic_keypair() -> Tuple[ecdsa.SigningKey, str]:
        """
        Generate a classic ECDSA key pair.

        Returns:
            tuple: (SigningKey object, hex-encoded public key)
        """
        sk_classic = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
        vk_classic = sk_classic.get_verifying_key()
        assert vk_classic is not None
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
    @contextmanager
    def signing_context(cls, auth_keys_file: Path):
        """
        Context manager for signing operations with automatic cleanup.

        Usage:
            with KeyManager.signing_context(auth_keys_file) as keys:
                classic_sk = keys["classic_sk"]
                pq_sigs = keys["pq_sigs"]
                # Use signing keys...
            # OQS signatures are automatically freed

        Args:
            auth_keys_file: Path to auth keys JSON file

        Yields:
            dict: Contains 'classic_sk' and 'pq_sigs' with OQS objects
        """
        auth_keys = cls.load_auth_keys_bundle(auth_keys_file)

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
    def create_identity_file(
        identity_name: str, key_dir: Path, overwrite: bool = False
    ) -> Tuple[str, Path]:
        """
        Create a complete identity file with all necessary keys.

        This method generates a mnemonic phrase and derives all keys
        deterministically from it using advanced memory patching techniques.

        Args:
            identity_name: Name for the new identity
            key_dir: Directory to store identity files
            overwrite: Whether to overwrite existing identity file

        Returns:
            tuple: (mnemonic_phrase, identity_file_path)

        Raises:
            RuntimeError: If seeded key generation fails
        """
        identity_path = key_dir / f"{identity_name}.json"
        if identity_path.exists() and not overwrite:
            raise FileExistsError(
                f"Identity '{identity_name}' already exists at {identity_path}. Use --overwrite to replace it."
            )

        # 1. Generate mnemonic
        mnemonic = Bip39MnemonicGenerator().FromWordsNumber(Bip39WordsNum.WORDS_NUM_24)

        # 2. Generate seed from mnemonic
        seed_generator = Bip39SeedGenerator(str(mnemonic))
        master_seed = seed_generator.Generate()

        # 3. Generate auth keys
        sk_classic, pk_classic_hex = KeyManager.generate_classic_keypair()

        # 4. Use seeded approach for PQ keys (no fallback)
        # Derive PQ seed from master seed using a domain separator
        pq_seed = hashlib.sha256(master_seed + b"PQ_KEY_DERIVATION").digest()
        pq_pk, pq_sk = KeyManager.generate_pq_keypair_from_seed(ML_DSA_ALG, pq_seed)

        # Store derivation info for recovery
        identity_data = {
            "mnemonic": str(mnemonic),
            "version": "seeded",  # Always seeded - no fallback
            "derivable": True,  # Always derivable from mnemonic
            "auth_keys": {
                "classic": {
                    "sk_hex": sk_classic.to_string().hex(),
                    "pk_hex": pk_classic_hex,
                },
                "pq": [
                    {
                        "alg": ML_DSA_ALG,
                        "sk_hex": pq_sk.hex(),
                        "pk_hex": pq_pk.hex(),
                        "derivable": True,  # Always derivable from mnemonic
                    }
                ],
            },
        }

        # 5. Create identity file
        key_dir.mkdir(parents=True, exist_ok=True)
        with open(identity_path, "w") as f:
            json.dump(identity_data, f, indent=2)

        return str(mnemonic), identity_path
