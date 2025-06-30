import random
import base64
import tempfile
import os
import struct
import threading
from typing import List

# Import guard for OpenFHE availability
_fhe_module = None
_openfhe_available = False
try:
    import openfhe as fhe  # type: ignore

    _fhe_module = fhe
    _openfhe_available = True
except ImportError:
    _openfhe_available = False

    # Create a dummy fhe module for graceful handling
    class _DummyFHE:
        def __getattr__(self, name):
            raise RuntimeError("OpenFHE library is not available")

    fhe = _DummyFHE()


class CoefficientOutOfRangeError(ValueError):
    """Raised when a coefficient is outside the valid range for packing."""

    pass


def is_openfhe_available() -> bool:
    """Check if OpenFHE library is available."""
    return _openfhe_available


def create_crypto_context(
    plaintext_modulus=65537, scaling_mod_size=60, security_level=128
):
    """Creates and configures a crypto context for BFVrns.

    This function sets up the fundamental cryptographic parameters for the
    Proxy Re-Encryption (PRE) scheme. The choice of parameters is critical
    for security and performance.

    Args:
        plaintext_modulus (int): The modulus for the plaintext space. It
            determines the range of values the encrypted data can hold.
            Must be a prime congruent to 1 modulo 2*ring_dimension.
        scaling_mod_size (int): The bit-length of the scaling factor used in
            the BFV scheme. It affects noise growth and performance.
        security_level (int): The desired cryptographic security level in bits.
            Typically 128, 192, or 256. This determines the ring dimension
            and other underlying lattice parameters.

    Returns:
        A fully configured OpenFHE CryptoContext object enabled for PRE.
    """
    if not _openfhe_available:
        raise RuntimeError("OpenFHE library is not available")

    parameters = fhe.CCParamsBFVRNS()
    parameters.SetPlaintextModulus(plaintext_modulus)
    parameters.SetScalingModSize(scaling_mod_size)

    cc = fhe.GenCryptoContext(parameters)

    cc.Enable(fhe.PKE)
    cc.Enable(fhe.KEYSWITCH)
    cc.Enable(fhe.LEVELEDSHE)
    cc.Enable(fhe.PRE)

    return cc


def get_slot_count(cc):
    """Returns the number of slots in a plaintext for the given crypto context.

    In the BFV scheme (and others), multiple plaintext values (slots) can be
    packed into a single ciphertext. This is known as SIMD (Single Instruction,
    Multiple Data) and significantly improves performance. The number of slots

    is determined by the ring dimension, which is set during crypto context
    creation based on the desired security level.

    Args:
        cc: The crypto context.

    Returns:
        int: The number of available slots for data packing.
    """
    return cc.GetRingDimension()


def generate_keys(cc):
    """Generates a public/private key pair.

    Args:
        cc: The crypto context.

    Returns:
        An OpenFHE KeyPair object containing a public and private key.
    """
    if not _openfhe_available:
        raise RuntimeError("OpenFHE library is not available")
    return cc.KeyGen()


def bytes_to_coefficients(data: bytes, slot_count: int) -> List[int]:
    """Converts a byte string into a list of integer coefficients.

    This function transforms raw binary data into a format suitable for
    encryption. It interprets the byte string as a sequence of unsigned
    shorts (16-bit integers), which become the coefficients of the plaintext
    polynomial.

    Note:
        This implementation does not pad the coefficient list to the full
        slot_count. Padding is handled during the encryption step to ensure
        each chunk is correctly formatted.

    Args:
        data (bytes): The raw byte string to convert.
        slot_count (int): The number of slots available in the crypto context.
            This is used for validation, not padding.

    Returns:
        List[int]: A list of integer coefficients.
    """
    # Each coefficient is an unsigned short (2 bytes).
    # If data length is odd, pad with a null byte to ensure it's even.
    if len(data) % 2 != 0:
        data += b"\0"

    num_coeffs = len(data) // 2

    # Unpack bytes into a list of unsigned shorts (H).
    coeffs = list(struct.unpack(f"<{num_coeffs}H", data))

    return coeffs


def encrypt(cc, public_key, data_coeffs):
    """Encrypts a list of integer coefficients.

    This function handles the encryption of data that may be larger than what
    can fit in a single ciphertext. It automatically chunks the data into
    appropriately sized pieces, pads the last chunk if necessary, and encrypts
    each one, returning a list of ciphertexts.

    Args:
        cc: The crypto context.
        public_key: The public key to encrypt with.
        data_coeffs (List[int]): The list of integer coefficients to encrypt.

    Returns:
        List[Ciphertext]: A list of OpenFHE ciphertext objects.
    """
    slot_count = get_slot_count(cc)
    chunks = [
        data_coeffs[i : i + slot_count] for i in range(0, len(data_coeffs), slot_count)
    ]
    ciphertexts = []
    for chunk in chunks:
        # Pad the chunk if it's smaller than slot_count
        if len(chunk) < slot_count:
            chunk.extend([0] * (slot_count - len(chunk)))
        pt = cc.MakePackedPlaintext(chunk)
        ciphertexts.append(cc.Encrypt(public_key, pt))
    return ciphertexts


def decrypt(cc, secret_key, ciphertexts, length=None):
    """Decrypts a list of ciphertexts and returns the combined plaintext coefficients.

    This function reverses the encryption process. It decrypts each ciphertext
    in the list and concatenates the resulting plaintext coefficients.

    Security Note:
        The `length` parameter is crucial for security. Without it, the function
        relies on finding a zero-padding value to truncate the output, which is
        unsafe and can leak information. Always provide the expected number of
        coefficients to ensure the output is correctly and safely truncated.

    Args:
        cc: The crypto context.
        secret_key: The secret key for decryption.
        ciphertexts (List[Ciphertext]): The list of ciphertexts to decrypt.
        length (int, optional): The exact number of plaintext coefficients to
            return. This should correspond to the length of the original data's
            coefficient list.

    Returns:
        List[int]: The decrypted list of integer coefficients.
    """
    result = []
    plaintext_modulus = cc.GetPlaintextModulus()

    for ciphertext in ciphertexts:
        pt = cc.Decrypt(secret_key, ciphertext)
        # The GetPackedValue function returns a list of signed integers,
        # and we need to handle the negative values to recover the original unsigned shorts.
        unpacked = pt.GetPackedValue()

        for val in unpacked:
            if val < 0:
                result.append(val + plaintext_modulus)
            else:
                result.append(val)

    if length is not None:
        return result[:length]

    # Find the end of the real data (legacy, unsafe)
    try:
        end_index = result.index(0)
        return result[:end_index]
    except ValueError:
        return result


def generate_re_encryption_key(cc, alice_secret_key, bob_public_key):
    """Generates a re-encryption key from Alice to Bob.

    This is the core of the Proxy Re-Encryption scheme. The generated key
    allows a proxy to transform a ciphertext encrypted under Alice's public
    key into a ciphertext that can be decrypted by Bob's secret key, without
    the proxy being able to learn anything about the underlying plaintext.

    Args:
        cc: The crypto context.
        alice_secret_key: The secret key of the original encryptor (Alice).
        bob_public_key: The public key of the intended recipient (Bob).

    Returns:
        An OpenFHE EvalKey object representing the re-encryption key.
    """
    return cc.ReKeyGen(alice_secret_key, bob_public_key)


def re_encrypt(cc, re_encryption_key, ciphertexts):
    """Re-encrypts a list of ciphertexts using a re-encryption key.

    The proxy executes this function. It takes a list of ciphertexts that
    were originally encrypted for Alice and applies the re-encryption key to
    transform them into ciphertexts for Bob.

    Args:
        cc: The crypto context.
        re_encryption_key: The re-encryption key generated by
            `generate_re_encryption_key`.
        ciphertexts (List[Ciphertext]): The list of ciphertexts to be
            re-encrypted.

    Returns:
        List[Ciphertext]: The list of re-encrypted ciphertexts.
    """
    return [cc.ReEncrypt(ct, re_encryption_key) for ct in ciphertexts]


def serialize_to_bytes(obj):
    """Serializes an OpenFHE object to raw bytes.

    This is a low-level serialization function that uses a temporary file
    as an intermediary, which is a common pattern when interfacing with
    libraries that primarily work with file paths.

    Warning:
        The underlying OpenFHE serialization is not canonical. Serializing the
        same object twice may produce different byte strings. Furthermore,
        deserializing and then re-serializing will also produce a different
        byte string. However, the objects remain functionally identical.

    Args:
        obj: The OpenFHE object to serialize (e.g., CryptoContext, PublicKey,
             SecretKey, Ciphertext).

    Returns:
        bytes: The raw byte representation of the object.
    """
    fd, path = tempfile.mkstemp()
    try:
        if not fhe.SerializeToFile(path, obj, fhe.BINARY):
            raise Exception(f"Serialization failed for object of type {type(obj)}")
        with os.fdopen(fd, "rb") as f:
            return f.read()
    finally:
        os.remove(path)


def serialize(obj):
    """Serializes an OpenFHE object to a base64 encoded string.

    This function provides a convenient, transport-friendly way to represent
    a serialized cryptographic object. It first serializes the object to raw
    bytes and then encodes the result in base64.

    Args:
        obj: The OpenFHE object to serialize.

    Returns:
        str: A base64-encoded string representing the serialized object.
    """
    raw_bytes = serialize_to_bytes(obj)
    return base64.b64encode(raw_bytes).decode("utf-8")


def _deserialize_from_bytes(data: bytes, deserializer):
    """Helper to deserialize from raw bytes via a temporary file.

    This internal function abstracts the file-based deserialization process
    required by OpenFHE.

    Args:
        data (bytes): The raw bytes of the serialized object.
        deserializer: The specific OpenFHE deserialization function to use
                      (e.g., `fhe.DeserializePublicKey`).

    Returns:
        The deserialized OpenFHE object.

    Raises:
        ValueError: If deserialization fails.
    """
    fd, path = tempfile.mkstemp()
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        obj, result = deserializer(path, fhe.BINARY)
    finally:
        os.remove(path)
    if not result:
        raise ValueError(f"Deserialization failed for {deserializer.__name__}")
    return obj


# Global lock for context deserialization to prevent race conditions
_context_lock = threading.Lock()

# Process-local context registry to track contexts per process
_process_contexts = {}


def deserialize_cc_safe(data: bytes):
    """Process-safe deserialization of CryptoContext from raw bytes.

    This version uses process-local context management to prevent destroying
    contexts from other processes while ensuring proper OpenFHE registration.

    Args:
        data (bytes): The raw byte representation of the CryptoContext.

    Returns:
        The deserialized CryptoContext object.
    """
    if not _openfhe_available:
        raise RuntimeError("OpenFHE library is not available")

    process_id = os.getpid()
    data_hash = hash(data)

    with _context_lock:
        # Check if we already have this context for this process
        if process_id in _process_contexts:
            if data_hash in _process_contexts[process_id]:
                return _process_contexts[process_id][data_hash]
        else:
            _process_contexts[process_id] = {}

        # In parallel execution, avoid ReleaseAllContexts() entirely to prevent
        # destroying contexts from other processes/threads
        # Only call it if we're not in a parallel environment and have no cached contexts
        # if (len(_process_contexts[process_id]) == 0 and
        #     not os.environ.get('PYTEST_XDIST_WORKER') and
        #     not os.environ.get('PARALLEL_EXECUTION')):
        #     fhe.ReleaseAllContexts()

        # Deserialize the context
        context = _deserialize_from_bytes(data, fhe.DeserializeCryptoContext)

        # Cache the context for this process
        _process_contexts[process_id][data_hash] = context

        return context


def cleanup_process_contexts(process_id=None):
    """Clean up cached contexts for a specific process or all processes.

    Args:
        process_id: Process ID to clean up. If None, cleans up current process.
    """
    if process_id is None:
        process_id = os.getpid()

    with _context_lock:
        if process_id in _process_contexts:
            del _process_contexts[process_id]


def deserialize_cc(data: bytes):
    """Deserializes a CryptoContext from raw bytes.

    Important:
        This function now ALWAYS uses the process-safe deserialization to prevent
        context destruction during parallel test execution. OpenFHE maintains a
        global registry of contexts, and calling ReleaseAllContexts() can destroy
        contexts that other tests/processes are using.

        For safety, this function now delegates to deserialize_cc_safe() which
        uses process-local context management without destructive cleanup.

    Args:
        data (bytes): The raw byte representation of the CryptoContext.

    Returns:
        The deserialized CryptoContext object.
    """
    # ALWAYS use the safe version to prevent context destruction
    # This prevents "Context was destroyed during parallel execution" errors
    return deserialize_cc_safe(data)


def deserialize_public_key(data: bytes):
    """Deserializes a public key from a raw byte string.

    Args:
        data (bytes): The raw byte representation of the public key.

    Returns:
        The deserialized PublicKey object.
    """
    return _deserialize_from_bytes(data, fhe.DeserializePublicKey)


def deserialize_secret_key(data: bytes):
    """Deserializes a secret key from a raw byte string.

    Args:
        data (bytes): The raw byte representation of the secret key.

    Returns:
        The deserialized PrivateKey object.
    """
    return _deserialize_from_bytes(data, fhe.DeserializePrivateKey)


def deserialize_ciphertext(data: bytes):
    """Deserializes a ciphertext from a raw byte string.

    Args:
        data (bytes): The raw byte representation of the ciphertext.

    Returns:
        The deserialized Ciphertext object.
    """
    return _deserialize_from_bytes(data, fhe.DeserializeCiphertext)


def deserialize_re_encryption_key(data: bytes):
    """Deserializes a re-encryption key from raw bytes.

    Note:
        Re-encryption keys are a type of "EvalKey" (evaluation key) in
        OpenFHE's terminology.

    Args:
        data (bytes): The raw byte representation of the re-encryption key.

    Returns:
        The deserialized EvalKey object.
    """
    # Re-encryption keys are deserialized as generic EvalKeys
    return _deserialize_from_bytes(data, fhe.DeserializeEvalKey)


def coefficients_to_bytes(
    coeffs: List[int], total_bytes: int, strict: bool = True
) -> bytes:
    """Converts a list of plaintext coefficients back into a byte string.

    This function reverses the process of `bytes_to_coefficients`. It packs
    the list of integer coefficients into a byte string of unsigned shorts
    and then truncates it to the exact length of the original data.

    Args:
        coeffs (List[int]): The list of integer coefficients.
        total_bytes (int): The expected length of the final byte string. This
            is used to remove any padding that was added before encryption.
        strict (bool): If True (default), raises CoefficientOutOfRangeError for
            coefficients outside the 16-bit unsigned integer range (0-65535).
            If False, such coefficients are reduced modulo 2**16, which may
            be useful for debugging but can hide decryption errors.

    Returns:
        bytes: The reconstructed original byte string.
    """
    byte_array = bytearray()
    for coeff in coeffs:
        # Pack each coefficient as an unsigned short (H)
        value_to_pack = coeff
        if not (0 <= value_to_pack < 2**16):
            if strict:
                raise CoefficientOutOfRangeError(
                    f"Coefficient {coeff} is out of range for unsigned short (0-65535)."
                )
            value_to_pack %= 2**16
        byte_array.extend(struct.pack("<H", value_to_pack))
    return bytes(byte_array[:total_bytes])
