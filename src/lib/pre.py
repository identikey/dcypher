import openfhe as fhe
import random
import base64
import tempfile
import os
import struct
from typing import List


def create_crypto_context(
    plaintext_modulus=65537, scaling_mod_size=60, security_level=128
):
    """
    Creates and configures a crypto context for BFVrns.
    """
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
    """
    Returns the number of slots in a plaintext for the given crypto context.
    """
    return cc.GetRingDimension()


def generate_keys(cc):
    """
    Generates a key pair.
    """
    return cc.KeyGen()


def bytes_to_coefficients(data: bytes, slot_count: int) -> List[int]:
    """
    Converts a byte string into a list of integer coefficients (unsigned shorts)
    for PRE, padding with zeros to fill all available slots.
    """
    # Each coefficient is an unsigned short (2 bytes).
    # If data length is odd, pad with a null byte.
    if len(data) % 2 != 0:
        data += b"\0"

    num_coeffs = len(data) // 2
    if num_coeffs > slot_count:
        raise ValueError(
            f"Data requires {num_coeffs} slots, but only {slot_count} are available."
        )

    # Unpack bytes into a list of unsigned shorts (H).
    coeffs = list(struct.unpack(f"<{num_coeffs}H", data))

    # Pad with zeros to fill all slots.
    if len(coeffs) < slot_count:
        coeffs.extend([0] * (slot_count - len(coeffs)))

    return coeffs


def encrypt(cc, public_key, data_coeffs):
    """
    Encrypts a list of integer coefficients, handling lists larger than the
    slot count by chunking.
    """
    slot_count = get_slot_count(cc)
    chunks = [
        data_coeffs[i : i + slot_count] for i in range(0, len(data_coeffs), slot_count)
    ]
    ciphertexts = []
    for chunk in chunks:
        pt = cc.MakePackedPlaintext(chunk)
        ciphertexts.append(cc.Encrypt(public_key, pt))
    return ciphertexts


def decrypt(cc, secret_key, ciphertexts, length=None):
    """
    Decrypts a list of ciphertexts and returns the combined plaintext data.
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
    """
    Generates a re-encryption key from Alice's secret key to Bob's public key.
    """
    return cc.ReKeyGen(alice_secret_key, bob_public_key)


def re_encrypt(cc, re_encryption_key, ciphertexts):
    """
    Re-encrypts a list of ciphertexts using a re-encryption key.
    """
    return [cc.ReEncrypt(ct, re_encryption_key) for ct in ciphertexts]


def serialize_to_bytes(obj):
    """
    Serializes an OpenFHE object to raw bytes.
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
    """
    Serializes an OpenFHE object to a base64 encoded string.
    """
    raw_bytes = serialize_to_bytes(obj)
    return base64.b64encode(raw_bytes).decode("utf-8")


def _deserialize_from_bytes(data: bytes, deserializer):
    """Helper to deserialize from raw bytes via a temporary file."""
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


def _deserialize_from_base64_string(encoded_str, deserializer):
    """Helper to deserialize from a base64 string via a temporary file."""
    data = base64.b64decode(encoded_str)
    return _deserialize_from_bytes(data, deserializer)


def deserialize_cc(encoded_str):
    """
    Deserializes a CryptoContext from a base64 encoded string.
    """
    fhe.ReleaseAllContexts()
    return _deserialize_from_base64_string(encoded_str, fhe.DeserializeCryptoContext)


def deserialize_public_key(data: bytes):
    """Deserializes a public key from a raw byte string."""
    return _deserialize_from_bytes(data, fhe.DeserializePublicKey)


def deserialize_secret_key(data: bytes):
    """Deserializes a secret key from a raw byte string."""
    return _deserialize_from_bytes(data, fhe.DeserializePrivateKey)


def deserialize_ciphertext(data: bytes):
    """Deserializes a ciphertext from a raw byte string."""
    return _deserialize_from_bytes(data, fhe.DeserializeCiphertext)


def deserialize_re_encryption_key(encoded_str):
    """
    Deserializes a re-encryption key from a base64 encoded string.
    """
    # Re-encryption keys are deserialized as generic EvalKeys
    return _deserialize_from_base64_string(encoded_str, fhe.DeserializeEvalKey)


def coefficients_to_bytes(coeffs: List[int], total_bytes: int) -> bytes:
    """
    Converts a list of plaintext coefficients (unsigned shorts) back into a
    byte string, truncating to the original data's byte length.
    """
    byte_array = bytearray()
    for coeff in coeffs:
        # Pack each coefficient as an unsigned short (H)
        byte_array.extend(struct.pack("<H", coeff))
    return bytes(byte_array[:total_bytes])
