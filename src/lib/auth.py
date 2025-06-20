import ecdsa
import hashlib


def verify_signature(public_key_hex: str, signature_hex: str, message: bytes) -> bool:
    """
    Verifies an ECDSA signature.

    Args:
        public_key_hex: The public key in hex format.
        signature_hex: The signature in hex format.
        message: The message that was signed.

    Returns:
        True if the signature is valid, False otherwise.
    """
    try:
        vk = ecdsa.VerifyingKey.from_string(
            bytes.fromhex(public_key_hex), curve=ecdsa.SECP256k1
        )
        signature = bytes.fromhex(signature_hex)
        # We expect the message to be hashed with SHA256 before signing
        return vk.verify(signature, message, hashfunc=hashlib.sha256)
    except (
        ecdsa.keys.MalformedPointError,
        ValueError,
        ecdsa.BadSignatureError,
    ):
        return False
