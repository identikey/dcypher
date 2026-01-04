import ecdsa
import hashlib
from typing import Dict, Any, Tuple, Optional
import oqs
import json
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature


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


def verify_ed25519_signature(
    public_key_hex: str, signature_hex: str, message: bytes
) -> bool:
    """
    Verifies an ED25519 signature.

    Args:
        public_key_hex: The ED25519 public key in hex format.
        signature_hex: The signature in hex format.
        message: The message that was signed.

    Returns:
        True if the signature is valid, False otherwise.
    """
    try:
        public_key_bytes = bytes.fromhex(public_key_hex)
        signature_bytes = bytes.fromhex(signature_hex)

        public_key = ed25519.Ed25519PublicKey.from_public_bytes(public_key_bytes)
        public_key.verify(signature_bytes, message)
        return True
    except (ValueError, InvalidSignature):
        return False


def verify_dual_classical_signatures(
    ecdsa_pk_hex: str,
    ecdsa_sig_hex: str,
    ed25519_pk_hex: str,
    ed25519_sig_hex: str,
    message: bytes,
) -> Tuple[bool, Optional[str]]:
    """
    Verifies both ECDSA and ED25519 signatures on the same message.

    Args:
        ecdsa_pk_hex: The ECDSA public key in hex format
        ecdsa_sig_hex: The ECDSA signature in hex format
        ed25519_pk_hex: The ED25519 public key in hex format
        ed25519_sig_hex: The ED25519 signature in hex format
        message: The message that was signed

    Returns:
        Tuple of (is_valid, error_message). If valid, error_message is None.
    """
    ecdsa_valid = verify_signature(ecdsa_pk_hex, ecdsa_sig_hex, message)
    ed25519_valid = verify_ed25519_signature(ed25519_pk_hex, ed25519_sig_hex, message)

    if ecdsa_valid and ed25519_valid:
        return True, None
    elif not ecdsa_valid and not ed25519_valid:
        return False, "Invalid dual classical signatures"
    elif not ecdsa_valid:
        return False, "Invalid ECDSA signature"
    else:
        return False, "Invalid Ed25519 signature"


def generate_ed25519_keypair() -> Tuple[ed25519.Ed25519PrivateKey, str]:
    """
    Generate a new ED25519 key pair.

    Returns:
        Tuple of (private_key, public_key_hex)
    """
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    return private_key, public_key_bytes.hex()


def sign_message(sk_hex: str, message: bytes) -> str:
    """
    Signs a message with a classical (ECDSA) and a post-quantum (OQS) key.
    This function is a placeholder for a more robust signing process.
    """
    # For now, we only use the classical key for signing storage-related messages.
    # The pq_keys are loaded but not used, pending a spec update.
    if isinstance(sk_hex, bytes):
        sk_hex = sk_hex.decode("ascii")
    sk = ecdsa.SigningKey.from_string(bytes.fromhex(sk_hex), curve=ecdsa.SECP256k1)
    return sk.sign(message, hashfunc=hashlib.sha256).hex()


def sign_message_with_keys(message: bytes, keys: Dict[str, Any]) -> Dict[str, Any]:
    """
    Signs a message with the provided classic and PQ keys.
    Now supports dual classical keys (ECDSA + ED25519).
    Returns a dictionary of the combined signature object.
    """
    classic_sk = keys["classic_sk"]
    pq_key_list = keys["pq_keys"]

    # Sign with ECDSA key
    ecdsa_sig_hex = classic_sk.sign(message, hashfunc=hashlib.sha256).hex()

    # Sign with ED25519 key if present
    ed25519_sig_hex = None
    if "ed25519_sk" in keys and keys["ed25519_sk"] is not None:
        ed25519_sk = keys["ed25519_sk"]
        ed25519_sig_bytes = ed25519_sk.sign(message)
        ed25519_sig_hex = ed25519_sig_bytes.hex()

    pq_signatures = []
    for pq_key_info in pq_key_list:
        pq_sk = pq_key_info["sk"]
        pq_alg = pq_key_info["alg"]
        pq_pk_hex = pq_key_info["pk_hex"]
        with oqs.Signature(pq_alg, pq_sk) as sig_ml_dsa:
            pq_sig_hex = sig_ml_dsa.sign(message).hex()
            pq_signatures.append(
                {"public_key": pq_pk_hex, "signature": pq_sig_hex, "alg": pq_alg}
            )

    signature_obj = {
        "classic_signature": ecdsa_sig_hex,
        "pq_signatures": pq_signatures,
    }

    # Add ED25519 signature if available
    if ed25519_sig_hex is not None:
        signature_obj["ed25519_signature"] = ed25519_sig_hex

    return signature_obj


def ed25519_private_key_from_hex(private_key_hex: str) -> ed25519.Ed25519PrivateKey:
    """
    Create an ED25519 private key from hex-encoded bytes.

    Args:
        private_key_hex: The private key in hex format

    Returns:
        ED25519 private key object
    """
    private_key_bytes = bytes.fromhex(private_key_hex)
    return ed25519.Ed25519PrivateKey.from_private_bytes(private_key_bytes)


def ed25519_private_key_to_hex(private_key: ed25519.Ed25519PrivateKey) -> str:
    """
    Convert an ED25519 private key to hex-encoded bytes.

    Args:
        private_key: The ED25519 private key

    Returns:
        Hex-encoded private key bytes
    """
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return private_bytes.hex()


def ed25519_public_key_from_hex(public_key_hex: str) -> ed25519.Ed25519PublicKey:
    """
    Create an ED25519 public key from hex-encoded bytes.

    Args:
        public_key_hex: The public key in hex format

    Returns:
        ED25519 public key object
    """
    public_key_bytes = bytes.fromhex(public_key_hex)
    return ed25519.Ed25519PublicKey.from_public_bytes(public_key_bytes)


def ed25519_public_key_to_hex(public_key: ed25519.Ed25519PublicKey) -> str:
    """
    Convert an ED25519 public key to hex-encoded bytes.

    Args:
        public_key: The ED25519 public key

    Returns:
        Hex-encoded public key bytes
    """
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    return public_bytes.hex()
