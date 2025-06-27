import ecdsa
import hashlib
from typing import Dict, Any
import oqs
import json


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
    Returns a dictionary of the combined signature object.
    """
    classic_sk = keys["classic_sk"]
    pq_key_list = keys["pq_keys"]

    classic_sig_hex = classic_sk.sign(message, hashfunc=hashlib.sha256).hex()

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
        "classic_signature": classic_sig_hex,
        "pq_signatures": pq_signatures,
    }
    return signature_obj
