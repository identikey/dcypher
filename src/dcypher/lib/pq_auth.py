import oqs

# SUPPORTED_SIG_ALGS = ["Dilithium2", "Falcon-512"]
SUPPORTED_SIG_ALGS = list(oqs.get_enabled_sig_mechanisms())


def generate_pq_keys(alg: str) -> tuple[bytes, bytes]:
    """Generates a post-quantum key pair for a given algorithm."""
    with oqs.Signature(alg) as sig:
        pk = sig.generate_keypair()
        sk = sig.export_secret_key()
        return pk, sk


def get_oqs_sig_from_path(sk_path: str, alg: str) -> oqs.Signature:
    """Loads a secret key from a file and returns an oqs.Signature object."""
    with open(sk_path, "rb") as f:
        sk = f.read()
    return oqs.Signature(alg, sk)


def verify_pq_signature(
    public_key_hex: str,
    signature_hex: str,
    message: bytes,
    alg: str,
) -> bool:
    """
    Verifies a post-quantum signature using liboqs.

    Args:
        public_key_hex: The public key in hex format.
        signature_hex: The signature in hex format.
        message: The message that was signed.
        alg: The post-quantum signature algorithm to use.

    Returns:
        True if the signature is valid, False otherwise.
    """
    if alg not in SUPPORTED_SIG_ALGS:
        return False

    try:
        with oqs.Signature(alg) as sig:
            public_key = bytes.fromhex(public_key_hex)
            signature = bytes.fromhex(signature_hex)
            return sig.verify(message, signature, public_key)
    except Exception:
        return False
