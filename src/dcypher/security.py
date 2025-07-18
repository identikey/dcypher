import time
import hmac
import hashlib

from dcypher import config

SERVER_SECRET = config.SERVER_SECRET


def generate_nonce() -> str:
    """Generates a time-based, HMAC-signed nonce."""
    timestamp = str(time.time())
    mac = hmac.new(
        SERVER_SECRET.encode(), timestamp.encode(), hashlib.sha256
    ).hexdigest()
    return f"{timestamp}:{mac}"


def verify_nonce(nonce: str) -> bool:
    """Verifies the integrity and expiration of a nonce."""
    try:
        timestamp_str, mac = nonce.split(":")
        timestamp = float(timestamp_str)
    except ValueError:
        return False  # Malformed nonce

    # 1. Check if expired (5-minute validity)
    if time.time() - timestamp > 300:
        return False

    # 2. Check HMAC signature
    expected_mac = hmac.new(
        SERVER_SECRET.encode(), timestamp_str.encode(), hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(expected_mac, mac):
        return False

    return True
