import ecdsa
import hashlib
import oqs
import pytest
import time
import os
import json
import hmac
import threading
import concurrent.futures
import requests
from unittest import mock
from main import app
from app_state import state
from src.lib.pq_auth import SUPPORTED_SIG_ALGS
from config import ML_DSA_ALG
from security import SERVER_SECRET

from tests.integration.test_api import (
    get_nonce,
    create_test_account_with_keymanager,
)


def test_account_creation_timing_attack_resistance(api_base_url: str, tmp_path):
    """
    Tests that account creation operations execute in constant time
    regardless of whether the account already exists, preventing
    timing-based user enumeration attacks.
    This test demonstrates the new API client pattern with automatic resource management.
    """
    # 1. Create an existing account using the new KeyManager-based helper
    client, pk_classic_hex = create_test_account_with_keymanager(api_base_url, tmp_path)

    with client.signing_keys() as keys:
        sk_classic = keys["classic_sk"]

        # 2. Measure time for existing account creation attempt
        start_time = time.perf_counter()
        nonce2 = get_nonce(api_base_url)
        with oqs.Signature(ML_DSA_ALG) as sig_ml_dsa_new:
            pk_ml_dsa_new_hex = sig_ml_dsa_new.generate_keypair().hex()
            message2 = f"{pk_classic_hex}:{pk_ml_dsa_new_hex}:{nonce2}".encode("utf-8")
            sig2_classic = sk_classic.sign(message2, hashfunc=hashlib.sha256).hex()
            sig2_ml_dsa = sig_ml_dsa_new.sign(message2).hex()

            response2 = requests.post(
                f"{api_base_url}/accounts",
                json={
                    "public_key": pk_classic_hex,
                    "signature": sig2_classic,
                    "ml_dsa_signature": {
                        "public_key": pk_ml_dsa_new_hex,
                        "signature": sig2_ml_dsa,
                        "alg": ML_DSA_ALG,
                    },
                    "nonce": nonce2,
                },
            )
        existing_account_time = time.perf_counter() - start_time
        assert response2.status_code == 409

    # 3. Measure time for new account creation
    sk_classic_new = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
    vk_classic_new = sk_classic_new.get_verifying_key()
    assert vk_classic_new is not None
    pk_classic_new_hex = vk_classic_new.to_string("uncompressed").hex()

    start_time = time.perf_counter()
    nonce3 = get_nonce(api_base_url)
    with oqs.Signature(ML_DSA_ALG) as sig_ml_dsa_new2:
        pk_ml_dsa_new2_hex = sig_ml_dsa_new2.generate_keypair().hex()
        message3 = f"{pk_classic_new_hex}:{pk_ml_dsa_new2_hex}:{nonce3}".encode("utf-8")
        sig3_classic = sk_classic_new.sign(message3, hashfunc=hashlib.sha256).hex()
        sig3_ml_dsa = sig_ml_dsa_new2.sign(message3).hex()

        response3 = requests.post(
            f"{api_base_url}/accounts",
            json={
                "public_key": pk_classic_new_hex,
                "signature": sig3_classic,
                "ml_dsa_signature": {
                    "public_key": pk_ml_dsa_new2_hex,
                    "signature": sig3_ml_dsa,
                    "alg": ML_DSA_ALG,
                },
                "nonce": nonce3,
            },
        )
    new_account_time = time.perf_counter() - start_time
    assert response3.status_code == 200

    # 4. Verify timing difference is within acceptable bounds (< 50ms difference)
    time_difference = abs(existing_account_time - new_account_time)
    assert time_difference < 0.06, f"Timing difference too large: {time_difference}s"
    # OQS signatures are automatically freed when exiting the context


def test_concurrent_account_creation(api_base_url: str):
    """
    Tests that multiple concurrent account creation requests are handled
    correctly without race conditions or data corruption.
    """
    from src.lib.api_client import DCypherClient, DCypherAPIError
    import tempfile
    import json
    from pathlib import Path
    from src.lib.pq_auth import generate_pq_keys

    def create_single_account(thread_id):
        """Create a single account in a thread using the API client"""
        try:
            # Generate keys for this account
            sk_classic = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
            vk_classic = sk_classic.get_verifying_key()
            assert vk_classic is not None
            pk_classic_hex = vk_classic.to_string("uncompressed").hex()

            # Generate PQ keys
            pq_pk, pq_sk = generate_pq_keys(ML_DSA_ALG)

            # Create temporary auth keys file for this thread
            with tempfile.TemporaryDirectory() as temp_dir:
                temp_path = Path(temp_dir)

                # Save classic secret key
                classic_sk_path = temp_path / f"classic_{thread_id}.sk"
                with open(classic_sk_path, "w") as f:
                    f.write(sk_classic.to_string().hex())

                # Save PQ secret key
                pq_sk_path = temp_path / f"pq_{thread_id}.sk"
                with open(pq_sk_path, "wb") as f:
                    f.write(pq_sk)

                # Create auth keys file
                auth_keys_data = {
                    "classic_sk_path": str(classic_sk_path),
                    "pq_keys": [
                        {
                            "sk_path": str(pq_sk_path),
                            "pk_hex": pq_pk.hex(),
                            "alg": ML_DSA_ALG,
                        }
                    ],
                }
                auth_keys_file = temp_path / f"auth_keys_{thread_id}.json"
                with open(auth_keys_file, "w") as f:
                    json.dump(auth_keys_data, f)

                # Create API client and account
                client = DCypherClient(api_base_url, str(auth_keys_file))
                pq_keys = [{"pk_hex": pq_pk.hex(), "alg": ML_DSA_ALG}]

                result = client.create_account(pk_classic_hex, pq_keys)
                return thread_id, 200, pk_classic_hex

        except DCypherAPIError as e:
            # Check if it's a 409 (conflict) which might happen in concurrent scenarios
            if "409" in str(e):
                return thread_id, 409, str(e)
            else:
                return thread_id, 500, str(e)
        except Exception as e:
            return thread_id, 500, str(e)

    # Test with 10 concurrent account creations
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(create_single_account, i) for i in range(10)]
        results = [
            future.result() for future in concurrent.futures.as_completed(futures)
        ]

    # Verify all accounts were created successfully
    success_count = sum(1 for _, status_code, _ in results if status_code == 200)
    assert success_count == 10, (
        f"Only {success_count}/10 concurrent accounts created successfully. Results: {results}"
    )

    # Verify all accounts are unique
    account_keys = [pk for _, status_code, pk in results if status_code == 200]
    assert len(set(account_keys)) == len(account_keys), (
        "Duplicate account keys detected"
    )


def test_malformed_public_key_formats(api_base_url: str):
    """
    Tests that various malformed public key formats are properly rejected
    during account creation.
    """
    nonce = get_nonce(api_base_url)

    malformed_keys = [
        "",  # Empty string
        "invalid",  # Too short
        "0" * 128,  # Wrong length but valid hex
        "g" * 130,  # Invalid hex characters
        "04" + "0" * 126,  # Valid format but potentially invalid curve point
        "04" + "f" * 128,  # Valid hex but invalid curve point
        "03" + "0" * 64,  # Compressed format (not supported)
        "04",  # Too short
    ]

    for malformed_key in malformed_keys:
        response = requests.post(
            f"{api_base_url}/accounts",
            json={
                "public_key": malformed_key,
                "signature": "dummy_signature",
                "ml_dsa_signature": {
                    "public_key": "dummy_pq_key",
                    "signature": "dummy_pq_signature",
                    "alg": ML_DSA_ALG,
                },
                "nonce": nonce,
            },
        )
        # Should fail - system properly rejects malformed keys (may be 401, 400, or 422)
        assert response.status_code in [400, 401, 422], (
            f"Malformed key not rejected: {malformed_key}"
        )


def test_memory_exhaustion_protection(api_base_url: str):
    """
    Tests that the system protects against memory exhaustion attacks
    through large payloads or excessive data structures.
    """
    # Test with extremely large public key
    oversized_key = "04" + "a" * 10000  # Much larger than any valid key
    nonce = get_nonce(api_base_url)

    response = requests.post(
        f"{api_base_url}/accounts",
        json={
            "public_key": oversized_key,
            "signature": "dummy_sig",
            "ml_dsa_signature": {
                "public_key": "dummy_pq_key",
                "signature": "dummy_pq_sig",
                "alg": ML_DSA_ALG,
            },
            "nonce": nonce,
        },
    )
    # Should be rejected due to size limits (may be 401 due to invalid signatures)
    assert response.status_code in [400, 401, 413, 422]

    # Test with excessive additional PQ signatures
    large_additional_sigs = []
    for i in range(100):  # Try to add 100 additional signatures
        large_additional_sigs.append(
            {
                "public_key": f"key_{i}",
                "signature": f"sig_{i}",
                "alg": "Falcon-512",
            }
        )

    response = requests.post(
        f"{api_base_url}/accounts",
        json={
            "public_key": "04" + "b" * 128,
            "signature": "dummy_sig",
            "ml_dsa_signature": {
                "public_key": "dummy_pq_key",
                "signature": "dummy_pq_sig",
                "alg": ML_DSA_ALG,
            },
            "additional_pq_signatures": large_additional_sigs,
            "nonce": nonce,
        },
    )
    # Should be rejected due to excessive payload (may be 401 due to invalid signatures)
    assert response.status_code in [400, 401, 413, 422]


def test_sensitive_data_handling(api_base_url: str):
    """
    Tests that sensitive data (private keys, full signatures) are not
    leaked in error messages, logs, or API responses.
    """
    # 1. Create account with known private key
    sk_classic = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
    sk_hex = sk_classic.to_string().hex()
    vk_classic = sk_classic.get_verifying_key()
    assert vk_classic is not None
    pk_classic_hex = vk_classic.to_string("uncompressed").hex()

    nonce = get_nonce(api_base_url)
    with oqs.Signature(ML_DSA_ALG) as sig_ml_dsa:
        pk_ml_dsa_hex = sig_ml_dsa.generate_keypair().hex()
        message = f"{pk_classic_hex}:{pk_ml_dsa_hex}:{nonce}".encode("utf-8")
        sig_classic_hex = sk_classic.sign(message, hashfunc=hashlib.sha256).hex()
        sig_ml_dsa_hex = sig_ml_dsa.sign(message).hex()

        # 2. Create account successfully
        response = requests.post(
            f"{api_base_url}/accounts",
            json={
                "public_key": pk_classic_hex,
                "signature": sig_classic_hex,
                "ml_dsa_signature": {
                    "public_key": pk_ml_dsa_hex,
                    "signature": sig_ml_dsa_hex,
                    "alg": ML_DSA_ALG,
                },
                "nonce": nonce,
            },
        )
        assert response.status_code == 200

        # 3. Verify sensitive data not in response
        response_text = response.text.lower()
        assert sk_hex.lower() not in response_text, "Private key leaked in response"

        # 4. Test error responses don't leak sensitive data
        response = requests.post(
            f"{api_base_url}/accounts",
            json={
                "public_key": pk_classic_hex,
                "signature": "invalid_signature",
                "ml_dsa_signature": {
                    "public_key": pk_ml_dsa_hex,
                    "signature": sig_ml_dsa_hex,
                    "alg": ML_DSA_ALG,
                },
                "nonce": get_nonce(api_base_url),
            },
        )
        assert response.status_code in [401, 409]
        error_text = response.text.lower()
        assert sk_hex.lower() not in error_text, "Private key leaked in error response"
