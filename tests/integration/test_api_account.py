import ecdsa
import hashlib
import oqs
import pytest
import time
import os
import json
import hmac
import requests
from unittest import mock
from main import (
    app,
)
from app_state import state
from lib.pq_auth import SUPPORTED_SIG_ALGS
from config import ML_DSA_ALG
from security import SERVER_SECRET

from tests.integration.test_api import (
    _create_test_account,
    get_nonce,
    _create_test_idk_file_parts,
    create_test_account_with_keymanager,
)


def test_create_account_successful(api_base_url: str, tmp_path):
    """
    Tests the successful creation of a hybrid account with one mandatory classic
    signature, one mandatory PQ signature (ML-DSA), and one additional optional
    PQ signature. This covers the full functionality of creating a complex
    hybrid account.

    This test now uses the enhanced DCypherClient with KeyManager for simplified testing.
    """
    # Create account with additional PQ algorithm using the streamlined helper
    client, pk_classic_hex = create_test_account_with_keymanager(
        api_base_url, tmp_path, additional_pq_algs=["Falcon-512"]
    )

    # Verify account details using the API client
    account_details = client.get_account(pk_classic_hex)
    assert account_details["public_key"] == pk_classic_hex
    assert len(account_details["pq_keys"]) == 2  # ML-DSA + Falcon-512

    # Verify both algorithms are present
    retrieved_algs = {item["alg"] for item in account_details["pq_keys"]}
    expected_algs = {ML_DSA_ALG, "Falcon-512"}
    assert retrieved_algs == expected_algs


def test_create_account_successful_mandatory_only(api_base_url: str, tmp_path):
    """
    Tests the successful creation of a hybrid account with only the mandatory
    classic and PQ signatures (ML-DSA), without any additional PQ signatures.
    This is the minimal successful account creation scenario.

    This test now uses the enhanced DCypherClient with KeyManager for simplified testing.
    """
    # Create account with only mandatory keys using the streamlined helper
    client, pk_classic_hex = create_test_account_with_keymanager(api_base_url, tmp_path)

    # Verify account details using the API client
    account_details = client.get_account(pk_classic_hex)
    assert account_details["public_key"] == pk_classic_hex
    assert len(account_details["pq_keys"]) == 1  # Only ML-DSA

    # Verify the mandatory algorithm is present
    retrieved_alg = account_details["pq_keys"][0]["alg"]
    assert retrieved_alg == ML_DSA_ALG


def test_create_account_invalid_nonce(api_base_url: str):
    """
    Tests that an account creation request fails if an invalid nonce is provided.
    An invalid nonce is one that does not match the expected format or signature.
    """
    response = requests.post(
        f"{api_base_url}/accounts",
        json={
            "public_key": "test",
            "signature": "test",
            "ml_dsa_signature": {
                "public_key": "test",
                "signature": "test",
                "alg": ML_DSA_ALG,
            },
            "nonce": "invalid-nonce",
        },
    )
    assert response.status_code == 400
    assert "Invalid or expired nonce" in response.text


def test_create_account_used_nonce(api_base_url: str, tmp_path):
    """
    Tests that an account creation request fails if a valid but already used
    nonce is provided. This prevents replay attacks.
    This test demonstrates the new API client pattern with automatic resource management.
    """
    # Create a valid account first using the new KeyManager-based helper
    client, pk_classic_hex = create_test_account_with_keymanager(api_base_url, tmp_path)

    # Now try to re-use the nonce from the `state` object by accessing it
    # via the live server instance.
    nonce = get_nonce(api_base_url)

    # To simulate a used nonce, we have to create an account first.
    # The create_test_account_with_keymanager helper already does that. Let's make a new one.
    sk_classic = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
    vk_classic = sk_classic.get_verifying_key()
    assert vk_classic is not None
    pk_classic_hex = vk_classic.to_string("uncompressed").hex()
    with oqs.Signature(ML_DSA_ALG) as sig_ml_dsa:
        pk_ml_dsa_hex = sig_ml_dsa.generate_keypair().hex()
        message = f"{pk_classic_hex}:{pk_ml_dsa_hex}:{nonce}".encode("utf-8")
        sig_classic = sk_classic.sign(message, hashfunc=hashlib.sha256).hex()
        sig_ml_dsa_hex = sig_ml_dsa.sign(message).hex()

        payload = {
            "public_key": pk_classic_hex,
            "signature": sig_classic,
            "ml_dsa_signature": {
                "public_key": pk_ml_dsa_hex,
                "signature": sig_ml_dsa_hex,
                "alg": ML_DSA_ALG,
            },
            "nonce": nonce,
        }
        # This one should succeed
        response = requests.post(f"{api_base_url}/accounts", json=payload)
        assert response.status_code == 200

        # This one should fail with a used nonce
        response = requests.post(f"{api_base_url}/accounts", json=payload)
        assert response.status_code == 400
        assert "Nonce has already been used" in response.text
    # OQS signature is automatically freed when exiting the context


def test_create_account_incorrect_mandatory_pq_alg(api_base_url: str):
    """
    Tests that account creation fails if the mandatory PQ algorithm is not the
    expected one (ML-DSA-87). The server must enforce this specific algorithm
    for the mandatory PQ signature.
    """
    nonce = get_nonce(api_base_url)
    response = requests.post(
        f"{api_base_url}/accounts",
        json={
            "public_key": "test",
            "signature": "test",
            "ml_dsa_signature": {
                "public_key": "test",
                "signature": "test",
                "alg": "Falcon-512",  # Not the mandatory ML-DSA-87
            },
            "nonce": nonce,
        },
    )
    assert response.status_code == 400
    assert "Incorrect mandatory PQ algorithm" in response.text


def test_create_account_unsupported_additional_pq_alg(api_base_url: str):
    """
    Tests that account creation fails if an additional PQ signature uses an
    algorithm that is not supported by the server.
    """
    nonce = get_nonce(api_base_url)
    response = requests.post(
        f"{api_base_url}/accounts",
        json={
            "public_key": "test",
            "signature": "test",
            "ml_dsa_signature": {
                "public_key": "test",
                "signature": "test",
                "alg": ML_DSA_ALG,
            },
            "additional_pq_signatures": [
                {
                    "public_key": "test",
                    "signature": "test",
                    "alg": "UnsupportedAlg",
                }
            ],
            "nonce": nonce,
        },
    )
    assert response.status_code == 400
    assert "Unsupported PQ algorithm" in response.text


def test_create_account_duplicate_pq_alg(api_base_url: str):
    """
    Tests that account creation fails if the request contains multiple signatures
    for the same post-quantum algorithm.
    """
    nonce = get_nonce(api_base_url)
    # Prepare a payload where an additional signature uses the mandatory alg
    response = requests.post(
        f"{api_base_url}/accounts",
        json={
            "public_key": "test",
            "signature": "test",
            "ml_dsa_signature": {
                "public_key": "test_ml_dsa",
                "signature": "test",
                "alg": ML_DSA_ALG,
            },
            "additional_pq_signatures": [
                {
                    "public_key": "test_falcon",
                    "signature": "test",
                    "alg": ML_DSA_ALG,  # Duplicate algorithm
                }
            ],
            "nonce": nonce,
        },
    )
    assert response.status_code == 400
    assert "Duplicate algorithm types are not allowed" in response.text


def test_create_account_invalid_classic_signature(api_base_url: str):
    """
    Tests that account creation fails when the classic ECDSA signature is
    invalid. A signature is considered invalid if it was not created by the
    private key corresponding to the provided public key over the correct
    message. This test simulates this by signing a different message.
    """
    # 1. Get nonce
    nonce = get_nonce(api_base_url)

    # 2. Prepare keys
    sk_classic = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
    vk_classic = sk_classic.get_verifying_key()
    assert vk_classic is not None
    pk_classic_hex = vk_classic.to_string("uncompressed").hex()

    with oqs.Signature(ML_DSA_ALG) as sig_ml_dsa:
        pk_ml_dsa_hex = sig_ml_dsa.generate_keypair().hex()

        # 3. Construct the correct message for other signatures
        message = f"{pk_classic_hex}:{pk_ml_dsa_hex}:{nonce}".encode("utf-8")
        sig_ml_dsa_hex = sig_ml_dsa.sign(message).hex()

        # 4. Create an invalid classic signature by signing a different message
        incorrect_message = b"this is not the message that was expected"
        invalid_sig_classic_hex = sk_classic.sign(
            incorrect_message, hashfunc=hashlib.sha256
        ).hex()

        # 5. Attempt to create account with the invalid signature
        response = requests.post(
            f"{api_base_url}/accounts",
            json={
                "public_key": pk_classic_hex,
                "signature": invalid_sig_classic_hex,
                "ml_dsa_signature": {
                    "public_key": pk_ml_dsa_hex,
                    "signature": sig_ml_dsa_hex,
                    "alg": ML_DSA_ALG,
                },
                "nonce": nonce,
            },
        )

        # 6. Assert failure
        assert response.status_code == 401
        assert "Invalid classic signature" in response.text


def test_create_account_invalid_mandatory_pq_signature(api_base_url: str):
    """
    Tests that account creation fails when the mandatory post-quantum signature
    is invalid. This is simulated by providing a valid signature for the wrong
    message.
    """
    # 1. Get nonce
    nonce = get_nonce(api_base_url)

    # 2. Prepare keys
    sk_classic = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
    vk_classic = sk_classic.get_verifying_key()
    assert vk_classic is not None
    pk_classic_hex = vk_classic.to_string("uncompressed").hex()

    with oqs.Signature(ML_DSA_ALG) as sig_ml_dsa:
        pk_ml_dsa_hex = sig_ml_dsa.generate_keypair().hex()

        # 3. Construct the correct message
        message = f"{pk_classic_hex}:{pk_ml_dsa_hex}:{nonce}".encode("utf-8")
        sig_classic_hex = sk_classic.sign(message, hashfunc=hashlib.sha256).hex()

        # 4. Create an invalid PQ signature by signing a different message
        incorrect_message = b"this is not the message that was expected"
        invalid_sig_ml_dsa_hex = sig_ml_dsa.sign(incorrect_message).hex()

        # 5. Attempt account creation
        response = requests.post(
            f"{api_base_url}/accounts",
            json={
                "public_key": pk_classic_hex,
                "signature": sig_classic_hex,
                "ml_dsa_signature": {
                    "public_key": pk_ml_dsa_hex,
                    "signature": invalid_sig_ml_dsa_hex,
                    "alg": ML_DSA_ALG,
                },
                "nonce": nonce,
            },
        )

        # 6. Assert failure
        assert response.status_code == 401
        assert (
            f"Invalid post-quantum signature for algorithm {ML_DSA_ALG}"
            in response.text
        )


def test_create_account_invalid_additional_pq_signature(api_base_url: str):
    """
    Tests that account creation fails when one of the additional post-quantum
    signatures is invalid. This is simulated by providing a valid signature for
    the wrong message.
    """
    # 1. Get nonce
    nonce = get_nonce(api_base_url)

    # 2. Prepare keys
    sk_classic = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
    vk_classic = sk_classic.get_verifying_key()
    assert vk_classic is not None
    pk_classic_hex = vk_classic.to_string("uncompressed").hex()
    add_pq_alg = "Falcon-512"

    with (
        oqs.Signature(ML_DSA_ALG) as sig_ml_dsa,
        oqs.Signature(add_pq_alg) as sig_add_pq,
    ):
        pk_ml_dsa_hex = sig_ml_dsa.generate_keypair().hex()
        pk_add_pq_hex = sig_add_pq.generate_keypair().hex()

        # 3. Construct the correct message
        message = f"{pk_classic_hex}:{pk_ml_dsa_hex}:{pk_add_pq_hex}:{nonce}".encode(
            "utf-8"
        )

        # 4. Create valid signatures for the correct message
        sig_classic_hex = sk_classic.sign(message, hashfunc=hashlib.sha256).hex()
        sig_ml_dsa_hex = sig_ml_dsa.sign(message).hex()

        # 5. Create an invalid signature for the additional PQ key
        incorrect_message = b"this is not the message that was expected"
        invalid_sig_add_pq_hex = sig_add_pq.sign(incorrect_message).hex()

        # 6. Attempt account creation
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
                "additional_pq_signatures": [
                    {
                        "public_key": pk_add_pq_hex,
                        "signature": invalid_sig_add_pq_hex,
                        "alg": add_pq_alg,
                    }
                ],
                "nonce": nonce,
            },
        )

        # 7. Assert failure
        assert response.status_code == 401
        assert (
            f"Invalid post-quantum signature for algorithm {add_pq_alg}"
            in response.text
        )


def test_create_account_already_exists(api_base_url: str, tmp_path):
    """
    Tests that the server prevents creating a new account with a classic public
    key that is already in use. The classic public key must be unique across
    all accounts.
    This test demonstrates the new API client pattern with automatic resource management.
    """
    # 1. Create an initial account using the new KeyManager-based helper
    client, pk_classic_hex = create_test_account_with_keymanager(api_base_url, tmp_path)

    # 2. Attempt to create a second account with the same classic public key
    with client.signing_keys() as keys:
        sk_classic = keys["classic_sk"]
        nonce2 = get_nonce(api_base_url)

        with oqs.Signature(ML_DSA_ALG) as sig_ml_dsa_new:
            pk_ml_dsa_new_hex = sig_ml_dsa_new.generate_keypair().hex()
            message2 = f"{pk_classic_hex}:{pk_ml_dsa_new_hex}:{nonce2}".encode("utf-8")
            sig2_classic = sk_classic.sign(message2, hashfunc=hashlib.sha256).hex()
            sig2_ml_dsa = sig_ml_dsa_new.sign(message2).hex()

            response2 = requests.post(
                f"{api_base_url}/accounts",
                json={
                    "public_key": pk_classic_hex,  # Same classic PK
                    "signature": sig2_classic,
                    "ml_dsa_signature": {
                        "public_key": pk_ml_dsa_new_hex,  # Different PQ PK
                        "signature": sig2_ml_dsa,
                        "alg": ML_DSA_ALG,
                    },
                    "nonce": nonce2,
                },
            )
            assert response2.status_code == 409
            assert (
                "Account with this classic public key already exists" in response2.text
            )
    # OQS signatures are automatically freed when exiting the context


def test_create_account_expired_nonce(api_base_url: str):
    """
    Tests that an account creation request fails if a nonce has expired.
    Nonces are time-sensitive and should be rejected after their validity
    period (5 minutes).
    """
    # 1. Manually create an expired nonce with a valid signature
    expired_timestamp = str(time.time() - 301)  # 301 seconds in the past
    mac = hmac.new(
        SERVER_SECRET.encode(), expired_timestamp.encode(), hashlib.sha256
    ).hexdigest()
    expired_nonce = f"{expired_timestamp}:{mac}"

    # 2. Attempt to use the expired nonce
    response = requests.post(
        f"{api_base_url}/accounts",
        json={
            "public_key": "test",
            "signature": "test",
            "ml_dsa_signature": {
                "public_key": "test",
                "signature": "test",
                "alg": ML_DSA_ALG,
            },
            "nonce": expired_nonce,
        },
    )
    assert response.status_code == 400
    assert "Invalid or expired nonce" in response.text


def test_create_account_malformed_nonce(api_base_url: str):
    """
    Tests that an account creation request fails if the nonce is malformed and
    does not fit the 'timestamp:mac' format.
    """
    response = requests.post(
        f"{api_base_url}/accounts",
        json={
            "public_key": "test",
            "signature": "test",
            "ml_dsa_signature": {
                "public_key": "test",
                "signature": "test",
                "alg": ML_DSA_ALG,
            },
            "nonce": "malformed:nonce",
        },
    )
    assert response.status_code == 400
    assert "Invalid or expired nonce" in response.text


def test_create_account_missing_field(api_base_url: str):
    """
    Tests that account creation fails if a required field is missing from the
    request payload. This ensures Pydantic model validation is working.
    """
    valid_payload = {
        "public_key": "test",
        "signature": "test",
        "ml_dsa_signature": {
            "public_key": "test",
            "signature": "test",
            "alg": ML_DSA_ALG,
        },
        "nonce": "test_nonce",
    }

    for field in valid_payload:
        payload = valid_payload.copy()
        del payload[field]
        response = requests.post(f"{api_base_url}/accounts", json=payload)
        assert response.status_code == 422, f"Failed for missing field: {field}"


def test_get_accounts_and_account_by_id(api_base_url: str, tmp_path):
    """
    Tests listing all accounts and retrieving individual accounts by public key.
    This test creates multiple accounts to ensure the endpoints handle more than
    one account correctly.

    This test demonstrates using the new DCypherClient for account retrieval
    with automatic resource management.
    """
    from src.lib.api_client import DCypherClient, ResourceNotFoundError

    # 1. Create two distinct accounts using the new KeyManager-based helper
    client1, pk_classic_1_hex = create_test_account_with_keymanager(
        api_base_url, tmp_path / "account1"
    )
    client2, pk_classic_2_hex = create_test_account_with_keymanager(
        api_base_url, tmp_path / "account2"
    )

    # Initialize API client for general operations
    client = DCypherClient(api_base_url)

    # 2. Test get all accounts - using client
    accounts = client.list_accounts()
    # Use sets for order-independent comparison
    assert set(accounts) == {
        pk_classic_1_hex,
        pk_classic_2_hex,
    }

    # 3. Test get single account (Account 1) - using client
    account_details = client.get_account(pk_classic_1_hex)
    assert account_details["public_key"] == pk_classic_1_hex
    assert len(account_details["pq_keys"]) == 1
    assert account_details["pq_keys"][0]["alg"] == ML_DSA_ALG

    # 4. Test get single account (Account 2) - using client
    account_details_2 = client.get_account(pk_classic_2_hex)
    assert account_details_2["public_key"] == pk_classic_2_hex
    assert len(account_details_2["pq_keys"]) == 1
    assert account_details_2["pq_keys"][0]["alg"] == ML_DSA_ALG

    # 5. Test get non-existent account - using client with exception handling
    try:
        client.get_account("nonexistentkey")
        assert False, "Expected ResourceNotFoundError"
    except ResourceNotFoundError:
        pass  # Expected behavior
    # OQS signatures are automatically freed when accounts are cleaned up
