import ecdsa
import hashlib
import oqs
import pytest
import time
from unittest import mock
from fastapi.testclient import TestClient
from src.main import app, accounts, used_nonces, SUPPORTED_SIG_ALGS, ML_DSA_ALG

client = TestClient(app)


@pytest.fixture(autouse=True)
def cleanup():
    """
    Pytest fixture to reset the application state before and after each test.
    This ensures that tests are isolated from each other.
    """
    # Reset state before each test
    accounts.clear()
    used_nonces.clear()
    yield
    # Cleanup after test if needed
    accounts.clear()
    used_nonces.clear()


def get_nonce():
    """
    Helper function to request a nonce from the /nonce endpoint.
    Asserts that the request is successful and returns the nonce.
    """
    response = client.get("/nonce")
    assert response.status_code == 200
    return response.json()["nonce"]


def test_get_nonce_endpoint():
    """
    Tests the /nonce endpoint to ensure it returns a valid, well-formed nonce.
    """
    response = client.get("/nonce")
    assert response.status_code == 200
    data = response.json()
    assert "nonce" in data
    nonce = data["nonce"]
    # The nonce should be in the format "timestamp:mac"
    parts = nonce.split(":")
    assert len(parts) == 2
    # Further validation of the nonce's cryptographic properties is implicitly
    # tested by the various `create_account` tests that consume the nonce.


def test_create_account_successful():
    """
    Tests the successful creation of a hybrid account with one mandatory classic
    signature, one mandatory PQ signature (ML-DSA), and one additional optional
    PQ signature. This covers the full functionality of creating a complex
    hybrid account.
    """
    # 1. Get nonce
    nonce = get_nonce()

    # 2. Prepare classic key
    sk_classic = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
    vk_classic = sk_classic.get_verifying_key()
    assert vk_classic is not None
    pk_classic_hex = vk_classic.to_string("uncompressed").hex()

    # 3. Prepare mandatory PQ key (ML-DSA)
    with oqs.Signature(ML_DSA_ALG) as sig_ml_dsa:
        pk_ml_dsa_hex = sig_ml_dsa.generate_keypair().hex()

        # 4. Prepare additional optional PQ key
        add_pq_alg = "Falcon-512"
        with oqs.Signature(add_pq_alg) as sig_add_pq:
            pk_add_pq_hex = sig_add_pq.generate_keypair().hex()

            # 5. Construct message from all public keys
            all_pks = [pk_classic_hex, pk_ml_dsa_hex, pk_add_pq_hex]
            message = f"{':'.join(all_pks)}:{nonce}".encode("utf-8")

            # 6. Sign with all keys
            sig_classic_hex = sk_classic.sign(message, hashfunc=hashlib.sha256).hex()
            sig_ml_dsa_hex = sig_ml_dsa.sign(message).hex()
            sig_add_pq_hex = sig_add_pq.sign(message).hex()

            # 7. Create account
            payload = {
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
                        "signature": sig_add_pq_hex,
                        "alg": add_pq_alg,
                    }
                ],
                "nonce": nonce,
            }
            response = client.post("/accounts", json=payload)

            # 8. Assert success
            assert response.status_code == 200, response.text
            assert response.json()["message"] == "Account created successfully"
            assert len(accounts) == 1
            account = accounts.pop()
            assert account[0] == pk_classic_hex
            expected_pq_keys = (
                (pk_ml_dsa_hex, ML_DSA_ALG),
                (pk_add_pq_hex, add_pq_alg),
            )
            assert account[1] == expected_pq_keys


def test_create_account_successful_mandatory_only():
    """
    Tests the successful creation of a hybrid account with only the mandatory
    classic and PQ signatures (ML-DSA), without any additional PQ signatures.
    This is the minimal successful account creation scenario.
    """
    # 1. Get nonce
    nonce = get_nonce()

    # 2. Prepare classic key
    sk_classic = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
    vk_classic = sk_classic.get_verifying_key()
    assert vk_classic is not None
    pk_classic_hex = vk_classic.to_string("uncompressed").hex()

    # 3. Prepare mandatory PQ key (ML-DSA)
    with oqs.Signature(ML_DSA_ALG) as sig_ml_dsa:
        pk_ml_dsa_hex = sig_ml_dsa.generate_keypair().hex()

        # 4. Construct message from all public keys and the nonce
        all_pks = [pk_classic_hex, pk_ml_dsa_hex]
        message = f"{':'.join(all_pks)}:{nonce}".encode("utf-8")

        # 5. Sign with all keys
        sig_classic_hex = sk_classic.sign(message, hashfunc=hashlib.sha256).hex()
        sig_ml_dsa_hex = sig_ml_dsa.sign(message).hex()

        # 6. Create account
        payload = {
            "public_key": pk_classic_hex,
            "signature": sig_classic_hex,
            "ml_dsa_signature": {
                "public_key": pk_ml_dsa_hex,
                "signature": sig_ml_dsa_hex,
                "alg": ML_DSA_ALG,
            },
            "nonce": nonce,
        }
        response = client.post("/accounts", json=payload)

        # 7. Assert success
        assert response.status_code == 200, response.text
        assert response.json()["message"] == "Account created successfully"
        assert len(accounts) == 1
        account = accounts.pop()
        assert account[0] == pk_classic_hex
        expected_pq_keys = ((pk_ml_dsa_hex, ML_DSA_ALG),)
        assert account[1] == expected_pq_keys


def test_create_account_invalid_nonce():
    """
    Tests that an account creation request fails if an invalid nonce is provided.
    An invalid nonce is one that does not match the expected format or signature.
    """
    response = client.post(
        "/accounts",
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


def test_create_account_used_nonce():
    """
    Tests that an account creation request fails if a valid but already used
    nonce is provided. This prevents replay attacks.
    """
    nonce = get_nonce()
    used_nonces.add(nonce)  # Manually add to used nonces
    response = client.post(
        "/accounts",
        json={
            "public_key": "test",
            "signature": "test",
            "ml_dsa_signature": {
                "public_key": "test",
                "signature": "test",
                "alg": ML_DSA_ALG,
            },
            "nonce": nonce,
        },
    )
    assert response.status_code == 400
    assert "Nonce has already been used" in response.text


def test_create_account_incorrect_mandatory_pq_alg():
    """
    Tests that account creation fails if the mandatory PQ algorithm is not the
    expected one (ML-DSA-87). The server must enforce this specific algorithm
    for the mandatory PQ signature.
    """
    nonce = get_nonce()
    response = client.post(
        "/accounts",
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


def test_create_account_unsupported_additional_pq_alg():
    """
    Tests that account creation fails if an additional PQ signature uses an
    algorithm that is not supported by the server.
    """
    nonce = get_nonce()
    response = client.post(
        "/accounts",
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


def test_create_account_invalid_classic_signature():
    """
    Tests that account creation fails when the classic ECDSA signature is
    invalid. A signature is considered invalid if it was not created by the
    private key corresponding to the provided public key over the correct
    message. This test simulates this by signing a different message.
    """
    # 1. Get nonce
    nonce = get_nonce()

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
        response = client.post(
            "/accounts",
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


def test_create_account_invalid_mandatory_pq_signature():
    """
    Tests that account creation fails when the mandatory post-quantum signature
    is invalid. This is simulated by providing a valid signature for the wrong
    message.
    """
    # 1. Get nonce
    nonce = get_nonce()

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
        response = client.post(
            "/accounts",
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


def test_create_account_invalid_additional_pq_signature():
    """
    Tests that account creation fails when one of the additional post-quantum
    signatures is invalid. This is simulated by providing a valid signature for
    the wrong message.
    """
    # 1. Get nonce
    nonce = get_nonce()

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
        response = client.post(
            "/accounts",
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


def test_create_account_already_exists():
    """
    Tests that the server prevents creating a new account with a classic public
    key that is already in use. The classic public key must be unique across
    all accounts.
    """
    # 1. Create an initial account
    nonce1 = get_nonce()
    sk_classic = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
    vk_classic = sk_classic.get_verifying_key()
    assert vk_classic is not None
    pk_classic_hex = vk_classic.to_string("uncompressed").hex()

    with oqs.Signature(ML_DSA_ALG) as sig_ml_dsa:
        pk_ml_dsa_hex = sig_ml_dsa.generate_keypair().hex()
        message1 = f"{pk_classic_hex}:{pk_ml_dsa_hex}:{nonce1}".encode("utf-8")
        sig1_classic = sk_classic.sign(message1, hashfunc=hashlib.sha256).hex()
        sig1_ml_dsa = sig_ml_dsa.sign(message1).hex()
        response = client.post(
            "/accounts",
            json={
                "public_key": pk_classic_hex,
                "signature": sig1_classic,
                "ml_dsa_signature": {
                    "public_key": pk_ml_dsa_hex,
                    "signature": sig1_ml_dsa,
                    "alg": ML_DSA_ALG,
                },
                "nonce": nonce1,
            },
        )
        assert response.status_code == 200, response.text

    # 2. Attempt to create a second account with the same classic public key
    nonce2 = get_nonce()
    with oqs.Signature(ML_DSA_ALG) as sig_ml_dsa_new:
        pk_ml_dsa_new_hex = sig_ml_dsa_new.generate_keypair().hex()
        message2 = f"{pk_classic_hex}:{pk_ml_dsa_new_hex}:{nonce2}".encode("utf-8")
        sig2_classic = sk_classic.sign(message2, hashfunc=hashlib.sha256).hex()
        sig2_ml_dsa = sig_ml_dsa_new.sign(message2).hex()

        response2 = client.post(
            "/accounts",
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
        assert "Account with this classic public key already exists" in response2.text


def test_create_account_expired_nonce():
    """
    Tests that an account creation request fails if a nonce has expired.
    Nonces are time-sensitive and should be rejected after their validity
    period (5 minutes).
    """
    with mock.patch("src.main.time") as mock_time:
        # 1. Get a nonce at a specific time
        mock_time.time.return_value = 1000.0
        nonce = get_nonce()

        # 2. Simulate time passing beyond the expiration date
        mock_time.time.return_value = 1000.0 + 301.0  # 301 seconds later

        # 3. Attempt to use the expired nonce
        response = client.post(
            "/accounts",
            json={
                "public_key": "test",
                "signature": "test",
                "ml_dsa_signature": {
                    "public_key": "test",
                    "signature": "test",
                    "alg": ML_DSA_ALG,
                },
                "nonce": nonce,
            },
        )
        assert response.status_code == 400
        assert "Invalid or expired nonce" in response.text


def test_create_account_malformed_nonce():
    """
    Tests that an account creation request fails if the nonce is malformed and
    does not fit the 'timestamp:mac' format.
    """
    response = client.post(
        "/accounts",
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


def test_create_account_missing_field():
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
        response = client.post("/accounts", json=payload)
        assert response.status_code == 422, f"Failed for missing field: {field}"


def test_get_supported_pq_algs():
    """
    Tests the /supported-pq-algs endpoint.
    It verifies that the endpoint returns a 200 OK status and that the list of
    algorithms in the response body matches the list defined in the application.
    """
    response = client.get("/supported-pq-algs")
    assert response.status_code == 200
    # Convert to set for order-independent comparison
    assert set(response.json()["algorithms"]) == set(SUPPORTED_SIG_ALGS)


def test_get_accounts_and_account_by_id():
    """
    Tests listing all accounts and retrieving individual accounts by public key.
    This test creates multiple accounts to ensure the endpoints handle more than
    one account correctly.
    """
    # 1. Create two distinct accounts
    # Account 1
    sk_classic_1 = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
    vk_classic_1 = sk_classic_1.get_verifying_key()
    assert vk_classic_1 is not None
    pk_classic_1_hex = vk_classic_1.to_string("uncompressed").hex()
    with oqs.Signature(ML_DSA_ALG) as sig_ml_dsa_1:
        pk_ml_dsa_1_hex = sig_ml_dsa_1.generate_keypair().hex()
        nonce1 = get_nonce()
        message1 = f"{pk_classic_1_hex}:{pk_ml_dsa_1_hex}:{nonce1}".encode("utf-8")
        sig1_classic = sk_classic_1.sign(message1, hashfunc=hashlib.sha256).hex()
        sig1_ml_dsa = sig_ml_dsa_1.sign(message1).hex()
        client.post(
            "/accounts",
            json={
                "public_key": pk_classic_1_hex,
                "signature": sig1_classic,
                "ml_dsa_signature": {
                    "public_key": pk_ml_dsa_1_hex,
                    "signature": sig1_ml_dsa,
                    "alg": ML_DSA_ALG,
                },
                "nonce": nonce1,
            },
        )

    # Account 2
    sk_classic_2 = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
    vk_classic_2 = sk_classic_2.get_verifying_key()
    assert vk_classic_2 is not None
    pk_classic_2_hex = vk_classic_2.to_string("uncompressed").hex()
    with oqs.Signature(ML_DSA_ALG) as sig_ml_dsa_2:
        pk_ml_dsa_2_hex = sig_ml_dsa_2.generate_keypair().hex()
        nonce2 = get_nonce()
        message2 = f"{pk_classic_2_hex}:{pk_ml_dsa_2_hex}:{nonce2}".encode("utf-8")
        sig2_classic = sk_classic_2.sign(message2, hashfunc=hashlib.sha256).hex()
        sig2_ml_dsa = sig_ml_dsa_2.sign(message2).hex()
        client.post(
            "/accounts",
            json={
                "public_key": pk_classic_2_hex,
                "signature": sig2_classic,
                "ml_dsa_signature": {
                    "public_key": pk_ml_dsa_2_hex,
                    "signature": sig2_ml_dsa,
                    "alg": ML_DSA_ALG,
                },
                "nonce": nonce2,
            },
        )

    # 2. Test get all accounts
    response = client.get("/accounts")
    assert response.status_code == 200
    # Use sets for order-independent comparison
    assert set(response.json()["accounts"]) == {pk_classic_1_hex, pk_classic_2_hex}

    # 3. Test get single account (Account 1)
    response = client.get(f"/accounts/{pk_classic_1_hex}")
    assert response.status_code == 200
    expected_pq_keys_1 = [{"public_key": pk_ml_dsa_1_hex, "alg": ML_DSA_ALG}]
    assert response.json() == {
        "public_key": pk_classic_1_hex,
        "pq_keys": expected_pq_keys_1,
    }

    # 4. Test get single account (Account 2)
    response = client.get(f"/accounts/{pk_classic_2_hex}")
    assert response.status_code == 200
    expected_pq_keys_2 = [{"public_key": pk_ml_dsa_2_hex, "alg": ML_DSA_ALG}]
    assert response.json() == {
        "public_key": pk_classic_2_hex,
        "pq_keys": expected_pq_keys_2,
    }

    # 5. Test get non-existent account
    response = client.get("/accounts/nonexistentkey")
    assert response.status_code == 404
