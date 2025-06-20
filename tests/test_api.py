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
            account = accounts[pk_classic_hex]
            expected_pq_keys = {
                ML_DSA_ALG: pk_ml_dsa_hex,
                add_pq_alg: pk_add_pq_hex,
            }
            assert account == expected_pq_keys


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
        account = accounts[pk_classic_hex]
        expected_pq_keys = {ML_DSA_ALG: pk_ml_dsa_hex}
        assert account == expected_pq_keys


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
    # Response should be a list of dicts, so we compare item by item
    assert len(response.json()["pq_keys"]) == 1
    assert response.json()["pq_keys"][0] == expected_pq_keys_1[0]
    assert response.json()["public_key"] == pk_classic_1_hex

    # 4. Test get single account (Account 2)
    response = client.get(f"/accounts/{pk_classic_2_hex}")
    assert response.status_code == 200
    expected_pq_keys_2 = [{"public_key": pk_ml_dsa_2_hex, "alg": ML_DSA_ALG}]
    assert len(response.json()["pq_keys"]) == 1
    assert response.json()["pq_keys"][0] == expected_pq_keys_2[0]
    assert response.json()["public_key"] == pk_classic_2_hex

    # 5. Test get non-existent account
    response = client.get("/accounts/nonexistentkey")
    assert response.status_code == 404


def test_add_and_remove_pq_keys():
    """
    Tests the full lifecycle of an account's post-quantum keys:
    1. Create an account with a classic key and two PQ keys.
    2. Successfully add a new PQ key.
    3. Successfully remove an optional PQ key.
    4. Verify the state of the account after each operation.
    """
    sk_classic = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
    vk_classic = sk_classic.get_verifying_key()
    assert vk_classic is not None
    pk_classic_hex = vk_classic.to_string("uncompressed").hex()
    add_pq_alg_1 = "Falcon-512"
    add_pq_alg_2 = "Falcon-1024"
    all_pq_sks = {}  # {pk_hex: (oqs_sig_obj, alg)}

    with (
        oqs.Signature(ML_DSA_ALG) as sig_ml_dsa,
        oqs.Signature(add_pq_alg_1) as sig_add_pq_1,
        oqs.Signature(add_pq_alg_2) as sig_add_pq_2,
    ):
        # === 1. Create an account with two PQ keys (one mandatory, one optional) ===
        pk_ml_dsa_hex = sig_ml_dsa.generate_keypair().hex()
        all_pq_sks[pk_ml_dsa_hex] = (sig_ml_dsa, ML_DSA_ALG)
        pk_add_pq_1_hex = sig_add_pq_1.generate_keypair().hex()
        all_pq_sks[pk_add_pq_1_hex] = (sig_add_pq_1, add_pq_alg_1)

        # Create account
        nonce1 = get_nonce()
        all_pks_creation = [pk_classic_hex, pk_ml_dsa_hex, pk_add_pq_1_hex]
        message1 = f"{':'.join(all_pks_creation)}:{nonce1}".encode("utf-8")
        sig_classic1 = sk_classic.sign(message1, hashfunc=hashlib.sha256).hex()
        sig_ml_dsa1 = sig_ml_dsa.sign(message1).hex()
        sig_add_pq_1_hex = sig_add_pq_1.sign(message1).hex()
        create_payload = {
            "public_key": pk_classic_hex,
            "signature": sig_classic1,
            "ml_dsa_signature": {
                "public_key": pk_ml_dsa_hex,
                "signature": sig_ml_dsa1,
                "alg": ML_DSA_ALG,
            },
            "additional_pq_signatures": [
                {
                    "public_key": pk_add_pq_1_hex,
                    "signature": sig_add_pq_1_hex,
                    "alg": add_pq_alg_1,
                }
            ],
            "nonce": nonce1,
        }
        response = client.post("/accounts", json=create_payload)
        assert response.status_code == 200

        # Verify initial account state
        response = client.get(f"/accounts/{pk_classic_hex}")
        assert response.status_code == 200
        assert len(response.json()["pq_keys"]) == 2

        # === 2. Add a new PQ key ===
        pk_add_pq_2_hex = sig_add_pq_2.generate_keypair().hex()
        all_pq_sks[pk_add_pq_2_hex] = (sig_add_pq_2, add_pq_alg_2)
        nonce2 = get_nonce()
        message2 = f"ADD-PQ:{pk_classic_hex}:{add_pq_alg_2}:{nonce2}".encode("utf-8")

        # Sign with all keys currently on the account, plus the new key
        classic_sig2 = sk_classic.sign(message2, hashfunc=hashlib.sha256).hex()
        existing_pq_sigs = [
            {
                "public_key": pk_ml_dsa_hex,
                "signature": sig_ml_dsa.sign(message2).hex(),
                "alg": ML_DSA_ALG,
            },
            {
                "public_key": pk_add_pq_1_hex,
                "signature": sig_add_pq_1.sign(message2).hex(),
                "alg": add_pq_alg_1,
            },
        ]
        new_pq_sig = {
            "public_key": pk_add_pq_2_hex,
            "signature": sig_add_pq_2.sign(message2).hex(),
            "alg": add_pq_alg_2,
        }

        add_payload = {
            "new_pq_signatures": [new_pq_sig],
            "classic_signature": classic_sig2,
            "existing_pq_signatures": existing_pq_sigs,
            "nonce": nonce2,
        }
        response = client.post(
            f"/accounts/{pk_classic_hex}/add-pq-keys", json=add_payload
        )
        assert response.status_code == 200, response.text
        assert response.json()["message"] == "Successfully added 1 PQ key(s)."

        # Verify account state after adding key
        response = client.get(f"/accounts/{pk_classic_hex}")
        assert response.status_code == 200
        pq_keys_after_add = response.json()["pq_keys"]
        assert len(pq_keys_after_add) == 3
        assert any(k["public_key"] == pk_add_pq_2_hex for k in pq_keys_after_add)

        # === 3. Remove an optional PQ key ===
        alg_to_remove = add_pq_alg_1
        pk_to_remove = pk_add_pq_1_hex
        nonce3 = get_nonce()
        message3 = f"REMOVE-PQ:{pk_classic_hex}:{alg_to_remove}:{nonce3}".encode(
            "utf-8"
        )

        classic_sig3 = sk_classic.sign(message3, hashfunc=hashlib.sha256).hex()

        # Get all active keys for signing
        active_pks = accounts[pk_classic_hex]
        all_pq_sigs3 = []
        for alg, pk in active_pks.items():
            signer = all_pq_sks[pk][0]
            all_pq_sigs3.append(
                {"public_key": pk, "signature": signer.sign(message3).hex(), "alg": alg}
            )

        remove_payload = {
            "algs_to_remove": [alg_to_remove],
            "classic_signature": classic_sig3,
            "pq_signatures": all_pq_sigs3,
            "nonce": nonce3,
        }
        response = client.post(
            f"/accounts/{pk_classic_hex}/remove-pq-keys", json=remove_payload
        )
        assert response.status_code == 200, response.text
        assert response.json()["message"] == "Successfully removed PQ key(s)."
        del all_pq_sks[pk_to_remove]  # Update our local record

        # Verify final account state
        response = client.get(f"/accounts/{pk_classic_hex}")
        assert response.status_code == 200
        keys_after_remove = response.json()["pq_keys"]
        assert len(keys_after_remove) == 2
        assert not any(k["public_key"] == pk_to_remove for k in keys_after_remove)
        assert any(k["public_key"] == pk_ml_dsa_hex for k in keys_after_remove)
        assert any(k["public_key"] == pk_add_pq_2_hex for k in keys_after_remove)


def test_remove_mandatory_pq_key_fails():
    """
    Tests that an attempt to remove the mandatory ML-DSA key from an account
    is rejected with a 400 error.
    """
    # 1. Create a minimal account
    sk_classic = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
    vk_classic = sk_classic.get_verifying_key()
    assert vk_classic is not None
    pk_classic_hex = vk_classic.to_string("uncompressed").hex()
    with oqs.Signature(ML_DSA_ALG) as sig_ml_dsa:
        pk_ml_dsa_hex = sig_ml_dsa.generate_keypair().hex()
        nonce1 = get_nonce()
        message1 = f"{pk_classic_hex}:{pk_ml_dsa_hex}:{nonce1}".encode("utf-8")
        sig_classic = sk_classic.sign(message1, hashfunc=hashlib.sha256).hex()
        sig_ml_dsa_hex = sig_ml_dsa.sign(message1).hex()
        client.post(
            "/accounts",
            json={
                "public_key": pk_classic_hex,
                "signature": sig_classic,
                "ml_dsa_signature": {
                    "public_key": pk_ml_dsa_hex,
                    "signature": sig_ml_dsa_hex,
                    "alg": ML_DSA_ALG,
                },
                "nonce": nonce1,
            },
        )

    # 2. Attempt to remove the mandatory key
    nonce2 = get_nonce()
    message2 = f"REMOVE-PQ:{pk_classic_hex}:{ML_DSA_ALG}:{nonce2}".encode("utf-8")
    classic_sig2 = sk_classic.sign(message2, hashfunc=hashlib.sha256).hex()
    pq_sig2 = {
        "public_key": pk_ml_dsa_hex,
        "signature": sig_ml_dsa.sign(message2).hex(),
        "alg": ML_DSA_ALG,
    }
    remove_payload = {
        "algs_to_remove": [ML_DSA_ALG],
        "classic_signature": classic_sig2,
        "pq_signatures": [pq_sig2],
        "nonce": nonce2,
    }
    response = client.post(
        f"/accounts/{pk_classic_hex}/remove-pq-keys", json=remove_payload
    )
    assert response.status_code == 400
    assert f"Cannot remove the mandatory PQ key ({ML_DSA_ALG})" in response.text


def test_add_pq_key_authorization_failures():
    """
    Tests various authorization failure scenarios when adding a PQ key.
    - Invalid classic signature.
    - Missing signature from an existing PQ key.
    - Invalid signature from an existing PQ key.
    - Invalid signature for the new PQ key itself.
    """
    # 1. Setup: Create an account with one mandatory and one optional key
    sk_classic = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
    vk_classic = sk_classic.get_verifying_key()
    assert vk_classic is not None
    pk_classic_hex = vk_classic.to_string("uncompressed").hex()
    add_pq_alg_1 = "Falcon-512"
    add_pq_alg_2 = "Falcon-1024"

    with (
        oqs.Signature(ML_DSA_ALG) as sig_ml_dsa,
        oqs.Signature(add_pq_alg_1) as sig_add_pq_1,
        oqs.Signature(add_pq_alg_2) as sig_add_pq_2,
    ):
        # Create the initial account
        pk_ml_dsa_hex = sig_ml_dsa.generate_keypair().hex()
        pk_add_pq_1_hex = sig_add_pq_1.generate_keypair().hex()
        nonce1 = get_nonce()
        create_msg = (
            f"{pk_classic_hex}:{pk_ml_dsa_hex}:{pk_add_pq_1_hex}:{nonce1}".encode()
        )
        create_payload = {
            "public_key": pk_classic_hex,
            "signature": sk_classic.sign(create_msg, hashfunc=hashlib.sha256).hex(),
            "ml_dsa_signature": {
                "public_key": pk_ml_dsa_hex,
                "signature": sig_ml_dsa.sign(create_msg).hex(),
                "alg": ML_DSA_ALG,
            },
            "additional_pq_signatures": [
                {
                    "public_key": pk_add_pq_1_hex,
                    "signature": sig_add_pq_1.sign(create_msg).hex(),
                    "alg": add_pq_alg_1,
                }
            ],
            "nonce": nonce1,
        }
        client.post("/accounts", json=create_payload)

        # 2. Prepare for a valid "add" operation
        pk_add_pq_2_hex = sig_add_pq_2.generate_keypair().hex()
        add_nonce = get_nonce()
        correct_add_msg = f"ADD-PQ:{pk_classic_hex}:{add_pq_alg_2}:{add_nonce}".encode()
        incorrect_msg = b"this is not the correct message"

        valid_classic_sig = sk_classic.sign(
            correct_add_msg, hashfunc=hashlib.sha256
        ).hex()
        valid_existing_sigs = [
            {
                "public_key": pk_ml_dsa_hex,
                "signature": sig_ml_dsa.sign(correct_add_msg).hex(),
                "alg": ML_DSA_ALG,
            },
            {
                "public_key": pk_add_pq_1_hex,
                "signature": sig_add_pq_1.sign(correct_add_msg).hex(),
                "alg": add_pq_alg_1,
            },
        ]
        valid_new_sig = {
            "public_key": pk_add_pq_2_hex,
            "signature": sig_add_pq_2.sign(correct_add_msg).hex(),
            "alg": add_pq_alg_2,
        }

        # --- Test Cases ---

        # Case 1: Invalid classic signature
        payload = {
            "new_pq_signatures": [valid_new_sig],
            "classic_signature": sk_classic.sign(
                incorrect_msg, hashfunc=hashlib.sha256
            ).hex(),
            "existing_pq_signatures": valid_existing_sigs,
            "nonce": add_nonce,
        }
        response = client.post(f"/accounts/{pk_classic_hex}/add-pq-keys", json=payload)
        assert response.status_code == 401
        assert "Invalid classic signature" in response.text

        # Case 2: Missing signature from an existing PQ key
        payload["classic_signature"] = valid_classic_sig
        payload["existing_pq_signatures"] = [valid_existing_sigs[0]]  # Missing one
        response = client.post(f"/accounts/{pk_classic_hex}/add-pq-keys", json=payload)
        assert response.status_code == 401
        assert "Signatures from all existing PQ keys are required" in response.text

        # Case 3: Invalid signature from an existing PQ key
        invalid_existing_sigs = [
            valid_existing_sigs[0],
            {
                "public_key": pk_add_pq_1_hex,
                "signature": sig_add_pq_1.sign(incorrect_msg).hex(),
                "alg": add_pq_alg_1,
            },
        ]
        payload["existing_pq_signatures"] = invalid_existing_sigs
        response = client.post(f"/accounts/{pk_classic_hex}/add-pq-keys", json=payload)
        assert response.status_code == 401
        assert f"Invalid signature for existing PQ key" in response.text

        # Case 4: Invalid signature for the new PQ key itself
        invalid_new_sig = {
            "public_key": pk_add_pq_2_hex,
            "signature": sig_add_pq_2.sign(incorrect_msg).hex(),
            "alg": add_pq_alg_2,
        }
        payload["existing_pq_signatures"] = valid_existing_sigs
        payload["new_pq_signatures"] = [invalid_new_sig]
        response = client.post(f"/accounts/{pk_classic_hex}/add-pq-keys", json=payload)
        assert response.status_code == 401
        assert f"Invalid signature for new PQ key" in response.text


def test_add_pq_key_input_validation_failures():
    """
    Tests various input validation failure scenarios when adding a PQ key.
    - Adding a key for an algorithm that already exists (should replace).
    - Adding a key with an unsupported algorithm.
    """
    # 1. Setup: Create an account with one mandatory and one optional key
    sk_classic = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
    vk_classic = sk_classic.get_verifying_key()
    assert vk_classic is not None
    pk_classic_hex = vk_classic.to_string("uncompressed").hex()
    add_pq_alg_1 = "Falcon-512"

    with (
        oqs.Signature(ML_DSA_ALG) as sig_ml_dsa,
        oqs.Signature(add_pq_alg_1) as sig_add_pq_1,
    ):
        # Create the initial account
        pk_ml_dsa_hex = sig_ml_dsa.generate_keypair().hex()
        pk_add_pq_1_hex = sig_add_pq_1.generate_keypair().hex()
        nonce1 = get_nonce()
        create_msg = (
            f"{pk_classic_hex}:{pk_ml_dsa_hex}:{pk_add_pq_1_hex}:{nonce1}".encode()
        )
        create_payload = {
            "public_key": pk_classic_hex,
            "signature": sk_classic.sign(create_msg, hashfunc=hashlib.sha256).hex(),
            "ml_dsa_signature": {
                "public_key": pk_ml_dsa_hex,
                "signature": sig_ml_dsa.sign(create_msg).hex(),
                "alg": ML_DSA_ALG,
            },
            "additional_pq_signatures": [
                {
                    "public_key": pk_add_pq_1_hex,
                    "signature": sig_add_pq_1.sign(create_msg).hex(),
                    "alg": add_pq_alg_1,
                }
            ],
            "nonce": nonce1,
        }
        client.post("/accounts", json=create_payload)

        # --- Test Cases ---

        # Case 1: Adding a key that already exists by algorithm type
        add_nonce = get_nonce()
        add_msg = f"ADD-PQ:{pk_classic_hex}:{add_pq_alg_1}:{add_nonce}".encode()
        # We need a new key pair for the same algorithm to replace the old one
        with oqs.Signature(add_pq_alg_1) as sig_add_pq_1_new:
            pk_add_pq_1_new_hex = sig_add_pq_1_new.generate_keypair().hex()
            payload = {
                "new_pq_signatures": [
                    {
                        "public_key": pk_add_pq_1_new_hex,
                        "signature": sig_add_pq_1_new.sign(add_msg).hex(),
                        "alg": add_pq_alg_1,
                    }
                ],
                "classic_signature": sk_classic.sign(
                    add_msg, hashfunc=hashlib.sha256
                ).hex(),
                "existing_pq_signatures": [
                    {
                        "public_key": pk_ml_dsa_hex,
                        "signature": sig_ml_dsa.sign(add_msg).hex(),
                        "alg": ML_DSA_ALG,
                    },
                    {
                        "public_key": pk_add_pq_1_hex,
                        "signature": sig_add_pq_1.sign(add_msg).hex(),
                        "alg": add_pq_alg_1,
                    },
                ],
                "nonce": add_nonce,
            }
            response = client.post(
                f"/accounts/{pk_classic_hex}/add-pq-keys", json=payload
            )
            assert response.status_code == 200, response.text
            assert "Successfully added 1 PQ key(s)" in response.json()["message"]

            # Verify state after adding: key count should be the same
            response = client.get(f"/accounts/{pk_classic_hex}")
            keys_after_add = response.json()["pq_keys"]
            assert len(keys_after_add) == 2

            # Verify the old key is in the graveyard
            response = client.get(f"/accounts/{pk_classic_hex}/graveyard")
            assert response.status_code == 200
            graveyard_keys = response.json()["graveyard"]
            assert len(graveyard_keys) == 1
            assert graveyard_keys[0]["public_key"] == pk_add_pq_1_hex
            assert graveyard_keys[0]["alg"] == add_pq_alg_1

            # Verify the new key is active
            active_pks = {k["public_key"] for k in keys_after_add}
            assert pk_add_pq_1_new_hex in active_pks, "New key should be active"
            assert pk_add_pq_1_hex not in active_pks, "Old key should not be active"

        # Case 2: Adding a key with an unsupported algorithm
        unsupported_alg = "Unsupported-Alg"
        unsupported_nonce = get_nonce()
        # The message to sign doesn't matter as much as the nonce check will fail first
        # if the nonce is bad, but we create a valid one for correctness.
        unsupported_msg = (
            f"ADD-PQ:{pk_classic_hex}:{unsupported_alg}:{unsupported_nonce}".encode()
        )
        payload = {
            "new_pq_signatures": [
                {"public_key": "junk", "signature": "junk", "alg": unsupported_alg}
            ],
            "classic_signature": sk_classic.sign(
                unsupported_msg, hashfunc=hashlib.sha256
            ).hex(),
            "existing_pq_signatures": [
                {
                    "public_key": pk_ml_dsa_hex,
                    "signature": sig_ml_dsa.sign(unsupported_msg).hex(),
                    "alg": ML_DSA_ALG,
                },
                {
                    "public_key": pk_add_pq_1_hex,
                    "signature": sig_add_pq_1.sign(unsupported_msg).hex(),
                    "alg": add_pq_alg_1,
                },
            ],
            "nonce": unsupported_nonce,
        }
        response = client.post(f"/accounts/{pk_classic_hex}/add-pq-keys", json=payload)
        assert response.status_code == 400
        assert f"Unsupported PQ algorithm: {unsupported_alg}" in response.text


def test_remove_pq_key_authorization_failures():
    """
    Tests various authorization failure scenarios when removing a PQ key.
    - Invalid classic signature.
    - Missing signature from an existing PQ key.
    """
    # 1. Setup: Create an account with one mandatory and two optional keys
    sk_classic = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
    vk_classic = sk_classic.get_verifying_key()
    assert vk_classic is not None
    pk_classic_hex = vk_classic.to_string("uncompressed").hex()
    add_pq_alg_1 = "Falcon-512"
    add_pq_alg_2 = "Falcon-1024"

    with (
        oqs.Signature(ML_DSA_ALG) as sig_ml_dsa,
        oqs.Signature(add_pq_alg_1) as sig_add_pq_1,
        oqs.Signature(add_pq_alg_2) as sig_add_pq_2,
    ):
        # Create the initial account
        pk_ml_dsa_hex = sig_ml_dsa.generate_keypair().hex()
        pk_add_pq_1_hex = sig_add_pq_1.generate_keypair().hex()
        pk_add_pq_2_hex = sig_add_pq_2.generate_keypair().hex()
        nonce1 = get_nonce()
        create_pks = [pk_classic_hex, pk_ml_dsa_hex, pk_add_pq_1_hex, pk_add_pq_2_hex]
        create_msg = f"{':'.join(create_pks)}:{nonce1}".encode()
        create_payload = {
            "public_key": pk_classic_hex,
            "signature": sk_classic.sign(create_msg, hashfunc=hashlib.sha256).hex(),
            "ml_dsa_signature": {
                "public_key": pk_ml_dsa_hex,
                "signature": sig_ml_dsa.sign(create_msg).hex(),
                "alg": ML_DSA_ALG,
            },
            "additional_pq_signatures": [
                {
                    "public_key": pk_add_pq_1_hex,
                    "signature": sig_add_pq_1.sign(create_msg).hex(),
                    "alg": add_pq_alg_1,
                },
                {
                    "public_key": pk_add_pq_2_hex,
                    "signature": sig_add_pq_2.sign(create_msg).hex(),
                    "alg": add_pq_alg_2,
                },
            ],
            "nonce": nonce1,
        }
        client.post("/accounts", json=create_payload)

        # 2. Prepare for a valid "remove" operation
        pk_to_remove = pk_add_pq_1_hex
        alg_to_remove = add_pq_alg_1
        remove_nonce = get_nonce()
        correct_remove_msg = (
            f"REMOVE-PQ:{pk_classic_hex}:{alg_to_remove}:{remove_nonce}".encode()
        )
        incorrect_msg = b"this is not the correct message"

        valid_classic_sig = sk_classic.sign(
            correct_remove_msg, hashfunc=hashlib.sha256
        ).hex()
        valid_pq_sigs = [
            {
                "public_key": pk_ml_dsa_hex,
                "signature": sig_ml_dsa.sign(correct_remove_msg).hex(),
                "alg": ML_DSA_ALG,
            },
            {
                "public_key": pk_add_pq_1_hex,
                "signature": sig_add_pq_1.sign(correct_remove_msg).hex(),
                "alg": add_pq_alg_1,
            },
            {
                "public_key": pk_add_pq_2_hex,
                "signature": sig_add_pq_2.sign(correct_remove_msg).hex(),
                "alg": add_pq_alg_2,
            },
        ]

        # --- Test Cases ---

        # Case 1: Invalid classic signature
        payload = {
            "algs_to_remove": [alg_to_remove],
            "classic_signature": sk_classic.sign(
                incorrect_msg, hashfunc=hashlib.sha256
            ).hex(),
            "pq_signatures": valid_pq_sigs,
            "nonce": remove_nonce,
        }
        response = client.post(
            f"/accounts/{pk_classic_hex}/remove-pq-keys", json=payload
        )
        assert response.status_code == 401
        assert "Invalid classic signature" in response.text

        # Case 2: Missing signature from an existing PQ key
        payload["classic_signature"] = valid_classic_sig
        payload["pq_signatures"] = [valid_pq_sigs[0], valid_pq_sigs[2]]  # Missing one
        response = client.post(
            f"/accounts/{pk_classic_hex}/remove-pq-keys", json=payload
        )
        assert response.status_code == 401
        assert "Signatures from all existing PQ keys are required" in response.text


def test_remove_nonexistent_pq_key_fails():
    """
    Tests that removing a PQ key not on the account fails.
    """
    # 1. Setup: Create a standard account
    sk_classic = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
    vk_classic = sk_classic.get_verifying_key()
    assert vk_classic is not None
    pk_classic_hex = vk_classic.to_string("uncompressed").hex()
    with oqs.Signature(ML_DSA_ALG) as sig_ml_dsa:
        pk_ml_dsa_hex = sig_ml_dsa.generate_keypair().hex()
        nonce1 = get_nonce()
        create_msg = f"{pk_classic_hex}:{pk_ml_dsa_hex}:{nonce1}".encode()
        client.post(
            "/accounts",
            json={
                "public_key": pk_classic_hex,
                "signature": sk_classic.sign(create_msg, hashfunc=hashlib.sha256).hex(),
                "ml_dsa_signature": {
                    "public_key": pk_ml_dsa_hex,
                    "signature": sig_ml_dsa.sign(create_msg).hex(),
                    "alg": ML_DSA_ALG,
                },
                "nonce": nonce1,
            },
        )

    # 2. Attempt to remove a key that doesn't exist
    alg_to_remove = "nonexistent-alg"
    remove_nonce = get_nonce()
    remove_msg = f"REMOVE-PQ:{pk_classic_hex}:{alg_to_remove}:{remove_nonce}".encode()
    payload = {
        "algs_to_remove": [alg_to_remove],
        "classic_signature": sk_classic.sign(remove_msg, hashfunc=hashlib.sha256).hex(),
        "pq_signatures": [
            {
                "public_key": pk_ml_dsa_hex,
                "signature": sig_ml_dsa.sign(remove_msg).hex(),
                "alg": ML_DSA_ALG,
            }
        ],
        "nonce": remove_nonce,
    }
    response = client.post(f"/accounts/{pk_classic_hex}/remove-pq-keys", json=payload)
    assert response.status_code == 404
    assert (
        f"PQ key for algorithm {alg_to_remove} not found on account." in response.text
    )


def test_add_and_remove_multiple_pq_keys():
    """
    Tests adding and removing multiple PQ keys in a single request.
    """
    # 1. Setup: Create a minimal account
    sk_classic = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
    vk_classic = sk_classic.get_verifying_key()
    assert vk_classic is not None
    pk_classic_hex = vk_classic.to_string("uncompressed").hex()
    add_pq_alg_1 = "Falcon-512"
    add_pq_alg_2 = "Falcon-1024"

    with (
        oqs.Signature(ML_DSA_ALG) as sig_ml_dsa,
        oqs.Signature(add_pq_alg_1) as sig_add_pq_1,
        oqs.Signature(add_pq_alg_2) as sig_add_pq_2,
    ):
        # Create the initial account
        pk_ml_dsa_hex = sig_ml_dsa.generate_keypair().hex()
        nonce1 = get_nonce()
        create_msg = f"{pk_classic_hex}:{pk_ml_dsa_hex}:{nonce1}".encode()
        client.post(
            "/accounts",
            json={
                "public_key": pk_classic_hex,
                "signature": sk_classic.sign(create_msg, hashfunc=hashlib.sha256).hex(),
                "ml_dsa_signature": {
                    "public_key": pk_ml_dsa_hex,
                    "signature": sig_ml_dsa.sign(create_msg).hex(),
                    "alg": ML_DSA_ALG,
                },
                "nonce": nonce1,
            },
        )
        response = client.get(f"/accounts/{pk_classic_hex}")
        assert len(response.json()["pq_keys"]) == 1

        # 2. Add two new PQ keys in a single request
        pk_add_pq_1_hex = sig_add_pq_1.generate_keypair().hex()
        pk_add_pq_2_hex = sig_add_pq_2.generate_keypair().hex()
        add_nonce = get_nonce()
        new_pks_str = ":".join(sorted([pk_add_pq_1_hex, pk_add_pq_2_hex]))
        add_algs_str = ":".join(sorted([add_pq_alg_1, add_pq_alg_2]))
        add_msg = f"ADD-PQ:{pk_classic_hex}:{add_algs_str}:{add_nonce}".encode()

        add_payload = {
            "new_pq_signatures": [
                {
                    "public_key": pk_add_pq_1_hex,
                    "signature": sig_add_pq_1.sign(add_msg).hex(),
                    "alg": add_pq_alg_1,
                },
                {
                    "public_key": pk_add_pq_2_hex,
                    "signature": sig_add_pq_2.sign(add_msg).hex(),
                    "alg": add_pq_alg_2,
                },
            ],
            "classic_signature": sk_classic.sign(
                add_msg, hashfunc=hashlib.sha256
            ).hex(),
            "existing_pq_signatures": [
                {
                    "public_key": pk_ml_dsa_hex,
                    "signature": sig_ml_dsa.sign(add_msg).hex(),
                    "alg": ML_DSA_ALG,
                }
            ],
            "nonce": add_nonce,
        }
        response = client.post(
            f"/accounts/{pk_classic_hex}/add-pq-keys", json=add_payload
        )
        assert response.status_code == 200, response.text
        assert "Successfully added 2 PQ key(s)" in response.json()["message"]

        # Verify state after adding
        response = client.get(f"/accounts/{pk_classic_hex}")
        keys_after_add = response.json()["pq_keys"]
        assert len(keys_after_add) == 3
        added_pks = {k["public_key"] for k in keys_after_add}
        assert pk_add_pq_1_hex in added_pks
        assert pk_add_pq_2_hex in added_pks

        # 3. Remove the two added PQ keys in a single request
        remove_nonce = get_nonce()
        algs_to_remove = sorted([add_pq_alg_1, add_pq_alg_2])
        remove_msg = f"REMOVE-PQ:{pk_classic_hex}:{':'.join(algs_to_remove)}:{remove_nonce}".encode()
        remove_payload = {
            "algs_to_remove": algs_to_remove,
            "classic_signature": sk_classic.sign(
                remove_msg, hashfunc=hashlib.sha256
            ).hex(),
            "pq_signatures": [
                {
                    "public_key": pk_ml_dsa_hex,
                    "signature": sig_ml_dsa.sign(remove_msg).hex(),
                    "alg": ML_DSA_ALG,
                },
                {
                    "public_key": pk_add_pq_1_hex,
                    "signature": sig_add_pq_1.sign(remove_msg).hex(),
                    "alg": add_pq_alg_1,
                },
                {
                    "public_key": pk_add_pq_2_hex,
                    "signature": sig_add_pq_2.sign(remove_msg).hex(),
                    "alg": add_pq_alg_2,
                },
            ],
            "nonce": remove_nonce,
        }
        response = client.post(
            f"/accounts/{pk_classic_hex}/remove-pq-keys", json=remove_payload
        )
        assert response.status_code == 200, response.text
        assert "Successfully removed PQ key(s)" in response.json()["message"]

        # Verify final state
        response = client.get(f"/accounts/{pk_classic_hex}")
        keys_after_remove = response.json()["pq_keys"]
        assert len(keys_after_remove) == 1
        assert keys_after_remove[0]["public_key"] == pk_ml_dsa_hex


def test_graveyard():
    """
    Tests the graveyard functionality:
    1. Create account.
    2. Replace a key and verify the old one is in the graveyard.
    3. Remove a key and verify it is also in the graveyard.
    """
    sk_classic = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
    vk_classic = sk_classic.get_verifying_key()
    assert vk_classic is not None
    pk_classic_hex = vk_classic.to_string("uncompressed").hex()
    falcon_alg = "Falcon-512"

    with (
        oqs.Signature(ML_DSA_ALG) as sig_ml_dsa,
        oqs.Signature(falcon_alg) as sig_falcon_1,
        oqs.Signature(falcon_alg) as sig_falcon_2,
    ):
        # 1. Create account with ML-DSA and one Falcon key
        pk_ml_dsa_hex = sig_ml_dsa.generate_keypair().hex()
        pk_falcon_1_hex = sig_falcon_1.generate_keypair().hex()
        nonce1 = get_nonce()
        create_msg = (
            f"{pk_classic_hex}:{pk_ml_dsa_hex}:{pk_falcon_1_hex}:{nonce1}".encode()
        )
        client.post(
            "/accounts",
            json={
                "public_key": pk_classic_hex,
                "signature": sk_classic.sign(create_msg, hashfunc=hashlib.sha256).hex(),
                "ml_dsa_signature": {
                    "public_key": pk_ml_dsa_hex,
                    "signature": sig_ml_dsa.sign(create_msg).hex(),
                    "alg": ML_DSA_ALG,
                },
                "additional_pq_signatures": [
                    {
                        "public_key": pk_falcon_1_hex,
                        "signature": sig_falcon_1.sign(create_msg).hex(),
                        "alg": falcon_alg,
                    }
                ],
                "nonce": nonce1,
            },
        )

        # 2. Replace the Falcon key with a new one
        pk_falcon_2_hex = sig_falcon_2.generate_keypair().hex()
        add_nonce = get_nonce()
        add_msg = f"ADD-PQ:{pk_classic_hex}:{falcon_alg}:{add_nonce}".encode()
        add_payload = {
            "new_pq_signatures": [
                {
                    "public_key": pk_falcon_2_hex,
                    "signature": sig_falcon_2.sign(add_msg).hex(),
                    "alg": falcon_alg,
                }
            ],
            "classic_signature": sk_classic.sign(
                add_msg, hashfunc=hashlib.sha256
            ).hex(),
            "existing_pq_signatures": [
                {
                    "public_key": pk_ml_dsa_hex,
                    "signature": sig_ml_dsa.sign(add_msg).hex(),
                    "alg": ML_DSA_ALG,
                },
                {
                    "public_key": pk_falcon_1_hex,
                    "signature": sig_falcon_1.sign(add_msg).hex(),
                    "alg": falcon_alg,
                },
            ],
            "nonce": add_nonce,
        }
        client.post(f"/accounts/{pk_classic_hex}/add-pq-keys", json=add_payload)

        # Verify pk_falcon_1_hex is in the graveyard
        response = client.get(f"/accounts/{pk_classic_hex}/graveyard")
        assert response.status_code == 200
        graveyard1 = response.json()["graveyard"]
        assert len(graveyard1) == 1
        assert graveyard1[0]["public_key"] == pk_falcon_1_hex

        # 3. Remove the second Falcon key
        remove_nonce = get_nonce()
        remove_msg = f"REMOVE-PQ:{pk_classic_hex}:{falcon_alg}:{remove_nonce}".encode()
        remove_payload = {
            "algs_to_remove": [falcon_alg],
            "classic_signature": sk_classic.sign(
                remove_msg, hashfunc=hashlib.sha256
            ).hex(),
            "pq_signatures": [
                {
                    "public_key": pk_ml_dsa_hex,
                    "signature": sig_ml_dsa.sign(remove_msg).hex(),
                    "alg": ML_DSA_ALG,
                },
                {
                    "public_key": pk_falcon_2_hex,
                    "signature": sig_falcon_2.sign(remove_msg).hex(),
                    "alg": falcon_alg,
                },
            ],
            "nonce": remove_nonce,
        }
        client.post(f"/accounts/{pk_classic_hex}/remove-pq-keys", json=remove_payload)

        # Verify both keys are now in the graveyard
        response = client.get(f"/accounts/{pk_classic_hex}/graveyard")
        assert response.status_code == 200
        graveyard2 = response.json()["graveyard"]
        assert len(graveyard2) == 2
        graveyard_pks = {k["public_key"] for k in graveyard2}
        assert pk_falcon_1_hex in graveyard_pks
        assert pk_falcon_2_hex in graveyard_pks
