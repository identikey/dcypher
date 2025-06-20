import ecdsa
import hashlib
import oqs
import pytest
import time
from unittest import mock
from fastapi.testclient import TestClient
from src.main import app, accounts, used_nonces, SUPPORTED_SIG_ALGS

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


@pytest.mark.parametrize("pq_alg", SUPPORTED_SIG_ALGS)
def test_create_account_successful(pq_alg):
    """
    Tests the successful creation of a hybrid account.

    This test is parameterized to run for all supported post-quantum algorithms.
    It follows these steps:
    1.  Get a nonce from the server.
    2.  Generate a classic (ECDSA) key pair.
    3.  Generate a post-quantum key pair for the given algorithm.
    4.  Construct the message to be signed (pk_classic:pk_pq:nonce).
    5.  Sign the message with both the classic and post-quantum private keys.
    6.  Send a POST request to /accounts with all the required data.
    7.  Assert that the account is created successfully (200 OK) and that the
        account details are correctly stored in the server's state.
    """
    # 1. Get nonce
    nonce = get_nonce()

    # 2. Prepare classic key
    sk_classic = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
    vk_classic = sk_classic.get_verifying_key()
    assert vk_classic is not None
    pk_classic_hex = vk_classic.to_string("uncompressed").hex()

    # 3. Prepare PQ key
    with oqs.Signature(pq_alg) as sig_pq:
        pk_pq = sig_pq.generate_keypair()
        pk_pq_hex = pk_pq.hex()

        # 4. Prepare message and sign with both keys
        message = f"{pk_classic_hex}:{pk_pq_hex}:{nonce}".encode("utf-8")
        signature_classic = sk_classic.sign(message, hashfunc=hashlib.sha256)
        signature_classic_hex = signature_classic.hex()

        signature_pq = sig_pq.sign(message)
        signature_pq_hex = signature_pq.hex()

        # 5. Create account
        response = client.post(
            "/accounts",
            json={
                "public_key": pk_classic_hex,
                "signature": signature_classic_hex,
                "pq_public_key": pk_pq_hex,
                "pq_signature": signature_pq_hex,
                "pq_alg": pq_alg,
                "nonce": nonce,
            },
        )

        # 6. Assert success
        assert response.status_code == 200
        assert response.json()["message"] == "Account created successfully"
        assert len(accounts) == 1
        account = accounts.pop()
        assert account[0] == pk_classic_hex
        assert account[1] == pk_pq_hex
        assert account[2] == pq_alg


def test_create_account_invalid_nonce():
    """
    Tests that an account creation request fails if an invalid nonce is provided.
    An invalid nonce is one that does not match the expected format or signature.
    Expects a 400 Bad Request response.
    """
    response = client.post(
        "/accounts",
        json={
            "public_key": "test",
            "signature": "test",
            "pq_public_key": "test",
            "pq_signature": "test",
            "pq_alg": "Dilithium2",
            "nonce": "invalid-nonce",
        },
    )
    assert response.status_code == 400
    assert "Invalid or expired nonce" in response.text


def test_create_account_used_nonce():
    """
    Tests that an account creation request fails if a valid but already used
    nonce is provided.
    Expects a 400 Bad Request response.
    """
    nonce = get_nonce()
    used_nonces.add(nonce)  # Manually add to used nonces
    response = client.post(
        "/accounts",
        json={
            "public_key": "test",
            "signature": "test",
            "pq_public_key": "test",
            "pq_signature": "test",
            "pq_alg": "Dilithium2",
            "nonce": nonce,
        },
    )
    assert response.status_code == 400
    assert "Nonce has already been used" in response.text


def test_create_account_unsupported_pq_alg():
    """
    Tests that an account creation request fails if an unsupported post-quantum
    algorithm is specified.
    Expects a 400 Bad Request response.
    """
    nonce = get_nonce()
    response = client.post(
        "/accounts",
        json={
            "public_key": "test",
            "signature": "test",
            "pq_public_key": "test",
            "pq_signature": "test",
            "pq_alg": "UnsupportedAlg",
            "nonce": nonce,
        },
    )
    assert response.status_code == 400
    assert "Unsupported PQ algorithm" in response.text


def test_create_account_invalid_classic_signature():
    """
    Tests that an account creation request fails if the classic (ECDSA)
    signature is invalid.
    This simulates a scenario where the client fails to prove ownership of the
    classic public key.
    Expects a 401 Unauthorized response.
    """
    nonce = get_nonce()
    sk_classic = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
    vk_classic = sk_classic.get_verifying_key()
    assert vk_classic is not None
    pk_classic_hex = vk_classic.to_string("uncompressed").hex()
    with oqs.Signature("Dilithium2") as sig_pq:
        pk_pq_hex = sig_pq.generate_keypair().hex()
        message = f"{pk_classic_hex}:{pk_pq_hex}:{nonce}".encode("utf-8")
        signature_pq_hex = sig_pq.sign(message).hex()

        response = client.post(
            "/accounts",
            json={
                "public_key": pk_classic_hex,
                "signature": "fakesignature",
                "pq_public_key": pk_pq_hex,
                "pq_signature": signature_pq_hex,
                "pq_alg": "Dilithium2",
                "nonce": nonce,
            },
        )
        assert response.status_code == 401
        assert "Invalid classic signature" in response.text


def test_create_account_invalid_pq_signature():
    """
    Tests that an account creation request fails if the post-quantum signature
    is invalid.
    This simulates a scenario where the client fails to prove ownership of the
    post-quantum public key.
    Expects a 401 Unauthorized response.
    """
    nonce = get_nonce()
    sk_classic = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
    vk_classic = sk_classic.get_verifying_key()
    assert vk_classic is not None
    pk_classic_hex = vk_classic.to_string("uncompressed").hex()
    with oqs.Signature("Dilithium2") as sig_pq:
        pk_pq_hex = sig_pq.generate_keypair().hex()
        message = f"{pk_classic_hex}:{pk_pq_hex}:{nonce}".encode("utf-8")
        signature_classic_hex = sk_classic.sign(message, hashfunc=hashlib.sha256).hex()

        response = client.post(
            "/accounts",
            json={
                "public_key": pk_classic_hex,
                "signature": signature_classic_hex,
                "pq_public_key": pk_pq_hex,
                "pq_signature": "fakesignature",
                "pq_alg": "Dilithium2",
                "nonce": nonce,
            },
        )
        assert response.status_code == 401
        assert "Invalid post-quantum signature" in response.text


def test_create_account_already_exists():
    """
    Tests that the server prevents creating a new account with a classic public
    key that is already in use.
    Expects a 409 Conflict response.
    """
    # 1. Create an initial account
    pq_alg = "Dilithium2"
    nonce1 = get_nonce()
    sk_classic = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
    vk_classic = sk_classic.get_verifying_key()
    assert vk_classic is not None
    pk_classic_hex = vk_classic.to_string("uncompressed").hex()
    with oqs.Signature(pq_alg) as sig_pq:
        pk_pq_hex = sig_pq.generate_keypair().hex()
        message1 = f"{pk_classic_hex}:{pk_pq_hex}:{nonce1}".encode("utf-8")
        sig1_classic = sk_classic.sign(message1, hashfunc=hashlib.sha256).hex()
        sig1_pq = sig_pq.sign(message1).hex()
        response = client.post(
            "/accounts",
            json={
                "public_key": pk_classic_hex,
                "signature": sig1_classic,
                "pq_public_key": pk_pq_hex,
                "pq_signature": sig1_pq,
                "pq_alg": pq_alg,
                "nonce": nonce1,
            },
        )
        assert response.status_code == 200

    # 2. Attempt to create a second account with the same classic public key
    nonce2 = get_nonce()
    with oqs.Signature(pq_alg) as sig_pq_new:
        pk_pq_new_hex = sig_pq_new.generate_keypair().hex()
        message2 = f"{pk_classic_hex}:{pk_pq_new_hex}:{nonce2}".encode("utf-8")
        sig2_classic = sk_classic.sign(message2, hashfunc=hashlib.sha256).hex()
        sig2_pq = sig_pq_new.sign(message2).hex()

        response2 = client.post(
            "/accounts",
            json={
                "public_key": pk_classic_hex,  # Same classic PK
                "signature": sig2_classic,
                "pq_public_key": pk_pq_new_hex,  # Different PQ PK
                "pq_signature": sig2_pq,
                "pq_alg": pq_alg,
                "nonce": nonce2,
            },
        )
        assert response2.status_code == 409
        assert "Account with this classic public key already exists" in response2.text


def test_create_account_expired_nonce():
    """
    Tests that an account creation request fails if a nonce has expired.
    A nonce is valid for 5 minutes (300 seconds). This test simulates waiting
    for more than 5 minutes before using the nonce.
    Expects a 400 Bad Request response.
    """
    with mock.patch("src.main.time") as mock_time:
        # 1. Get a nonce at a fixed point in time
        mock_time.time.return_value = 1000.0
        nonce = get_nonce()

        # 2. Simulate time passing beyond the 5-minute validity window
        mock_time.time.return_value = 1301.0

        # 3. Attempt to create an account with the now-expired nonce
        response = client.post(
            "/accounts",
            json={
                "public_key": "test",
                "signature": "test",
                "pq_public_key": "test",
                "pq_signature": "test",
                "pq_alg": "Dilithium2",
                "nonce": nonce,
            },
        )
        assert response.status_code == 400
        assert "Invalid or expired nonce" in response.text


def test_create_account_malformed_nonce():
    """
    Tests that an account creation request fails if the nonce is malformed.
    A malformed nonce could be one that doesn't split into two parts with a
    colon, or one where the signature is incorrect.
    Expects a 400 Bad Request response.
    """
    response = client.post(
        "/accounts",
        json={
            "public_key": "test",
            "signature": "test",
            "pq_public_key": "test",
            "pq_signature": "test",
            "pq_alg": "Dilithium2",
            "nonce": "malformed:nonce",
        },
    )
    assert response.status_code == 400
    assert "Invalid or expired nonce" in response.text


@pytest.mark.parametrize(
    "field_to_corrupt, expected_status, expected_detail",
    [
        ("public_key", 401, "Invalid classic signature"),
        ("signature", 401, "Invalid classic signature"),
        ("pq_public_key", 401, "Invalid post-quantum signature"),
        ("pq_signature", 401, "Invalid post-quantum signature"),
    ],
)
def test_create_account_malformed_hex_input(
    field_to_corrupt, expected_status, expected_detail
):
    """
    Tests that account creation fails if any of the key or signature fields
    contain malformed (non-hex) data.
    The server should gracefully handle these errors and return a 401, as
    the signature verification will fail upon attempting to decode the hex data.
    """
    nonce = get_nonce()
    corrupted_value = "this-is-not-hex-data"

    # Generate real keys to isolate the failure to the corrupted field
    sk_classic = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
    vk_classic = sk_classic.get_verifying_key()
    assert vk_classic is not None
    pk_classic_hex = vk_classic.to_string("uncompressed").hex()

    with oqs.Signature("Dilithium2") as sig_pq:
        pk_pq_hex = sig_pq.generate_keypair().hex()
        # This signature is not used, but we need a placeholder.
        pq_sig_hex = "a" * 200

        payload = {
            "public_key": pk_classic_hex,
            "signature": "dummy_sig",  # Placeholder
            "pq_public_key": pk_pq_hex,
            "pq_signature": pq_sig_hex,
            "pq_alg": "Dilithium2",
            "nonce": nonce,
        }

        # For the PQ failure cases, we need a valid classic signature.
        if field_to_corrupt in ["pq_public_key", "pq_signature"]:
            # The message includes the (potentially corrupted) pq_public_key
            temp_payload = payload.copy()
            temp_payload[field_to_corrupt] = corrupted_value
            message_to_sign = (
                f"{temp_payload['public_key']}:{temp_payload['pq_public_key']}:{nonce}"
            ).encode("utf-8")
            payload["signature"] = sk_classic.sign(
                message_to_sign, hashfunc=hashlib.sha256
            ).hex()

        # Now, corrupt the field in the final payload
        payload[field_to_corrupt] = corrupted_value

        response = client.post("/accounts", json=payload)

        assert response.status_code == expected_status
        assert expected_detail in response.text


def test_create_account_missing_field():
    """
    Tests that account creation fails if a required field is missing from
    the request payload.
    Expects a 422 Unprocessable Entity response, as this is a validation error.
    """
    nonce = get_nonce()
    valid_payload = {
        "public_key": "test",
        "signature": "test",
        "pq_public_key": "test",
        "pq_signature": "test",
        "pq_alg": "Dilithium2",
        "nonce": nonce,
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
    algorithms in the response matches the list defined in the application.
    """
    response = client.get("/supported-pq-algs")
    assert response.status_code == 200
    assert response.json() == {"algorithms": list(SUPPORTED_SIG_ALGS)}


def test_get_accounts_and_account_by_id():
    """
    Tests the functionality of listing all accounts and retrieving a single
    account by its public key.

    It performs the following checks:
    1.  Successfully creates a new account to ensure there is data to retrieve.
    2.  Fetches all accounts via GET /accounts and verifies the new account's
        public key is in the list.
    3.  Fetches the specific account via GET /accounts/{public_key} and
        verifies that all its details are correct.
    4.  Attempts to fetch a non-existent account and asserts that a 404 Not Found
        response is returned.
    """
    # Create an account first
    pq_alg = "Dilithium2"
    nonce = get_nonce()
    sk_classic = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
    vk_classic = sk_classic.get_verifying_key()
    assert vk_classic is not None
    pk_classic_hex = vk_classic.to_string("uncompressed").hex()
    with oqs.Signature(pq_alg) as sig_pq:
        pk_pq_hex = sig_pq.generate_keypair().hex()
        message = f"{pk_classic_hex}:{pk_pq_hex}:{nonce}".encode("utf-8")
        signature_classic_hex = sk_classic.sign(message, hashfunc=hashlib.sha256).hex()
        signature_pq_hex = sig_pq.sign(message).hex()
        client.post(
            "/accounts",
            json={
                "public_key": pk_classic_hex,
                "signature": signature_classic_hex,
                "pq_public_key": pk_pq_hex,
                "pq_signature": signature_pq_hex,
                "pq_alg": pq_alg,
                "nonce": nonce,
            },
        )

    # Test get all accounts
    response = client.get("/accounts")
    assert response.status_code == 200
    assert response.json() == {"accounts": [pk_classic_hex]}

    # Test get single account
    response = client.get(f"/accounts/{pk_classic_hex}")
    assert response.status_code == 200
    assert response.json() == {
        "public_key": pk_classic_hex,
        "pq_public_key": pk_pq_hex,
        "pq_alg": pq_alg,
    }

    # Test get non-existent account
    response = client.get("/accounts/nonexistentkey")
    assert response.status_code == 404
