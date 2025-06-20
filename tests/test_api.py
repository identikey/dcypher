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


def test_create_account_successful():
    """
    Tests the successful creation of a hybrid account with one mandatory
    PQ signature (ML-DSA) and one additional optional PQ signature.
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


def test_create_account_invalid_nonce():
    """
    Tests that an account creation request fails if an invalid nonce is provided.
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
    nonce is provided.
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
    Tests failure if the mandatory PQ algorithm is not the expected one.
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
    Tests failure if an additional PQ signature uses an unsupported algorithm.
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
    Tests failure when the classic ECDSA signature is invalid.
    """
    nonce = get_nonce()
    sk_classic = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
    vk_classic = sk_classic.get_verifying_key()
    assert vk_classic is not None
    pk_classic_hex = vk_classic.to_string("uncompressed").hex()

    with oqs.Signature(ML_DSA_ALG) as sig_ml_dsa:
        pk_ml_dsa_hex = sig_ml_dsa.generate_keypair().hex()
        message = f"{pk_classic_hex}:{pk_ml_dsa_hex}:{nonce}".encode("utf-8")
        sig_ml_dsa_hex = sig_ml_dsa.sign(message).hex()

        response = client.post(
            "/accounts",
            json={
                "public_key": pk_classic_hex,
                "signature": "fakesignature",
                "ml_dsa_signature": {
                    "public_key": pk_ml_dsa_hex,
                    "signature": sig_ml_dsa_hex,
                    "alg": ML_DSA_ALG,
                },
                "nonce": nonce,
            },
        )
        assert response.status_code == 401
        assert "Invalid classic signature" in response.text


def test_create_account_invalid_mandatory_pq_signature():
    """
    Tests failure when the mandatory post-quantum signature is invalid.
    """
    nonce = get_nonce()
    sk_classic = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
    vk_classic = sk_classic.get_verifying_key()
    assert vk_classic is not None
    pk_classic_hex = vk_classic.to_string("uncompressed").hex()

    with oqs.Signature(ML_DSA_ALG) as sig_ml_dsa:
        pk_ml_dsa_hex = sig_ml_dsa.generate_keypair().hex()
        message = f"{pk_classic_hex}:{pk_ml_dsa_hex}:{nonce}".encode("utf-8")
        sig_classic_hex = sk_classic.sign(message, hashfunc=hashlib.sha256).hex()

        response = client.post(
            "/accounts",
            json={
                "public_key": pk_classic_hex,
                "signature": sig_classic_hex,
                "ml_dsa_signature": {
                    "public_key": pk_ml_dsa_hex,
                    "signature": "fakesignature",
                    "alg": ML_DSA_ALG,
                },
                "nonce": nonce,
            },
        )
        assert response.status_code == 401
        assert (
            f"Invalid post-quantum signature for algorithm {ML_DSA_ALG}"
            in response.text
        )


def test_create_account_invalid_additional_pq_signature():
    """
    Tests failure when one of the additional post-quantum signatures is invalid.
    """
    nonce = get_nonce()
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

        message = f"{pk_classic_hex}:{pk_ml_dsa_hex}:{pk_add_pq_hex}:{nonce}".encode(
            "utf-8"
        )

        sig_classic_hex = sk_classic.sign(message, hashfunc=hashlib.sha256).hex()
        sig_ml_dsa_hex = sig_ml_dsa.sign(message).hex()

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
                        "signature": "fakesignature",
                        "alg": add_pq_alg,
                    }
                ],
                "nonce": nonce,
            },
        )
        assert response.status_code == 401
        assert (
            f"Invalid post-quantum signature for algorithm {add_pq_alg}"
            in response.text
        )


def test_create_account_already_exists():
    """
    Tests that the server prevents creating a new account with a classic public
    key that is already in use.
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
    """
    with mock.patch("src.main.time") as mock_time:
        mock_time.time.return_value = 1000.0
        nonce = get_nonce()
        mock_time.time.return_value = 1301.0
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
    Tests that an account creation request fails if the nonce is malformed.
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
    Tests that account creation fails if a required field is missing.
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
    algorithms in the response matches the list defined in the application.
    """
    response = client.get("/supported-pq-algs")
    assert response.status_code == 200
    assert response.json() == {"algorithms": list(SUPPORTED_SIG_ALGS)}


def test_get_accounts_and_account_by_id():
    """
    Tests listing all accounts and retrieving a single account by public key.
    """
    # 1. Create an account first
    nonce = get_nonce()
    sk_classic = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
    vk_classic = sk_classic.get_verifying_key()
    assert vk_classic is not None
    pk_classic_hex = vk_classic.to_string("uncompressed").hex()

    with oqs.Signature(ML_DSA_ALG) as sig_ml_dsa:
        pk_ml_dsa_hex = sig_ml_dsa.generate_keypair().hex()
        message = f"{pk_classic_hex}:{pk_ml_dsa_hex}:{nonce}".encode("utf-8")
        sig_classic_hex = sk_classic.sign(message, hashfunc=hashlib.sha256).hex()
        sig_ml_dsa_hex = sig_ml_dsa.sign(message).hex()

        client.post(
            "/accounts",
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

    # 2. Test get all accounts
    response = client.get("/accounts")
    assert response.status_code == 200
    assert response.json() == {"accounts": [pk_classic_hex]}

    # 3. Test get single account
    response = client.get(f"/accounts/{pk_classic_hex}")
    assert response.status_code == 200
    expected_pq_keys = [{"public_key": pk_ml_dsa_hex, "alg": ML_DSA_ALG}]
    assert response.json() == {
        "public_key": pk_classic_hex,
        "pq_keys": expected_pq_keys,
    }

    # 4. Test get non-existent account
    response = client.get("/accounts/nonexistentkey")
    assert response.status_code == 404
