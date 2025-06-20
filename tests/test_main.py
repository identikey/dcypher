import ecdsa
import hashlib
import pytest
from fastapi.testclient import TestClient
from src.main import app, accounts, used_nonces

client = TestClient(app)


@pytest.fixture(autouse=True)
def clear_state():
    """A fixture to clear the server state before each test."""
    accounts.clear()
    used_nonces.clear()
    yield


def get_new_keypair():
    sk = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
    vk = sk.get_verifying_key()
    assert vk is not None
    public_key = vk.to_string("uncompressed").hex()
    return sk, public_key


def test_create_account_success():
    sk, public_key = get_new_keypair()

    # Get nonce from server
    response = client.get("/nonce")
    assert response.status_code == 200
    nonce = response.json()["nonce"]

    message = f"{public_key}:{nonce}".encode("utf-8")
    signature = sk.sign(message, hashfunc=hashlib.sha256).hex()

    response = client.post(
        "/accounts",
        json={"public_key": public_key, "signature": signature, "nonce": nonce},
    )
    assert response.status_code == 200
    response_json = response.json()
    assert response_json["message"] == "Account created successfully"
    assert response_json["public_key"] == public_key
    assert public_key in accounts
    assert nonce in used_nonces


def test_create_account_invalid_signature():
    sk1, public_key1 = get_new_keypair()
    sk2, _ = get_new_keypair()

    response = client.get("/nonce")
    assert response.status_code == 200
    nonce = response.json()["nonce"]

    # Sign with the wrong key
    message = f"{public_key1}:{nonce}".encode("utf-8")
    signature = sk2.sign(message, hashfunc=hashlib.sha256).hex()

    response = client.post(
        "/accounts",
        json={"public_key": public_key1, "signature": signature, "nonce": nonce},
    )
    assert response.status_code == 401
    assert "Invalid signature" in response.text


def test_create_account_malformed_signature():
    """
    Tests that a malformed signature is rejected.
    """
    sk, public_key = get_new_keypair()
    response = client.get("/nonce")
    assert response.status_code == 200
    nonce = response.json()["nonce"]

    response = client.post(
        "/accounts",
        json={
            "public_key": public_key,
            "signature": "this-is-not-a-valid-hex-signature",
            "nonce": nonce,
        },
    )
    assert response.status_code == 401
    assert "Invalid signature" in response.text


def test_create_account_nonce_reused():
    sk, public_key = get_new_keypair()

    response = client.get("/nonce")
    assert response.status_code == 200
    nonce = response.json()["nonce"]

    message = f"{public_key}:{nonce}".encode("utf-8")
    signature = sk.sign(message, hashfunc=hashlib.sha256).hex()

    # First request - should succeed
    client.post(
        "/accounts",
        json={"public_key": public_key, "signature": signature, "nonce": nonce},
    )

    # Second request with the same nonce - should fail
    response = client.post(
        "/accounts",
        json={"public_key": public_key, "signature": signature, "nonce": nonce},
    )
    assert response.status_code == 400
    assert "Nonce has already been used" in response.text


def test_create_account_already_exists():
    sk, public_key = get_new_keypair()

    # First request
    response1 = client.get("/nonce")
    assert response1.status_code == 200
    nonce1 = response1.json()["nonce"]
    message1 = f"{public_key}:{nonce1}".encode("utf-8")
    signature1 = sk.sign(message1, hashfunc=hashlib.sha256).hex()
    client.post(
        "/accounts",
        json={"public_key": public_key, "signature": signature1, "nonce": nonce1},
    )

    # Second request with different nonce but same key
    response2 = client.get("/nonce")
    assert response2.status_code == 200
    nonce2 = response2.json()["nonce"]
    message2 = f"{public_key}:{nonce2}".encode("utf-8")
    signature2 = sk.sign(message2, hashfunc=hashlib.sha256).hex()
    response = client.post(
        "/accounts",
        json={"public_key": public_key, "signature": signature2, "nonce": nonce2},
    )
    assert response.status_code == 409
    assert "Account already exists" in response.text


def test_get_accounts():
    response = client.get("/accounts")
    assert response.status_code == 200
    assert response.json() == {"accounts": []}

    # Create an account
    sk, public_key = get_new_keypair()
    response = client.get("/nonce")
    assert response.status_code == 200
    nonce = response.json()["nonce"]
    message = f"{public_key}:{nonce}".encode("utf-8")
    signature = sk.sign(message, hashfunc=hashlib.sha256).hex()
    client.post(
        "/accounts",
        json={"public_key": public_key, "signature": signature, "nonce": nonce},
    )

    response = client.get("/accounts")
    assert response.status_code == 200
    assert response.json() == {"accounts": [public_key]}


def test_get_account_found():
    # Create an account
    sk, public_key = get_new_keypair()
    response = client.get("/nonce")
    assert response.status_code == 200
    nonce = response.json()["nonce"]
    message = f"{public_key}:{nonce}".encode("utf-8")
    signature = sk.sign(message, hashfunc=hashlib.sha256).hex()
    client.post(
        "/accounts",
        json={"public_key": public_key, "signature": signature, "nonce": nonce},
    )

    response = client.get(f"/accounts/{public_key}")
    assert response.status_code == 200
    assert response.json() == {"public_key": public_key}


def test_get_account_not_found():
    response = client.get("/accounts/nonexistentkey")
    assert response.status_code == 404
    assert "Account not found" in response.text
