import ecdsa
import hashlib
import oqs
import pytest
from fastapi.testclient import TestClient
from src.main import app, accounts, used_nonces, SUPPORTED_SIG_ALGS

client = TestClient(app)


@pytest.fixture(autouse=True)
def cleanup():
    # Reset state before each test
    accounts.clear()
    used_nonces.clear()
    yield
    # Cleanup after test if needed
    accounts.clear()
    used_nonces.clear()


def get_nonce():
    response = client.get("/nonce")
    assert response.status_code == 200
    return response.json()["nonce"]


@pytest.mark.parametrize("pq_alg", SUPPORTED_SIG_ALGS)
def test_create_account_successful(pq_alg):
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


def test_get_supported_pq_algs():
    response = client.get("/supported-pq-algs")
    assert response.status_code == 200
    assert response.json() == {"algorithms": SUPPORTED_SIG_ALGS}


def test_get_accounts_and_account_by_id():
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
