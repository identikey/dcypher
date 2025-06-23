import ecdsa
import hashlib
import oqs
import pytest
import time
import os
import json
import requests
from unittest import mock
from main import (
    app,
)
from app_state import state
from lib.pq_auth import SUPPORTED_SIG_ALGS
from config import ML_DSA_ALG

from tests.integration.test_api import (
    _create_test_account,
    get_nonce,
)


def test_get_supported_pq_algs(api_base_url: str):
    """
    Tests the /supported-pq-algs endpoint.
    It verifies that the endpoint returns a 200 OK status and that the list of
    algorithms in the response body matches the list defined in the application.
    """
    response = requests.get(f"{api_base_url}/supported-pq-algs")
    assert response.status_code == 200
    # Convert to set for order-independent comparison
    assert set(response.json()["algorithms"]) == set(SUPPORTED_SIG_ALGS)


def test_add_and_remove_pq_keys(api_base_url: str):
    """
    Tests the full lifecycle of an account's post-quantum keys:
    1. Create an account with a classic key and two PQ keys.
    2. Successfully add a new PQ key.
    3. Successfully remove an optional PQ key.
    4. Verify the state of the account after each operation.
    """
    add_pq_alg_1 = "Falcon-512"
    add_pq_alg_2 = "Falcon-1024"

    # === 1. Create an account with two PQ keys (one mandatory, one optional) ===
    sk_classic, pk_classic_hex, all_pq_sks, oqs_sigs_to_free = _create_test_account(
        api_base_url, add_pq_algs=[add_pq_alg_1]
    )
    try:
        pk_ml_dsa_hex = next(
            pk for pk, (_, alg) in all_pq_sks.items() if alg == ML_DSA_ALG
        )
        pk_add_pq_1_hex = next(
            pk for pk, (_, alg) in all_pq_sks.items() if alg == add_pq_alg_1
        )
        sig_ml_dsa, _ = all_pq_sks[pk_ml_dsa_hex]
        sig_add_pq_1, _ = all_pq_sks[pk_add_pq_1_hex]

        # Verify initial account state
        response = requests.get(f"{api_base_url}/accounts/{pk_classic_hex}")
        assert response.status_code == 200
        assert len(response.json()["pq_keys"]) == 2

        # === 2. Add a new PQ key ===
        sig_add_pq_2 = oqs.Signature(add_pq_alg_2)
        oqs_sigs_to_free.append(sig_add_pq_2)
        pk_add_pq_2_hex = sig_add_pq_2.generate_keypair().hex()
        all_pq_sks[pk_add_pq_2_hex] = (sig_add_pq_2, add_pq_alg_2)
        nonce2 = get_nonce(api_base_url)
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
        response = requests.post(
            f"{api_base_url}/accounts/{pk_classic_hex}/add-pq-keys", json=add_payload
        )
        assert response.status_code == 200, response.text
        assert response.json()["message"] == "Successfully added 1 PQ key(s)."

        # Verify account state after adding key
        response = requests.get(f"{api_base_url}/accounts/{pk_classic_hex}")
        assert response.status_code == 200
        pq_keys_after_add = response.json()["pq_keys"]
        assert len(pq_keys_after_add) == 3
        assert any(k["public_key"] == pk_add_pq_2_hex for k in pq_keys_after_add)

        # === 3. Remove an optional PQ key ===
        alg_to_remove = add_pq_alg_1
        pk_to_remove = pk_add_pq_1_hex
        nonce3 = get_nonce(api_base_url)
        message3 = f"REMOVE-PQ:{pk_classic_hex}:{alg_to_remove}:{nonce3}".encode(
            "utf-8"
        )

        classic_sig3 = sk_classic.sign(message3, hashfunc=hashlib.sha256).hex()

        # Get all active keys for signing from the API
        active_keys_resp = requests.get(f"{api_base_url}/accounts/{pk_classic_hex}")
        assert active_keys_resp.status_code == 200
        active_pq_keys = active_keys_resp.json()["pq_keys"]
        all_pq_sigs3 = []
        for key_info in active_pq_keys:
            pk = key_info["public_key"]
            alg = key_info["alg"]
            signer, _ = all_pq_sks[pk]
            all_pq_sigs3.append(
                {"public_key": pk, "signature": signer.sign(message3).hex(), "alg": alg}
            )

        remove_payload = {
            "algs_to_remove": [alg_to_remove],
            "classic_signature": classic_sig3,
            "pq_signatures": all_pq_sigs3,
            "nonce": nonce3,
        }
        response = requests.post(
            f"{api_base_url}/accounts/{pk_classic_hex}/remove-pq-keys",
            json=remove_payload,
        )
        assert response.status_code == 200, response.text
        assert response.json()["message"] == "Successfully removed PQ key(s)."

        # Verify final account state
        response = requests.get(f"{api_base_url}/accounts/{pk_classic_hex}")
        assert response.status_code == 200
        keys_after_remove = response.json()["pq_keys"]
        assert len(keys_after_remove) == 2
        assert not any(k["public_key"] == pk_to_remove for k in keys_after_remove)
        assert any(k["public_key"] == pk_ml_dsa_hex for k in keys_after_remove)
        assert any(k["public_key"] == pk_add_pq_2_hex for k in keys_after_remove)
    finally:
        # Clean up oqs signatures
        for sig in oqs_sigs_to_free:
            sig.free()


def test_remove_mandatory_pq_key_fails(api_base_url: str):
    """
    Tests that an attempt to remove the mandatory ML-DSA key from an account
    is rejected with a 400 error.
    """
    # 1. Create a minimal account
    sk_classic, pk_classic_hex, all_pq_sks, oqs_sigs_to_free = _create_test_account(
        api_base_url
    )
    try:
        pk_ml_dsa_hex = next(iter(all_pq_sks))
        sig_ml_dsa, _ = all_pq_sks[pk_ml_dsa_hex]

        # 2. Attempt to remove the mandatory key
        nonce2 = get_nonce(api_base_url)
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
        response = requests.post(
            f"{api_base_url}/accounts/{pk_classic_hex}/remove-pq-keys",
            json=remove_payload,
        )
        assert response.status_code == 400
        assert f"Cannot remove the mandatory PQ key ({ML_DSA_ALG})" in response.text
    finally:
        # Clean up oqs signatures
        for sig in oqs_sigs_to_free:
            sig.free()


def test_add_pq_key_authorization_failures(api_base_url: str):
    """
    Tests various authorization failure scenarios when adding a PQ key.
    - Invalid classic signature.
    - Missing signature from an existing PQ key.
    - Invalid signature from an existing PQ key.
    - Invalid signature for the new PQ key itself.
    """
    # 1. Setup: Create an account with one mandatory and one optional key
    add_pq_alg_1 = "Falcon-512"
    add_pq_alg_2 = "Falcon-1024"

    (
        sk_classic,
        pk_classic_hex,
        all_pq_sks,
        oqs_sigs_to_free,
    ) = _create_test_account(api_base_url, add_pq_algs=[add_pq_alg_1])
    try:
        pk_ml_dsa_hex = next(
            pk for pk, (_, alg) in all_pq_sks.items() if alg == ML_DSA_ALG
        )
        pk_add_pq_1_hex = next(
            pk for pk, (_, alg) in all_pq_sks.items() if alg == add_pq_alg_1
        )
        sig_ml_dsa, _ = all_pq_sks[pk_ml_dsa_hex]
        sig_add_pq_1, _ = all_pq_sks[pk_add_pq_1_hex]

        sig_add_pq_2 = oqs.Signature(add_pq_alg_2)
        oqs_sigs_to_free.append(sig_add_pq_2)
        pk_add_pq_2_hex = sig_add_pq_2.generate_keypair().hex()
        all_pq_sks[pk_add_pq_2_hex] = (sig_add_pq_2, add_pq_alg_2)

        # 2. Prepare for a valid "add" operation
        add_nonce = get_nonce(api_base_url)
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
        response = requests.post(
            f"{api_base_url}/accounts/{pk_classic_hex}/add-pq-keys", json=payload
        )
        assert response.status_code == 401
        assert "Invalid classic signature" in response.text

        # Case 2: Missing signature from an existing PQ key
        payload["classic_signature"] = valid_classic_sig
        payload["existing_pq_signatures"] = [valid_existing_sigs[0]]  # Missing one
        response = requests.post(
            f"{api_base_url}/accounts/{pk_classic_hex}/add-pq-keys", json=payload
        )
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
        response = requests.post(
            f"{api_base_url}/accounts/{pk_classic_hex}/add-pq-keys", json=payload
        )
        assert response.status_code == 401
        assert "Invalid signature for existing PQ key" in response.text

        # Case 4: Invalid signature for the new PQ key itself
        invalid_new_sig = {
            "public_key": pk_add_pq_2_hex,
            "signature": sig_add_pq_2.sign(incorrect_msg).hex(),
            "alg": add_pq_alg_2,
        }
        payload["existing_pq_signatures"] = valid_existing_sigs
        payload["new_pq_signatures"] = [invalid_new_sig]
        response = requests.post(
            f"{api_base_url}/accounts/{pk_classic_hex}/add-pq-keys", json=payload
        )
        assert response.status_code == 401
        assert "Invalid signature for new PQ key" in response.text
    finally:
        # Clean up oqs signatures
        for sig in oqs_sigs_to_free:
            sig.free()


def test_replace_existing_pq_key(api_base_url: str):
    """Tests that adding a key for an existing algorithm replaces the old key."""
    falcon_alg = "Falcon-512"
    sk_classic, pk_classic_hex, all_pq_sks, oqs_sigs_to_free = _create_test_account(
        api_base_url, add_pq_algs=[falcon_alg]
    )
    try:
        pk_ml_dsa_hex = next(
            pk for pk, (_, alg) in all_pq_sks.items() if alg == ML_DSA_ALG
        )
        pk_falcon_old_hex = next(
            pk for pk, (_, alg) in all_pq_sks.items() if alg == falcon_alg
        )
        sig_ml_dsa, _ = all_pq_sks[pk_ml_dsa_hex]
        sig_falcon_old, _ = all_pq_sks[pk_falcon_old_hex]

        add_nonce = get_nonce(api_base_url)
        add_msg = f"ADD-PQ:{pk_classic_hex}:{falcon_alg}:{add_nonce}".encode()

        # Create a new key pair for the same algorithm
        sig_falcon_new = oqs.Signature(falcon_alg)
        oqs_sigs_to_free.append(sig_falcon_new)
        pk_falcon_new_hex = sig_falcon_new.generate_keypair().hex()

        payload = {
            "new_pq_signatures": [
                {
                    "public_key": pk_falcon_new_hex,
                    "signature": sig_falcon_new.sign(add_msg).hex(),
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
                    "public_key": pk_falcon_old_hex,
                    "signature": sig_falcon_old.sign(add_msg).hex(),
                    "alg": falcon_alg,
                },
            ],
            "nonce": add_nonce,
        }
        response = requests.post(
            f"{api_base_url}/accounts/{pk_classic_hex}/add-pq-keys", json=payload
        )
        assert response.status_code == 200, response.text
        assert "Successfully added 1 PQ key(s)" in response.json()["message"]

        # Add the new signer to the dict for cleanup. The signer for the old key
        # remains in all_pq_sks and will be cleaned up in the 'finally' block.
        all_pq_sks[pk_falcon_new_hex] = (sig_falcon_new, falcon_alg)

        # Verify state after adding: key count should be the same
        response = requests.get(f"{api_base_url}/accounts/{pk_classic_hex}")
        keys_after_add = response.json()["pq_keys"]
        assert len(keys_after_add) == 2

        # Verify the old key is in the graveyard
        response = requests.get(f"{api_base_url}/accounts/{pk_classic_hex}/graveyard")
        assert response.status_code == 200
        graveyard_keys = response.json()["graveyard"]
        assert len(graveyard_keys) == 1
        assert graveyard_keys[0]["public_key"] == pk_falcon_old_hex
        assert graveyard_keys[0]["alg"] == falcon_alg

        # Verify the new key is active
        active_pks = {k["public_key"] for k in keys_after_add}
        assert pk_falcon_new_hex in active_pks, "New key should be active"
        assert pk_falcon_old_hex not in active_pks, "Old key should not be active"

    finally:
        for sig in oqs_sigs_to_free:
            sig.free()


def test_add_unsupported_pq_key_fails(api_base_url: str):
    """Tests adding a key with an unsupported algorithm fails."""
    sk_classic, pk_classic_hex, all_pq_sks, oqs_sigs_to_free = _create_test_account(
        api_base_url
    )
    try:
        unsupported_alg = "Unsupported-Alg"
        unsupported_nonce = get_nonce(api_base_url)
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
            "existing_pq_signatures": [],
            "nonce": unsupported_nonce,
        }
        response = requests.post(
            f"{api_base_url}/accounts/{pk_classic_hex}/add-pq-keys", json=payload
        )
        assert response.status_code == 400
        assert f"Unsupported PQ algorithm: {unsupported_alg}" in response.text
    finally:
        for sig in oqs_sigs_to_free:
            sig.free()


def test_add_mandatory_pq_key_again_fails(api_base_url: str):
    """Tests that attempting to add another ML_DSA_ALG key fails."""
    sk_classic, pk_classic_hex, all_pq_sks, oqs_sigs_to_free = _create_test_account(
        api_base_url
    )
    try:
        mandatory_nonce = get_nonce(api_base_url)
        mandatory_msg = (
            f"ADD-PQ:{pk_classic_hex}:{ML_DSA_ALG}:{mandatory_nonce}".encode()
        )

        sig_ml_dsa_new = oqs.Signature(ML_DSA_ALG)
        oqs_sigs_to_free.append(sig_ml_dsa_new)
        pk_ml_dsa_new_hex = sig_ml_dsa_new.generate_keypair().hex()
        all_pq_sks[pk_ml_dsa_new_hex] = (sig_ml_dsa_new, ML_DSA_ALG)

        payload = {
            "new_pq_signatures": [
                {
                    "public_key": pk_ml_dsa_new_hex,
                    "signature": sig_ml_dsa_new.sign(mandatory_msg).hex(),
                    "alg": ML_DSA_ALG,
                }
            ],
            "classic_signature": sk_classic.sign(
                mandatory_msg, hashfunc=hashlib.sha256
            ).hex(),
            "existing_pq_signatures": [],
            "nonce": mandatory_nonce,
        }
        response = requests.post(
            f"{api_base_url}/accounts/{pk_classic_hex}/add-pq-keys", json=payload
        )
        assert response.status_code == 400
        assert (
            f"Cannot add another key for the mandatory algorithm {ML_DSA_ALG}"
            in response.text
        )
    finally:
        for sig in oqs_sigs_to_free:
            sig.free()


def test_remove_pq_key_authorization_failures(api_base_url: str):
    """
    Tests various authorization failure scenarios when removing a PQ key.
    - Invalid classic signature.
    - Missing signature from an existing PQ key.
    - Invalid signature from an existing PQ key.
    """
    # 1. Setup: Create an account with one mandatory and two optional keys
    add_pq_alg_1 = "Falcon-512"
    add_pq_alg_2 = "Falcon-1024"

    sk_classic, pk_classic_hex, all_pq_sks, oqs_sigs_to_free = _create_test_account(
        api_base_url, add_pq_algs=[add_pq_alg_1, add_pq_alg_2]
    )
    try:
        pk_ml_dsa_hex = next(
            pk for pk, (_, alg) in all_pq_sks.items() if alg == ML_DSA_ALG
        )
        pk_add_pq_1_hex = next(
            pk for pk, (_, alg) in all_pq_sks.items() if alg == add_pq_alg_1
        )
        pk_add_pq_2_hex = next(
            pk for pk, (_, alg) in all_pq_sks.items() if alg == add_pq_alg_2
        )
        sig_ml_dsa, _ = all_pq_sks[pk_ml_dsa_hex]
        sig_add_pq_1, _ = all_pq_sks[pk_add_pq_1_hex]
        sig_add_pq_2, _ = all_pq_sks[pk_add_pq_2_hex]

        # 2. Prepare for a valid "remove" operation
        pk_to_remove = pk_add_pq_1_hex
        alg_to_remove = add_pq_alg_1
        remove_nonce = get_nonce(api_base_url)
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
        response = requests.post(
            f"{api_base_url}/accounts/{pk_classic_hex}/remove-pq-keys", json=payload
        )
        assert response.status_code == 401
        assert "Invalid classic signature" in response.text

        # Case 2: Missing signature from an existing PQ key
        payload["classic_signature"] = valid_classic_sig
        payload["pq_signatures"] = [valid_pq_sigs[0], valid_pq_sigs[2]]  # Missing one
        response = requests.post(
            f"{api_base_url}/accounts/{pk_classic_hex}/remove-pq-keys", json=payload
        )
        assert response.status_code == 401
        assert "Signatures from all existing PQ keys are required" in response.text

        # Case 3: Invalid signature from an existing PQ key
        invalid_pq_sigs = [
            valid_pq_sigs[0],
            valid_pq_sigs[1],
            {
                "public_key": pk_add_pq_2_hex,
                "signature": sig_add_pq_2.sign(incorrect_msg).hex(),
                "alg": add_pq_alg_2,
            },
        ]
        payload["pq_signatures"] = invalid_pq_sigs
        response = requests.post(
            f"{api_base_url}/accounts/{pk_classic_hex}/remove-pq-keys", json=payload
        )
        assert response.status_code == 401
        assert "Invalid signature for existing PQ key" in response.text
    finally:
        # Clean up oqs signatures
        for sig, _ in all_pq_sks.values():
            sig.free()


def test_remove_nonexistent_pq_key_fails(api_base_url: str):
    """
    Tests that removing a PQ key not on the account fails.
    """
    # 1. Setup: Create a standard account
    sk_classic, pk_classic_hex, all_pq_sks, oqs_sigs_to_free = _create_test_account(
        api_base_url
    )
    try:
        pk_ml_dsa_hex = next(iter(all_pq_sks))
        sig_ml_dsa, _ = all_pq_sks[pk_ml_dsa_hex]

        # 2. Attempt to remove a key that doesn't exist
        alg_to_remove = "nonexistent-alg"
        remove_nonce = get_nonce(api_base_url)
        remove_msg = (
            f"REMOVE-PQ:{pk_classic_hex}:{alg_to_remove}:{remove_nonce}".encode()
        )
        payload = {
            "algs_to_remove": [alg_to_remove],
            "classic_signature": sk_classic.sign(
                remove_msg, hashfunc=hashlib.sha256
            ).hex(),
            "pq_signatures": [
                {
                    "public_key": pk_ml_dsa_hex,
                    "signature": sig_ml_dsa.sign(remove_msg).hex(),
                    "alg": ML_DSA_ALG,
                }
            ],
            "nonce": remove_nonce,
        }
        response = requests.post(
            f"{api_base_url}/accounts/{pk_classic_hex}/remove-pq-keys", json=payload
        )
        assert response.status_code == 404
        assert (
            f"PQ key for algorithm {alg_to_remove} not found on account."
            in response.text
        )
    finally:
        # Clean up oqs signatures
        for sig in oqs_sigs_to_free:
            sig.free()


def test_add_and_remove_multiple_pq_keys(api_base_url: str):
    """
    Tests adding and removing multiple PQ keys in a single request.
    """
    # 1. Setup: Create a minimal account
    add_pq_alg_1 = "Falcon-512"
    add_pq_alg_2 = "Falcon-1024"

    sk_classic, pk_classic_hex, all_pq_sks, oqs_sigs_to_free = _create_test_account(
        api_base_url
    )
    try:
        pk_ml_dsa_hex = next(iter(all_pq_sks))
        sig_ml_dsa, _ = all_pq_sks[pk_ml_dsa_hex]

        response = requests.get(f"{api_base_url}/accounts/{pk_classic_hex}")
        assert len(response.json()["pq_keys"]) == 1

        # 2. Add two new PQ keys in a single request
        sig_add_pq_1 = oqs.Signature(add_pq_alg_1)
        sig_add_pq_2 = oqs.Signature(add_pq_alg_2)
        oqs_sigs_to_free.extend([sig_add_pq_1, sig_add_pq_2])
        pk_add_pq_1_hex = sig_add_pq_1.generate_keypair().hex()
        pk_add_pq_2_hex = sig_add_pq_2.generate_keypair().hex()
        all_pq_sks[pk_add_pq_1_hex] = (sig_add_pq_1, add_pq_alg_1)
        all_pq_sks[pk_add_pq_2_hex] = (sig_add_pq_2, add_pq_alg_2)
        add_nonce = get_nonce(api_base_url)
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
        response = requests.post(
            f"{api_base_url}/accounts/{pk_classic_hex}/add-pq-keys", json=add_payload
        )
        assert response.status_code == 200, response.text
        assert "Successfully added 2 PQ key(s)" in response.json()["message"]

        # Verify state after adding
        response = requests.get(f"{api_base_url}/accounts/{pk_classic_hex}")
        keys_after_add = response.json()["pq_keys"]
        assert len(keys_after_add) == 3
        added_pks = {k["public_key"] for k in keys_after_add}
        assert pk_add_pq_1_hex in added_pks
        assert pk_add_pq_2_hex in added_pks

        # 3. Remove the two added PQ keys in a single request
        remove_nonce = get_nonce(api_base_url)
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
        response = requests.post(
            f"{api_base_url}/accounts/{pk_classic_hex}/remove-pq-keys",
            json=remove_payload,
        )
        assert response.status_code == 200, response.text
        assert "Successfully removed PQ key(s)" in response.json()["message"]

        # Verify final state
        response = requests.get(f"{api_base_url}/accounts/{pk_classic_hex}")
        keys_after_remove = response.json()["pq_keys"]
        assert len(keys_after_remove) == 1
        assert keys_after_remove[0]["public_key"] == pk_ml_dsa_hex
    finally:
        # Clean up oqs signatures
        for sig in oqs_sigs_to_free:
            sig.free()


def test_graveyard(api_base_url: str):
    """
    Tests the graveyard functionality:
    1. Create account.
    2. Replace a key and verify the old one is in the graveyard.
    3. Remove a key and verify it is also in the graveyard.
    """
    falcon_alg = "Falcon-512"

    # 1. Create account with ML-DSA and one Falcon key
    sk_classic, pk_classic_hex, all_pq_sks, oqs_sigs_to_free = _create_test_account(
        api_base_url, add_pq_algs=[falcon_alg]
    )
    try:
        pk_ml_dsa_hex = next(
            pk for pk, (_, alg) in all_pq_sks.items() if alg == ML_DSA_ALG
        )
        pk_falcon_1_hex = next(
            pk for pk, (_, alg) in all_pq_sks.items() if alg == falcon_alg
        )
        sig_ml_dsa, _ = all_pq_sks[pk_ml_dsa_hex]
        sig_falcon_1, _ = all_pq_sks[pk_falcon_1_hex]

        # 2. Replace the Falcon key with a new one
        sig_falcon_2 = oqs.Signature(falcon_alg)
        oqs_sigs_to_free.append(sig_falcon_2)
        pk_falcon_2_hex = sig_falcon_2.generate_keypair().hex()
        add_nonce = get_nonce(api_base_url)
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
        requests.post(
            f"{api_base_url}/accounts/{pk_classic_hex}/add-pq-keys", json=add_payload
        )
        all_pq_sks[pk_falcon_2_hex] = (sig_falcon_2, falcon_alg)

        # Verify pk_falcon_1_hex is in the graveyard
        response = requests.get(f"{api_base_url}/accounts/{pk_classic_hex}/graveyard")
        assert response.status_code == 200
        graveyard1 = response.json()["graveyard"]
        assert len(graveyard1) == 1
        assert graveyard1[0]["public_key"] == pk_falcon_1_hex

        # 3. Remove the second Falcon key
        remove_nonce = get_nonce(api_base_url)
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
        requests.post(
            f"{api_base_url}/accounts/{pk_classic_hex}/remove-pq-keys",
            json=remove_payload,
        )

        # Verify both keys are now in the graveyard
        response = requests.get(f"{api_base_url}/accounts/{pk_classic_hex}/graveyard")
        assert response.status_code == 200
        graveyard2 = response.json()["graveyard"]
        assert len(graveyard2) == 2
        graveyard_pks = {k["public_key"] for k in graveyard2}
        assert pk_falcon_1_hex in graveyard_pks
        assert pk_falcon_2_hex in graveyard_pks
    finally:
        # Clean up oqs signatures
        for sig in oqs_sigs_to_free:
            sig.free()


def test_pq_key_timing_attack_resistance(api_base_url: str):
    """
    Tests that PQ key operations execute in constant time regardless of
    key existence to prevent timing-based enumeration attacks.

    This is a critical security test for audit compliance that ensures
    the system doesn't leak information about key existence through
    response time variations.
    """
    add_pq_alg = "Falcon-512"
    sk_classic, pk_classic_hex, all_pq_sks, oqs_sigs_to_free = _create_test_account(
        api_base_url, add_pq_algs=[add_pq_alg]
    )

    try:
        pk_ml_dsa_hex = next(
            pk for pk, (_, alg) in all_pq_sks.items() if alg == ML_DSA_ALG
        )
        pk_falcon_hex = next(
            pk for pk, (_, alg) in all_pq_sks.items() if alg == add_pq_alg
        )
        sig_ml_dsa, _ = all_pq_sks[pk_ml_dsa_hex]
        sig_falcon, _ = all_pq_sks[pk_falcon_hex]

        # Test removal timing for existing vs non-existent algorithms
        # 1. Remove existing algorithm (Falcon) - measure time
        nonce1 = get_nonce(api_base_url)
        message1 = f"REMOVE-PQ:{pk_classic_hex}:{add_pq_alg}:{nonce1}".encode()

        start_time = time.perf_counter()
        response1 = requests.post(
            f"{api_base_url}/accounts/{pk_classic_hex}/remove-pq-keys",
            json={
                "algs_to_remove": [add_pq_alg],
                "classic_signature": sk_classic.sign(
                    message1, hashfunc=hashlib.sha256
                ).hex(),
                "pq_signatures": [
                    {
                        "public_key": pk_ml_dsa_hex,
                        "signature": sig_ml_dsa.sign(message1).hex(),
                        "alg": ML_DSA_ALG,
                    },
                    {
                        "public_key": pk_falcon_hex,
                        "signature": sig_falcon.sign(message1).hex(),
                        "alg": add_pq_alg,
                    },
                ],
                "nonce": nonce1,
            },
        )
        existing_time = time.perf_counter() - start_time
        assert response1.status_code == 200

        # 2. Try to remove non-existent algorithm - measure time
        nonce2 = get_nonce(api_base_url)
        nonexistent_alg = "NonExistentAlg"
        message2 = f"REMOVE-PQ:{pk_classic_hex}:{nonexistent_alg}:{nonce2}".encode()

        start_time = time.perf_counter()
        response2 = requests.post(
            f"{api_base_url}/accounts/{pk_classic_hex}/remove-pq-keys",
            json={
                "algs_to_remove": [nonexistent_alg],
                "classic_signature": sk_classic.sign(
                    message2, hashfunc=hashlib.sha256
                ).hex(),
                "pq_signatures": [
                    {
                        "public_key": pk_ml_dsa_hex,
                        "signature": sig_ml_dsa.sign(message2).hex(),
                        "alg": ML_DSA_ALG,
                    }
                ],
                "nonce": nonce2,
            },
        )
        nonexistent_time = time.perf_counter() - start_time
        assert response2.status_code == 404

        # 3. Verify timing difference is within acceptable bounds (<50ms)
        time_difference = abs(existing_time - nonexistent_time)
        assert time_difference < 0.05, (
            f"Timing difference too large: {time_difference}s"
        )

    finally:
        for sig in oqs_sigs_to_free:
            sig.free()
