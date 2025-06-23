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
    create_test_account_with_keymanager,
)


def test_get_supported_pq_algs(api_base_url: str):
    """
    Tests the /supported-pq-algs endpoint.
    It verifies that the endpoint returns a 200 OK status and that the list of
    algorithms in the response body matches the list defined in the application.

    This test now uses the DCypherClient for more realistic usage patterns.
    """
    from src.lib.api_client import DCypherClient, DCypherAPIError

    client = DCypherClient(api_base_url)
    algorithms = client.get_supported_algorithms()

    # Convert to set for order-independent comparison
    assert set(algorithms) == set(SUPPORTED_SIG_ALGS)


def test_add_and_remove_pq_keys(api_base_url: str):
    """
    Tests the full lifecycle of an account's post-quantum keys:
    1. Create an account with a classic key and two PQ keys.
    2. Successfully add a new PQ key.
    3. Successfully remove an optional PQ key.
    4. Verify the state of the account after each operation.

    This test now uses the DCypherClient for realistic usage patterns.
    """
    from src.lib.api_client import DCypherClient, DCypherAPIError
    import tempfile
    import json
    from pathlib import Path
    from lib.pq_auth import generate_pq_keys

    add_pq_alg_1 = "Falcon-512"
    add_pq_alg_2 = "Falcon-1024"

    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)

        # === 1. Create an account with a classic key and two PQ keys ===

        # Generate classic key
        sk_classic = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
        vk_classic = sk_classic.get_verifying_key()
        assert vk_classic is not None
        pk_classic_hex = vk_classic.to_string().hex()

        # Save classic key
        classic_sk_path = temp_path / "classic.sk"
        with open(classic_sk_path, "w") as f:
            f.write(sk_classic.to_string().hex())

        # Generate PQ keys
        ml_dsa_pk, ml_dsa_sk = generate_pq_keys(ML_DSA_ALG)
        falcon_pk_1, falcon_sk_1 = generate_pq_keys(add_pq_alg_1)

        # Save PQ keys
        ml_dsa_sk_path = temp_path / "ml_dsa.sk"
        with open(ml_dsa_sk_path, "wb") as f:
            f.write(ml_dsa_sk)

        falcon_sk_1_path = temp_path / "falcon_1.sk"
        with open(falcon_sk_1_path, "wb") as f:
            f.write(falcon_sk_1)

        # Create auth keys file
        auth_keys_data = {
            "classic_sk_path": str(classic_sk_path),
            "pq_keys": [
                {
                    "sk_path": str(ml_dsa_sk_path),
                    "pk_hex": ml_dsa_pk.hex(),
                    "alg": ML_DSA_ALG,
                },
                {
                    "sk_path": str(falcon_sk_1_path),
                    "pk_hex": falcon_pk_1.hex(),
                    "alg": add_pq_alg_1,
                },
            ],
        }
        auth_keys_file = temp_path / "auth_keys.json"
        with open(auth_keys_file, "w") as f:
            json.dump(auth_keys_data, f)

        # Create API client and account
        client = DCypherClient(api_base_url, str(auth_keys_file))

        initial_pq_keys = [
            {"pk_hex": ml_dsa_pk.hex(), "alg": ML_DSA_ALG},
            {"pk_hex": falcon_pk_1.hex(), "alg": add_pq_alg_1},
        ]
        client.create_account(pk_classic_hex, initial_pq_keys)

        # Verify initial account state
        account_info = client.get_account(pk_classic_hex)
        assert len(account_info["pq_keys"]) == 2

        # === 2. Add a new PQ key ===

        # Generate new PQ key for addition
        falcon_pk_2, falcon_sk_2 = generate_pq_keys(add_pq_alg_2)

        # Save the new PQ key
        falcon_sk_2_path = temp_path / "falcon_2.sk"
        with open(falcon_sk_2_path, "wb") as f:
            f.write(falcon_sk_2)

        # Update auth keys to include the new key
        auth_keys_data = {
            "classic_sk_path": str(classic_sk_path),
            "pq_keys": [
                {
                    "sk_path": str(ml_dsa_sk_path),
                    "pk_hex": ml_dsa_pk.hex(),
                    "alg": ML_DSA_ALG,
                },
                {
                    "sk_path": str(falcon_sk_1_path),
                    "pk_hex": falcon_pk_1.hex(),
                    "alg": add_pq_alg_1,
                },
                {
                    "sk_path": str(falcon_sk_2_path),
                    "pk_hex": falcon_pk_2.hex(),
                    "alg": add_pq_alg_2,
                },
            ],
        }
        with open(auth_keys_file, "w") as f:
            json.dump(auth_keys_data, f)

        # Reload the client with updated auth keys
        client = DCypherClient(api_base_url, str(auth_keys_file))

        # Add the new PQ key using API client
        new_keys = [{"pk_hex": falcon_pk_2.hex(), "alg": add_pq_alg_2}]
        result = client.add_pq_keys(pk_classic_hex, new_keys)
        assert "Successfully added 1 PQ key(s)" in result["message"]

        # Verify account state after adding key
        account_info_after_add = client.get_account(pk_classic_hex)
        pq_keys_after_add = account_info_after_add["pq_keys"]
        assert len(pq_keys_after_add) == 3
        assert any(k["public_key"] == falcon_pk_2.hex() for k in pq_keys_after_add)

        # === 3. Remove an optional PQ key ===

        # Remove the first Falcon key using API client
        result = client.remove_pq_keys(pk_classic_hex, [add_pq_alg_1])
        assert "Successfully removed PQ key(s)" in result["message"]

        # Verify final account state
        account_info_final = client.get_account(pk_classic_hex)
        keys_after_remove = account_info_final["pq_keys"]
        assert len(keys_after_remove) == 2
        assert not any(k["public_key"] == falcon_pk_1.hex() for k in keys_after_remove)
        assert any(k["public_key"] == ml_dsa_pk.hex() for k in keys_after_remove)
        assert any(k["public_key"] == falcon_pk_2.hex() for k in keys_after_remove)


def test_remove_mandatory_pq_key_fails(api_base_url: str, tmp_path):
    """
    Tests that an attempt to remove the mandatory ML-DSA key from an account
    is rejected with a 400 error.

    This test now uses the enhanced DCypherClient with KeyManager for simplified testing.
    """
    # Create minimal account with only mandatory ML-DSA key using streamlined helper
    client, pk_classic_hex = create_test_account_with_keymanager(api_base_url, tmp_path)

    # Verify initial account state
    account_info = client.get_account(pk_classic_hex)
    assert len(account_info["pq_keys"]) == 1
    assert account_info["pq_keys"][0]["alg"] == ML_DSA_ALG

    # Attempt to remove the mandatory key - should raise ValidationError
    from src.lib.api_client import ValidationError

    with pytest.raises(ValidationError) as exc_info:
        client.remove_pq_keys(pk_classic_hex, [ML_DSA_ALG])

    # Verify the error message contains the expected text
    assert f"Cannot remove the mandatory PQ key ({ML_DSA_ALG})" in str(exc_info.value)


def test_add_pq_key_authorization_failures(api_base_url: str, tmp_path):
    """
    Tests various authorization failure scenarios when adding a PQ key.
    - Invalid classic signature.
    - Missing signature from an existing PQ key.
    - Invalid signature from an existing PQ key.
    - Invalid signature for the new PQ key itself.
    This test demonstrates the new API client pattern with automatic resource management.
    """
    # 1. Setup: Create an account with one mandatory and one optional key using streamlined helper
    add_pq_alg_1 = "Falcon-512"
    add_pq_alg_2 = "Falcon-1024"

    # Create account with additional PQ algorithm using the streamlined helper
    client, pk_classic_hex = create_test_account_with_keymanager(
        api_base_url, tmp_path, additional_pq_algs=[add_pq_alg_1]
    )

    with client.signing_keys() as keys:
        sk_classic = keys["classic_sk"]

        # Get the existing PQ keys from the signing keys
        ml_dsa_key = None
        falcon_key = None
        for pq_key in keys["pq_sigs"]:
            if pq_key["alg"] == ML_DSA_ALG:
                ml_dsa_key = pq_key
            elif pq_key["alg"] == add_pq_alg_1:
                falcon_key = pq_key

        assert ml_dsa_key is not None, "ML-DSA key should be present"
        assert falcon_key is not None, "Falcon key should be present"

        pk_ml_dsa_hex = ml_dsa_key["pk_hex"]
        sig_ml_dsa = ml_dsa_key["sig"]
        pk_add_pq_1_hex = falcon_key["pk_hex"]
        sig_add_pq_1 = falcon_key["sig"]

        # Create a new key for the test
        with oqs.Signature(add_pq_alg_2) as sig_add_pq_2:
            pk_add_pq_2_hex = sig_add_pq_2.generate_keypair().hex()

            # 2. Prepare for a valid "add" operation
            add_nonce = get_nonce(api_base_url)
            correct_add_msg = (
                f"ADD-PQ:{pk_classic_hex}:{add_pq_alg_2}:{add_nonce}".encode()
            )
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
    # OQS signatures are automatically freed when exiting the context


def test_replace_existing_pq_key(api_base_url: str, tmp_path):
    """Tests that adding a key for an existing algorithm replaces the old key.

    This test now uses the DCypherClient for account and graveyard operations.
    """
    from src.lib.api_client import DCypherClient, DCypherAPIError

    falcon_alg = "Falcon-512"
    # Create account with additional Falcon algorithm using KeyManager-based helper
    client, pk_classic_hex = create_test_account_with_keymanager(
        api_base_url, tmp_path, additional_pq_algs=[falcon_alg]
    )

    with client.signing_keys() as keys:
        sk_classic = keys["classic_sk"]

        # Get the existing keys from the signing keys
        ml_dsa_key = None
        falcon_old_key = None
        for pq_key in keys["pq_sigs"]:
            if pq_key["alg"] == ML_DSA_ALG:
                ml_dsa_key = pq_key
            elif pq_key["alg"] == falcon_alg:
                falcon_old_key = pq_key

        assert ml_dsa_key is not None, "ML-DSA key should be present"
        assert falcon_old_key is not None, "Falcon key should be present"

        pk_ml_dsa_hex = ml_dsa_key["pk_hex"]
        sig_ml_dsa = ml_dsa_key["sig"]
        pk_falcon_old_hex = falcon_old_key["pk_hex"]
        sig_falcon_old = falcon_old_key["sig"]

        # Create API client for verification operations
        api_client = DCypherClient(api_base_url)

        add_nonce = get_nonce(api_base_url)
        add_msg = f"ADD-PQ:{pk_classic_hex}:{falcon_alg}:{add_nonce}".encode()

        # Create a new key pair for the same algorithm
        with oqs.Signature(falcon_alg) as sig_falcon_new:
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

            # Verify state after adding: key count should be the same using API client
            account_info = api_client.get_account(pk_classic_hex)
            keys_after_add = account_info["pq_keys"]
            assert len(keys_after_add) == 2

            # Verify the old key is in the graveyard using API client
            graveyard_keys = api_client.get_account_graveyard(pk_classic_hex)
            assert len(graveyard_keys) == 1
            assert graveyard_keys[0]["public_key"] == pk_falcon_old_hex
            assert graveyard_keys[0]["alg"] == falcon_alg

            # Verify the new key is active
            active_pks = {k["public_key"] for k in keys_after_add}
            assert pk_falcon_new_hex in active_pks, "New key should be active"
            assert pk_falcon_old_hex not in active_pks, "Old key should not be active"
        # OQS signature for new falcon key is automatically freed when exiting context
    # OQS signatures are automatically freed when exiting the context


def test_add_unsupported_pq_key_fails(api_base_url: str, tmp_path):
    """Tests adding a key with an unsupported algorithm fails."""
    # Create account using KeyManager-based helper
    client, pk_classic_hex = create_test_account_with_keymanager(api_base_url, tmp_path)

    with client.signing_keys() as keys:
        sk_classic = keys["classic_sk"]

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
    # OQS signatures are automatically freed when exiting the context


def test_rotate_mandatory_pq_key_succeeds(api_base_url: str):
    """Tests that ML-DSA key rotation works correctly for security purposes.

    This test demonstrates that users can rotate their mandatory ML-DSA key
    if it becomes compromised or for routine security maintenance.
    """
    from src.lib.api_client import DCypherClient, DCypherAPIError
    import tempfile
    import json
    from pathlib import Path
    from lib.pq_auth import generate_pq_keys

    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)

        # === 1. Create account with initial ML-DSA key ===

        # Generate classic key
        sk_classic = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
        vk_classic = sk_classic.get_verifying_key()
        assert vk_classic is not None
        pk_classic_hex = vk_classic.to_string().hex()

        # Save classic key
        classic_sk_path = temp_path / "classic.sk"
        with open(classic_sk_path, "w") as f:
            f.write(sk_classic.to_string().hex())

        # Generate initial ML-DSA key
        ml_dsa_pk_old, ml_dsa_sk_old = generate_pq_keys(ML_DSA_ALG)

        # Save initial ML-DSA key
        ml_dsa_sk_old_path = temp_path / "ml_dsa_old.sk"
        with open(ml_dsa_sk_old_path, "wb") as f:
            f.write(ml_dsa_sk_old)

        # Create auth keys file with initial ML-DSA key
        auth_keys_data = {
            "classic_sk_path": str(classic_sk_path),
            "pq_keys": [
                {
                    "sk_path": str(ml_dsa_sk_old_path),
                    "pk_hex": ml_dsa_pk_old.hex(),
                    "alg": ML_DSA_ALG,
                }
            ],
        }
        auth_keys_file = temp_path / "auth_keys.json"
        with open(auth_keys_file, "w") as f:
            json.dump(auth_keys_data, f)

        # Create API client and initial account
        client = DCypherClient(api_base_url, str(auth_keys_file))

        initial_pq_keys = [{"pk_hex": ml_dsa_pk_old.hex(), "alg": ML_DSA_ALG}]
        client.create_account(pk_classic_hex, initial_pq_keys)

        # Verify initial account state
        account_info = client.get_account(pk_classic_hex)
        assert len(account_info["pq_keys"]) == 1
        assert account_info["pq_keys"][0]["alg"] == ML_DSA_ALG
        assert account_info["pq_keys"][0]["public_key"] == ml_dsa_pk_old.hex()

        # === 2. Rotate the ML-DSA key ===

        # Generate new ML-DSA key
        ml_dsa_pk_new, ml_dsa_sk_new = generate_pq_keys(ML_DSA_ALG)

        # Save new ML-DSA key
        ml_dsa_sk_new_path = temp_path / "ml_dsa_new.sk"
        with open(ml_dsa_sk_new_path, "wb") as f:
            f.write(ml_dsa_sk_new)

        # Update auth keys to include both old and new ML-DSA keys for the rotation
        auth_keys_data = {
            "classic_sk_path": str(classic_sk_path),
            "pq_keys": [
                {
                    "sk_path": str(ml_dsa_sk_old_path),
                    "pk_hex": ml_dsa_pk_old.hex(),
                    "alg": ML_DSA_ALG,
                },
                {
                    "sk_path": str(ml_dsa_sk_new_path),
                    "pk_hex": ml_dsa_pk_new.hex(),
                    "alg": ML_DSA_ALG,
                },
            ],
        }
        with open(auth_keys_file, "w") as f:
            json.dump(auth_keys_data, f)

        # Reload client with updated auth keys
        client = DCypherClient(api_base_url, str(auth_keys_file))

        # Rotate the ML-DSA key using API client
        new_keys = [{"pk_hex": ml_dsa_pk_new.hex(), "alg": ML_DSA_ALG}]
        result = client.add_pq_keys(pk_classic_hex, new_keys)
        assert "Successfully added 1 PQ key(s)" in result["message"]

        # === 3. Verify the rotation succeeded ===

        # Verify account state after rotation
        account_info_after = client.get_account(pk_classic_hex)
        assert len(account_info_after["pq_keys"]) == 1  # Still only one ML-DSA key
        assert account_info_after["pq_keys"][0]["alg"] == ML_DSA_ALG
        assert (
            account_info_after["pq_keys"][0]["public_key"] == ml_dsa_pk_new.hex()
        )  # New key is active

        # Verify old key is in graveyard
        graveyard = client.get_account_graveyard(pk_classic_hex)
        assert len(graveyard) == 1
        assert graveyard[0]["public_key"] == ml_dsa_pk_old.hex()
        assert graveyard[0]["alg"] == ML_DSA_ALG

        # === 4. Verify the new key works for authentication ===

        # Update auth keys to only include the new ML-DSA key
        auth_keys_data = {
            "classic_sk_path": str(classic_sk_path),
            "pq_keys": [
                {
                    "sk_path": str(ml_dsa_sk_new_path),
                    "pk_hex": ml_dsa_pk_new.hex(),
                    "alg": ML_DSA_ALG,
                }
            ],
        }
        with open(auth_keys_file, "w") as f:
            json.dump(auth_keys_data, f)

        # Create new client with rotated key and verify it can perform operations
        client_new = DCypherClient(api_base_url, str(auth_keys_file))

        # Should be able to query account with new key
        final_account_info = client_new.get_account(pk_classic_hex)
        assert len(final_account_info["pq_keys"]) == 1
        assert final_account_info["pq_keys"][0]["public_key"] == ml_dsa_pk_new.hex()


def test_remove_pq_key_authorization_failures(api_base_url: str, tmp_path):
    """
    Tests various authorization failure scenarios when removing a PQ key.
    - Invalid classic signature.
    - Missing signature from an existing PQ key.
    - Invalid signature from an existing PQ key.
    This test demonstrates the new API client pattern with automatic resource management.
    """
    # 1. Setup: Create an account with ML-DSA key and one additional key using streamlined helper
    add_pq_alg_1 = "Falcon-512"

    # Create account with additional PQ algorithm using the streamlined helper
    client, pk_classic_hex = create_test_account_with_keymanager(
        api_base_url, tmp_path, additional_pq_algs=[add_pq_alg_1]
    )

    with client.signing_keys() as keys:
        sk_classic = keys["classic_sk"]

        # Get the existing PQ keys from the signing keys
        ml_dsa_key = None
        falcon_key = None
        for pq_key in keys["pq_sigs"]:
            if pq_key["alg"] == ML_DSA_ALG:
                ml_dsa_key = pq_key
            elif pq_key["alg"] == add_pq_alg_1:
                falcon_key = pq_key

        assert ml_dsa_key is not None, "ML-DSA key should be present"
        assert falcon_key is not None, "Falcon-512 key should be present"

        pk_ml_dsa_hex = ml_dsa_key["pk_hex"]
        sig_ml_dsa = ml_dsa_key["sig"]
        pk_add_pq_1_hex = falcon_key["pk_hex"]
        sig_add_pq_1 = falcon_key["sig"]

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
        payload["pq_signatures"] = [valid_pq_sigs[0]]  # Missing one
        response = requests.post(
            f"{api_base_url}/accounts/{pk_classic_hex}/remove-pq-keys", json=payload
        )
        assert response.status_code == 401
        assert "Signatures from all existing PQ keys are required" in response.text

        # Case 3: Invalid signature from an existing PQ key
        invalid_pq_sigs = [
            valid_pq_sigs[0],
            {
                "public_key": pk_add_pq_1_hex,
                "signature": sig_add_pq_1.sign(incorrect_msg).hex(),
                "alg": add_pq_alg_1,
            },
        ]
        payload["pq_signatures"] = invalid_pq_sigs
        response = requests.post(
            f"{api_base_url}/accounts/{pk_classic_hex}/remove-pq-keys", json=payload
        )
        assert response.status_code == 401
        assert "Invalid signature for existing PQ key" in response.text
    # OQS signatures are automatically freed when exiting the context


def test_remove_nonexistent_pq_key_fails(api_base_url: str, tmp_path):
    """
    Tests that removing a PQ key not on the account fails.
    """
    # 1. Setup: Create a standard account using KeyManager-based helper
    client, pk_classic_hex = create_test_account_with_keymanager(api_base_url, tmp_path)

    with client.signing_keys() as keys:
        pk_ml_dsa_hex = keys["pq_sigs"][0]["pk_hex"]
        sig_ml_dsa = keys["pq_sigs"][0]["sig"]
        sk_classic = keys["classic_sk"]

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
    # OQS signatures are automatically freed when exiting the context


def test_add_and_remove_multiple_pq_keys(api_base_url: str, tmp_path):
    """
    Tests adding and removing multiple PQ keys in a single request.

    This test now uses the DCypherClient for account verification operations.
    """
    from src.lib.api_client import DCypherClient, DCypherAPIError

    # 1. Setup: Create a minimal account using KeyManager-based helper
    add_pq_alg_1 = "Falcon-512"
    add_pq_alg_2 = "Falcon-1024"

    client, pk_classic_hex = create_test_account_with_keymanager(api_base_url, tmp_path)

    with client.signing_keys() as keys:
        pk_ml_dsa_hex = keys["pq_sigs"][0]["pk_hex"]
        sig_ml_dsa = keys["pq_sigs"][0]["sig"]
        sk_classic = keys["classic_sk"]

        # Create API client for verification operations
        api_client = DCypherClient(api_base_url)

        # Verify initial account state using API client
        account_info = api_client.get_account(pk_classic_hex)
        assert len(account_info["pq_keys"]) == 1

        # 2. Add two new PQ keys in a single request
        sig_add_pq_1 = oqs.Signature(add_pq_alg_1)
        sig_add_pq_2 = oqs.Signature(add_pq_alg_2)
        pk_add_pq_1_hex = sig_add_pq_1.generate_keypair().hex()
        pk_add_pq_2_hex = sig_add_pq_2.generate_keypair().hex()
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

        # Verify state after adding using API client
        account_info_after_add = api_client.get_account(pk_classic_hex)
        keys_after_add = account_info_after_add["pq_keys"]
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

        # Verify final state using API client
        account_info_after_remove = api_client.get_account(pk_classic_hex)
        keys_after_remove = account_info_after_remove["pq_keys"]
        assert len(keys_after_remove) == 1
        assert keys_after_remove[0]["public_key"] == pk_ml_dsa_hex

        # Clean up the additional OQS signatures we created
        sig_add_pq_1.free()
        sig_add_pq_2.free()
    # OQS signatures are automatically freed when exiting the context


def test_graveyard(api_base_url: str, tmp_path):
    """
    Tests the graveyard functionality:
    1. Create account.
    2. Replace a key and verify the old one is in the graveyard.
    3. Remove a key and verify it is also in the graveyard.

    This test now uses the DCypherClient for graveyard checks.
    """
    from src.lib.api_client import DCypherClient, DCypherAPIError

    falcon_alg = "Falcon-512"

    # 1. Create account with ML-DSA and one Falcon key using KeyManager-based helper
    client, pk_classic_hex = create_test_account_with_keymanager(
        api_base_url, tmp_path, additional_pq_algs=[falcon_alg]
    )

    with client.signing_keys() as keys:
        # Find the ML-DSA and Falcon keys
        ml_dsa_key = None
        falcon_key = None
        for pq_key in keys["pq_sigs"]:
            if pq_key["alg"] == ML_DSA_ALG:
                ml_dsa_key = pq_key
            elif pq_key["alg"] == falcon_alg:
                falcon_key = pq_key

        assert ml_dsa_key is not None, "ML-DSA key should be present"
        assert falcon_key is not None, "Falcon key should be present"

        pk_ml_dsa_hex = ml_dsa_key["pk_hex"]
        sig_ml_dsa = ml_dsa_key["sig"]
        pk_falcon_1_hex = falcon_key["pk_hex"]
        sig_falcon_1 = falcon_key["sig"]
        sk_classic = keys["classic_sk"]

        # Create API client for graveyard operations
        api_client = DCypherClient(api_base_url)

        # 2. Replace the Falcon key with a new one
        sig_falcon_2 = oqs.Signature(falcon_alg)
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

        # Verify pk_falcon_1_hex is in the graveyard using API client
        graveyard1 = api_client.get_account_graveyard(pk_classic_hex)
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

        # Verify both keys are now in the graveyard using API client
        graveyard2 = api_client.get_account_graveyard(pk_classic_hex)
        assert len(graveyard2) == 2
        graveyard_pks = {k["public_key"] for k in graveyard2}
        assert pk_falcon_1_hex in graveyard_pks
        assert pk_falcon_2_hex in graveyard_pks

        # Clean up the additional OQS signature we created
        sig_falcon_2.free()
    # OQS signatures are automatically freed when exiting the context


def test_pq_key_timing_attack_resistance(api_base_url: str, tmp_path):
    """
    Tests that PQ key operations execute in constant time regardless of
    key existence to prevent timing-based enumeration attacks.

    This is a critical security test for audit compliance that ensures
    the system doesn't leak information about key existence through
    response time variations.
    """
    add_pq_alg = "Falcon-512"

    # Create account with additional Falcon key using KeyManager-based helper
    client, pk_classic_hex = create_test_account_with_keymanager(
        api_base_url, tmp_path, additional_pq_algs=[add_pq_alg]
    )

    with client.signing_keys() as keys:
        # Find the ML-DSA and Falcon keys
        ml_dsa_key = None
        falcon_key = None
        for pq_key in keys["pq_sigs"]:
            if pq_key["alg"] == ML_DSA_ALG:
                ml_dsa_key = pq_key
            elif pq_key["alg"] == add_pq_alg:
                falcon_key = pq_key

        assert ml_dsa_key is not None, "ML-DSA key should be present"
        assert falcon_key is not None, "Falcon key should be present"

        pk_ml_dsa_hex = ml_dsa_key["pk_hex"]
        sig_ml_dsa = ml_dsa_key["sig"]
        pk_falcon_hex = falcon_key["pk_hex"]
        sig_falcon = falcon_key["sig"]
        sk_classic = keys["classic_sk"]

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
    # OQS signatures are automatically freed when exiting the context
