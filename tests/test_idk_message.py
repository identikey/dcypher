"""
Tests for the IdentiKey (IDK) message format implementation.

These tests ensure that the creation, parsing, and verification of IDK messages
adhere to the `spec.md` document.
"""

import pytest
import os
import json
import ecdsa
import hashlib
import base64
from src.lib import pre
from src.lib import idk_message
from src.lib.idk_message import MerkleTree


@pytest.fixture
def crypto_setup():
    """Provides a crypto context and a pair of keys for testing."""
    cc = pre.create_crypto_context()
    keys = pre.generate_keys(cc)
    signing_key = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
    return {
        "cc": cc,
        "keys": keys,
        "sk": signing_key,
        "vk": signing_key.get_verifying_key(),
    }


def test_merkle_tree_creation():
    """
    Tests the basic creation of a Merkle tree and the root calculation.
    """
    pieces = [b"piece1", b"piece2", b"piece3", b"piece4"]
    tree = MerkleTree(pieces)

    h1 = hashlib.blake2b(b"piece1").digest()
    h2 = hashlib.blake2b(b"piece2").digest()
    h3 = hashlib.blake2b(b"piece3").digest()
    h4 = hashlib.blake2b(b"piece4").digest()

    p12 = hashlib.blake2b(h1 + h2).digest()
    p34 = hashlib.blake2b(h3 + h4).digest()

    root = hashlib.blake2b(p12 + p34).digest()

    assert tree.root == root.hex()


def test_merkle_tree_odd_leaves():
    """
    Tests that the Merkle tree handles an odd number of leaves correctly
    by duplicating the last leaf's hash at the first level.
    """
    pieces = [b"a", b"b", b"c"]
    tree = MerkleTree(pieces)

    h1 = hashlib.blake2b(b"a").digest()
    h2 = hashlib.blake2b(b"b").digest()
    h3 = hashlib.blake2b(b"c").digest()

    p12 = hashlib.blake2b(h1 + h2).digest()
    # The spec says the last node is paired with itself.
    p33 = hashlib.blake2b(h3 + h3).digest()

    root = hashlib.blake2b(p12 + p33).digest()
    assert tree.root == root.hex()


def test_merkle_auth_path():
    """
    Tests that the authentication path for a leaf is generated correctly.
    """
    pieces = [b"a", b"b", b"c", b"d"]
    tree = MerkleTree(pieces)

    h1 = hashlib.blake2b(b"a").digest()
    h2 = hashlib.blake2b(b"b").digest()
    h3 = hashlib.blake2b(b"c").digest()
    h4 = hashlib.blake2b(b"d").digest()
    p34 = hashlib.blake2b(h3 + h4).digest()

    # The auth path for 'a' (index 0) should be [hash(b), hash(hash(c)+hash(d))]
    auth_path_0 = tree.get_auth_path(0)

    # We need to manually calculate the parent node of h3 and h4.
    p34_hex = hashlib.blake2b(h3 + h4).digest().hex()

    assert auth_path_0 == [h2.hex(), p34_hex]

    # Verify the path
    computed_p12 = hashlib.blake2b(h1 + bytes.fromhex(auth_path_0[0])).digest()
    computed_root = hashlib.blake2b(
        computed_p12 + bytes.fromhex(auth_path_0[1])
    ).digest()
    assert computed_root.hex() == tree.root


def test_create_and_verify_idk_message(crypto_setup):
    """
    Tests the full lifecycle of creating and verifying an IDK message.
    This test ensures that a multi-part message can be generated and that
    a single part from it can be successfully verified against the spec.
    """
    # 1. Setup
    cc = crypto_setup["cc"]
    keys = crypto_setup["keys"]
    sk = crypto_setup["sk"]
    vk = crypto_setup["vk"]

    original_data = os.urandom(
        pre.get_slot_count(cc) * 3 + 10
    )  # ensure multiple pieces
    pieces_per_part = 1

    # 2. Create the message parts
    message_parts = idk_message.create_idk_message_parts(
        data=original_data,
        cc=cc,
        pk=keys.publicKey,
        signing_key=sk,
        pieces_per_part=pieces_per_part,
    )

    assert len(message_parts) > 1

    # 3. Choose a part to verify (e.g., the second part)
    part_index_to_test = 1
    part_to_verify_str = message_parts[part_index_to_test]

    # 4. Parse the part using the library function
    parsed_part = idk_message.parse_idk_message_part(part_to_verify_str)
    headers = parsed_part["headers"]
    payload_b64 = parsed_part["payload_b64"]

    # 5. Verify all aspects of the parsed part
    # a. Verify Signature
    signature_hex = headers.pop("Signature")
    canonical_header_str = ""
    # Re-add Part to headers dict for canonical string (it was removed during parsing)
    headers["Part"] = f"{headers['PartNum']}/{headers['TotalParts']}"

    for key in sorted(headers.keys()):
        # skip derived keys
        if key in ["PartNum", "TotalParts"]:
            continue
        canonical_header_str += f"{key}: {headers[key]}\n"

    header_hash = hashlib.sha256(canonical_header_str.encode("utf-8")).digest()

    try:
        vk.verify_digest(bytes.fromhex(signature_hex), header_hash)
    except ecdsa.BadSignatureError:
        pytest.fail("ECDSA signature verification failed")

    # b. Verify ChunkHash
    payload_bytes = base64.b64decode(payload_b64)
    computed_chunk_hash = hashlib.blake2b(payload_bytes).hexdigest()
    assert computed_chunk_hash == headers["ChunkHash"]

    # c. Verify AuthPath
    merkle_root = headers["MerkleRoot"]
    auth_path = json.loads(headers["AuthPath"])

    # Since pieces_per_part=1, the piece index is the part index.
    piece_index = part_index_to_test

    # The payload is the serialized ciphertext piece. We need its hash.
    leaf_hash_bytes = hashlib.blake2b(payload_bytes).digest()

    assert idk_message.verify_merkle_path(
        leaf_hash_bytes=leaf_hash_bytes,
        auth_path_hex=auth_path,
        piece_index=piece_index,
        expected_root_hex=merkle_root,
    ), "Merkle path verification failed"
