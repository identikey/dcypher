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
    by pairing the last leaf's hash with a zero-hash, per the spec.
    """
    pieces = [b"a", b"b", b"c"]
    tree = MerkleTree(pieces)

    h1 = hashlib.blake2b(b"a").digest()
    h2 = hashlib.blake2b(b"b").digest()
    h3 = hashlib.blake2b(b"c").digest()
    zero_hash = bytes(len(h3))  # A zero-filled hash of the same length

    p12 = hashlib.blake2b(h1 + h2).digest()
    # The spec says the last node is paired with a zero-filled hash.
    p3_zero = hashlib.blake2b(h3 + zero_hash).digest()

    root = hashlib.blake2b(p12 + p3_zero).digest()
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


def test_idk_message_format_conformance(crypto_setup):
    """
    Tests that the generated IDK message part string conforms to the spec's
    textual format, ensuring it can be parsed by any compliant tool.
    """
    # 1. Setup
    cc = crypto_setup["cc"]
    keys = crypto_setup["keys"]
    sk = crypto_setup["sk"]
    original_data = os.urandom(100)  # small but non-trivial data
    pieces_per_part = 1

    # 2. Create message parts
    message_parts = idk_message.create_idk_message_parts(
        data=original_data,
        cc=cc,
        pk=keys.publicKey,
        signing_key=sk,
        pieces_per_part=pieces_per_part,
    )

    # 3. Take the first part and inspect its raw string format
    part_to_test_str = message_parts[0]
    lines = part_to_test_str.split("\n")
    total_parts = len(message_parts)
    part_num = 1

    # a. Check BEGIN/END markers
    assert lines[0] == f"----- BEGIN IDK MESSAGE PART {part_num}/{total_parts} -----"
    assert lines[-1] == f"----- END IDK MESSAGE PART {part_num}/{total_parts} -----"

    # b. Check for a single empty line between headers and payload
    empty_line_indices = [i for i, line in enumerate(lines) if line == ""]
    assert len(empty_line_indices) == 1, "There should be exactly one empty line"
    header_end_index = empty_line_indices[0]

    # c. Check header format (Key: Value) and alphabetical order
    header_lines = lines[1:header_end_index]
    header_keys = []
    for header_line in header_lines:
        assert ": " in header_line, f"Header line '{header_line}' is malformed"
        key, _ = header_line.split(": ", 1)
        header_keys.append(key)

    assert header_keys == sorted(header_keys), "Headers are not in alphabetical order"

    # d. Check payload is valid Base64
    payload_b64 = "".join(lines[header_end_index + 1 : -1])
    try:
        base64.b64decode(payload_b64, validate=True)
    except Exception:
        pytest.fail("Payload is not valid Base64")

    # e. Check all mandatory headers from the spec are present
    expected_headers = {
        "Version",
        "SlotsTotal",
        "SlotsUsed",
        "BytesTotal",
        "MerkleRoot",
        "Signature",
        "Part",
        "ChunkHash",
        "AuthPath",
    }
    assert set(header_keys).issuperset(expected_headers), (
        f"Missing headers: {expected_headers - set(header_keys)}"
    )


def test_full_message_reconstruction_and_decryption(crypto_setup):
    """
    Tests the end-to-end process of creating, parsing, reassembling,
    and decrypting a multi-part message to verify data integrity.
    This also implicitly tests the correct usage of SlotsUsed and BytesTotal.
    """
    # 1. Setup
    cc = crypto_setup["cc"]
    keys = crypto_setup["keys"]
    sk = crypto_setup["sk"]
    vk = crypto_setup["vk"]

    # Use data that reliably creates multiple parts
    # Ensure data size is just over what fits in a single ciphertext.
    # With a 2-bytes-per-coeff ratio, this creates slots_used > slots_total.
    original_data = os.urandom(pre.get_slot_count(cc) * 2 + 1)
    pieces_per_part = 1

    # 2. Create the message parts
    message_parts = idk_message.create_idk_message_parts(
        data=original_data,
        cc=cc,
        pk=keys.publicKey,
        signing_key=sk,
        pieces_per_part=pieces_per_part,
    )
    assert len(message_parts) > 1, (
        "Test requires multiple message parts to be generated"
    )

    # 3. Process each part and reconstruct pieces
    reconstructed_pieces_bytes = []
    merkle_root_from_headers = None
    bytes_total_from_headers = None
    total_slots_from_parts = 0

    for i, part_str in enumerate(message_parts):
        parsed_part = idk_message.parse_idk_message_part(part_str)
        headers = parsed_part["headers"]
        payload_b64 = parsed_part["payload_b64"]

        # a. Verify Signature
        signature_hex = headers.pop("Signature")
        headers["Part"] = f"{headers['PartNum']}/{headers['TotalParts']}"
        canonical_header_str = ""
        for key in sorted(headers.keys()):
            if key in ["PartNum", "TotalParts"]:
                continue
            canonical_header_str += f"{key}: {headers[key]}\n"
        header_hash = hashlib.sha256(canonical_header_str.encode("utf-8")).digest()
        try:
            vk.verify_digest(bytes.fromhex(signature_hex), header_hash)
        except ecdsa.BadSignatureError:
            pytest.fail(f"ECDSA signature verification failed for part {i + 1}")

        # b. Store and check for header consistency across parts
        if merkle_root_from_headers is None:
            merkle_root_from_headers = headers["MerkleRoot"]
            bytes_total_from_headers = int(headers["BytesTotal"])
        else:
            assert headers["MerkleRoot"] == merkle_root_from_headers
            assert int(headers["BytesTotal"]) == bytes_total_from_headers

        # c. Verify payload and its place in the Merkle tree
        payload_bytes = base64.b64decode(payload_b64)
        assert hashlib.blake2b(payload_bytes).hexdigest() == headers["ChunkHash"]
        leaf_hash_bytes = hashlib.blake2b(payload_bytes).digest()
        assert idk_message.verify_merkle_path(
            leaf_hash_bytes=leaf_hash_bytes,
            auth_path_hex=json.loads(headers["AuthPath"]),
            piece_index=i,  # Since pieces_per_part=1, piece_index == part_index
            expected_root_hex=merkle_root_from_headers,
        ), f"Merkle path verification failed for part {i + 1}"

        reconstructed_pieces_bytes.append(payload_bytes)

    # 4. Deserialize, decrypt, and reconstruct original data
    assert len(reconstructed_pieces_bytes) == len(message_parts)
    deserialized_ciphertexts = [
        pre.deserialize_ciphertext(piece_bytes)
        for piece_bytes in reconstructed_pieces_bytes
    ]
    # Calculate total slots used from the message-wide BytesTotal header.
    assert bytes_total_from_headers is not None
    total_slots_for_message = (bytes_total_from_headers + 1) // 2
    decrypted_coeffs = pre.decrypt(
        cc, keys.secretKey, deserialized_ciphertexts, total_slots_for_message
    )

    # 5. Convert back to bytes and verify final data integrity
    # This function is expected to handle the truncation based on total_bytes.
    final_data = pre.coefficients_to_bytes(
        decrypted_coeffs, total_bytes=bytes_total_from_headers
    )
    assert final_data == original_data


def test_create_and_verify_with_optional_headers(crypto_setup):
    """
    Tests that optional headers are correctly included, signed, and verified.
    """
    # 1. Setup
    cc = crypto_setup["cc"]
    keys = crypto_setup["keys"]
    sk = crypto_setup["sk"]
    vk = crypto_setup["vk"]
    original_data = os.urandom(50)
    optional_headers = {"Comment": "This is a test comment."}

    # 2. Create message with optional headers
    message_parts = idk_message.create_idk_message_parts(
        data=original_data,
        cc=cc,
        pk=keys.publicKey,
        signing_key=sk,
        optional_headers=optional_headers,
    )
    part_to_verify_str = message_parts[0]

    # 3. Parse and verify
    parsed_part = idk_message.parse_idk_message_part(part_to_verify_str)
    headers = parsed_part["headers"]

    # a. Check that the optional header is present
    assert "Comment" in headers
    assert headers["Comment"] == "This is a test comment."

    # b. Verify the signature, which must now include the optional header
    signature_hex = headers.pop("Signature")
    headers["Part"] = f"{headers['PartNum']}/{headers['TotalParts']}"
    canonical_header_str = ""
    # The optional header must be part of the canonical string for signature to be valid
    for key in sorted(headers.keys()):
        if key in ["PartNum", "TotalParts"]:
            continue
        canonical_header_str += f"{key}: {headers[key]}\n"
    header_hash = hashlib.sha256(canonical_header_str.encode("utf-8")).digest()

    try:
        vk.verify_digest(bytes.fromhex(signature_hex), header_hash)
    except ecdsa.BadSignatureError:
        pytest.fail("Signature verification failed with optional header")


@pytest.mark.parametrize(
    "tamper_func, error_msg",
    [
        (
            lambda h, p: ({**h, "Signature": "00" * 64}, p),
            "Signature verification should fail for a bad signature",
        ),
        (
            # Tamper payload with invalid Base64 characters
            lambda h, p: (h, p + "!@#$"),
            "Parsing should fail for a payload with invalid Base64 characters",
        ),
        (
            # Tamper payload with valid Base64 but wrong content
            lambda h, p: (h, p[:-1] + ("a" if p[-1] != "a" else "b")),
            "ChunkHash verification should fail for tampered but valid Base64 payload",
        ),
        (
            lambda h, p: ({**h, "ChunkHash": "00" * 64}, p),
            "ChunkHash verification should fail for a bad hash",
        ),
        (
            lambda h, p: ({**h, "MerkleRoot": "00" * 64}, p),
            "Merkle path verification should fail for a bad root",
        ),
        (
            lambda h, p: ({**h, "AuthPath": "[]"}, p),
            "Merkle path verification should fail for a bad auth path",
        ),
    ],
)
def test_verification_failures(crypto_setup, tamper_func, error_msg):
    """
    Tests that message verification fails when parts of the message are tampered with.
    """
    # 1. Create a valid baseline message part
    cc = crypto_setup["cc"]
    keys = crypto_setup["keys"]
    sk = crypto_setup["sk"]
    vk = crypto_setup["vk"]
    # Use enough data to guarantee multiple pieces, so AuthPath is never empty.
    original_data = os.urandom(pre.get_slot_count(cc) * 2 + 1)
    message_parts = idk_message.create_idk_message_parts(
        data=original_data, cc=cc, pk=keys.publicKey, signing_key=sk
    )
    part_str = message_parts[0]
    parsed_part = idk_message.parse_idk_message_part(part_str)
    original_headers = parsed_part["headers"]
    original_payload_b64 = parsed_part["payload_b64"]

    # 2. Tamper with the headers or payload
    tampered_headers, tampered_payload_b64 = tamper_func(
        original_headers.copy(), original_payload_b64
    )

    # 3. Re-assemble the tampered message part string
    header_block = ""
    for key in sorted(tampered_headers.keys()):
        # Don't include derived fields in the raw string
        if key not in ["PartNum", "TotalParts"]:
            header_block += f"{key}: {tampered_headers[key]}\n"

    part_num = tampered_headers["PartNum"]
    total_parts = tampered_headers["TotalParts"]
    tampered_part_str = (
        f"----- BEGIN IDK MESSAGE PART {part_num}/{total_parts} -----\n"
        f"{header_block}\n"
        f"{tampered_payload_b64}\n"
        f"----- END IDK MESSAGE PART {part_num}/{total_parts} -----"
    )

    # 4. Assert that the high-level decryption/verification function raises an error
    with pytest.raises(ValueError, match="Verification failed"):
        idk_message.decrypt_idk_message(
            cc=cc, sk=keys.secretKey, vk=vk, message_str=tampered_part_str
        )


def test_multiple_pieces_per_part_limitation(crypto_setup):
    """
    Tests message creation with multiple pieces per part and verifies the
    known limitation that the AuthPath only validates the first piece.
    """
    # 1. Setup
    cc = crypto_setup["cc"]
    keys = crypto_setup["keys"]
    sk = crypto_setup["sk"]
    # Generate enough data for at least 2 pieces.
    original_data = os.urandom(pre.get_slot_count(cc) * 4)

    # 2. Create a message with 2 pieces per part
    message_parts = idk_message.create_idk_message_parts(
        data=original_data,
        cc=cc,
        pk=keys.publicKey,
        signing_key=sk,
        pieces_per_part=2,
    )
    assert len(message_parts) > 0
    part_to_verify_str = message_parts[0]

    # 3. Manually verify the pieces from the first part
    parsed_part = idk_message.parse_idk_message_part(part_to_verify_str)
    headers = parsed_part["headers"]
    payload_bytes = base64.b64decode(parsed_part["payload_b64"])

    # We can get this by re-creating the first two pieces and checking their length.
    temp_coeffs_1 = pre.bytes_to_coefficients(
        original_data[: pre.get_slot_count(cc) * 2], pre.get_slot_count(cc)
    )
    temp_piece_1 = pre.encrypt(cc, keys.publicKey, temp_coeffs_1)[0]
    ser_piece_1 = pre.serialize_to_bytes(temp_piece_1)

    temp_coeffs_2 = pre.bytes_to_coefficients(
        original_data[pre.get_slot_count(cc) * 2 : pre.get_slot_count(cc) * 4],
        pre.get_slot_count(cc),
    )
    temp_piece_2 = pre.encrypt(cc, keys.publicKey, temp_coeffs_2)[0]
    ser_piece_2 = pre.serialize_to_bytes(temp_piece_2)

    # The payload is the concatenation of the raw bytes of the pieces
    piece_1_bytes = payload_bytes[: len(ser_piece_1)]
    piece_2_bytes = payload_bytes[len(ser_piece_1) :]

    # 4. Verify the AuthPath for the first piece (should succeed)
    leaf_hash_1_bytes = hashlib.blake2b(piece_1_bytes).digest()
    auth_path = json.loads(headers["AuthPath"])
    assert idk_message.verify_merkle_path(
        leaf_hash_bytes=leaf_hash_1_bytes,
        auth_path_hex=auth_path,
        piece_index=0,  # The path is for the first piece (index 0)
        expected_root_hex=headers["MerkleRoot"],
    ), "Merkle path for the first piece in the part should be valid"

    # 5. Verify the AuthPath for the second piece (should fail)
    leaf_hash_2_bytes = hashlib.blake2b(piece_2_bytes).digest()
    assert not idk_message.verify_merkle_path(
        leaf_hash_bytes=leaf_hash_2_bytes,
        auth_path_hex=auth_path,
        piece_index=1,  # This path is not for the second piece
        expected_root_hex=headers["MerkleRoot"],
    ), "Merkle path for the second piece should be invalid"


def test_slots_used_le_slots_total(crypto_setup):
    """
    Tests that the SlotsUsed header is always less than or equal to SlotsTotal.
    """
    cc = crypto_setup["cc"]
    keys = crypto_setup["keys"]
    sk = crypto_setup["sk"]

    # This will create more than one piece, and with the previous logic,
    # SlotsUsed would have been > SlotsTotal.
    original_data = os.urandom(pre.get_slot_count(cc) * 2 + 1)

    message_parts = idk_message.create_idk_message_parts(
        data=original_data,
        cc=cc,
        pk=keys.publicKey,
        signing_key=sk,
        pieces_per_part=1,
    )

    for part_str in message_parts:
        parsed_part = idk_message.parse_idk_message_part(part_str)
        headers = parsed_part["headers"]
        slots_used = int(headers["SlotsUsed"])
        slots_total = int(headers["SlotsTotal"])
        assert slots_used <= slots_total, (
            f"SlotsUsed ({slots_used}) should not be greater than "
            f"SlotsTotal ({slots_total})"
        )
