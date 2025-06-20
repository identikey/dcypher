"""
This library handles the creation, parsing, and verification of IdentiKey (IDK)
messages, as defined in the specification.

An IDK message is a chunkable, verifiable, and secure format for transmitting
data, such as ciphertexts from the proxy re-encryption library.
"""

import json
import base64
import hashlib
from typing import List, Dict, Any, Tuple
from lib.auth import sign_message, verify_signature
from lib import pre
import ecdsa

# Constants from the specification
IDK_VERSION = "0"
HASH_ALG = "blake2b"
BEGIN_IDK_MESSAGE = "----- BEGIN IDK MESSAGE PART {part_num}/{total_parts} -----"
END_IDK_MESSAGE = "----- END IDK MESSAGE PART {part_num}/{total_parts} -----"


class MerkleTree:
    """A simple Merkle tree implementation for IDK message integrity."""

    def __init__(self, pieces: List[bytes]):
        if not pieces:
            raise ValueError("Cannot build a Merkle tree with no pieces.")

        self.pieces = pieces
        self.leaves = [self._hash_piece(p) for p in pieces]
        self.tree = self._build_tree(self.leaves)

    def _hash_piece(self, piece: bytes) -> bytes:
        return hashlib.blake2b(piece).digest()

    def _hash_internal_node(self, left: bytes, right: bytes) -> bytes:
        return hashlib.blake2b(left + right).digest()

    def _build_tree(self, nodes: List[bytes]) -> List[List[bytes]]:
        tree = [nodes]
        current_level = nodes
        while len(current_level) > 1:
            next_level = []
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                # If there's an odd number of nodes, duplicate the last one's hash
                right = current_level[i + 1] if i + 1 < len(current_level) else left
                next_level.append(self._hash_internal_node(left, right))
            tree.append(next_level)
            current_level = next_level
        return tree

    @property
    def root(self) -> str:
        """Returns the hex-encoded root of the Merkle tree."""
        return self.tree[-1][0].hex()

    def get_auth_path(self, piece_index: int) -> List[str]:
        """
        Calculates the authentication path for a given piece index.
        The path consists of the sibling hashes needed to reconstruct the root.
        """
        auth_path = []
        current_index = piece_index
        for level in self.tree[:-1]:
            # Determine the sibling index
            if current_index % 2 == 0:
                sibling_index = current_index + 1
            else:
                sibling_index = current_index - 1

            # If the sibling exists, add its hash to the path
            if sibling_index < len(level):
                auth_path.append(level[sibling_index].hex())
            else:
                # If there's no sibling (odd number of nodes), the node was paired
                # with itself, so we add its own hash.
                auth_path.append(level[current_index].hex())

            # Move to the parent's index in the next level up
            current_index //= 2

        return auth_path


def create_idk_message_parts(
    data: bytes,
    cc,
    pk,
    signing_key: ecdsa.SigningKey,
    pieces_per_part: int = 1,
) -> List[str]:
    """
    Encrypts data and formats it into a list of IDK message part strings.

    Args:
        data: The raw byte data to encrypt and package.
        cc: The crypto context for PRE operations.
        pk: The public key for encryption.
        signing_key: The ECDSA signing key for signing the headers.
        pieces_per_part: The number of encrypted ciphertext pieces per message part.

    Returns:
        A list of strings, where each string is a fully formatted IDK message part.
    """
    original_data_len = len(data)

    # 1. Convert data to coefficients and encrypt
    pt_coeffs = pre.bytes_to_coefficients(data)
    slots_used = len(pt_coeffs)
    encrypted_pieces = pre.encrypt(cc, pk, pt_coeffs)

    # 2. Serialize each ciphertext piece to its raw byte representation
    serialized_pieces_bytes = [pre.serialize_to_bytes(p) for p in encrypted_pieces]

    # 3. Build the Merkle tree from the raw byte pieces
    merkle_tree = MerkleTree(serialized_pieces_bytes)
    merkle_root = merkle_tree.root

    total_parts = (
        len(serialized_pieces_bytes) + pieces_per_part - 1
    ) // pieces_per_part
    message_parts = []

    # 4. Create each message part
    for i in range(0, len(serialized_pieces_bytes), pieces_per_part):
        part_num = (i // pieces_per_part) + 1

        # a. Get the chunk of raw byte pieces for this part
        part_pieces = serialized_pieces_bytes[i : i + pieces_per_part]

        # b. Concatenate and Base64-encode the payload
        payload_bytes = b"".join(part_pieces)
        payload_b64 = base64.b64encode(payload_bytes).decode("ascii")

        # c. Prepare headers
        # NOTE: The AuthPath is for the *first* piece in the chunk.
        # A more robust implementation would handle paths for all pieces in a chunk.
        headers = {
            "Version": IDK_VERSION,
            "SlotsTotal": pre.get_slot_count(cc),
            "SlotsUsed": slots_used,
            "BytesTotal": original_data_len,
            "MerkleRoot": merkle_root,
            "Part": f"{part_num}/{total_parts}",
            "ChunkHash": hashlib.blake2b(payload_bytes).hexdigest(),
            "AuthPath": json.dumps(merkle_tree.get_auth_path(i)),
        }

        # d. Sign the headers
        canonical_header_str = ""
        for key in sorted(headers.keys()):
            canonical_header_str += f"{key}: {headers[key]}\n"

        header_hash = hashlib.sha256(canonical_header_str.encode("utf-8")).digest()
        signature = signing_key.sign_digest(header_hash).hex()
        headers["Signature"] = signature

        # e. Assemble the final message part
        header_block = ""
        for key in sorted(headers.keys()):
            header_block += f"{key}: {headers[key]}\n"

        message_part = (
            f"{BEGIN_IDK_MESSAGE.format(part_num=part_num, total_parts=total_parts)}\n"
            f"{header_block}\n"
            f"{payload_b64}\n"
            f"{END_IDK_MESSAGE.format(part_num=part_num, total_parts=total_parts)}"
        )
        message_parts.append(message_part)

    return message_parts


def parse_idk_message_part(part_str: str) -> Dict[str, Any]:
    """
    Parses a single IDK message part string into its components.

    Args:
        part_str: The raw string of the message part.

    Returns:
        A dictionary containing the headers and the Base64-encoded payload.
    """
    lines = part_str.strip().split("\n")
    if len(lines) < 4:
        raise ValueError("Invalid IDK message part format: too few lines.")

    begin_marker = lines[0]
    end_marker = lines[-1]

    try:
        part_info = begin_marker.split(" ")[-2]
        part_num, total_parts = map(int, part_info.split("/"))
    except (ValueError, IndexError):
        raise ValueError("Invalid BEGIN/END marker format.")

    if begin_marker != BEGIN_IDK_MESSAGE.format(
        part_num=part_num, total_parts=total_parts
    ):
        raise ValueError("Invalid BEGIN marker.")
    if end_marker != END_IDK_MESSAGE.format(part_num=part_num, total_parts=total_parts):
        raise ValueError("Invalid END marker.")

    headers = {}
    header_lines = []
    payload_line_index = -1
    # Headers are from line 1 until we hit a blank line
    for i, line in enumerate(lines[1:-1], start=1):
        if not line.strip():
            payload_line_index = i + 1
            break
        header_lines.append(line)

    if payload_line_index == -1 or not header_lines:
        raise ValueError("Malformed part: missing separator or headers.")

    for line in header_lines:
        key, value = line.split(": ", 1)
        headers[key] = value

    # The payload is everything between the blank line and the END marker
    payload_b64 = "".join(lines[payload_line_index:-1])

    # Do not convert to int here. The caller should do it after verification.
    # The part number in the header is a string "num/total"
    if "Part" in headers:
        try:
            num, total = map(int, headers["Part"].split("/"))
            headers["PartNum"] = num
            headers["TotalParts"] = total
        except (ValueError, IndexError):
            # Let it pass, verification will fail later if 'Part' is malformed
            pass

    return {"headers": headers, "payload_b64": payload_b64}


def verify_merkle_path(
    leaf_hash_bytes: bytes,
    auth_path_hex: List[str],
    piece_index: int,
    expected_root_hex: str,
) -> bool:
    """
    Verifies that a leaf hash is part of a Merkle tree with a given root.

    Args:
        leaf_hash_bytes: The hash of the piece being verified.
        auth_path_hex: The list of sibling hashes (in hex) from the leaf to the root.
        piece_index: The original index of the piece in the list of all pieces.
        expected_root_hex: The hex-encoded Merkle root to verify against.

    Returns:
        True if the verification succeeds, False otherwise.
    """
    computed_hash = leaf_hash_bytes
    current_index = piece_index

    for sibling_hex in auth_path_hex:
        sibling_bytes = bytes.fromhex(sibling_hex)
        if current_index % 2 == 0:  # Our node is a left child
            computed_hash = hashlib.blake2b(computed_hash + sibling_bytes).digest()
        else:  # Our node is a right child
            computed_hash = hashlib.blake2b(sibling_bytes + computed_hash).digest()
        current_index //= 2

    return computed_hash.hex() == expected_root_hex
