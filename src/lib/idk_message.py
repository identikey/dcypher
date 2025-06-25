"""
This library handles the creation, parsing, and verification of IdentiKey (IDK)
messages, as defined in the specification.

An IDK message is a chunkable, verifiable, and secure format for transmitting
data, such as ciphertexts from the proxy re-encryption library.
"""

import json
import base64
import hashlib
import binascii
from typing import List, Dict, Any, Tuple, Optional
from lib.auth import sign_message, verify_signature
from lib import pre
import ecdsa

# Constants from the specification
IDK_VERSION = "0.1"
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
                # If there's an odd number of nodes, pair the last one with a zero-hash.
                if i + 1 < len(current_level):
                    right = current_level[i + 1]
                else:
                    # Per spec, pad with a zero-filled hash of the same length.
                    right = bytes(len(left))
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
                # If there's no sibling (odd number of nodes), it was paired with a
                # zero-hash of the same length as the current node.
                zero_hash = bytes(len(level[current_index]))
                auth_path.append(zero_hash.hex())

            # Move to the parent's index in the next level up
            current_index //= 2

        return auth_path


def create_idk_message_parts(
    data: bytes,
    cc,
    pk,
    signing_key: ecdsa.SigningKey,
    optional_headers: Optional[Dict[str, str]] = None,
) -> List[str]:
    """
    Encrypts data and formats it into a list of IDK message part strings.

    Args:
        data: The raw byte data to encrypt and package.
        cc: The crypto context for PRE operations.
        pk: The public key for encryption.
        signing_key: The ECDSA signing key for signing the headers.
        optional_headers: A dictionary of optional headers to merge into the message headers.

    Returns:
        A list of strings, where each string is a fully formatted IDK message part.
    """
    original_data_len = len(data)
    # The total number of coefficients used by the original data, for the header.
    total_slots_used = (original_data_len + 1) // 2
    slot_count = pre.get_slot_count(cc)
    max_bytes_per_chunk = (
        slot_count * 2
    )  # Each coefficient is an unsigned short (2 bytes)

    # 1. Chunk the data, encrypt each chunk into a piece.
    all_encrypted_pieces = []
    for i in range(0, original_data_len, max_bytes_per_chunk):
        data_chunk = data[i : i + max_bytes_per_chunk]
        # Convert just the chunk to coefficients.
        pt_coeffs = pre.bytes_to_coefficients(data_chunk, slot_count)
        # Encrypt the coefficients for this chunk into a single ciphertext piece.
        # pre.encrypt returns a list, so we expect one piece here.
        encrypted_piece = pre.encrypt(cc, pk, pt_coeffs)
        all_encrypted_pieces.extend(encrypted_piece)

    # 2. Serialize each ciphertext piece to its raw byte representation
    serialized_pieces_bytes = [pre.serialize_to_bytes(p) for p in all_encrypted_pieces]

    # 3. Build the Merkle tree from the raw byte pieces
    merkle_tree = MerkleTree(serialized_pieces_bytes)
    merkle_root = merkle_tree.root

    total_parts = len(serialized_pieces_bytes)
    message_parts = []

    # 4. Create each message part
    for i, piece_bytes in enumerate(serialized_pieces_bytes):
        part_num = i + 1

        # a. Each part now corresponds to a single piece.
        part_slots_total = slot_count

        # b. Calculate PartSlotsUsed for this specific part's data content.
        start_byte_index = i * max_bytes_per_chunk
        # The end byte index is capped by the original data length
        end_byte_index = min((i + 1) * max_bytes_per_chunk, original_data_len)
        part_data_len = end_byte_index - start_byte_index
        part_slots_used = (part_data_len + 1) // 2

        # c. Concatenate and Base64-encode the payload
        payload_bytes = piece_bytes
        payload_b64 = base64.b64encode(payload_bytes).decode("ascii")

        # d. Prepare headers
        headers = {
            "Version": IDK_VERSION,
            "PartSlotsTotal": str(part_slots_total),
            "PartSlotsUsed": str(part_slots_used),
            "BytesTotal": str(original_data_len),
            "MerkleRoot": merkle_root,
            "Part": f"{part_num}/{total_parts}",
            "ChunkHash": hashlib.blake2b(payload_bytes).hexdigest(),
        }

        # Add optional headers first, so they are part of the signed content
        # in the same way as mandatory headers.
        if optional_headers:
            for key, value in optional_headers.items():
                if key not in headers:
                    headers[key] = value

        # AuthPath is calculated for the current piece.
        headers["AuthPath"] = json.dumps(merkle_tree.get_auth_path(i))

        # e. Sign the headers
        canonical_header_str = ""
        for key in sorted(headers.keys()):
            value = headers[key]
            if key in ["PartSlotsTotal", "PartSlotsUsed", "BytesTotal", "AuthPath"]:
                canonical_header_str += f"{key}: {value}\n"
            else:
                canonical_header_str += f'{key}: "{value}"\n'

        header_hash = hashlib.sha256(canonical_header_str.encode("utf-8")).digest()
        signature = signing_key.sign_digest(header_hash).hex()
        headers["Signature"] = signature

        # f. Assemble the final message part
        header_block = ""
        for key in sorted(headers.keys()):
            value = headers[key]
            if key in ["PartSlotsTotal", "PartSlotsUsed", "BytesTotal", "AuthPath"]:
                header_block += f"{key}: {value}\n"
            else:
                header_block += f'{key}: "{value}"\n'

        message_part = (
            f"{BEGIN_IDK_MESSAGE.format(part_num=part_num, total_parts=total_parts)}\n"
            f"{header_block}"
            f"{payload_b64}\n"
            f"{END_IDK_MESSAGE.format(part_num=part_num, total_parts=total_parts)}"
        )
        message_parts.append(message_part)

    return message_parts


def parse_idk_message_part(part_str: str) -> Dict[str, Any]:
    """
    Parses a single IDK message part string into its components.
    If the string contains multiple concatenated parts, this will parse the first one.
    """
    lines = part_str.strip().split("\n")
    if len(lines) < 3:
        raise ValueError("Invalid IDK message part format: too few lines.")

    begin_marker = lines[0]

    if not begin_marker.startswith("----- BEGIN IDK MESSAGE PART"):
        raise ValueError("Invalid BEGIN marker.")

    try:
        part_info = begin_marker.split(" ")[-2]
        part_num, total_parts = map(int, part_info.split("/"))
    except (ValueError, IndexError):
        raise ValueError("Invalid BEGIN/END marker format.")

    expected_end_marker = END_IDK_MESSAGE.format(
        part_num=part_num, total_parts=total_parts
    )

    # Find the end marker corresponding to our begin marker to handle concatenated files
    end_marker_index = -1
    for i, line in enumerate(lines):
        if line.strip() == expected_end_marker:
            end_marker_index = i
            break

    if end_marker_index == -1:
        raise ValueError("Invalid END marker.")

    # Limit lines to only the first valid part found
    part_lines = lines[: end_marker_index + 1]

    headers = {}
    header_lines = []
    payload_line_index = -1
    # Headers are lines with ": ". The first line without is the payload.
    for i, line in enumerate(part_lines[1:-1], start=1):
        # The payload is the first line without a colon-space separator.
        if ": " not in line:
            payload_line_index = i
            break
        header_lines.append(line)

    if payload_line_index == -1 or not header_lines:
        raise ValueError("Malformed part: missing payload separator or headers.")

    for line in header_lines:
        key, value = line.split(": ", 1)
        # Strip quotes from string values
        if value.startswith('"') and value.endswith('"'):
            value = value[1:-1]
        headers[key] = value

    # The payload is everything from the separator line to the END marker
    payload_b64 = "".join(part_lines[payload_line_index:-1])

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


def decrypt_idk_message(
    cc, sk: ecdsa.SigningKey, vk: ecdsa.VerifyingKey, message_str: str
) -> bytes:
    """
    Parses, verifies, and decrypts a full IDK message string.

    This is a high-level convenience function that encapsulates the entire
    process of handling an incoming IDK message.

    Args:
        cc: The crypto context.
        sk: The recipient's secret key for decryption.
        vk: The sender's verifying key for signature verification.
        message_str: The complete, raw IDK message string (can contain multiple parts).

    Returns:
        The decrypted original data as a byte string.

    Raises:
        ValueError: If any part of the verification or decryption fails.
    """
    # This regex splits the content by the BEGIN marker, but keeps the marker
    # as part of the result list, allowing us to reconstruct each part.
    import re

    parts_with_empties = re.split(r"(----- BEGIN IDK MESSAGE PART)", message_str)
    message_parts = []
    # The result of the split will be like ['', 'DELIMITER', 'CONTENT', 'DELIMITER', 'CONTENT', ...].
    for i in range(1, len(parts_with_empties), 2):
        if i + 1 < len(parts_with_empties):
            full_part = parts_with_empties[i] + parts_with_empties[i + 1]
            message_parts.append(full_part.strip())

    if not message_parts:
        raise ValueError("No valid IDK message parts found in the input string.")

    # 1. Parse all parts first to sort them
    parsed_parts = []
    for part_str in message_parts:
        parsed_parts.append(parse_idk_message_part(part_str))

    # 2. Sort parts by their part number to process them in order.
    # This is crucial for calculating the piece index correctly.
    try:
        sorted_parts = sorted(parsed_parts, key=lambda p: p["headers"]["PartNum"])
    except KeyError:
        raise ValueError("Malformed message part missing 'PartNum' header.")

    all_pieces = {}
    total_bytes = 0
    merkle_root = ""
    current_piece_index = 0
    slot_count = pre.get_slot_count(cc)

    for parsed in sorted_parts:
        try:
            headers = parsed["headers"]
            payload_b64 = parsed["payload_b64"]

            # Verify signature
            signature_hex = headers.pop("Signature")
            # Reconstruct the "Part" header for canonical string verification
            headers["Part"] = f"{headers['PartNum']}/{headers['TotalParts']}"

            canonical_header_str = ""
            for key in sorted(headers.keys()):
                if key in ["PartNum", "TotalParts"]:
                    continue
                value = headers[key]
                # Re-create the canonical string by quoting string values
                if key in [
                    "PartSlotsTotal",
                    "PartSlotsUsed",
                    "BytesTotal",
                    "AuthPath",
                ]:
                    canonical_header_str += f"{key}: {value}\n"
                else:
                    canonical_header_str += f'{key}: "{value}"\n'

            header_hash = hashlib.sha256(canonical_header_str.encode("utf-8")).digest()
            # The signature from the header is already unquoted by parse_idk_message_part
            vk.verify_digest(bytes.fromhex(signature_hex), header_hash)

            # Validate part-specific headers
            part_slots_used = int(headers["PartSlotsUsed"])
            part_slots_total = int(headers["PartSlotsTotal"])
            if part_slots_used > part_slots_total:
                raise ValueError(
                    f"PartSlotsUsed ({part_slots_used}) "
                    f"cannot exceed PartSlotsTotal ({part_slots_total})"
                )

            # Validate the payload format and content.
            payload_bytes = base64.b64decode(payload_b64, validate=True)
            if hashlib.blake2b(payload_bytes).hexdigest() != headers["ChunkHash"]:
                raise ValueError("ChunkHash verification failed")

            # Check if this is a re-encrypted message
            is_re_encrypted = headers.get("ReEncrypted", "false").lower() == "true"

            if is_re_encrypted:
                # Handle re-encrypted messages according to new specification

                # Verify required re-encryption headers are present
                required_re_headers = [
                    "OriginalSender",
                    "ReEncryptedBy",
                    "ReEncryptedFor",
                    "ReEncryptionTimestamp",
                    "ProxySignature",
                ]
                for req_header in required_re_headers:
                    if req_header not in headers:
                        raise ValueError(
                            f"Re-encrypted message missing required header: {req_header}"
                        )

                # Verify proxy signature
                # Create canonical header string (same as server does)
                canonical_headers = []
                for key in sorted(headers.keys()):
                    if key != "ProxySignature":
                        value = headers[key]
                        canonical_headers.append(f"{key}: {value}")

                canonical_string = "\n".join(canonical_headers)
                canonical_hash = hashlib.sha256(
                    canonical_string.encode("utf-8")
                ).digest()

                # TODO: Add proxy signature verification here when server public key is available
                # For now, we trust that the message came from the server

                # Skip Merkle verification for re-encrypted messages
                print(
                    f"📝 Processing re-encrypted message part {headers.get('Part', '?')}"
                )
                print(f"   Original sender: {headers['OriginalSender'][:16]}...")
                print(f"   Re-encrypted by: {headers['ReEncryptedBy'][:16]}...")
                print(f"   Re-encrypted for: {headers['ReEncryptedFor'][:16]}...")
                print(f"   Timestamp: {headers['ReEncryptionTimestamp']}")

            else:
                # Handle original (non-re-encrypted) messages with full verification

                # The payload *is* the single serialized ciphertext piece.
                # Hash it for Merkle path verification.
                leaf_hash_bytes = hashlib.blake2b(payload_bytes).digest()

                if not verify_merkle_path(
                    leaf_hash_bytes,
                    json.loads(headers["AuthPath"]),
                    current_piece_index,  # The index is the running total of pieces
                    headers["MerkleRoot"],
                ):
                    raise ValueError("Merkle path verification failed")

            if not merkle_root:
                merkle_root = headers["MerkleRoot"]
                total_bytes = int(headers["BytesTotal"])
            elif headers["MerkleRoot"] != merkle_root:
                raise ValueError("Inconsistent Merkle roots across message parts")

            # Correctly deserialize the single piece from the payload.
            piece_obj = pre.deserialize_ciphertext(payload_bytes)
            all_pieces[current_piece_index] = piece_obj

            # Update the piece index for the next part
            current_piece_index += 1

        except (ValueError, ecdsa.BadSignatureError, binascii.Error, KeyError) as e:
            part_num_str = parsed.get("headers", {}).get("PartNum", "unknown")
            raise ValueError(f"Verification failed for part {part_num_str}: {e}")

    # Calculate total slots used from the message-wide BytesTotal header.
    total_slots_for_message = (total_bytes + 1) // 2
    sorted_pieces = [all_pieces[i] for i in sorted(all_pieces.keys())]
    decrypted_coeffs = pre.decrypt(cc, sk, sorted_pieces, total_slots_for_message)
    final_data = pre.coefficients_to_bytes(decrypted_coeffs, total_bytes)
    return final_data
