# dCypher Recryption

[description](https://identikey.io/recryption)

## IdentiKey Message Specification

The IdentiKey Message Specification provides a secure, verifiable, and chunkable format for transmitting data. It is inspired by PGP's ASCII armor and leverages Merkle trees for efficient content integrity verification, similar to BitTorrent's BEP 30.

This format is designed to encapsulate data, such as ciphertexts from the proxy Recryption library, for transmission, storage, and homomorphic operations.

### Architectural Assumptions

* **CryptoContext:** All cryptographic operations (encryption, decryption, key generation) depend on a shared `CryptoContext`. This specification assumes that the recipient has access to the *exact same* `CryptoContext` used by the sender. This context is expected to be managed and transmitted out-of-band and is not part of the message payload itself.
* **Public Keys:** To verify a signature, the recipient must have access to the sender's public key. This key is also assumed to be known beforehand, likely through a trusted key directory or a previous exchange.

### Format Overview

An IdentiKey message is composed of one or more parts. Each part is a standalone text block that can be transmitted separately.

```text
----- BEGIN IDK MESSAGE PART <part_num>/<total_parts> -----
<headers>

<base64_encoded_payload>
----- END IDK MESSAGE PART <part_num>/<total_parts> -----
```

### Headers

The headers are in `Key: Value` format.

#### Mandatory Headers (in every part)

* `Version`: The version of the message specification. Current version is 0.
* `SlotsTotal`: The total number of available slots per ciphertext, as determined by the `CryptoContext`.
* `SlotsUsed`: The total number of coefficients (or slots) in the original data vector. This is used to correctly truncate the decrypted vector before byte conversion.
* `BytesTotal`: The total size in bytes of the original, unencoded message data. This is critical for correctly truncating the data after decryption.
* `MerkleRoot`: The BLAKE2b hash of the root of the Merle tree. This also serves as the unique identifier for the message.
* `Signature`: An ECDSA signature of the canonicalized headers, to authenticate the metadata.

#### Part-specific Headers

* `Part`: The sequence number of this part and the total number of parts (e.g., `1/5`).
* `ChunkHash`: The BLAKE2b hash of the raw Base64 payload block for this part.
* `AuthPath`: A JSON-encoded list of hashes. These are the sibling hashes required to compute the `MerkleRoot` from the pieces contained in this part. The hashes are ordered from the leaves of the tree towards the root.

#### Optional Headers

* `Comment`: A human-readable comment.
* `CharacterSet`: The character set of the original data. Defaults to `UTF-8`.

### Encryption and Piece Creation

The raw message data is first encrypted using the proxy Recryption library. The encryption process produces a list of serializable ciphertext objects. Each of these objects is then serialized into a byte array. These byte arrays are the fundamental "pieces" of the message.

The `BytesTotal` header must be set to the size in bytes of the original, pre-encryption data. The `SlotsUsed` header must be set to the number of coefficients in the vector that was encrypted. The `SlotsTotal` header must be set to the value returned by `get_slot_count()` for the `CryptoContext`.

### Payload

The payload of each part contains one or more of the serialized ciphertext pieces (as byte arrays), which are concatenated. This single resulting byte array is then encoded in Base64 to form the payload string.

### Merkle Tree and Message Assembly

1. A Merkle tree is constructed from the hashes of the ciphertext pieces. The BLAKE2b hash of each piece's byte array is calculated to form the leaves of the tree.
2. The tree is constructed by recursively hashing pairs of nodes until a single root hash, the `MerkleRoot`, is obtained. If there is an odd number of nodes at any level, the last node is paired with a zero-filled hash of the same length. The hashing algorithm for internal nodes is `BLAKE2b(left_child_hash + right_child_hash)`, where `+` denotes byte concatenation.
3. The message is split into one or more parts for transmission. Each part's payload will contain one or more of the ciphertext pieces.
4. The headers for each part are created, including the `AuthPath` required to verify the pieces contained within that part.

### Signature Generation

The `Signature` is calculated and included for each part of the message to provide authenticity for all data within that part.

1. A canonical text representation of the headers for the part is created. This includes all Mandatory headers (except `Signature` itself) and all Part-specific headers. The headers are ordered alphabetically by key and formatted as `Key: Value\n`.
2. The SHA-256 hash of the resulting concatenated string is calculated.
3. This hash is signed using ECDSA with the sender's private key to produce the `Signature` value for the part.

### Decryption and Verification

A recipient performs the following steps for each part received:

1. Verify the signature. To do this, recreate the signed message by building the canonical header string (as described in Signature Generation). The SHA-256 hash of this string is then verified against the `Signature` header using the sender's public key. If the signature is invalid, the part must be discarded.
2. With the signature verified, the recipient knows the payload and headers are authentic. It can then proceed with verifying the ciphertext pieces against the `MerkleRoot` using the `AuthPath`.
3. Once all parts are received and verified, extract and assemble the list of all ciphertext pieces.
4. Deserialize and decrypt the ciphertext pieces using the appropriate key and the `SlotsUsed` from the header.
5. If the original data was a byte stream, convert the coefficient vector to bytes.
6. Use the `BytesTotal` header value to truncate the resulting data to its original byte length.

### Example

Consider a message that, after encryption, results in 8 ciphertext pieces. We'll transmit these in 8 parts (1 piece per part). The Merkle tree is built on the hashes of these ciphertext pieces, where `H_n` is the hash of `Ciphertext Piece n`, and `P_xy` is the hash of its children.

```mermaid
graph TD
    subgraph Tree
        direction LR
        Root --- P1234
        Root --- P5678

        P1234 --- P12
        P1234 --- P34
        P12 --- H1[H_1]
        P12 --- H2[H_2]
        P34 --- H3[H_3]
        P34 --- H4[H_4]

        P5678 --- P56
        P5678 --- P78
        P56 --- H5[H_5]
        P56 --- H6[H_6]
        P78 --- H7[H_7]
        P78 --- H8[H_8]
    end
```

If a recipient receives `Part 1/8`, it contains `Ciphertext Piece 1`.

1. The recipient decodes the Base64 payload to get the byte array for the ciphertext piece. It hashes this byte array to get `H1`.
2. To verify this against the `MerkleRoot`, the recipient needs the sibling hashes up the tree. The `AuthPath` provides these hashes in order from the leaf's sibling to the highest-level sibling. For `H1`, the `AuthPath` will be `[H2, P34, P5678]`.
3. The recipient computes `P12 = hash(H1 + H2)`.
4. The recipient then computes `P1234 = hash(P12 + P34)`.
5. Finally, the recipient computes `Root = hash(P1234 + P5678)`.
6. This computed `Root` is compared to the `MerkleRoot` in the header to verify integrity.

To further illustrate, the following diagrams show the verification process for `Part 1/8` and `Part 8/8`.

#### Part 1/8 AuthPath Walkthrough

For `Part 1/8`, the recipient uses the `AuthPath` `[H2, P34, P5678]` to compute the root hash from `H1`.

```mermaid
graph TD
    subgraph "Verification for Part 1/8"
        direction LR

        subgraph "Start"
            H1["H1<br/>(from payload)"]
        end

        subgraph "AuthPath"
            H2["H2<br/>(from AuthPath)"]
            P34["P34<br/>(from AuthPath)"]
            P5678_auth["P5678<br/>(from AuthPath)"]
        end

        subgraph "Computation"
            H1 -- + --> P12("P12 =<br/>hash(H1+H2)")
            H2 -- + --> P12

            P12 -- + --> P1234("P1234 =<br/>hash(P12+P34)")
            P34 -- + --> P1234

            P1234 -- + --> Root("Root =<br/>hash(P1234+P5678)")
            P5678_auth -- + --> Root
        end

        Root --> Result{Compare with<br/>MerkleRoot header}
    end
```

#### Part 8/8 AuthPath Walkthrough

For `Part 8/8`, the recipient uses `AuthPath` `[H7, P56, P1234]` to compute the root hash from `H8`.

```mermaid
graph TD
    subgraph "Verification for Part 8/8"
        direction LR

        subgraph "Start"
            H8["H8<br/>(from payload)"]
        end

        subgraph "AuthPath"
            H7["H7<br/>(from AuthPath)"]
            P56["P56<br/>(from AuthPath)"]
            P1234_auth["P1234<br/>(from AuthPath)"]
        end

        subgraph "Computation"
            H8 -- + --> P78("P78 =<br/>hash(H7+H8)")
            H7 -- + --> P78

            P78 -- + --> P5678("P5678 =<br/>hash(P56+P78)")
            P56 -- + --> P5678

            P5678 -- + --> Root("Root =<br/>hash(P1234+P5678)")
            P1234_auth -- + --> Root
        end

        Root --> Result{Compare with<br/>MerkleRoot header}
    end
```

Once all parts are verified and all 8 ciphertext pieces are collected, they are decrypted using the `SlotsUsed`, and the resulting plaintext is truncated to the `BytesTotal` specified in the header.

The message for `Part 1/8` would look like this (note that `SlotsUsed` and `SlotsTotal` are example values and depend on the original data and `CryptoContext`):

```text
----- BEGIN IDK MESSAGE PART 1/8 -----
AuthPath: ["<hash_of_H2>", "<hash_of_P34>", "<hash_of_P5678>"]
BytesTotal: "8192"
CharacterSet: "UTF-8"
ChunkHash: "<blake2b_hash_of_the_base64_payload_below>"
Comment: "IYKYK"
MerkleRoot: "<blake2b_root_hash_for_all_8_pieces>"
Part: "1/8"
Signature: "<ecdsa_signature>"
SlotsTotal: "1024"
SlotsUsed: "1024"
Version: "0"

<base64_encoded_payload_of_ciphertext_piece_1>
----- END IDK MESSAGE PART 1/8 -----
<...>
----- BEGIN IDK MESSAGE PART 8/8 -----
AuthPath: ["<hash_of_H7>", "<hash_of_P56>", "<hash_of_P1234>"]
BytesTotal: "8192"
CharacterSet: "UTF-8"
ChunkHash: "<blake2b_hash_of_the_base64_payload_below>"
Comment: "IYKYK"
MerkleRoot: "<blake2b_root_hash_for_all_8_pieces>"
Part: "8/8"
Signature: "<ecdsa_signature>"
SlotsTotal: "1024"
SlotsUsed: "512"
Version: "0"

<base64_encoded_payload_of_ciphertext_piece_8>
----- END IDK MESSAGE PART 8/8 -----
```
