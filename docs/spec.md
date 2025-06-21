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
* `PartSlotsTotal`: The total number of available slots per ciphertext, as determined by the `CryptoContext`.
* `PartSlotsUsed`: The total number of coefficients (or slots) in the original data vector. This is used to correctly truncate the decrypted vector before byte conversion.
* `BytesTotal`: The total size in bytes of the original, unencoded message data. This is critical for correctly truncating the data after decryption.
* `MerkleRoot`: The BLAKE2b hash of the root of the Merle tree. This also serves as the unique identifier for the message.
* `Signature`: An ECDSA signature of the canonicalized headers, to authenticate the metadata.

#### Part-specific Headers

* `Part`: The sequence number of this part and the total number of parts (e.g., `1/5`).
* `ChunkHash`: The BLAKE2b hash of the decoded Base64 payload for this part. The payload string should first be Base64-decoded into its raw bytes, and then those bytes should be hashed.
* `AuthPath`: A JSON-encoded list of hex-encoded hashes. These are the sibling hashes required to compute the `MerkleRoot` from the pieces contained in this part. The hashes are ordered from the leaves of the tree towards the root.

#### Optional Headers

* `Comment`: A human-readable comment.
* `CharacterSet`: The character set of the original data. Defaults to `UTF-8`.

### Encryption and Piece Creation

The raw message data is first encrypted using the proxy Recryption library. The encryption process produces a list of serializable ciphertext objects. Each of these objects is then serialized into a byte array. These byte arrays are the fundamental "pieces" of the message.

The `BytesTotal` header must be set to the size in bytes of the original, pre-encryption data. The `PartSlotsUsed` header must be set to the number of coefficients in the vector that was encrypted. The `PartSlotsTotal` header must be set to the value returned by `get_slot_count()` for the `CryptoContext`.

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
4. Deserialize and decrypt the ciphertext pieces using the appropriate key and the `PartSlotsUsed` from the header.
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

Once all parts are verified and all 8 ciphertext pieces are collected, they are decrypted using the `PartSlotsUsed`, and the resulting plaintext is truncated to the `BytesTotal` specified in the header.

The message for `Part 1/8` would look like this (note that `PartSlotsUsed` and `PartSlotsTotal` are example values and depend on the original data and `CryptoContext`):

```text
----- BEGIN IDK MESSAGE PART 1/8 -----
AuthPath: ["<hash_of_H2>", "<hash_of_P34>", "<hash_of_P5678>"]
BytesTotal: "8192"
CharacterSet: "UTF-8"
ChunkHash: "<blake2b_hash_of_the_base64_payload_below>"
Comment: "IYKYK"
MerkleRoot: "<blake2b_root_hash_for_all_8_pieces>"
Part: "1/8"
Signature: "<ecdsa_signature_of_the_canonicalized_headers>"
PartSlotsTotal: "1024"
PartSlotsUsed: "1024"
Version: "0.1"

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
Signature: "<ecdsa_signature_of_the_canonicalized_headers>"
PartSlotsTotal: "1024"
PartSlotsUsed: "512"
Version: "0.1"

<base64_encoded_payload_of_ciphertext_piece_8>
----- END IDK MESSAGE PART 8/8 -----
```

```text
----- BEGIN IDK MESSAGE PART 1/64 -----
AuthPath: ["33c908344d2f7f13325f0e26faf7fc68548324ab822167893b74aceed70457b39f152092194280c5870c6982c7d3f079b25c1d281f36c0091fea2cfeebf5f558", "52ff84a09d98261917a2dab2e51acc0b9f4115baa9e96ec7fb91287869a86a894af07843c22ecf522c96d390181cc21f914171a21eac69d0d6f97f1ea0ead5f4", "b0cfc444436783b60ebe6a46bab226fdcdcea0d56187b30ddfb0235e9721afd600eee8f2b1feea9b2c131c83cb519a9cd7bd335573941fc90b37a63707975233", "1deda5608c7e5212c707e6be75cdf47b6ec42f5e4412129e535be7f5a2e94a3cf36b8431252bc7fe456fd7293e728c73c16f9afdfbad6f40c3013bb4b40673a6", "990f19b51c22a3477bfbb19054b734a46ff99808ce53f456e9e73058229695a4de9723552855da4c7e5e79f0127f0d26b87dbe2c7ee689d1544daf5e0c0bd5a2", "59ab828336c84b6d3158a4d515af0f06e0c2c5a9d9ab029f017d532ae88396b74df35c29d9d4c7fe8dbc44fa3b972e225003f313e7b171ae2317a3a7e2b3adb2"]
BytesTotal: 1048576
ChunkHash: "757f6c518d23ce69cce3d9dd182614f5956fc707a466f4e91d5c3faf975531e59c2b3b8ec129749aabeef362befb47aa32c77f884fb705823792417441916e89"
MerkleRoot: "783ede6d23ab237608e410f9443ef2daa4f8b1d6790510a028735ae9c2d59a9ff69fc935a6ad9fbeca54e33e61181830708f95e86dce04b415ad6dd73b79d3f9"
Part: "1/64"
PartSlotsTotal: 8192
PartSlotsUsed: 8192
PieceLength: 263211
Signature: "a4e18290d664d2574ee915ecbf3b72b5e88cfbb3cee2ad423dd52213e3252a5b154e8598e9ff236e34032df8bb08a3750413f64d2b2f2eeb9d13f0ffd851971a"
Version: "0.1"

AQAAAEABAACAAQAAA...
----- END IDK MESSAGE PART 1/64 -----

----- BEGIN IDK MESSAGE PART 2/64 -----
AuthPath: ["757f6c518d23ce69cce3d9dd182614f5956fc707a466f4e91d5c3faf975531e59c2b3b8ec129749aabeef362befb47aa32c77f884fb705823792417441916e89", "52ff84a09d98261917a2dab2e51acc0b9f4115baa9e96ec7fb91287869a86a894af07843c22ecf522c96d390181cc21f914171a21eac69d0d6f97f1ea0ead5f4", "b0cfc444436783b60ebe6a46bab226fdcdcea0d56187b30ddfb0235e9721afd600eee8f2b1feea9b2c131c83cb519a9cd7bd335573941fc90b37a63707975233", "1deda5608c7e5212c707e6be75cdf47b6ec42f5e4412129e535be7f5a2e94a3cf36b8431252bc7fe456fd7293e728c73c16f9afdfbad6f40c3013bb4b40673a6", "990f19b51c22a3477bfbb19054b734a46ff99808ce53f456e9e73058229695a4de9723552855da4c7e5e79f0127f0d26b87dbe2c7ee689d1544daf5e0c0bd5a2", "59ab828336c84b6d3158a4d515af0f06e0c2c5a9d9ab029f017d532ae88396b74df35c29d9d4c7fe8dbc44fa3b972e225003f313e7b171ae2317a3a7e2b3adb2"]
BytesTotal: 1048576
ChunkHash: "33c908344d2f7f13325f0e26faf7fc68548324ab822167893b74aceed70457b39f152092194280c5870c6982c7d3f079b25c1d281f36c0091fea2cfeebf5f558"
MerkleRoot: "783ede6d23ab237608e410f9443ef2daa4f8b1d6790510a028735ae9c2d59a9ff69fc935a6ad9fbeca54e33e61181830708f95e86dce04b415ad6dd73b79d3f9"
Part: "2/64"
PartSlotsTotal: 8192
PartSlotsUsed: 8192
PieceLength: 263211
Signature: "c3cd6f7a74949d598000ac2c08d57660dcdbcefd2ea596058dbe570516ea6924c9a3856319e24d64e2fe993807d90da35fc076f2c982381c1c5131d4abc1e164"
Version: "0.1"

AQAAAEABAACAAQAAA...
----- END IDK MESSAGE PART 2/64 -----
```
