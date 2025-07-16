# dCypher Proxy Service Discovery Specification

## Overview

This document specifies the discovery mechanism for dCypher proxy recryption services using a Distributed Hash Table (DHT). The system enables clients to discover which proxies can perform ciphertext transformations (CT_A → CT_B) for specific data and recipients while preserving privacy of both the plaintext and social graph.

## Design Analysis

This specification addresses the fundamental challenge of proxy discovery in a privacy-preserving manner. Traditional content-addressed systems leak information through deterministic hashing, while naive approaches expose social graphs through recipient identifiers.

### Core Design Principles

**Privacy-First Identifier Design**: The Capability-Scoped Content ID (CIDᶜ) uses `BLAKE2b(ciphertext_root ∥ owner_nonce)` to create unique identifiers per ciphertext instance, preventing equality attacks while maintaining cryptographic binding to the actual encrypted content.

**Social Graph Protection**: Recipient blinding through `R_tag = SHA256(recipient_pk || CIDᶜ || "dcypher-tag")` ensures that passive DHT observers cannot correlate data access patterns with recipient identities.

**Decentralized Trust Model**: The system assumes no trusted third parties beyond the data owner's cryptographic signatures, making it suitable for fully decentralized deployment scenarios.

**Temporal Security**: TTL-based expiry combined with capability token timestamps provides natural revocation without requiring global coordination or certificate revocation lists.

---

# SERVICE-DISCOVERY SPECIFICATION – dCypher PRE Mesh v0.1

## 1. DESIGN GOALS

• **Zero-configuration discovery** of any proxy that can perform the mapping `CT_A → CT_B` for a given `(data, recipient_pk)`
• **Preserve confidentiality** of both the plaintext and the social graph (who is sharing with whom) to the maximum practical extent
• **Allow immediate revocation** and natural expiry; avoid permanent index entries
• **Survive a fully decentralised** "anyone can run a proxy" network, tolerate byzantine nodes, and be embeddable in an IPFS / libp2p stack or any Kademlia-like DHT

## 2. THREAT MODEL (RELEVANT TO DISCOVERY)

Adversary controls any number of DHT nodes, can collect all queries and stored records, and attempts:

- **A.** Plaintext recovery or guessing via the discovery namespace
- **B.** Mapping relationships between _data_, _owner_ and _recipient_ ("social graph" leakage)
- **C.** Denial-of-service or poisoning of the discovery tables

## 3. IDENTIFIER CHOICE

### 3.1 "Capability-Scoped Content ID" (CIDᶜ)

```
CIDᶜ = BLAKE2b(ciphertext_root ∥ owner_nonce)
```

where:

- `ciphertext_root` = MerkleRoot already present in the IDK
- `owner_nonce` = 128-bit random, stored encrypted in the ciphertext header and revealed only to authorised proxies

**Properties:**
• One-way binding to specific ciphertext instance (there can be many encryptions of the same plaintext)
• Offline dictionary attacks impossible without seeing the ciphertext anyway
• Owner can rotate CIDᶜ by recrypting the same plaintext with a new nonce; revokes previous discovery entries

### 3.2 RECIPIENT BLINDING

Do **not** put the raw recipient public key in the DHT key (otherwise a passive observer immediately learns who wants what). Instead use:

```
R_tag = SHA256(recipient_pk || CIDᶜ || "dcypher-tag")
```

Any holder of `recipient_pk` can compute R_tag offline. Anyone else cannot invert it, so the social graph is hidden.

### 3.3 FINAL 256-bit DHT KEY

```
DHT_key = SHA256(CIDᶜ || R_tag)
```

## 4. DHT RECORD VALUE FORMAT (CBOR encoded)

```json
{
  "cid_c": "<32-bytes>",
  "recipient_pk": "<compressed ECC/LWE pk>",
  "proxy_endpoint": ["/dns4/proxy1.example/tcp/4444", "…"],
  "proxy_pubkey": "<Ed25519-pk>",
  "capability_tok": "<Recryption Capability Token>",
  "ttl": "<unix_seconds>",
  "sig_owner": "<Ed25519 signature over all above fields>"
}
```

• `capability_tok` – short binary credential signed by the owner proving that `proxy_pubkey` is authorised to transform _this_ ciphertext instance for `recipient_pk`. See Section 4.1 for detailed format.
• `sig_owner` – protects the record against poisoning; a node MUST discard a record whose signature fails.

### 4.1 CAPABILITY TOKEN FORMAT

The capability token is a JWT-like structure containing:

```json
{
  "sub": "<cid_c>",
  "aud": "<recipient_pk>", 
  "exp": 1720281470,
  "iat": 1720195070,
  "jti": "<unique_token_id>",
  "capabilities": ["recrypt"],
  "proxy_pubkey": "<Ed25519-pk>"
}
```

**Fields:**

- `sub` (subject): The CIDᶜ this token authorizes access to
- `aud` (audience): The recipient public key
- `exp` (expiry): Unix timestamp when token expires
- `iat` (issued at): Unix timestamp when token was created
- `jti` (JWT ID): Unique identifier for this token instance
- `capabilities`: Array of permitted operations ("recrypt", "decrypt")
- `proxy_pubkey`: The proxy's public key authorized to use this token

**Signature**: The entire JSON payload is signed with the data owner's private key using Ed25519.

## 5. WORKFLOWS

### 5.1 REGISTRATION (proxy side)

1. Proxy receives `(cid_c, capability_tok)` from the data owner
2. Validates token. Determines `ttl = min(token.expiry, 24h)`
3. Computes `R_tag` and `DHT_key`
4. Stores value record under `DHT_key` with ttl, periodically re-publishes until token expires

### 5.2 LOOKUP (client side)

1. Given ciphertext → extract `cid_c`
2. Compute `R_tag` from own `recipient_pk`
3. Compute `DHT_key`, perform `FIND_VALUE`
4. Verify `sig_owner` and that `recipient_pk` matches self
5. Connect to any listed `proxy_endpoint`, present `capability_tok` in TLS-like handshake, obtain recrypted shards

## 6. SECURITY PROPERTIES

• **Plaintext confidentiality**: dictionary attacks require full ciphertext (not present in discovery), and the nonce prevents easy equality checks across owners or time
• **Social-graph confidentiality**: observer only sees R_tag hashes, unlinkable without recipient_pk
• **Forward revocation**: owner stops refreshing a record or pushes a token with `exp=0`; ttl ensures disappearance in ≤ 24h
• **Integrity**: owner signature + proxy certificate checked peer-to-peer; malicious nodes cannot forge capability

## 7. CORNER CASES & MITIGATIONS

**Duplicate uploads / collisions**
• Different `owner_nonce` ⇒ different `cid_c` ⇒ no collision

**Key rotation for recipient**
• New `recipient_pk` ⇒ new `R_tag` ⇒ new `DHT_key`; old entries unreachable; owner can issue new capability tokens

**Large group shares**
• `Recipient_pk` may correspond to a group aggregate key; same flow applies. For N recipients the owner publishes N records (or one record with a Bloom filter of authorised recipients if desired)

**DoS / flood of bogus records**
• Nodes only store records whose `sig_owner` verifies and whose `capability_tok.exp` is in the future
• Per-key record limit (e.g., 32) to avoid storage exhaustion

**Long-lived data**
• Owner-side daemon re-signs & republishes capability tokens every 12h; proxies refuse to serve with stale tokens

## 8. OPEN INTERFACES

### 8.1 Libp2p "Discovery-PRE/1.0.0" protocol

• Message type PUT, GET, RESPONSE (CBOR)
• Uses libp2p‐records with `authoritative=true`, sequence = exp

### 8.2 REST bootstrap endpoint (optional)

• For mobile / firewalled clients a bootstrap server can echo the same DHT API over HTTPS; same record schema

## 9. EXAMPLE (human-readable)

```
CIDᶜ (hex): 9a13…ef
Recipient:  02b7…c1
R_tag:      e4d1…88
DHT_key:    6b09…42

Value:
{
  "cid_c": "9a13…ef",
  "recipient_pk": "02b7…c1",
  "proxy_endpoint": ["/dns4/proxy.dc.net/tcp/4001/wss"],
  "proxy_pubkey": "5bf9…11",
  "capability_tok": "eyJhbGci…",
  "ttl": 172800,
  "sig_owner": "3045022100…"
}
```

## 10. IMPLEMENTATION CHECKLIST

- [ ] Generate `owner_nonce` during first encryption
- [ ] Extend IDK header to carry `owner_nonce` (AES-GCM encrypted for authorised proxies, opaque to storage)
- [ ] Add "dcypher-discover" module implementing PUT/GET & signature verification
- [ ] Unit-tests: privacy (no raw plaintext hash visible), revocation (record disappears), replay attack (expired token rejected), poisoning (bad sig rejected)
- [ ] Fuzz test DHT value parser

---

## SUGGESTED IMPROVEMENTS

### Multi-Recipient Optimization

For scenarios where data is shared with multiple recipients, the current design requires N separate DHT records for N recipients. An optimization using Bloom filters can reduce this to a single record:

```json
{
  "cid_c": "<32-bytes>",
  "recipient_filter": "<bloom_filter_bytes>",
  "filter_params": {
    "k": 3,
    "m": 1024, 
    "expected_items": 50,
    "false_positive_rate": 0.01
  },
  "proxy_endpoint": ["/dns4/proxy1.example/tcp/4444"],
  "proxy_pubkey": "<Ed25519-pk>",
  "capability_tok": "<Multi-recipient capability token>",
  "ttl": "<unix_seconds>",
  "sig_owner": "<Ed25519 signature>"
}
```

**Benefits:**

- Reduces DHT storage requirements for group shares
- Maintains privacy through probabilistic membership testing
- Scales efficiently with group size

**Trade-offs:**

- Small false positive rate may cause unnecessary proxy queries
- Requires capability tokens to handle multiple recipients
- More complex validation logic

### Enhanced DoS Protection

For production deployments, additional DoS protection mechanisms may be beneficial:

**Proof-of-Work**: Require small computational proof for record insertion to prevent spam
**Rate Limiting**: Implement per-IP and per-key rate limits at DHT nodes
**Stake-based Priority**: Allow proxies to stake tokens for higher priority record placement

### Performance Optimizations

**Caching Layer**: Local cache for frequently accessed records to reduce DHT queries
**Batch Operations**: Support batch PUT/GET operations for multiple records
**Compression**: Optional compression for large capability tokens

---

## SUMMARY OF KEY RECOMMENDATIONS

• **Do NOT expose raw plaintext hash**; use per-ciphertext, nonce-blinded content IDs (CIDᶜ)
• **Blind recipient identity** in the lookup key (R_tag)
• **Store signed, short-lived capability records** in the DHT; signature by the data owner prevents poisoning
• **TTL-bound records + token expiry** give revocation without global CRLs
• **Same design works** atop libp2p-Kademlia, IPFS DHT, or custom overlay

This specification integrates with the existing IdentiKey Message Spec and keeps the discovery layer privacy-preserving and robust for a true mesh proxy-recryption network.
