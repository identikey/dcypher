# Dual Classical Keys Support

DCypher now supports dual classical cryptographic keys: **ECDSA (SECP256k1)** and **ED25519**. This provides enhanced security and flexibility by combining both elliptic curve signature schemes.

## Overview

### Key Components

1. **ECDSA (SECP256k1)**: Traditional elliptic curve signatures (same as Bitcoin)
2. **ED25519**: Modern, high-performance elliptic curve signatures (RFC 8032)
3. **Post-Quantum**: ML-DSA and other quantum-resistant algorithms

### Security Benefits

- **Defense in depth**: Multiple signature schemes protect against algorithm-specific vulnerabilities
- **Performance diversity**: ED25519 is faster while ECDSA provides wide compatibility
- **Future-proofing**: Gradual migration path between signature schemes

## Implementation Details

### Authentication Module (`src/dcypher/lib/auth.py`)

New functions added:

```python
def verify_ed25519_signature(public_key_hex: str, signature_hex: str, message: bytes) -> bool
def verify_dual_classical_signatures(ecdsa_pk_hex: str, ecdsa_sig_hex: str, 
                                   ed25519_pk_hex: str, ed25519_sig_hex: str, message: bytes) -> bool
def generate_ed25519_keypair() -> Tuple[ed25519.Ed25519PrivateKey, str]
def sign_message_with_keys(message: bytes, keys: Dict[str, Any]) -> Dict[str, Any]
```

### Key Manager (`src/dcypher/lib/key_manager.py`)

Enhanced to support:

- **ED25519 key generation**: `generate_ed25519_keypair()`
- **Deterministic derivation**: ED25519 keys derived from mnemonic using BIP44 path `m/44'/1729'/0'/0/0`
- **Identity file format**: Now includes both `classic` (ECDSA) and `ed25519` sections
- **Unified loading**: `load_identity_file()` and `signing_context()` handle both key types

### API Client (`src/dcypher/lib/api_client.py`)

New methods:

```python
def get_dual_classical_public_keys(self) -> Dict[str, str]
def create_account_dual_classical(self, ecdsa_pk_hex: str, ed25519_pk_hex: str, pq_keys: List[Dict[str, str]]) -> Dict[str, Any]
def create_test_account_dual_classical(cls, api_url: str, temp_dir: Path, additional_pq_algs: Optional[List[str]] = None) -> Tuple["DCypherClient", str, str]
```

### FastAPI Server (`src/dcypher/routers/accounts.py`)

New endpoint:

```
POST /accounts/dual-classical
```

Accepts `CreateDualClassicalAccountRequest` with:

- `ecdsa_public_key` and `ecdsa_signature`
- `ed25519_public_key` and `ed25519_signature`
- ML-DSA and additional PQ signatures

## Message Format

For dual classical accounts, the signed message format is:

```
{ecdsa_pk_hex}:{ed25519_pk_hex}:{ml_dsa_pk_hex}:{other_pq_pk_hex}:...:{nonce}
```

Both ECDSA and ED25519 signatures must be valid for the same message.

## Account Storage

Dual classical accounts are stored with a composite key:

```
{ecdsa_public_key}:{ed25519_public_key}
```

Account data includes:

```json
{
  "type": "dual_classical",
  "ecdsa_public_key": "04...",
  "ed25519_public_key": "a1b2...",
  "pq_keys": {...}
}
```

## Identity File Format

New identity files include both classical keys:

```json
{
  "auth_keys": {
    "classic": {
      "pk_hex": "04...",
      "sk_hex": "..."
    },
    "ed25519": {
      "pk_hex": "a1b2...",
      "sk_hex": "..."
    },
    "pq": [...],
    "pre": {...}
  },
  "derivation_paths": {
    "classic": "m/44'/60'/0'/0/0",
    "ed25519": "m/44'/1729'/0'/0/0",
    "pq": "m/44'/9999'/0'/0/0"
  }
}
```

## Usage Examples

### Creating a Dual Classical Account

```python
from dcypher.lib.api_client import DCypherClient
from pathlib import Path

# Create test account with dual classical keys
client, ecdsa_pk, ed25519_pk = DCypherClient.create_test_account_dual_classical(
    api_url="http://localhost:8000",
    temp_dir=Path("/tmp")
)

print(f"ECDSA Public Key: {ecdsa_pk}")
print(f"ED25519 Public Key: {ed25519_pk}")
```

### Manual Key Generation

```python
from dcypher.lib.key_manager import KeyManager
from dcypher.lib.auth import generate_ed25519_keypair

# Generate ECDSA key
ecdsa_sk, ecdsa_pk_hex = KeyManager.generate_classic_keypair()

# Generate ED25519 key  
ed25519_sk, ed25519_pk_hex = KeyManager.generate_ed25519_keypair()

print(f"ECDSA: {ecdsa_pk_hex}")
print(f"ED25519: {ed25519_pk_hex}")
```

### Signing with Dual Keys

```python
from dcypher.lib.auth import sign_message_with_keys

keys_data = {
    "classic_sk": ecdsa_sk,
    "ed25519_sk": ed25519_sk,
    "pq_keys": [...]
}

message = b"Hello, dual classical world!"
signatures = sign_message_with_keys(message, keys_data)

# Returns:
# {
#   "classic_signature": "3045...",
#   "ed25519_signature": "a1b2...", 
#   "pq_signatures": [...]
# }
```

## Testing

Run the dual classical key tests:

```bash
uv run python3 tests/integration/test_basic_dual_classical.py
```

All tests should pass:

- ✅ ED25519 key generation
- ✅ Dual classical signature verification  
- ✅ KeyManager dual key generation
- ✅ Dual classical signing

## Migration Path

1. **Phase 1**: Deploy dual classical support (current implementation)
2. **Phase 2**: Update clients to use dual classical accounts
3. **Phase 3**: Gradually migrate existing single-key accounts
4. **Phase 4**: Potentially deprecate single-key accounts (future consideration)

## Security Considerations

- Both signatures must be valid for account operations
- Composite key format prevents collision with single-key accounts
- ED25519 provides resistance against certain side-channel attacks
- ECDSA maintains compatibility with existing Bitcoin-style tooling

## Dependencies

- `cryptography>=45.0.4` for ED25519 support
- `ecdsa>=0.19.1` for SECP256k1 support
- `liboqs-python` for post-quantum algorithms
