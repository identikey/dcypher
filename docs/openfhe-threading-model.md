# OpenFHE Threading Model

> **Audience**: Developers building multi-tenant/concurrent services using recrypt-ffi

## TL;DR

OpenFHE is thread-safe for **read operations** (encrypt, decrypt, recrypt) when:

1. `CryptoContext` is created once at startup, then treated as immutable
2. Keys are loaded once, then treated as immutable
3. Each thread operates on different ciphertext instances

OpenMP (optional) parallelizes **within** each operation for speed, but doesn't provide thread safety.

---

## Common Confusion: OpenMP ≠ Thread Safety

| Concept           | What It Does                                  | When It Helps                               |
| ----------------- | --------------------------------------------- | ------------------------------------------- |
| **OpenMP**        | Uses multiple cores for ONE operation         | A single `recrypt()` call runs 4-8x faster  |
| **Thread safety** | Multiple threads call operations concurrently | Your proxy handles 100 requests in parallel |

You want **both**:

- OpenMP: Each request completes faster
- Thread safety: Handle many requests concurrently

---

## Thread Safety by Operation

### ❌ Unsafe (Single-Thread Only)

These touch global state or internal mutexes that aren't designed for concurrent access:

```rust
// Do these ONCE at startup, in a single thread
let ctx = PreContext::new()?;              // Global RNG seeding, logging init
let (pk, sk) = ctx.generate_keys()?;       // Modifies internal key tables
let rk = ctx.generate_recrypt_key(&sk_a, &pk_b)?;  // Same
```

### ✅ Safe (Concurrent OK)

These only read from immutable context/keys and create new ciphertext values:

```rust
// These can run from any thread, concurrently
let ciphertext = ctx.encrypt(&pk, &plaintext)?;    // Reads ctx + pk
let plaintext = ctx.decrypt(&sk, &ciphertext)?;    // Reads ctx + sk
let recrypted = ctx.recrypt(&rk, &ciphertext)?;    // Reads ctx + rk
```

---

## Production Pattern: Recryption Proxy

```rust
use std::sync::Arc;
use tokio::sync::RwLock;

struct RecryptionProxy {
    // Created once at startup, never modified
    ctx: Arc<PreContext>,

    // Loaded at startup, immutable thereafter
    // Key: (delegator_id, delegatee_id) -> recryption key
    recrypt_keys: Arc<DashMap<(String, String), RecryptionKey>>,
}

impl RecryptionProxy {
    /// Call ONCE at startup (single-threaded init)
    pub fn new() -> Result<Self, Error> {
        let ctx = Arc::new(PreContext::new()?);
        let recrypt_keys = Arc::new(DashMap::new());

        // Load pre-generated recryption keys from storage
        // This is the only time we modify recrypt_keys
        for (delegator, delegatee, rk_bytes) in load_keys_from_db()? {
            let rk = ctx.deserialize_recrypt_key(&rk_bytes)?;
            recrypt_keys.insert((delegator, delegatee), rk);
        }

        Ok(Self { ctx, recrypt_keys })
    }

    /// Safe to call from any thread, concurrently
    pub fn recrypt(
        &self,
        delegator: &str,
        delegatee: &str,
        ciphertext: &Ciphertext,
    ) -> Result<Ciphertext, Error> {
        let key = (delegator.to_string(), delegatee.to_string());
        let rk = self.recrypt_keys
            .get(&key)
            .ok_or(Error::NoRecryptionKey)?;

        // This is thread-safe: reads immutable ctx + rk, creates new ciphertext
        self.ctx.recrypt(&rk, ciphertext)
    }
}
```

---

## Adding New Recryption Keys at Runtime

If you need to add new delegations while the service is running:

```rust
impl RecryptionProxy {
    /// Generate and store a new recryption key
    ///
    /// IMPORTANT: Key generation itself should be serialized (one at a time)
    /// but lookups remain concurrent.
    pub async fn add_delegation(
        &self,
        delegator_sk: &SecretKey,  // Must be provided by delegator
        delegatee_pk: &PublicKey,
        delegator_id: &str,
        delegatee_id: &str,
    ) -> Result<(), Error> {
        // Generate key (this is the non-thread-safe part)
        // Use a mutex or actor pattern to serialize key generation
        let rk = {
            let _guard = KEY_GEN_MUTEX.lock().await;
            self.ctx.generate_recrypt_key(delegator_sk, delegatee_pk)?
        };

        // Store in map (DashMap handles concurrent insert safely)
        let key = (delegator_id.to_string(), delegatee_id.to_string());
        self.recrypt_keys.insert(key, rk);

        // Persist to storage
        save_key_to_db(delegator_id, delegatee_id, &rk.serialize()?)?;

        Ok(())
    }
}
```

---

## Why Tests Use `--test-threads=1`

Our test suite runs with `cargo test -- --test-threads=1` because:

1. **Tests create/destroy contexts**: Each test calls `PreContext::new()`, hitting the unsafe global state
2. **Tests generate keys**: Key generation modifies internal state
3. **Tests are isolated**: Each test wants a clean slate

This is NOT a limitation of production code—it's a testing artifact. A production service that:

- Creates context once
- Loads keys once
- Only calls encrypt/decrypt/recrypt

...can safely use a thread pool for concurrent request handling.

---

## OpenMP Configuration

When OpenFHE is built with `-DWITH_OPENMP=ON`:

```bash
# Control parallelism at runtime (optional)
export OMP_NUM_THREADS=4  # Limit to 4 cores per operation

# Or let it auto-detect (default)
unset OMP_NUM_THREADS     # Uses all available cores
```

For a busy proxy, you might want to limit OpenMP threads to leave cores free for concurrent requests:

```bash
# 8-core machine handling many concurrent requests
export OMP_NUM_THREADS=2  # Each recrypt uses 2 cores, leaving 6 for concurrency
```

---

## Summary

| Scenario                               | Safe?              | Notes                         |
| -------------------------------------- | ------------------ | ----------------------------- |
| Startup: create context, generate keys | Single-threaded    | Do once, at init              |
| Runtime: encrypt/decrypt/recrypt       | Multi-threaded ✅  | Concurrent calls OK           |
| Runtime: add new recryption key        | Serialize key gen  | Then lookups are concurrent   |
| Tests                                  | `--test-threads=1` | Tests create/destroy contexts |

The key insight: OpenFHE uses shared_ptr internally and is designed for the "create once, use many" pattern. Treat context and keys as immutable after setup, and concurrent operations just work.
