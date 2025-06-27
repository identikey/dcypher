# Shared application constants

ML_DSA_ALG = "ML-DSA-87"

# --- Storage Configuration ---
# These paths can be monkeypatched in tests to redirect storage.
BLOCK_STORE_ROOT = "block_store"
CHUNK_STORE_ROOT = "chunk_store"

# In a real application, this should be loaded from a secure configuration manager
# or environment variable, and it should be a long, random string.
SERVER_SECRET = "a-very-secret-key-that-should-be-changed"
