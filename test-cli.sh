#!/bin/bash
set -e

TEST_DIR=$(mktemp -d)
export RECRYPT_WALLET="$TEST_DIR/test-wallet.recrypt"
export RECRYPT_BACKEND="mock"
export RECRYPT_WALLET_PASSWORD="testpass123"
CLI="./target/release/recrypt"

echo "=== CLI TEST SUITE ==="
echo "Dir: $TEST_DIR"
echo "Backend: $RECRYPT_BACKEND"
echo ""

echo "=== 1. Create identities ==="
$CLI identity new --name alice
$CLI identity new --name bob
echo ""

echo "=== 2. List identities ==="
$CLI identity list
echo ""

echo "=== 3. Show alice ==="
$CLI identity show --name alice
echo ""

echo "=== 4. Switch to bob ==="
$CLI identity use bob
echo ""

echo "=== 5. Create test file ==="
echo "Hello, this is a secret message for testing Recrypt!" > "$TEST_DIR/plaintext.txt"
cat "$TEST_DIR/plaintext.txt"
echo ""

echo "=== 6. Encrypt for alice (using bob's session) ==="
$CLI encrypt "$TEST_DIR/plaintext.txt" --for alice --output "$TEST_DIR/encrypted.enc"
ls -la "$TEST_DIR/encrypted.enc"
echo ""

echo "=== 7. Switch to alice and decrypt ==="
$CLI identity use alice
$CLI decrypt "$TEST_DIR/encrypted.enc" --output "$TEST_DIR/decrypted.txt"
echo ""

echo "=== 8. Verify roundtrip ==="
echo "Original:"
cat "$TEST_DIR/plaintext.txt"
echo "Decrypted:"
cat "$TEST_DIR/decrypted.txt"
if diff -q "$TEST_DIR/plaintext.txt" "$TEST_DIR/decrypted.txt"; then
    echo "✓ Files match!"
else
    echo "✗ Files differ!"
    exit 1
fi
echo ""

echo "=== 9. Test config commands ==="
$CLI config show
echo ""

echo "=== 10. Delete bob ==="
$CLI identity delete bob
$CLI identity list
echo ""

echo "=== 11. JSON output mode ==="
$CLI --json identity show --name alice
echo ""

echo "=== CLEANUP ==="
rm -rf "$TEST_DIR"
echo "✓ All tests passed!"
