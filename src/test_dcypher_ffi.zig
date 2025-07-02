const std = @import("std");
const c = @cImport({
    @cInclude("dcypher_ffi.h");
});

pub fn main() !void {
    std.debug.print("Testing dCypher Unified FFI API for static linking...\n", .{});
    
    // Test 1: Create crypto context
    std.debug.print("1. Creating crypto context...\n", .{});
    const ctx = c.dcypher_context_create(65537, 128);
    if (ctx == null) {
        const error_msg = c.dcypher_get_last_error();
        if (error_msg != null) {
            std.debug.print("   Error: {s}\n", .{error_msg});
        } else {
            std.debug.print("   Error: Failed to create context (no error message)\n", .{});
        }
        return;
    }
    defer c.dcypher_context_destroy(ctx);
    std.debug.print("   ✓ Context created successfully\n", .{});
    
    // Test 2: Generate key pair
    std.debug.print("2. Generating key pair...\n", .{});
    const keypair = c.dcypher_keygen(ctx);
    if (keypair == null) {
        const error_msg = c.dcypher_get_last_error();
        if (error_msg != null) {
            std.debug.print("   Error: {s}\n", .{error_msg});
        } else {
            std.debug.print("   Error: Failed to generate keys (no error message)\n", .{});
        }
        return;
    }
    defer c.dcypher_keypair_destroy(keypair);
    std.debug.print("   ✓ Key pair generated successfully\n", .{});
    
    // Test 3: Encrypt data
    std.debug.print("3. Encrypting data...\n", .{});
    var test_data: [2]i64 = [_]i64{ 42, 84 };
    const ciphertext = c.dcypher_encrypt(ctx, keypair, &test_data, test_data.len);
    if (ciphertext == null) {
        const error_msg = c.dcypher_get_last_error();
        if (error_msg != null) {
            std.debug.print("   Error: {s}\n", .{error_msg});
        } else {
            std.debug.print("   Error: Failed to encrypt (no error message)\n", .{});
        }
        return;
    }
    defer c.dcypher_ciphertext_destroy(ciphertext);
    std.debug.print("   ✓ Data encrypted successfully\n", .{});
    
    // Test 4: Decrypt data
    std.debug.print("4. Decrypting data...\n", .{});
    var decrypted_data: [*c]i64 = null;
    var decrypted_len: usize = 2;
    const decrypt_result = c.dcypher_decrypt(ctx, keypair, ciphertext, &decrypted_data, &decrypted_len);
    if (decrypt_result != c.DCYPHER_SUCCESS) {
        const error_msg = c.dcypher_get_last_error();
        if (error_msg != null) {
            std.debug.print("   Error: {s}\n", .{error_msg});
        } else {
            std.debug.print("   Error: Failed to decrypt (no error message)\n", .{});
        }
        return;
    }
    defer if (decrypted_data != null) std.c.free(decrypted_data);
    
    std.debug.print("   ✓ Data decrypted successfully\n", .{});
    std.debug.print("   Original: [{}, {}]\n", .{ test_data[0], test_data[1] });
    if (decrypted_len >= 2) {
        std.debug.print("   Decrypted: [{}, {}]\n", .{ decrypted_data[0], decrypted_data[1] });
    }
    
    // Test 5: Generate second key pair for PRE test
    std.debug.print("5. Testing Proxy Re-Encryption...\n", .{});
    const keypair2 = c.dcypher_keygen(ctx);
    if (keypair2 == null) {
        std.debug.print("   Error: Failed to generate second key pair\n", .{});
        return;
    }
    defer c.dcypher_keypair_destroy(keypair2);
    
    // Generate re-encryption key
    const reenc_key = c.dcypher_rekey_gen(ctx, keypair, keypair2);
    if (reenc_key == null) {
        const error_msg = c.dcypher_get_last_error();
        if (error_msg != null) {
            std.debug.print("   Error: {s}\n", .{error_msg});
        } else {
            std.debug.print("   Error: Failed to generate re-encryption key\n", .{});
        }
        return;
    }
    defer c.dcypher_reenc_key_destroy(reenc_key);
    
    // Re-encrypt
    const reencrypted = c.dcypher_reencrypt(ctx, ciphertext, reenc_key);
    if (reencrypted == null) {
        const error_msg = c.dcypher_get_last_error();
        if (error_msg != null) {
            std.debug.print("   Error: {s}\n", .{error_msg});
        } else {
            std.debug.print("   Error: Failed to re-encrypt\n", .{});
        }
        return;
    }
    defer c.dcypher_ciphertext_destroy(reencrypted);
    std.debug.print("   ✓ Proxy Re-Encryption completed successfully\n", .{});
    
    std.debug.print("\n🎉 All tests passed! dCypher unified FFI is working with static linking.\n", .{});
}
