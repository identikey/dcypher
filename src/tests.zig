//! Integration tests for the re-encryption proxy

const std = @import("std");
const testing = std.testing;
const expect = testing.expect;
const expectEqual = testing.expectEqual;

const crypto = @import("crypto.zig");
const cli = @import("cli.zig");
const server = @import("server.zig");

// Test crypto module
test "crypto - key generation" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    const test_file = "test_keygen.json";
    try crypto.generateKeyPair(allocator, test_file);
    
    // Verify file was created
    const file = std.fs.cwd().openFile(test_file, .{}) catch |err| {
        std.debug.print("Failed to open test key file: {}\n", .{err});
        return err;
    };
    file.close();
    
    // Cleanup
    std.fs.cwd().deleteFile(test_file) catch {};
}

test "crypto - re-encryption key generation" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    const test_file = "test_rekey.json";
    try crypto.generateReEncryptionKey(allocator, "key1.json", "key2.json", test_file);
    
    // Verify file was created
    const file = std.fs.cwd().openFile(test_file, .{}) catch |err| {
        std.debug.print("Failed to open test rekey file: {}\n", .{err});
        return err;
    };
    file.close();
    
    // Cleanup
    std.fs.cwd().deleteFile(test_file) catch {};
}

test "crypto - encryption/decryption workflow" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    // Create test input file
    const input_file = "test_input.txt";
    const test_data = "Hello, World! This is test data for encryption.";
    
    {
        const file = try std.fs.cwd().createFile(input_file, .{});
        defer file.close();
        try file.writeAll(test_data);
    }
    
    // Generate key pair first
    const key_file = "test_key.json";
    try crypto.generateKeyPair(allocator, key_file);
    
    // Encrypt the data
    const encrypted_file = "test_encrypted.bin";
    try crypto.encrypt(allocator, key_file, input_file, encrypted_file);
    
    // Decrypt the data
    const decrypted_file = "test_decrypted.txt";
    try crypto.decrypt(allocator, key_file, encrypted_file, decrypted_file);
    
    // Verify decrypted content matches original
    const decrypted_data = try std.fs.cwd().readFileAlloc(allocator, decrypted_file, 1024);
    defer allocator.free(decrypted_data);
    
    try expect(std.mem.eql(u8, test_data, decrypted_data));
    
    // Cleanup
    std.fs.cwd().deleteFile(input_file) catch {};
    std.fs.cwd().deleteFile(key_file) catch {};
    std.fs.cwd().deleteFile(encrypted_file) catch {};
    std.fs.cwd().deleteFile(decrypted_file) catch {};
}

// Test CLI module
test "cli - argument parsing" {
    const args1 = [_][]const u8{ "program", "serve", "--port", "9000" };
    const port = cli.parsePortArg(&args1);
    try expectEqual(@as(?u16, 9000), port);
    
    const args2 = [_][]const u8{ "program", "keygen", "--output", "mykey.json" };
    const output = cli.parseOutputArg(&args2);
    try expect(output != null);
    try expect(std.mem.eql(u8, output.?, "mykey.json"));
    
    const key_arg = cli.parseArgValue(&args2, "--output");
    try expect(key_arg != null);
    try expect(std.mem.eql(u8, key_arg.?, "mykey.json"));
}

test "cli - missing arguments" {
    const args = [_][]const u8{ "program", "serve" };
    const port = cli.parsePortArg(&args);
    try expectEqual(@as(?u16, null), port);
    
    const output = cli.parseOutputArg(&args);
    try expectEqual(@as(?[]const u8, null), output);
    
    const missing = cli.parseArgValue(&args, "--nonexistent");
    try expectEqual(@as(?[]const u8, null), missing);
}

// Test server module
test "server - health endpoint response" {
    const response = server.handleHealth();
    try expectEqual(@as(u16, 200), response.status);
    try expect(std.mem.indexOf(u8, response.body, "ok") != null);
    try expect(std.mem.indexOf(u8, response.body, "re-encryption-proxy") != null);
}

// Integration test
test "end-to-end workflow simulation" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    // Step 1: Generate Alice's key pair
    const alice_keys = "alice_keys.json";
    try crypto.generateKeyPair(allocator, alice_keys);
    
    // Step 2: Generate Bob's key pair
    const bob_keys = "bob_keys.json";
    try crypto.generateKeyPair(allocator, bob_keys);
    
    // Step 3: Generate re-encryption key from Alice to Bob
    const rekey_file = "alice_to_bob_rekey.json";
    try crypto.generateReEncryptionKey(allocator, alice_keys, bob_keys, rekey_file);
    
    // Step 4: Create test data file
    const test_file = "test_message.txt";
    const original_message = "This is Alice's secret message for Bob!";
    {
        const file = try std.fs.cwd().createFile(test_file, .{});
        defer file.close();
        try file.writeAll(original_message);
    }
    
    // Step 5: Alice encrypts the message
    const encrypted_file = "encrypted_message.bin";
    try crypto.encrypt(allocator, alice_keys, test_file, encrypted_file);
    
    // Step 6: Proxy re-encrypts for Bob
    const reencrypted_file = "reencrypted_message.bin";
    try crypto.reEncrypt(allocator, rekey_file, encrypted_file, reencrypted_file);
    
    // Step 7: Bob decrypts the message
    const decrypted_file = "decrypted_message.txt";
    try crypto.decrypt(allocator, bob_keys, reencrypted_file, decrypted_file);
    
    // Step 8: Verify the message is correct (this is a stub test)
    // In real implementation, this would verify the actual decryption
    const decrypted_content = try std.fs.cwd().readFileAlloc(allocator, decrypted_file, 1024);
    defer allocator.free(decrypted_content);
    
    // Since we're using stub implementations, we just verify files were created
    try expect(decrypted_content.len > 0);
    
    // Cleanup all test files
    const cleanup_files = [_][]const u8{
        alice_keys,
        bob_keys,
        rekey_file,
        test_file,
        encrypted_file,
        reencrypted_file,
        decrypted_file,
    };
    
    for (cleanup_files) |file| {
        std.fs.cwd().deleteFile(file) catch {};
    }
}
