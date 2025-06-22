//! Re-encryption Proxy Library
//! 
//! This module exports the main library functions for use by other applications
//! or for building as a shared library.

const std = @import("std");
const testing = std.testing;

pub const crypto = @import("crypto.zig");
pub const server = @import("server.zig");
pub const cli = @import("cli.zig");

// Export key types
pub const KeyPair = crypto.KeyPair;
pub const ReEncryptionKey = crypto.ReEncryptionKey;
pub const Ciphertext = crypto.Ciphertext;

// Export main crypto functions
pub const generateKeyPair = crypto.generateKeyPair;
pub const generateReEncryptionKey = crypto.generateReEncryptionKey;
pub const encrypt = crypto.encrypt;
pub const reEncrypt = crypto.reEncrypt;
pub const decrypt = crypto.decrypt;

// Export server function
pub const startServer = server.start;

// Export CLI utilities
pub const parsePortArg = cli.parsePortArg;
pub const parseArgValue = cli.parseArgValue;

// Version info
pub const version = "0.1.0";
pub const name = "zig-proxy";

/// Initialize the library (placeholder for future initialization needs)
pub fn init() void {
    // Future initialization code here
}

/// Cleanup the library (placeholder for future cleanup needs)
pub fn deinit() void {
    // Future cleanup code here
}

// Tests
test "library initialization" {
    init();
    deinit();
    // Should not crash
}

test "version and name constants" {
    try testing.expect(version.len > 0);
    try testing.expect(name.len > 0);
}
