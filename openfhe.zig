const std = @import("std");
const c = @cImport({
    @cInclude("openfhe_wrapper.h");
});

// Zig wrapper types
pub const CryptoContext = struct {
    ptr: ?*c.openfhe_cryptocontext_t,
    
    const Self = @This();
    
    pub fn init(plaintextModulus: i32, securityLevel: i32, distributionParameter: f32, maxDepth: i32) !Self {
        const ptr = c.openfhe_gen_cryptocontext_bfv(plaintextModulus, securityLevel, distributionParameter, maxDepth);
        if (ptr == null) return error.ContextCreationFailed;
        
        return Self{ .ptr = ptr };
    }
    
    pub fn deinit(self: *Self) void {
        if (self.ptr) |ptr| {
            c.openfhe_cryptocontext_destroy(ptr);
            self.ptr = null;
        }
    }
    
    pub fn enablePKE(self: Self) !void {
        if (self.ptr) |ptr| {
            if (c.openfhe_cryptocontext_enable_pke(ptr) == 0) {
                return error.EnablePKEFailed;
            }
        } else return error.NullContext;
    }
    
    pub fn enableKeySwitch(self: Self) !void {
        if (self.ptr) |ptr| {
            if (c.openfhe_cryptocontext_enable_keyswitch(ptr) == 0) {
                return error.EnableKeySwitchFailed;
            }
        } else return error.NullContext;
    }
    
    pub fn enableLeveledSHE(self: Self) !void {
        if (self.ptr) |ptr| {
            if (c.openfhe_cryptocontext_enable_leveledshe(ptr) == 0) {
                return error.EnableLeveledSHEFailed;
            }
        } else return error.NullContext;
    }
    
    pub fn enablePRE(self: Self) !void {
        if (self.ptr) |ptr| {
            if (c.openfhe_cryptocontext_enable_pre(ptr) == 0) {
                return error.EnablePREFailed;
            }
        } else return error.NullContext;
    }
    
    pub fn keyGen(self: Self) !KeyPair {
        if (self.ptr) |ptr| {
            const keypair_ptr = c.openfhe_keygen(ptr);
            if (keypair_ptr == null) return error.KeyGenFailed;
            return KeyPair{ .ptr = keypair_ptr };
        } else return error.NullContext;
    }
    
    pub fn makePackedPlaintext(self: Self, values: []const i64) !Plaintext {
        if (self.ptr) |ptr| {
            const plaintext_ptr = c.openfhe_make_packed_plaintext(ptr, @ptrCast(values.ptr), values.len);
            if (plaintext_ptr == null) return error.PlaintextCreationFailed;
            return Plaintext{ .ptr = plaintext_ptr };
        } else return error.NullContext;
    }
    
    pub fn encrypt(self: Self, publicKey: PublicKey, plaintext: Plaintext) !Ciphertext {
        if (self.ptr) |ptr| {
            const ciphertext_ptr = c.openfhe_encrypt(ptr, publicKey.ptr, plaintext.ptr);
            if (ciphertext_ptr == null) return error.EncryptionFailed;
            return Ciphertext{ .ptr = ciphertext_ptr };
        } else return error.NullContext;
    }
    
    pub fn decrypt(self: Self, privateKey: PrivateKey, ciphertext: Ciphertext) !Plaintext {
        if (self.ptr) |ptr| {
            const plaintext_ptr = c.openfhe_decrypt(ptr, privateKey.ptr, ciphertext.ptr);
            if (plaintext_ptr == null) return error.DecryptionFailed;
            return Plaintext{ .ptr = plaintext_ptr };
        } else return error.NullContext;
    }
    
    pub fn reKeyGen(self: Self, oldKey: PrivateKey, newKey: PublicKey) !ReEncryptionKey {
        if (self.ptr) |ptr| {
            const reenc_key_ptr = c.openfhe_rekeygen(ptr, oldKey.ptr, newKey.ptr);
            if (reenc_key_ptr == null) return error.ReKeyGenFailed;
            return ReEncryptionKey{ .ptr = reenc_key_ptr };
        } else return error.NullContext;
    }
    
    pub fn reEncrypt(self: Self, ciphertext: Ciphertext, reencKey: ReEncryptionKey) !Ciphertext {
        if (self.ptr) |ptr| {
            const ciphertext_ptr = c.openfhe_reencrypt(ptr, ciphertext.ptr, reencKey.ptr);
            if (ciphertext_ptr == null) return error.ReEncryptionFailed;
            return Ciphertext{ .ptr = ciphertext_ptr };
        } else return error.NullContext;
    }
};

pub const KeyPair = struct {
    ptr: ?*c.openfhe_keypair_t,
    
    const Self = @This();
    
    pub fn deinit(self: *Self) void {
        if (self.ptr) |ptr| {
            c.openfhe_keypair_destroy(ptr);
            self.ptr = null;
        }
    }
    
    pub fn getPublicKey(self: Self) PublicKey {
        const pub_key_ptr = c.openfhe_keypair_get_publickey(self.ptr);
        return PublicKey{ .ptr = pub_key_ptr };
    }
    
    pub fn getPrivateKey(self: Self) PrivateKey {
        const priv_key_ptr = c.openfhe_keypair_get_privatekey(self.ptr);
        return PrivateKey{ .ptr = priv_key_ptr };
    }
};

pub const PublicKey = struct {
    ptr: ?*c.openfhe_publickey_t,
};

pub const PrivateKey = struct {
    ptr: ?*c.openfhe_privatekey_t,
};

pub const Plaintext = struct {
    ptr: ?*c.openfhe_plaintext_t,
    
    const Self = @This();
    
    pub fn deinit(self: *Self) void {
        if (self.ptr) |ptr| {
            c.openfhe_plaintext_destroy(ptr);
            self.ptr = null;
        }
    }
    
    pub fn getPackedValue(self: Self, allocator: std.mem.Allocator) ![]i64 {
        if (self.ptr) |ptr| {
            var count: usize = 0;
            // First call to get the size
            _ = c.openfhe_plaintext_get_packed_value(ptr, null, &count);
            
            const values = try allocator.alloc(i64, count);
            errdefer allocator.free(values);
            
            var actual_count = count;
            if (c.openfhe_plaintext_get_packed_value(ptr, values.ptr, &actual_count) == 0) {
                allocator.free(values);
                return error.GetPackedValueFailed;
            }
            
            return values[0..actual_count];
        } else return error.NullPlaintext;
    }
};

pub const Ciphertext = struct {
    ptr: ?*c.openfhe_ciphertext_t,
    
    const Self = @This();
    
    pub fn deinit(self: *Self) void {
        if (self.ptr) |ptr| {
            c.openfhe_ciphertext_destroy(ptr);
            self.ptr = null;
        }
    }
};

pub const ReEncryptionKey = struct {
    ptr: ?*c.openfhe_reencryptionkey_t,
    
    const Self = @This();
    
    pub fn deinit(self: *Self) void {
        if (self.ptr) |ptr| {
            c.openfhe_reencryptionkey_destroy(ptr);
            self.ptr = null;
        }
    }
};

// Example usage function
pub fn proxyReEncryptionExample(allocator: std.mem.Allocator) !void {
    std.debug.print("Starting OpenFHE Proxy Re-Encryption example from Zig...\n");
    
    // Initialize crypto context
    var context = try CryptoContext.init(65537, 128, 3.2, 2);
    defer context.deinit();
    
    // Enable features
    try context.enablePKE();
    try context.enableKeySwitch();
    try context.enableLeveledSHE();
    try context.enablePRE();
    
    std.debug.print("Crypto context initialized and features enabled.\n");
    
    // Generate Alice's key pair
    var aliceKeyPair = try context.keyGen();
    defer aliceKeyPair.deinit();
    
    const alicePublicKey = aliceKeyPair.getPublicKey();
    const alicePrivateKey = aliceKeyPair.getPrivateKey();
    
    // Generate Bob's key pair
    var bobKeyPair = try context.keyGen();
    defer bobKeyPair.deinit();
    
    const bobPublicKey = bobKeyPair.getPublicKey();
    const bobPrivateKey = bobKeyPair.getPrivateKey();
    
    std.debug.print("Generated key pairs for Alice and Bob.\n");
    
    // Create plaintext data
    const vectorData = [_]i64{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 };
    var plaintext = try context.makePackedPlaintext(&vectorData);
    defer plaintext.deinit();
    
    std.debug.print("Created plaintext with data: [");
    for (vectorData, 0..) |val, i| {
        if (i > 0) std.debug.print(", ");
        std.debug.print("{}", .{val});
    }
    std.debug.print("]\n");
    
    // Alice encrypts data
    var aliceCiphertext = try context.encrypt(alicePublicKey, plaintext);
    defer aliceCiphertext.deinit();
    
    std.debug.print("Alice encrypted the data.\n");
    
    // Generate re-encryption key from Alice to Bob
    var reencryptionKey = try context.reKeyGen(alicePrivateKey, bobPublicKey);
    defer reencryptionKey.deinit();
    
    std.debug.print("Generated re-encryption key from Alice to Bob.\n");
    
    // Re-encrypt Alice's ciphertext for Bob
    var bobCiphertext = try context.reEncrypt(aliceCiphertext, reencryptionKey);
    defer bobCiphertext.deinit();
    
    std.debug.print("Re-encrypted ciphertext for Bob.\n");
    
    // Bob decrypts the re-encrypted ciphertext
    var decryptedPlaintext = try context.decrypt(bobPrivateKey, bobCiphertext);
    defer decryptedPlaintext.deinit();
    
    // Get the decrypted values
    const decryptedValues = try decryptedPlaintext.getPackedValue(allocator);
    defer allocator.free(decryptedValues);
    
    std.debug.print("Bob decrypted result: [");
    for (decryptedValues, 0..) |val, i| {
        if (i > 0) std.debug.print(", ");
        std.debug.print("{}", .{val});
    }
    std.debug.print("]\n");
    
    std.debug.print("Proxy re-encryption example completed successfully!\n");
}
