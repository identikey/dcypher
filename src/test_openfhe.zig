const std = @import("std");
const c = @cImport({
    @cInclude("openfhe_wrapper.h");
});

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Create crypto context
    const ctx = c.openfhe_gen_cryptocontext_bfv(
        2,          // plaintextModulus
        128,        // securityLevel
        3.2,        // distributionParameter
        2           // maxDepth
    ) orelse {
        std.debug.print("Failed to create crypto context\n", .{});
        return error.OpenFHEFailed;
    };
    defer c.openfhe_cryptocontext_destroy(ctx);

    // Enable required features
    if (c.openfhe_cryptocontext_enable_pke(ctx) != 0) {
        std.debug.print("Failed to enable PKE\n", .{});
        return error.OpenFHEFailed;
    }
    if (c.openfhe_cryptocontext_enable_keyswitch(ctx) != 0) {
        std.debug.print("Failed to enable KEYSWITCH\n", .{});
        return error.OpenFHEFailed;
    }
    if (c.openfhe_cryptocontext_enable_leveledshe(ctx) != 0) {
        std.debug.print("Failed to enable LEVELEDSHE\n", .{});
        return error.OpenFHEFailed;
    }
    if (c.openfhe_cryptocontext_enable_pre(ctx) != 0) {
        std.debug.print("Failed to enable PRE\n", .{});
        return error.OpenFHEFailed;
    }

    // Generate key pair
    const keypair = c.openfhe_keygen(ctx) orelse {
        std.debug.print("Failed to generate key pair\n", .{});
        return error.OpenFHEFailed;
    };
    defer c.openfhe_keypair_destroy(keypair);

    // Get public and private keys
    const publicKey = c.openfhe_keypair_get_publickey(keypair) orelse {
        std.debug.print("Failed to get public key\n", .{});
        return error.OpenFHEFailed;
    };
    const privateKey = c.openfhe_keypair_get_privatekey(keypair) orelse {
        std.debug.print("Failed to get private key\n", .{});
        return error.OpenFHEFailed;
    };

    // Test encryption/decryption
    var values: [2]i64 = [_]i64{42, 84};
    const plaintext = c.openfhe_make_packed_plaintext(ctx, &values, values.len) orelse {
        std.debug.print("Failed to create plaintext\n", .{});
        return error.OpenFHEFailed;
    };
    defer c.openfhe_plaintext_destroy(plaintext);

    const ciphertext = c.openfhe_encrypt(ctx, publicKey, plaintext) orelse {
        std.debug.print("Failed to encrypt\n", .{});
        return error.OpenFHEFailed;
    };
    defer c.openfhe_ciphertext_destroy(ciphertext);

    const decrypted = c.openfhe_decrypt(ctx, privateKey, ciphertext) orelse {
        std.debug.print("Failed to decrypt\n", .{});
        return error.OpenFHEFailed;
    };
    defer c.openfhe_plaintext_destroy(decrypted);

    std.debug.print("OpenFHE test successful!\n", .{});
}
