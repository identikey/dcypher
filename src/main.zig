//! Re-encryption Proxy CLI
//! 
//! This application provides both CLI commands for key generation and proxy operations,
//! and can run as a service to handle re-encryption requests over HTTP.

const std = @import("std");
const print = std.debug.print;
const ArrayList = std.ArrayList;
const Allocator = std.mem.Allocator;

const cli = @import("cli.zig");
const server = @import("server.zig");
const crypto = @import("crypto.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 2) {
        try printUsage();
        return;
    }

    const command = args[1];

    if (std.mem.eql(u8, command, "serve")) {
        try runServer(allocator, args);
    } else if (std.mem.eql(u8, command, "keygen")) {
        try runKeyGen(allocator, args);
    } else if (std.mem.eql(u8, command, "rekey")) {
        try runReKey(allocator, args);
    } else if (std.mem.eql(u8, command, "encrypt")) {
        try runEncrypt(allocator, args);
    } else if (std.mem.eql(u8, command, "reencrypt")) {
        try runReEncrypt(allocator, args);
    } else if (std.mem.eql(u8, command, "decrypt")) {
        try runDecrypt(allocator, args);
    } else {
        print("Unknown command: {s}\n", .{command});
        try printUsage();
        std.process.exit(1);
    }
}

fn printUsage() !void {
    print("Re-encryption Proxy CLI\n\n", .{});
    print("Usage: zig-proxy <command> [options]\n\n", .{});
    print("Commands:\n", .{});
    print("  serve          Start the re-encryption proxy server\n", .{});
    print("    --port <port>  Port to bind to (default: 8080)\n\n", .{});
    print("  keygen         Generate a new key pair\n", .{});
    print("    --output <file>  Output file for key pair (default: key.json)\n\n", .{});
    print("  rekey          Generate re-encryption key\n", .{});
    print("    --from <key>   Source private key file\n", .{});
    print("    --to <key>     Target public key file\n", .{});
    print("    --output <file> Output re-encryption key file\n\n", .{});
    print("  encrypt        Encrypt data\n", .{});
    print("    --key <file>   Public key file\n", .{});
    print("    --input <file> Input file to encrypt\n", .{});
    print("    --output <file> Output encrypted file\n\n", .{});
    print("  reencrypt      Re-encrypt data using re-encryption key\n", .{});
    print("    --rekey <file> Re-encryption key file\n", .{});
    print("    --input <file> Input encrypted file\n", .{});
    print("    --output <file> Output re-encrypted file\n\n", .{});
    print("  decrypt        Decrypt data\n", .{});
    print("    --key <file>   Private key file\n", .{});
    print("    --input <file> Input encrypted file\n", .{});
    print("    --output <file> Output decrypted file\n\n", .{});
}

fn runServer(allocator: Allocator, args: [][:0]u8) !void {
    const port = cli.parsePortArg(args) orelse 8080;
    print("Starting re-encryption proxy server on port {d}...\n", .{port});
    try server.start(allocator, port);
}

fn runKeyGen(allocator: Allocator, args: [][:0]u8) !void {
    const output_file = cli.parseOutputArg(args) orelse "key.json";
    print("Generating key pair to {s}...\n", .{output_file});
    try crypto.generateKeyPair(allocator, output_file);
    print("Key pair generated successfully!\n", .{});
}

fn runReKey(allocator: Allocator, args: [][:0]u8) !void {
    const from_key = cli.parseArgValue(args, "--from") orelse {
        print("Error: --from argument required\n", .{});
        std.process.exit(1);
    };
    const to_key = cli.parseArgValue(args, "--to") orelse {
        print("Error: --to argument required\n", .{});
        std.process.exit(1);
    };
    const output_file = cli.parseOutputArg(args) orelse "rekey.json";
    
    print("Generating re-encryption key from {s} to {s}...\n", .{ from_key, to_key });
    try crypto.generateReEncryptionKey(allocator, from_key, to_key, output_file);
    print("Re-encryption key generated successfully!\n", .{});
}

fn runEncrypt(allocator: Allocator, args: [][:0]u8) !void {
    const key_file = cli.parseArgValue(args, "--key") orelse {
        print("Error: --key argument required\n", .{});
        std.process.exit(1);
    };
    const input_file = cli.parseArgValue(args, "--input") orelse {
        print("Error: --input argument required\n", .{});
        std.process.exit(1);
    };
    const output_file = cli.parseOutputArg(args) orelse "encrypted.bin";
    
    print("Encrypting {s} with key {s}...\n", .{ input_file, key_file });
    try crypto.encrypt(allocator, key_file, input_file, output_file);
    print("File encrypted successfully!\n", .{});
}

fn runReEncrypt(allocator: Allocator, args: [][:0]u8) !void {
    const rekey_file = cli.parseArgValue(args, "--rekey") orelse {
        print("Error: --rekey argument required\n", .{});
        std.process.exit(1);
    };
    const input_file = cli.parseArgValue(args, "--input") orelse {
        print("Error: --input argument required\n", .{});
        std.process.exit(1);
    };
    const output_file = cli.parseOutputArg(args) orelse "reencrypted.bin";
    
    print("Re-encrypting {s} with re-key {s}...\n", .{ input_file, rekey_file });
    try crypto.reEncrypt(allocator, rekey_file, input_file, output_file);
    print("File re-encrypted successfully!\n", .{});
}

fn runDecrypt(allocator: Allocator, args: [][:0]u8) !void {
    const key_file = cli.parseArgValue(args, "--key") orelse {
        print("Error: --key argument required\n", .{});
        std.process.exit(1);
    };
    const input_file = cli.parseArgValue(args, "--input") orelse {
        print("Error: --input argument required\n", .{});
        std.process.exit(1);
    };
    const output_file = cli.parseOutputArg(args) orelse "decrypted.txt";
    
    print("Decrypting {s} with key {s}...\n", .{ input_file, key_file });
    try crypto.decrypt(allocator, key_file, input_file, output_file);
    print("File decrypted successfully!\n", .{});
}

// Tests
test "main function with no args shows usage" {
    // This would require mocking stdin/stdout for proper testing
    // For now, we'll test the individual functions
}
