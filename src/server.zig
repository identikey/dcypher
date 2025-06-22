//! HTTP Server for re-encryption proxy service

const std = @import("std");
const net = std.net;
const print = std.debug.print;
const Allocator = std.mem.Allocator;

const crypto = @import("crypto.zig");

const Response = struct {
    status: u16,
    headers: []const u8,
    body: []const u8,
};

/// Start the HTTP server
pub fn start(allocator: Allocator, port: u16) !void {
    const address = net.Address.parseIp("127.0.0.1", port) catch unreachable;
    
    var server = try address.listen(.{
        .reuse_address = true,
    });
    defer server.deinit();
    
    print("Re-encryption proxy server listening on http://127.0.0.1:{d}\n", .{port});
    print("Available endpoints:\n", .{});
    print("  POST /api/keygen - Generate key pair\n", .{});
    print("  POST /api/rekey - Generate re-encryption key\n", .{});
    print("  POST /api/encrypt - Encrypt data\n", .{});
    print("  POST /api/reencrypt - Re-encrypt data\n", .{});
    print("  POST /api/decrypt - Decrypt data\n", .{});
    print("  GET /health - Health check\n", .{});
    
    while (true) {
        const connection = server.accept() catch |err| {
            print("Failed to accept connection: {s}\n", .{@errorName(err)});
            continue;
        };
        
        // Handle connection in a separate thread for better performance
        const thread = std.Thread.spawn(.{}, handleConnection, .{ allocator, connection }) catch |err| {
            print("Failed to spawn thread: {s}\n", .{@errorName(err)});
            connection.stream.close();
            continue;
        };
        thread.detach();
    }
}

fn handleConnection(allocator: Allocator, connection: net.Server.Connection) void {
    defer connection.stream.close();
    
    const reader = connection.stream.reader();
    const writer = connection.stream.writer();
    
    // Read HTTP request (simplified parser)
    var buffer: [4096]u8 = undefined;
    const bytes_read = reader.readAll(&buffer) catch |err| {
        print("Failed to read request: {s}\n", .{@errorName(err)});
        return;
    };
    
    if (bytes_read == 0) return;
    
    const request = buffer[0..bytes_read];
    const response = handleRequest(allocator, request) catch |err| {
        print("Failed to handle request: {s}\n", .{@errorName(err)});
        return;
    };
    
    // Send response
    writer.print("HTTP/1.1 {d} OK\r\n", .{response.status}) catch return;
    writer.print("{s}\r\n", .{response.headers}) catch return;
    writer.print("Content-Length: {d}\r\n", .{response.body.len}) catch return;
    writer.print("\r\n", .{}) catch return;
    writer.print("{s}", .{response.body}) catch return;
}

fn handleRequest(allocator: Allocator, request: []const u8) !Response {
    // Parse HTTP method and path (simplified)
    var lines = std.mem.splitSequence(u8, request, "\r\n");
    const first_line = lines.next() orelse return Response{
        .status = 400,
        .headers = "Content-Type: text/plain",
        .body = "Bad Request",
    };
    
    var parts = std.mem.splitSequence(u8, first_line, " ");
    const method = parts.next() orelse "GET";
    const path = parts.next() orelse "/";
    
    // Route requests
    if (std.mem.eql(u8, method, "GET") and std.mem.eql(u8, path, "/health")) {
        return handleHealth();
    } else if (std.mem.eql(u8, method, "POST") and std.mem.eql(u8, path, "/api/keygen")) {
        return try handleKeyGen(allocator, request);
    } else if (std.mem.eql(u8, method, "POST") and std.mem.eql(u8, path, "/api/rekey")) {
        return try handleReKey(allocator, request);
    } else if (std.mem.eql(u8, method, "POST") and std.mem.eql(u8, path, "/api/encrypt")) {
        return try handleEncrypt(allocator, request);
    } else if (std.mem.eql(u8, method, "POST") and std.mem.eql(u8, path, "/api/reencrypt")) {
        return try handleReEncrypt(allocator, request);
    } else if (std.mem.eql(u8, method, "POST") and std.mem.eql(u8, path, "/api/decrypt")) {
        return try handleDecrypt(allocator, request);
    } else {
        return Response{
            .status = 404,
            .headers = "Content-Type: text/plain",
            .body = "Not Found",
        };
    }
}

fn handleHealth() Response {
    return Response{
        .status = 200,
        .headers = "Content-Type: application/json",
        .body = "{\"status\":\"ok\",\"service\":\"re-encryption-proxy\"}",
    };
}

fn handleKeyGen(allocator: Allocator, request: []const u8) !Response {
    _ = allocator;
    _ = request;
    
    // Stub implementation - generate and return key pair
    return Response{
        .status = 200,
        .headers = "Content-Type: application/json",
        .body = "{\"message\":\"Key generation not yet implemented\",\"public_key\":\"stub_public_key\",\"private_key\":\"stub_private_key\"}",
    };
}

fn handleReKey(allocator: Allocator, request: []const u8) !Response {
    _ = allocator;
    _ = request;
    
    // Stub implementation - generate re-encryption key
    return Response{
        .status = 200,
        .headers = "Content-Type: application/json",
        .body = "{\"message\":\"Re-encryption key generation not yet implemented\",\"rekey\":\"stub_reencryption_key\"}",
    };
}

fn handleEncrypt(allocator: Allocator, request: []const u8) !Response {
    _ = allocator;
    _ = request;
    
    // Stub implementation - encrypt data
    return Response{
        .status = 200,
        .headers = "Content-Type: application/json",
        .body = "{\"message\":\"Encryption not yet implemented\",\"ciphertext\":\"stub_encrypted_data\"}",
    };
}

fn handleReEncrypt(allocator: Allocator, request: []const u8) !Response {
    _ = allocator;
    _ = request;
    
    // Stub implementation - re-encrypt data
    return Response{
        .status = 200,
        .headers = "Content-Type: application/json",
        .body = "{\"message\":\"Re-encryption not yet implemented\",\"ciphertext\":\"stub_reencrypted_data\"}",
    };
}

fn handleDecrypt(allocator: Allocator, request: []const u8) !Response {
    _ = allocator;
    _ = request;
    
    // Stub implementation - decrypt data
    return Response{
        .status = 200,
        .headers = "Content-Type: application/json",
        .body = "{\"message\":\"Decryption not yet implemented\",\"plaintext\":\"stub_decrypted_data\"}",
    };
}

// Tests
test "handleHealth returns ok status" {
    const response = handleHealth();
    try std.testing.expectEqual(@as(u16, 200), response.status);
    try std.testing.expect(std.mem.indexOf(u8, response.body, "ok") != null);
}
