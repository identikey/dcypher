//! CLI argument parsing utilities

const std = @import("std");

/// Parse port argument from command line args
pub fn parsePortArg(args: [][:0]u8) ?u16 {
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--port") and i + 1 < args.len) {
            return std.fmt.parseInt(u16, args[i + 1], 10) catch null;
        }
    }
    return null;
}

/// Parse output file argument from command line args
pub fn parseOutputArg(args: [][:0]u8) ?[]const u8 {
    return parseArgValue(args, "--output");
}

/// Parse a generic argument value from command line args
pub fn parseArgValue(args: [][:0]u8, arg_name: []const u8) ?[]const u8 {
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], arg_name) and i + 1 < args.len) {
            return args[i + 1];
        }
    }
    return null;
}

// Tests
test "parsePortArg with valid port" {
    const args = [_][:0]u8{ "program", "serve", "--port", "9000" };
    const port = parsePortArg(&args);
    try std.testing.expectEqual(@as(?u16, 9000), port);
}

test "parsePortArg with no port" {
    const args = [_][:0]u8{ "program", "serve" };
    const port = parsePortArg(&args);
    try std.testing.expectEqual(@as(?u16, null), port);
}

test "parseArgValue finds argument" {
    const args = [_][:0]u8{ "program", "cmd", "--key", "mykey.json" };
    const value = parseArgValue(&args, "--key");
    try std.testing.expect(std.mem.eql(u8, value.?, "mykey.json"));
}

test "parseArgValue missing argument" {
    const args = [_][:0]u8{ "program", "cmd" };
    const value = parseArgValue(&args, "--key");
    try std.testing.expectEqual(@as(?[]const u8, null), value);
}
