/// BigSize encoding/decoding as defined in BOLT 1.
///
/// BigSize is a variable-length unsigned integer encoding:
///   0x00-0xfc:       1 byte (value itself)
///   0xfd + u16:      3 bytes (values 0xfd-0xffff)
///   0xfe + u32:      5 bytes (values 0x10000-0xffffffff)
///   0xff + u64:      9 bytes (values 0x100000000+)

pub const BigSizeResult = struct {
    value: u64,
    bytes_read: usize,
};

pub const BigSizeError = error{
    Truncated,
    NonMinimalEncoding,
};

/// Read a BigSize value from a buffer at the given offset.
pub fn read(buf: []const u8, offset: usize) BigSizeError!BigSizeResult {
    if (offset >= buf.len) {
        return BigSizeError.Truncated;
    }

    const first = buf[offset];

    if (first < 0xfd) {
        return .{ .value = first, .bytes_read = 1 };
    }

    if (first == 0xfd) {
        if (offset + 3 > buf.len) {
            return BigSizeError.Truncated;
        }
        const val: u16 = (@as(u16, buf[offset + 1]) << 8) | buf[offset + 2];
        if (val < 0xfd) {
            return BigSizeError.NonMinimalEncoding;
        }
        return .{ .value = val, .bytes_read = 3 };
    }

    if (first == 0xfe) {
        if (offset + 5 > buf.len) {
            return BigSizeError.Truncated;
        }
        const val: u32 = (@as(u32, buf[offset + 1]) << 24) |
            (@as(u32, buf[offset + 2]) << 16) |
            (@as(u32, buf[offset + 3]) << 8) |
            buf[offset + 4];
        if (val < 0x10000) {
            return BigSizeError.NonMinimalEncoding;
        }
        return .{ .value = val, .bytes_read = 5 };
    }

    // first == 0xff
    if (offset + 9 > buf.len) {
        return BigSizeError.Truncated;
    }
    const hi: u64 = (@as(u64, buf[offset + 1]) << 56) |
        (@as(u64, buf[offset + 2]) << 48) |
        (@as(u64, buf[offset + 3]) << 40) |
        (@as(u64, buf[offset + 4]) << 32);
    const lo: u64 = (@as(u64, buf[offset + 5]) << 24) |
        (@as(u64, buf[offset + 6]) << 16) |
        (@as(u64, buf[offset + 7]) << 8) |
        buf[offset + 8];
    const val = hi | lo;
    if (val < 0x100000000) {
        return BigSizeError.NonMinimalEncoding;
    }
    return .{ .value = val, .bytes_read = 9 };
}

/// Encode a BigSize value into a buffer. Returns the number of bytes written.
/// Buffer must be at least 9 bytes.
pub fn write(buf: []u8, value: u64) usize {
    if (value < 0xfd) {
        buf[0] = @intCast(value);
        return 1;
    }

    if (value <= 0xffff) {
        buf[0] = 0xfd;
        buf[1] = @intCast((value >> 8) & 0xff);
        buf[2] = @intCast(value & 0xff);
        return 3;
    }

    if (value <= 0xffffffff) {
        buf[0] = 0xfe;
        buf[1] = @intCast((value >> 24) & 0xff);
        buf[2] = @intCast((value >> 16) & 0xff);
        buf[3] = @intCast((value >> 8) & 0xff);
        buf[4] = @intCast(value & 0xff);
        return 5;
    }

    buf[0] = 0xff;
    buf[1] = @intCast((value >> 56) & 0xff);
    buf[2] = @intCast((value >> 48) & 0xff);
    buf[3] = @intCast((value >> 40) & 0xff);
    buf[4] = @intCast((value >> 32) & 0xff);
    buf[5] = @intCast((value >> 24) & 0xff);
    buf[6] = @intCast((value >> 16) & 0xff);
    buf[7] = @intCast((value >> 8) & 0xff);
    buf[8] = @intCast(value & 0xff);
    return 9;
}

/// Write a BigSize value into a stack-allocated array and return a slice.
pub fn writeToArray(value: u64) struct { data: [9]u8, len: usize } {
    var buf: [9]u8 = undefined;
    const len = write(&buf, value);
    return .{ .data = buf, .len = len };
}

// ---- Tests ----

const testing = @import("std").testing;

test "bigsize: single byte values" {
    const result = try read(&[_]u8{0x00}, 0);
    try testing.expectEqual(@as(u64, 0), result.value);
    try testing.expectEqual(@as(usize, 1), result.bytes_read);

    const r2 = try read(&[_]u8{0xfc}, 0);
    try testing.expectEqual(@as(u64, 0xfc), r2.value);
    try testing.expectEqual(@as(usize, 1), r2.bytes_read);
}

test "bigsize: two byte values" {
    const result = try read(&[_]u8{ 0xfd, 0x00, 0xfd }, 0);
    try testing.expectEqual(@as(u64, 0xfd), result.value);
    try testing.expectEqual(@as(usize, 3), result.bytes_read);

    const r2 = try read(&[_]u8{ 0xfd, 0xff, 0xff }, 0);
    try testing.expectEqual(@as(u64, 0xffff), r2.value);
}

test "bigsize: four byte values" {
    const result = try read(&[_]u8{ 0xfe, 0x00, 0x01, 0x00, 0x00 }, 0);
    try testing.expectEqual(@as(u64, 0x10000), result.value);
    try testing.expectEqual(@as(usize, 5), result.bytes_read);
}

test "bigsize: eight byte values" {
    const result = try read(&[_]u8{ 0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00 }, 0);
    try testing.expectEqual(@as(u64, 0x100000000), result.value);
    try testing.expectEqual(@as(usize, 9), result.bytes_read);
}

test "bigsize: non-minimal encoding rejected" {
    // 0xfd prefix but value < 0xfd
    try testing.expectError(BigSizeError.NonMinimalEncoding, read(&[_]u8{ 0xfd, 0x00, 0x01 }, 0));
    // 0xfe prefix but value < 0x10000
    try testing.expectError(BigSizeError.NonMinimalEncoding, read(&[_]u8{ 0xfe, 0x00, 0x00, 0x00, 0x01 }, 0));
}

test "bigsize: truncated data" {
    try testing.expectError(BigSizeError.Truncated, read(&[_]u8{}, 0));
    try testing.expectError(BigSizeError.Truncated, read(&[_]u8{0xfd}, 0));
    try testing.expectError(BigSizeError.Truncated, read(&[_]u8{ 0xfe, 0x00 }, 0));
}

test "bigsize: roundtrip encoding" {
    const test_values = [_]u64{ 0, 1, 0xfc, 0xfd, 0xffff, 0x10000, 0xffffffff, 0x100000000, 0xffffffffffffffff };
    for (test_values) |val| {
        var buf: [9]u8 = undefined;
        const written = write(&buf, val);
        const result = try read(&buf, 0);
        try testing.expectEqual(val, result.value);
        try testing.expectEqual(written, result.bytes_read);
    }
}
