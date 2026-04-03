/// TLV (Type-Length-Value) stream parsing for BOLT12.
///
/// A TLV stream is a sequence of records, each consisting of:
///   - type: BigSize
///   - length: BigSize
///   - value: `length` bytes
///
/// Records MUST appear in strictly ascending type order.

const std = @import("std");
const bigsize = @import("bigsize.zig");

pub const TlvRecord = struct {
    tlv_type: u64,
    length: u64,
    value: []const u8,
};

pub const TlvError = error{
    NotAscending,
    TruncatedLength,
    TruncatedValue,
    OutOfMemory,
    Truncated,
    NonMinimalEncoding,
};

/// Parse a TLV stream from raw bytes.
/// Returns an array of TLV records. Caller owns the returned slice.
/// The value fields point into the original data buffer.
pub fn parseTlvStream(allocator: std.mem.Allocator, data: []const u8) TlvError![]TlvRecord {
    var records: std.ArrayList(TlvRecord) = .{};
    errdefer records.deinit(allocator);

    var offset: usize = 0;
    var last_type: ?u64 = null;

    while (offset < data.len) {
        // Read type
        const type_result = bigsize.read(data, offset) catch |e| switch (e) {
            bigsize.BigSizeError.Truncated => return TlvError.Truncated,
            bigsize.BigSizeError.NonMinimalEncoding => return TlvError.NonMinimalEncoding,
        };
        offset += type_result.bytes_read;
        const tlv_type = type_result.value;

        // Check ascending order
        if (last_type) |lt| {
            if (tlv_type <= lt) {
                return TlvError.NotAscending;
            }
        }
        last_type = tlv_type;

        // Read length
        if (offset >= data.len) {
            return TlvError.TruncatedLength;
        }
        const length_result = bigsize.read(data, offset) catch |e| switch (e) {
            bigsize.BigSizeError.Truncated => return TlvError.Truncated,
            bigsize.BigSizeError.NonMinimalEncoding => return TlvError.NonMinimalEncoding,
        };
        offset += length_result.bytes_read;
        const tlv_length = length_result.value;

        // Read value
        const len: usize = @intCast(tlv_length);
        if (offset + len > data.len) {
            return TlvError.TruncatedValue;
        }
        const value = data[offset .. offset + len];
        offset += len;

        records.append(allocator, .{
            .tlv_type = tlv_type,
            .length = tlv_length,
            .value = value,
        }) catch return TlvError.OutOfMemory;
    }

    return records.toOwnedSlice(allocator) catch return TlvError.OutOfMemory;
}

/// Serialize a TLV record to bytes (type + length + value).
pub fn serializeTlvRecord(allocator: std.mem.Allocator, record: TlvRecord) ![]u8 {
    var type_buf: [9]u8 = undefined;
    const type_len = bigsize.write(&type_buf, record.tlv_type);
    var length_buf: [9]u8 = undefined;
    const length_len = bigsize.write(&length_buf, record.length);

    const total = type_len + length_len + record.value.len;
    const result = try allocator.alloc(u8, total);

    @memcpy(result[0..type_len], type_buf[0..type_len]);
    @memcpy(result[type_len .. type_len + length_len], length_buf[0..length_len]);
    @memcpy(result[type_len + length_len ..], record.value);

    return result;
}

/// Get the wire-format byte length of a TLV record.
pub fn recordWireLength(record: TlvRecord) usize {
    const type_r = bigsize.writeToArray(record.tlv_type);
    const length_r = bigsize.writeToArray(record.length);
    return type_r.len + length_r.len + record.value.len;
}

// ---- Tests ----

const testing = std.testing;

test "tlv: parse single record" {
    // type=10 (0x0a), length=3, value="abc"
    const data = [_]u8{ 0x0a, 0x03, 'a', 'b', 'c' };
    const records = try parseTlvStream(testing.allocator, &data);
    defer testing.allocator.free(records);

    try testing.expectEqual(@as(usize, 1), records.len);
    try testing.expectEqual(@as(u64, 10), records[0].tlv_type);
    try testing.expectEqual(@as(u64, 3), records[0].length);
    try testing.expectEqualStrings("abc", records[0].value);
}

test "tlv: parse multiple records in ascending order" {
    // type=2, length=1, value=0x01
    // type=10, length=2, value=0x02,0x03
    const data = [_]u8{ 0x02, 0x01, 0x01, 0x0a, 0x02, 0x02, 0x03 };
    const records = try parseTlvStream(testing.allocator, &data);
    defer testing.allocator.free(records);

    try testing.expectEqual(@as(usize, 2), records.len);
    try testing.expectEqual(@as(u64, 2), records[0].tlv_type);
    try testing.expectEqual(@as(u64, 10), records[1].tlv_type);
}

test "tlv: reject non-ascending types" {
    // type=10, then type=2 (not ascending)
    const data = [_]u8{ 0x0a, 0x01, 0x01, 0x02, 0x01, 0x02 };
    try testing.expectError(TlvError.NotAscending, parseTlvStream(testing.allocator, &data));
}

test "tlv: reject truncated value" {
    // type=10, length=5, but only 2 bytes of value
    const data = [_]u8{ 0x0a, 0x05, 0x01, 0x02 };
    try testing.expectError(TlvError.TruncatedValue, parseTlvStream(testing.allocator, &data));
}

test "tlv: serialize roundtrip" {
    const record = TlvRecord{ .tlv_type = 10, .length = 3, .value = "abc" };
    const bytes = try serializeTlvRecord(testing.allocator, record);
    defer testing.allocator.free(bytes);

    const parsed = try parseTlvStream(testing.allocator, bytes);
    defer testing.allocator.free(parsed);

    try testing.expectEqual(@as(usize, 1), parsed.len);
    try testing.expectEqual(@as(u64, 10), parsed[0].tlv_type);
    try testing.expectEqualStrings("abc", parsed[0].value);
}
