/// BOLT12 bech32 encoding/decoding.
///
/// BOLT12 uses bech32-style encoding WITHOUT a checksum:
///   <hrp> "1" <bech32-data>
///
/// The human-readable prefix (hrp) is one of: lno, lnr, lni, lnp.
/// The data part uses the standard bech32 alphabet to encode 5-bit groups
/// which are then converted to 8-bit bytes.
///
/// BOLT12 also supports "+" continuation: a "+" followed by optional
/// whitespace can join multiple lines.

const std = @import("std");

const BECH32_ALPHABET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

/// Reverse lookup: ASCII byte -> 5-bit value (255 = invalid).
const ALPHABET_MAP: [128]u8 = blk: {
    var map: [128]u8 = [_]u8{0xff} ** 128;
    for (BECH32_ALPHABET, 0..) |c, i| {
        map[c] = @intCast(i);
    }
    break :blk map;
};

pub const Hrp = enum {
    lno,
    lnr,
    lni,
    lnp,

    pub fn toSlice(self: Hrp) []const u8 {
        return switch (self) {
            .lno => "lno",
            .lnr => "lnr",
            .lni => "lni",
            .lnp => "lnp",
        };
    }
};

pub const DecodeError = error{
    InvalidInput,
    InvalidContinuation,
    MixedCase,
    NotLightning,
    NoSeparator,
    UnknownPrefix,
    EmptyData,
    InvalidCharacter,
    ExcessPadding,
    NonZeroPadding,
    OutOfMemory,
};

pub const Decoded = struct {
    hrp: Hrp,
    data: []const u8,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *const Decoded) void {
        self.allocator.free(self.data);
    }
};

/// Convert between bit groups (e.g., 5-bit to 8-bit).
fn convertBits(
    allocator: std.mem.Allocator,
    data: []const u8,
    from_bits: u4,
    to_bits: u4,
    strict: bool,
) DecodeError![]u8 {
    var value: u32 = 0;
    var bits: u5 = 0;
    const max_v: u32 = (@as(u32, 1) << to_bits) - 1;

    var result: std.ArrayList(u8) = .{};
    errdefer result.deinit(allocator);

    for (data) |d| {
        value = (value << from_bits) | d;
        bits += from_bits;

        while (bits >= to_bits) {
            bits -= to_bits;
            result.append(allocator, @intCast((value >> bits) & max_v)) catch return DecodeError.OutOfMemory;
        }
    }

    if (strict) {
        if (bits > 0) {
            const pad: u32 = (value << (@as(u5, to_bits) - bits)) & max_v;
            if (bits >= from_bits) {
                return DecodeError.ExcessPadding;
            }
            if (pad != 0) {
                return DecodeError.NonZeroPadding;
            }
        }
    } else {
        if (bits > 0) {
            result.append(allocator, @intCast((value << (@as(u5, to_bits) - bits)) & max_v)) catch return DecodeError.OutOfMemory;
        }
    }

    return result.toOwnedSlice(allocator) catch return DecodeError.OutOfMemory;
}

/// Decode a BOLT12 string into its hrp and raw TLV bytes.
pub fn decode(allocator: std.mem.Allocator, input: []const u8) DecodeError!Decoded {
    // Handle "+" continuation and strip whitespace
    var clean: std.ArrayList(u8) = .{};
    defer clean.deinit(allocator);

    var i: usize = 0;
    while (i < input.len) {
        if (input[i] == '+') {
            if (clean.items.len == 0) {
                return DecodeError.InvalidContinuation;
            }
            // Previous char must be valid bech32
            const prev = std.ascii.toLower(clean.items[clean.items.len - 1]);
            if (prev >= 128 or ALPHABET_MAP[prev] == 0xff) {
                return DecodeError.InvalidContinuation;
            }
            i += 1;
            // Skip optional whitespace
            while (i < input.len and (input[i] == ' ' or input[i] == '\n' or input[i] == '\r')) {
                i += 1;
            }
            if (i >= input.len) {
                return DecodeError.InvalidContinuation;
            }
            const next = std.ascii.toLower(input[i]);
            if (next >= 128 or ALPHABET_MAP[next] == 0xff) {
                return DecodeError.InvalidContinuation;
            }
            continue;
        }
        if (input[i] == '\n' or input[i] == '\r') {
            i += 1;
            continue;
        }
        clean.append(allocator, input[i]) catch return DecodeError.OutOfMemory;
        i += 1;
    }

    const str = clean.items;

    // Check no embedded spaces
    for (str) |c| {
        if (c == ' ') return DecodeError.InvalidInput;
    }

    // Check mixed case
    var has_upper = false;
    var has_lower = false;
    for (str) |c| {
        if (std.ascii.isUpper(c)) has_upper = true;
        if (std.ascii.isLower(c)) has_lower = true;
    }
    if (has_upper and has_lower) return DecodeError.MixedCase;

    // Convert to lowercase for processing
    var lower_buf = allocator.alloc(u8, str.len) catch return DecodeError.OutOfMemory;
    defer allocator.free(lower_buf);
    for (str, 0..) |c, idx| {
        lower_buf[idx] = std.ascii.toLower(c);
    }
    const lower = lower_buf;

    // Must start with "ln"
    if (lower.len < 2 or !std.mem.startsWith(u8, lower, "ln")) {
        return DecodeError.NotLightning;
    }

    // Find separator "1" (last occurrence)
    var sep_idx: ?usize = null;
    var j: usize = lower.len;
    while (j > 0) {
        j -= 1;
        if (lower[j] == '1') {
            sep_idx = j;
            break;
        }
    }

    const sep = sep_idx orelse return DecodeError.NoSeparator;
    const hrp_str = lower[0..sep];
    const data_str = lower[sep + 1 ..];

    const hrp: Hrp = if (std.mem.eql(u8, hrp_str, "lno"))
        .lno
    else if (std.mem.eql(u8, hrp_str, "lnr"))
        .lnr
    else if (std.mem.eql(u8, hrp_str, "lni"))
        .lni
    else if (std.mem.eql(u8, hrp_str, "lnp"))
        .lnp
    else
        return DecodeError.UnknownPrefix;

    if (data_str.len == 0) {
        return DecodeError.EmptyData;
    }

    // Decode bech32 characters to 5-bit values
    var words = allocator.alloc(u8, data_str.len) catch return DecodeError.OutOfMemory;
    defer allocator.free(words);

    for (data_str, 0..) |c, idx| {
        if (c >= 128 or ALPHABET_MAP[c] == 0xff) {
            return DecodeError.InvalidCharacter;
        }
        words[idx] = ALPHABET_MAP[c];
    }

    // Convert 5-bit to 8-bit
    const bytes = try convertBits(allocator, words, 5, 8, true);

    return Decoded{
        .hrp = hrp,
        .data = bytes,
        .allocator = allocator,
    };
}

/// Encode raw TLV bytes into a BOLT12 bech32 string.
pub fn encode(allocator: std.mem.Allocator, hrp: Hrp, data: []const u8) DecodeError![]u8 {
    // Convert data to 5-bit words (8->5, non-strict for padding)
    var input_5bit = allocator.alloc(u8, data.len) catch return DecodeError.OutOfMemory;
    defer allocator.free(input_5bit);
    for (data, 0..) |b, idx| {
        input_5bit[idx] = b;
    }
    const words = try convertBits(allocator, input_5bit, 8, 5, false);
    defer allocator.free(words);

    const hrp_str = hrp.toSlice();
    // result = hrp + "1" + bech32 chars
    var result: std.ArrayList(u8) = .{};
    errdefer result.deinit(allocator);

    result.appendSlice(allocator, hrp_str) catch return DecodeError.OutOfMemory;
    result.append(allocator, '1') catch return DecodeError.OutOfMemory;
    for (words) |w| {
        result.append(allocator, BECH32_ALPHABET[w]) catch return DecodeError.OutOfMemory;
    }

    return result.toOwnedSlice(allocator) catch return DecodeError.OutOfMemory;
}

// ---- Tests ----

const testing = std.testing;

test "bech32: decode minimal offer" {
    const bolt12_str = "lno1zcss9mk8y3wkklfvevcrszlmu23kfrxh49px20665dqwmn4p72pksese";
    const result = try decode(testing.allocator, bolt12_str);
    defer result.deinit();

    try testing.expectEqual(Hrp.lno, result.hrp);
    try testing.expect(result.data.len > 0);
}

test "bech32: decode with description" {
    const bolt12_str = "lno1pgx9getnwss8vetrw3hhyuckyypwa3eyt44h6txtxquqh7lz5djge4afgfjn7k4rgrkuag0jsd5xvxg";
    const result = try decode(testing.allocator, bolt12_str);
    defer result.deinit();

    try testing.expectEqual(Hrp.lno, result.hrp);
    try testing.expect(result.data.len > 0);
}

test "bech32: roundtrip encode/decode" {
    const original = "lno1zcss9mk8y3wkklfvevcrszlmu23kfrxh49px20665dqwmn4p72pksese";
    const decoded = try decode(testing.allocator, original);
    defer decoded.deinit();

    const encoded = try encode(testing.allocator, decoded.hrp, decoded.data);
    defer testing.allocator.free(encoded);

    try testing.expectEqualStrings(original, encoded);
}

test "bech32: reject mixed case" {
    try testing.expectError(DecodeError.MixedCase, decode(testing.allocator, "LNO1zcss9mk8y3wkklfvevcrszlmu23kfrxh49px20665dqwmn4p72pksese"));
}

test "bech32: reject unknown prefix" {
    try testing.expectError(DecodeError.UnknownPrefix, decode(testing.allocator, "lnx1zcss9mk8y3wkklfvevcrszlmu23kfrxh49px20665dqwmn4p72pksese"));
}

test "bech32: handle continuation" {
    // A bech32 string split with + continuation
    const part1 = "lno1zcss9mk8y3wkklfvevcrszlmu23kfrxh49px20665dqwmn4p72pksese";
    const split_pos = part1.len / 2;
    var buf: [256]u8 = undefined;
    const with_cont = std.fmt.bufPrint(&buf, "{s}+\n{s}", .{ part1[0..split_pos], part1[split_pos..] }) catch unreachable;
    const result = try decode(testing.allocator, with_cont);
    defer result.deinit();
    try testing.expectEqual(Hrp.lno, result.hrp);
}
