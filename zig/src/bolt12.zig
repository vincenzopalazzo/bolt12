/// bolt12-zig: Pure Zig BOLT12 implementation.
///
/// Supports decoding and validating BOLT12 offers, invoice requests,
/// and invoices. Zero dependencies beyond the Zig standard library
/// (uses std.crypto.hash.sha2 for SHA256).
///
/// Ported from the TypeScript reference implementation (bolt12-utils).

const std = @import("std");

pub const bigsize = @import("bigsize.zig");
pub const bech32 = @import("bech32.zig");
pub const tlv = @import("tlv.zig");
pub const merkle = @import("merkle.zig");
pub const offer = @import("offer.zig");

pub const Hrp = bech32.Hrp;
pub const TlvRecord = tlv.TlvRecord;
pub const ValidatedOffer = offer.ValidatedOffer;

pub const DecodeError = error{
    ExpectedOffer,
    // Include all downstream errors
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
    NotAscending,
    TruncatedLength,
    TruncatedValue,
    Truncated,
    NonMinimalEncoding,
    InvalidOfferType,
    UnknownEvenType,
    InvalidChains,
    InvalidUtf8,
    ZeroAmount,
    InvalidPoint,
    InvalidBlindedPaths,
    UnknownEvenFeature,
    MissingDescriptionWithAmount,
    MissingAmountWithCurrency,
    MissingIssuerIdAndPaths,
    TruncatedBlindedPath,
    InvalidBlindedPathPrefix,
};

/// A decoded and validated BOLT12 offer.
pub const DecodedOffer = struct {
    hrp: Hrp,
    records: []const TlvRecord,
    offer_id: [32]u8,
    validated: ValidatedOffer,
    /// The raw TLV bytes (for advanced access)
    raw_data: []const u8,

    allocator: std.mem.Allocator,

    pub fn deinit(self: *const DecodedOffer) void {
        self.allocator.free(self.records);
        self.allocator.free(self.raw_data);
    }

    /// Get the offer description, if present.
    pub fn description(self: *const DecodedOffer) ?[]const u8 {
        for (self.records) |r| {
            if (r.tlv_type == offer.OFFER_DESCRIPTION) {
                return r.value;
            }
        }
        return null;
    }

    /// Get the offer amount as a truncated uint, if present.
    pub fn amount(self: *const DecodedOffer) ?u64 {
        for (self.records) |r| {
            if (r.tlv_type == offer.OFFER_AMOUNT) {
                const val = offer.readTruncatedUint(r.value);
                if (val > 0) return val;
            }
        }
        return null;
    }

    /// Get the offer currency string, if present.
    pub fn currency(self: *const DecodedOffer) ?[]const u8 {
        for (self.records) |r| {
            if (r.tlv_type == offer.OFFER_CURRENCY) {
                return r.value;
            }
        }
        return null;
    }

    /// Get the offer issuer string, if present.
    pub fn issuer(self: *const DecodedOffer) ?[]const u8 {
        for (self.records) |r| {
            if (r.tlv_type == offer.OFFER_ISSUER) {
                return r.value;
            }
        }
        return null;
    }

    /// Get the offer issuer_id (33-byte compressed point), if present.
    pub fn issuerId(self: *const DecodedOffer) ?[]const u8 {
        for (self.records) |r| {
            if (r.tlv_type == offer.OFFER_ISSUER_ID) {
                return r.value;
            }
        }
        return null;
    }

    /// Get the offer chains (array of 32-byte hashes), if present.
    pub fn chains(self: *const DecodedOffer) ?[]const u8 {
        for (self.records) |r| {
            if (r.tlv_type == offer.OFFER_CHAINS) {
                return r.value;
            }
        }
        return null;
    }

    /// Convert offer_id to hex string.
    pub fn offerIdHex(self: *const DecodedOffer) [64]u8 {
        return hexEncode(self.offer_id);
    }
};

/// Decode and validate a BOLT12 offer string.
pub fn decodeOffer(allocator: std.mem.Allocator, bolt12_string: []const u8) DecodeError!DecodedOffer {
    const decoded = bech32.decode(allocator, bolt12_string) catch |e| {
        return switch (e) {
            bech32.DecodeError.InvalidInput => DecodeError.InvalidInput,
            bech32.DecodeError.InvalidContinuation => DecodeError.InvalidContinuation,
            bech32.DecodeError.MixedCase => DecodeError.MixedCase,
            bech32.DecodeError.NotLightning => DecodeError.NotLightning,
            bech32.DecodeError.NoSeparator => DecodeError.NoSeparator,
            bech32.DecodeError.UnknownPrefix => DecodeError.UnknownPrefix,
            bech32.DecodeError.EmptyData => DecodeError.EmptyData,
            bech32.DecodeError.InvalidCharacter => DecodeError.InvalidCharacter,
            bech32.DecodeError.ExcessPadding => DecodeError.ExcessPadding,
            bech32.DecodeError.NonZeroPadding => DecodeError.NonZeroPadding,
            bech32.DecodeError.OutOfMemory => DecodeError.OutOfMemory,
        };
    };
    errdefer decoded.deinit();

    if (decoded.hrp != .lno) {
        return DecodeError.ExpectedOffer;
    }

    const records = tlv.parseTlvStream(allocator, decoded.data) catch |e| {
        return switch (e) {
            tlv.TlvError.NotAscending => DecodeError.NotAscending,
            tlv.TlvError.TruncatedLength => DecodeError.TruncatedLength,
            tlv.TlvError.TruncatedValue => DecodeError.TruncatedValue,
            tlv.TlvError.OutOfMemory => DecodeError.OutOfMemory,
            tlv.TlvError.Truncated => DecodeError.Truncated,
            tlv.TlvError.NonMinimalEncoding => DecodeError.NonMinimalEncoding,
        };
    };
    errdefer allocator.free(records);

    const validated = offer.validateOffer(records) catch |e| {
        return switch (e) {
            offer.OfferError.InvalidOfferType => DecodeError.InvalidOfferType,
            offer.OfferError.UnknownEvenType => DecodeError.UnknownEvenType,
            offer.OfferError.InvalidChains => DecodeError.InvalidChains,
            offer.OfferError.InvalidUtf8 => DecodeError.InvalidUtf8,
            offer.OfferError.ZeroAmount => DecodeError.ZeroAmount,
            offer.OfferError.InvalidPoint => DecodeError.InvalidPoint,
            offer.OfferError.InvalidBlindedPaths => DecodeError.InvalidBlindedPaths,
            offer.OfferError.UnknownEvenFeature => DecodeError.UnknownEvenFeature,
            offer.OfferError.MissingDescriptionWithAmount => DecodeError.MissingDescriptionWithAmount,
            offer.OfferError.MissingAmountWithCurrency => DecodeError.MissingAmountWithCurrency,
            offer.OfferError.MissingIssuerIdAndPaths => DecodeError.MissingIssuerIdAndPaths,
            offer.OfferError.TruncatedBlindedPath => DecodeError.TruncatedBlindedPath,
            offer.OfferError.InvalidBlindedPathPrefix => DecodeError.InvalidBlindedPathPrefix,
        };
    };

    const offer_id = merkle.computeMerkleRoot(allocator, records) catch {
        return DecodeError.OutOfMemory;
    } orelse {
        return DecodeError.InvalidInput;
    };

    return DecodedOffer{
        .hrp = decoded.hrp,
        .records = records,
        .offer_id = offer_id,
        .validated = validated,
        .raw_data = decoded.data,
        .allocator = allocator,
    };
}

/// Convert a 32-byte array to a 64-char hex string.
pub fn hexEncode(data: [32]u8) [64]u8 {
    const hex_chars = "0123456789abcdef";
    var result: [64]u8 = undefined;
    for (data, 0..) |b, i| {
        result[i * 2] = hex_chars[b >> 4];
        result[i * 2 + 1] = hex_chars[b & 0x0f];
    }
    return result;
}

/// Convert a byte slice to a hex string (allocates).
pub fn toHex(allocator: std.mem.Allocator, data: []const u8) ![]u8 {
    const hex_chars = "0123456789abcdef";
    const result = try allocator.alloc(u8, data.len * 2);
    for (data, 0..) |b, i| {
        result[i * 2] = hex_chars[b >> 4];
        result[i * 2 + 1] = hex_chars[b & 0x0f];
    }
    return result;
}

/// Parse a hex string into bytes (allocates).
pub fn fromHex(allocator: std.mem.Allocator, hex: []const u8) ![]u8 {
    if (hex.len % 2 != 0) return error.InvalidLength;
    const result = try allocator.alloc(u8, hex.len / 2);
    errdefer allocator.free(result);
    for (0..result.len) |i| {
        result[i] = (try hexDigit(hex[i * 2])) << 4 | try hexDigit(hex[i * 2 + 1]);
    }
    return result;
}

fn hexDigit(c: u8) !u8 {
    if (c >= '0' and c <= '9') return c - '0';
    if (c >= 'a' and c <= 'f') return c - 'a' + 10;
    if (c >= 'A' and c <= 'F') return c - 'A' + 10;
    return error.InvalidCharacter;
}

// ---- Tests ----

const testing = std.testing;

test "bolt12: decode minimal offer" {
    const bolt12_str = "lno1zcss9mk8y3wkklfvevcrszlmu23kfrxh49px20665dqwmn4p72pksese";
    const result = try decodeOffer(testing.allocator, bolt12_str);
    defer result.deinit();

    try testing.expectEqual(Hrp.lno, result.hrp);
    try testing.expect(result.records.len > 0);
    // Should have issuer_id
    try testing.expect(result.issuerId() != null);
    try testing.expect(result.description() == null);
}

test "bolt12: decode offer with description" {
    const bolt12_str = "lno1pgx9getnwss8vetrw3hhyuckyypwa3eyt44h6txtxquqh7lz5djge4afgfjn7k4rgrkuag0jsd5xvxg";
    const result = try decodeOffer(testing.allocator, bolt12_str);
    defer result.deinit();

    try testing.expect(result.description() != null);
    try testing.expectEqualStrings("Test vectors", result.description().?);
    try testing.expect(result.issuerId() != null);
}

test "bolt12: decode testnet offer" {
    const bolt12_str = "lno1qgsyxjtl6luzd9t3pr62xr7eemp6awnejusgf6gw45q75vcfqqqqqqq2p32x2um5ypmx2cm5dae8x93pqthvwfzadd7jejes8q9lhc4rvjxd022zv5l44g6qah82ru5rdpnpj";
    const result = try decodeOffer(testing.allocator, bolt12_str);
    defer result.deinit();

    try testing.expect(result.chains() != null);
    try testing.expectEqual(@as(usize, 32), result.chains().?.len);
}

test "bolt12: reject non-offer prefix" {
    // This would need an lnr-prefixed string, but let's test with a modified one
    try testing.expectError(DecodeError.UnknownPrefix, decodeOffer(testing.allocator, "lnx1zcss9mk8y3wkklfvevcrszlmu23kfrxh49px20665dqwmn4p72pksese"));
}

test "bolt12: hexEncode" {
    var data: [32]u8 = undefined;
    @memset(&data, 0xab);
    const hex = hexEncode(data);
    try testing.expectEqual(@as(usize, 64), hex.len);
    // Compare byte by byte
    for (0..32) |i| {
        try testing.expectEqual(@as(u8, 'a'), hex[i * 2]);
        try testing.expectEqual(@as(u8, 'b'), hex[i * 2 + 1]);
    }
}

test "bolt12: hex roundtrip" {
    const hex_str = "deadbeef01020304";
    const bytes = try fromHex(testing.allocator, hex_str);
    defer testing.allocator.free(bytes);
    const back = try toHex(testing.allocator, bytes);
    defer testing.allocator.free(back);
    try testing.expectEqualStrings(hex_str, back);
}
