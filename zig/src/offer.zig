/// BOLT12 Offer validation.
///
/// An offer is a TLV stream encoded with the "lno" prefix.
/// This module validates the semantic rules for offers as specified
/// in BOLT 12.
///
/// Offer TLV types (from the spec):
///   2  - offer_chains          (array of 32-byte chain_hashes)
///   4  - offer_metadata        (arbitrary bytes)
///   6  - offer_currency        (UTF-8 ISO 4217 code)
///   8  - offer_amount          (tu64 msat or currency units)
///   10 - offer_description     (UTF-8 string)
///   12 - offer_features        (feature bits)
///   14 - offer_absolute_expiry (tu64 seconds since epoch)
///   16 - offer_paths           (blinded_path array)
///   18 - offer_issuer          (UTF-8 string)
///   20 - offer_quantity_max    (tu64)
///   22 - offer_issuer_id       (point, 33 bytes)

const std = @import("std");
const tlv = @import("tlv.zig");

// Offer TLV type constants
pub const OFFER_CHAINS: u64 = 2;
pub const OFFER_METADATA: u64 = 4;
pub const OFFER_CURRENCY: u64 = 6;
pub const OFFER_AMOUNT: u64 = 8;
pub const OFFER_DESCRIPTION: u64 = 10;
pub const OFFER_FEATURES: u64 = 12;
pub const OFFER_ABSOLUTE_EXPIRY: u64 = 14;
pub const OFFER_PATHS: u64 = 16;
pub const OFFER_ISSUER: u64 = 18;
pub const OFFER_QUANTITY_MAX: u64 = 20;
pub const OFFER_ISSUER_ID: u64 = 22;

pub const OfferError = error{
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

pub const ValidatedOffer = struct {
    records: []const tlv.TlvRecord,
    has_description: bool,
    has_amount: bool,
    has_currency: bool,
    has_issuer_id: bool,
    has_paths: bool,
};

fn isKnownOfferType(typ: u64) bool {
    return typ == OFFER_CHAINS or
        typ == OFFER_METADATA or
        typ == OFFER_CURRENCY or
        typ == OFFER_AMOUNT or
        typ == OFFER_DESCRIPTION or
        typ == OFFER_FEATURES or
        typ == OFFER_ABSOLUTE_EXPIRY or
        typ == OFFER_PATHS or
        typ == OFFER_ISSUER or
        typ == OFFER_QUANTITY_MAX or
        typ == OFFER_ISSUER_ID;
}

/// Check if a type is in the valid offer range.
/// Offers may contain types 1-79 and 1000000000-1999999999.
fn isValidOfferType(typ: u64) bool {
    if (typ >= 1 and typ <= 79) return true;
    if (typ >= 1000000000 and typ <= 1999999999) return true;
    return false;
}

/// Read a truncated big-endian unsigned integer from bytes.
pub fn readTruncatedUint(data: []const u8) u64 {
    if (data.len == 0) return 0;
    var val: u64 = 0;
    for (data) |b| {
        val = (val << 8) | b;
    }
    return val;
}

/// Validate UTF-8 encoding of a byte array.
fn validateUtf8(data: []const u8) OfferError!void {
    if (!std.unicode.utf8ValidateSlice(data)) {
        return OfferError.InvalidUtf8;
    }
}

/// Validate a compressed public key (33 bytes, starts with 02 or 03).
fn validatePoint(data: []const u8) OfferError!void {
    if (data.len != 33) {
        return OfferError.InvalidPoint;
    }
    if (data[0] != 0x02 and data[0] != 0x03) {
        return OfferError.InvalidPoint;
    }
    // Note: full secp256k1 point-on-curve validation would require a crypto library.
    // For now, we validate the basic format constraints.
}

/// Validate offer_chains field: must be a multiple of 32 bytes, and non-empty.
fn validateChains(data: []const u8) OfferError!void {
    if (data.len == 0 or data.len % 32 != 0) {
        return OfferError.InvalidChains;
    }
}

/// Validate blinded paths (offer_paths field, type 16).
fn validateBlindedPaths(data: []const u8) OfferError!void {
    var offset: usize = 0;
    var path_count: usize = 0;

    while (offset < data.len) {
        path_count += 1;

        if (offset >= data.len) {
            return OfferError.TruncatedBlindedPath;
        }

        const first_byte = data[offset];
        var first_node_id_len: usize = undefined;
        if (first_byte == 0x00 or first_byte == 0x01) {
            // sciddir: 1 byte direction + 8 byte short_channel_id = 9 bytes
            first_node_id_len = 9;
        } else if (first_byte == 0x02 or first_byte == 0x03) {
            // Regular compressed point: 33 bytes
            first_node_id_len = 33;
        } else {
            return OfferError.InvalidBlindedPathPrefix;
        }

        if (offset + first_node_id_len > data.len) {
            return OfferError.TruncatedBlindedPath;
        }
        offset += first_node_id_len;

        // path_key: 33-byte compressed point
        if (offset + 33 > data.len) {
            return OfferError.TruncatedBlindedPath;
        }
        const path_key_prefix = data[offset];
        if (path_key_prefix != 0x02 and path_key_prefix != 0x03) {
            return OfferError.InvalidBlindedPathPrefix;
        }
        offset += 33;

        // num_hops: u8
        if (offset >= data.len) {
            return OfferError.TruncatedBlindedPath;
        }
        const num_hops = data[offset];
        offset += 1;

        if (num_hops == 0) {
            return OfferError.InvalidBlindedPaths;
        }

        // Parse each hop
        var h: usize = 0;
        while (h < num_hops) : (h += 1) {
            // blinded_node_id: 33-byte point
            if (offset + 33 > data.len) {
                return OfferError.TruncatedBlindedPath;
            }
            const blinded_prefix = data[offset];
            if (blinded_prefix != 0x02 and blinded_prefix != 0x03) {
                return OfferError.InvalidBlindedPathPrefix;
            }
            offset += 33;

            // enclen: u16
            if (offset + 2 > data.len) {
                return OfferError.TruncatedBlindedPath;
            }
            const enclen: usize = (@as(usize, data[offset]) << 8) | data[offset + 1];
            offset += 2;

            // encrypted_recipient_data
            if (offset + enclen > data.len) {
                return OfferError.TruncatedBlindedPath;
            }
            offset += enclen;
        }
    }

    if (path_count == 0) {
        return OfferError.InvalidBlindedPaths;
    }
}

/// Validate feature bits. Unknown even feature bits must cause rejection.
fn validateFeatures(data: []const u8) OfferError!void {
    for (data, 0..) |byte, byte_idx| {
        if (byte == 0) continue;

        const bit_offset = (data.len - 1 - byte_idx) * 8;

        var bit: u3 = 0;
        while (true) {
            if (byte & (@as(u8, 1) << bit) != 0) {
                const feature_bit = bit_offset + bit;
                if (feature_bit % 2 == 0) {
                    return OfferError.UnknownEvenFeature;
                }
            }
            if (bit == 7) break;
            bit += 1;
        }
    }
}

/// Validate an offer's TLV records according to BOLT12 semantic rules.
pub fn validateOffer(records: []const tlv.TlvRecord) OfferError!ValidatedOffer {
    var has_description = false;
    var has_amount = false;
    var has_currency = false;
    var has_issuer_id = false;
    var has_paths = false;

    for (records) |record| {
        const typ = record.tlv_type;

        // Check type is in valid offer range
        if (!isValidOfferType(typ)) {
            return OfferError.InvalidOfferType;
        }

        // Unknown even types must be rejected
        if (!isKnownOfferType(typ) and typ % 2 == 0) {
            return OfferError.UnknownEvenType;
        }

        // Validate specific fields
        if (typ == OFFER_CHAINS) {
            try validateChains(record.value);
        } else if (typ == OFFER_CURRENCY) {
            try validateUtf8(record.value);
            has_currency = true;
        } else if (typ == OFFER_AMOUNT) {
            const amount = readTruncatedUint(record.value);
            if (amount == 0) {
                return OfferError.ZeroAmount;
            }
            has_amount = true;
        } else if (typ == OFFER_DESCRIPTION) {
            try validateUtf8(record.value);
            has_description = true;
        } else if (typ == OFFER_FEATURES) {
            try validateFeatures(record.value);
        } else if (typ == OFFER_PATHS) {
            try validateBlindedPaths(record.value);
            has_paths = true;
        } else if (typ == OFFER_ISSUER) {
            try validateUtf8(record.value);
        } else if (typ == OFFER_ISSUER_ID) {
            try validatePoint(record.value);
            has_issuer_id = true;
        }
    }

    // Semantic validation rules:

    // An offer with amount but no description is invalid
    if (has_amount and !has_description) {
        return OfferError.MissingDescriptionWithAmount;
    }

    // Currency requires amount
    if (has_currency and !has_amount) {
        return OfferError.MissingAmountWithCurrency;
    }

    // Must have either issuer_id or paths (or both)
    if (!has_issuer_id and !has_paths) {
        return OfferError.MissingIssuerIdAndPaths;
    }

    return ValidatedOffer{
        .records = records,
        .has_description = has_description,
        .has_amount = has_amount,
        .has_currency = has_currency,
        .has_issuer_id = has_issuer_id,
        .has_paths = has_paths,
    };
}

// ---- Tests ----

const testing = std.testing;

test "offer: validate minimal offer (issuer_id only)" {
    // type=22, length=33, value=02+32 bytes
    var value: [33]u8 = undefined;
    value[0] = 0x02;
    @memset(value[1..], 0xee);

    const records = [_]tlv.TlvRecord{
        .{ .tlv_type = 22, .length = 33, .value = &value },
    };

    const validated = try validateOffer(&records);
    try testing.expect(!validated.has_description);
    try testing.expect(!validated.has_amount);
    try testing.expect(validated.has_issuer_id);
}

test "offer: validate offer with description" {
    var pubkey: [33]u8 = undefined;
    pubkey[0] = 0x03;
    @memset(pubkey[1..], 0xaa);

    const records = [_]tlv.TlvRecord{
        .{ .tlv_type = 10, .length = 12, .value = "Test vectors" },
        .{ .tlv_type = 22, .length = 33, .value = &pubkey },
    };

    const validated = try validateOffer(&records);
    try testing.expect(validated.has_description);
    try testing.expect(validated.has_issuer_id);
}

test "offer: reject missing issuer_id and paths" {
    const records = [_]tlv.TlvRecord{
        .{ .tlv_type = 10, .length = 12, .value = "Test vectors" },
    };

    try testing.expectError(OfferError.MissingIssuerIdAndPaths, validateOffer(&records));
}

test "offer: reject amount without description" {
    var pubkey: [33]u8 = undefined;
    pubkey[0] = 0x02;
    @memset(pubkey[1..], 0xbb);

    const records = [_]tlv.TlvRecord{
        .{ .tlv_type = 8, .length = 1, .value = &[_]u8{0x64} }, // amount=100
        .{ .tlv_type = 22, .length = 33, .value = &pubkey },
    };

    try testing.expectError(OfferError.MissingDescriptionWithAmount, validateOffer(&records));
}

test "offer: reject currency without amount" {
    var pubkey: [33]u8 = undefined;
    pubkey[0] = 0x02;
    @memset(pubkey[1..], 0xcc);

    const records = [_]tlv.TlvRecord{
        .{ .tlv_type = 6, .length = 3, .value = "USD" },
        .{ .tlv_type = 10, .length = 4, .value = "test" },
        .{ .tlv_type = 22, .length = 33, .value = &pubkey },
    };

    try testing.expectError(OfferError.MissingAmountWithCurrency, validateOffer(&records));
}

test "offer: reject invalid point" {
    const records = [_]tlv.TlvRecord{
        .{ .tlv_type = 22, .length = 10, .value = "0123456789" },
    };

    try testing.expectError(OfferError.InvalidPoint, validateOffer(&records));
}

test "offer: reject type outside offer range" {
    var pubkey: [33]u8 = undefined;
    pubkey[0] = 0x02;
    @memset(pubkey[1..], 0xdd);

    const records = [_]tlv.TlvRecord{
        .{ .tlv_type = 22, .length = 33, .value = &pubkey },
        .{ .tlv_type = 240, .length = 1, .value = &[_]u8{0x00} },
    };

    try testing.expectError(OfferError.InvalidOfferType, validateOffer(&records));
}

test "offer: readTruncatedUint" {
    try testing.expectEqual(@as(u64, 0), readTruncatedUint(&[_]u8{}));
    try testing.expectEqual(@as(u64, 1), readTruncatedUint(&[_]u8{0x01}));
    try testing.expectEqual(@as(u64, 256), readTruncatedUint(&[_]u8{ 0x01, 0x00 }));
    try testing.expectEqual(@as(u64, 0x010203), readTruncatedUint(&[_]u8{ 0x01, 0x02, 0x03 }));
}
