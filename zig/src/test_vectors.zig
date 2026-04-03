/// Integration test: validates the Zig implementation against the BOLT12 test vectors
/// from test-vectors/offers-bolt-test.json.
///
/// This uses a hardcoded subset of test vectors to avoid needing JSON parsing.
/// The vectors are taken directly from the offers-bolt-test.json file.

const std = @import("std");
const testing = std.testing;

const bolt12 = @import("bolt12.zig");
const bech32 = @import("bech32.zig");
const tlv_mod = @import("tlv.zig");
const offer_mod = @import("offer.zig");

const TestField = struct {
    tlv_type: u64,
    length: u64,
    hex: []const u8,
};

const TestVector = struct {
    description: []const u8,
    valid: bool,
    bolt12_str: []const u8,
    expected_fields: ?[]const TestField = null,
};

fn hexToBytes(allocator: std.mem.Allocator, hex: []const u8) ![]u8 {
    return bolt12.fromHex(allocator, hex);
}

fn bytesToHex(allocator: std.mem.Allocator, data: []const u8) ![]u8 {
    return bolt12.toHex(allocator, data);
}

// Test vectors from test-vectors/offers-bolt-test.json
const test_vectors = [_]TestVector{
    // #1: Minimal bolt12 offer
    .{
        .description = "Minimal bolt12 offer",
        .valid = true,
        .bolt12_str = "lno1zcss9mk8y3wkklfvevcrszlmu23kfrxh49px20665dqwmn4p72pksese",
        .expected_fields = &[_]TestField{
            .{
                .tlv_type = 22,
                .length = 33,
                .hex = "02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619",
            },
        },
    },
    // #2: with description (but no amount)
    .{
        .description = "with description (but no amount)",
        .valid = true,
        .bolt12_str = "lno1pgx9getnwss8vetrw3hhyuckyypwa3eyt44h6txtxquqh7lz5djge4afgfjn7k4rgrkuag0jsd5xvxg",
        .expected_fields = &[_]TestField{
            .{
                .tlv_type = 10,
                .length = 12,
                .hex = "5465737420766563746f7273",
            },
            .{
                .tlv_type = 22,
                .length = 33,
                .hex = "02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619",
            },
        },
    },
    // #3: for testnet
    .{
        .description = "for testnet",
        .valid = true,
        .bolt12_str = "lno1qgsyxjtl6luzd9t3pr62xr7eemp6awnejusgf6gw45q75vcfqqqqqqq2p32x2um5ypmx2cm5dae8x93pqthvwfzadd7jejes8q9lhc4rvjxd022zv5l44g6qah82ru5rdpnpj",
        .expected_fields = &[_]TestField{
            .{
                .tlv_type = 2,
                .length = 32,
                .hex = "43497fd7f826957108f4a30fd9cec3aeba79972084e90ead01ea330900000000",
            },
            .{
                .tlv_type = 10,
                .length = 12,
                .hex = "5465737420766563746f7273",
            },
            .{
                .tlv_type = 22,
                .length = 33,
                .hex = "02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619",
            },
        },
    },
    // #4: for bitcoin (redundant)
    .{
        .description = "for bitcoin (redundant)",
        .valid = true,
        .bolt12_str = "lno1qgsxlc5vp2m0rvmjcxn2y34wv0m5lyc7sdj7zksgn35dvxgqqqqqqqq2p32x2um5ypmx2cm5dae8x93pqthvwfzadd7jejes8q9lhc4rvjxd022zv5l44g6qah82ru5rdpnpj",
        .expected_fields = &[_]TestField{
            .{
                .tlv_type = 2,
                .length = 32,
                .hex = "6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000",
            },
            .{
                .tlv_type = 10,
                .length = 12,
                .hex = "5465737420766563746f7273",
            },
            .{
                .tlv_type = 22,
                .length = 33,
                .hex = "02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619",
            },
        },
    },
    // #5: for bitcoin or liquidv1
    .{
        .description = "for bitcoin or liquidv1",
        .valid = true,
        .bolt12_str = "lno1qfqpge38tqmzyrdjj3x2qkdr5y80dlfw56ztq6yd9sme995g3gsxqqm0u2xq4dh3kdevrf4zg6hx8a60jv0gxe0ptgyfc6xkryqqqqqqqq9qc4r9wd6zqan9vd6x7unnzcss9mk8y3wkklfvevcrszlmu23kfrxh49px20665dqwmn4p72pksese",
        .expected_fields = &[_]TestField{
            .{
                .tlv_type = 2,
                .length = 64,
                .hex = "1466275836220db2944ca059a3a10ef6fd2ea684b0688d2c379296888a2060036fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000",
            },
            .{
                .tlv_type = 10,
                .length = 12,
                .hex = "5465737420766563746f7273",
            },
            .{
                .tlv_type = 22,
                .length = 33,
                .hex = "02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619",
            },
        },
    },
    // Invalid: missing issuer_id and paths
    .{
        .description = "missing issuer_id and paths",
        .valid = false,
        .bolt12_str = "lno1pgx9getnwss8vetrw3hhyucs5ypjgef743p",
    },
};

test "test vectors: valid offers decode and match fields" {
    for (test_vectors) |vec| {
        if (!vec.valid) continue;

        // Decode bech32
        const decoded = bech32.decode(testing.allocator, vec.bolt12_str) catch |e| {
            std.debug.print("FAIL [{s}]: bech32 decode error: {}\n", .{ vec.description, e });
            return e;
        };
        defer decoded.deinit();

        try testing.expectEqual(bech32.Hrp.lno, decoded.hrp);

        // Parse TLV stream
        const records = tlv_mod.parseTlvStream(testing.allocator, decoded.data) catch |e| {
            std.debug.print("FAIL [{s}]: TLV parse error: {}\n", .{ vec.description, e });
            return e;
        };
        defer testing.allocator.free(records);

        // Validate offer semantics
        _ = offer_mod.validateOffer(records) catch |e| {
            std.debug.print("FAIL [{s}]: offer validation error: {}\n", .{ vec.description, e });
            return e;
        };

        // Compare fields if provided
        if (vec.expected_fields) |expected_fields| {
            try testing.expectEqual(expected_fields.len, records.len);

            for (expected_fields, records) |expected, actual| {
                try testing.expectEqual(expected.tlv_type, actual.tlv_type);
                try testing.expectEqual(expected.length, actual.length);

                const actual_hex = try bytesToHex(testing.allocator, actual.value);
                defer testing.allocator.free(actual_hex);
                try testing.expectEqualStrings(expected.hex, actual_hex);
            }
        }
    }
}

test "test vectors: invalid offers are rejected" {
    for (test_vectors) |vec| {
        if (vec.valid) continue;

        // Should fail at decode, TLV parse, or validation stage
        const decoded = bech32.decode(testing.allocator, vec.bolt12_str) catch {
            continue; // Expected failure
        };
        defer decoded.deinit();

        const records = tlv_mod.parseTlvStream(testing.allocator, decoded.data) catch {
            continue; // Expected failure
        };
        defer testing.allocator.free(records);

        _ = offer_mod.validateOffer(records) catch {
            continue; // Expected failure
        };

        // If we get here, the invalid vector was accepted - that's a bug
        std.debug.print("FAIL [{s}]: expected rejection but offer was accepted\n", .{vec.description});
        return error.TestUnexpectedResult;
    }
}

test "test vectors: full pipeline decodeOffer" {
    for (test_vectors) |vec| {
        if (!vec.valid) continue;

        const result = bolt12.decodeOffer(testing.allocator, vec.bolt12_str) catch |e| {
            std.debug.print("FAIL [{s}]: decodeOffer error: {}\n", .{ vec.description, e });
            return e;
        };
        defer result.deinit();

        // Verify offer_id is 32 bytes (always true by type, but sanity check)
        try testing.expectEqual(@as(usize, 32), result.offer_id.len);
    }
}
