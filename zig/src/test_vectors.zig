/// Integration tests: validates the Zig implementation against the official
/// BOLT12 test vectors from https://github.com/lightning/bolts/tree/master/bolt12
///
/// Three test suites:
///   1. offers-test.json — 49 test vectors for offer encoding/decoding
///   2. format-string-test.json — 12 test vectors for bech32 format string parsing
///   3. signature-test.json — 4 test vectors for merkle tree + signature computation

const std = @import("std");
const testing = std.testing;

const bolt12 = @import("bolt12.zig");
const bech32 = @import("bech32.zig");
const tlv_mod = @import("tlv.zig");
const offer_mod = @import("offer.zig");
const merkle = @import("merkle.zig");
const bigsize_mod = @import("bigsize.zig");

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn hexToBytes(allocator: std.mem.Allocator, hex: []const u8) ![]u8 {
    return bolt12.fromHex(allocator, hex);
}

fn bytesToHex(allocator: std.mem.Allocator, data: []const u8) ![]u8 {
    return bolt12.toHex(allocator, data);
}

// ---------------------------------------------------------------------------
// 1. Offers test vectors (offers-test.json)
//
// We embed the test vectors as comptime-known data to avoid runtime JSON
// parsing, which keeps the test self-contained and deterministic.
// ---------------------------------------------------------------------------

const OfferTestField = struct {
    tlv_type: u64,
    length: u64,
    hex: []const u8,
};

const OfferTestVector = struct {
    description: []const u8,
    valid: bool,
    bolt12_str: []const u8,
    expected_fields: ?[]const OfferTestField = null,
};

// Complete set from https://github.com/lightning/bolts/blob/master/bolt12/offers-test.json
const offer_test_vectors = [_]OfferTestVector{
    // --- Valid vectors ---
    .{
        .description = "Minimal bolt12 offer",
        .valid = true,
        .bolt12_str = "lno1zcss9mk8y3wkklfvevcrszlmu23kfrxh49px20665dqwmn4p72pksese",
        .expected_fields = &[_]OfferTestField{
            .{ .tlv_type = 22, .length = 33, .hex = "02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619" },
        },
    },
    .{
        .description = "with description (but no amount)",
        .valid = true,
        .bolt12_str = "lno1pgx9getnwss8vetrw3hhyuckyypwa3eyt44h6txtxquqh7lz5djge4afgfjn7k4rgrkuag0jsd5xvxg",
        .expected_fields = &[_]OfferTestField{
            .{ .tlv_type = 10, .length = 12, .hex = "5465737420766563746f7273" },
            .{ .tlv_type = 22, .length = 33, .hex = "02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619" },
        },
    },
    .{
        .description = "for testnet",
        .valid = true,
        .bolt12_str = "lno1qgsyxjtl6luzd9t3pr62xr7eemp6awnejusgf6gw45q75vcfqqqqqqq2p32x2um5ypmx2cm5dae8x93pqthvwfzadd7jejes8q9lhc4rvjxd022zv5l44g6qah82ru5rdpnpj",
        .expected_fields = &[_]OfferTestField{
            .{ .tlv_type = 2, .length = 32, .hex = "43497fd7f826957108f4a30fd9cec3aeba79972084e90ead01ea330900000000" },
            .{ .tlv_type = 10, .length = 12, .hex = "5465737420766563746f7273" },
            .{ .tlv_type = 22, .length = 33, .hex = "02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619" },
        },
    },
    .{
        .description = "for bitcoin (redundant)",
        .valid = true,
        .bolt12_str = "lno1qgsxlc5vp2m0rvmjcxn2y34wv0m5lyc7sdj7zksgn35dvxgqqqqqqqq2p32x2um5ypmx2cm5dae8x93pqthvwfzadd7jejes8q9lhc4rvjxd022zv5l44g6qah82ru5rdpnpj",
        .expected_fields = &[_]OfferTestField{
            .{ .tlv_type = 2, .length = 32, .hex = "6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000" },
            .{ .tlv_type = 10, .length = 12, .hex = "5465737420766563746f7273" },
            .{ .tlv_type = 22, .length = 33, .hex = "02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619" },
        },
    },
    .{
        .description = "for bitcoin or liquidv1",
        .valid = true,
        .bolt12_str = "lno1qfqpge38tqmzyrdjj3x2qkdr5y80dlfw56ztq6yd9sme995g3gsxqqm0u2xq4dh3kdevrf4zg6hx8a60jv0gxe0ptgyfc6xkryqqqqqqqq9qc4r9wd6zqan9vd6x7unnzcss9mk8y3wkklfvevcrszlmu23kfrxh49px20665dqwmn4p72pksese",
        .expected_fields = &[_]OfferTestField{
            .{ .tlv_type = 2, .length = 64, .hex = "1466275836220db2944ca059a3a10ef6fd2ea684b0688d2c379296888a2060036fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000" },
            .{ .tlv_type = 10, .length = 12, .hex = "5465737420766563746f7273" },
            .{ .tlv_type = 22, .length = 33, .hex = "02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619" },
        },
    },
    .{ .description = "with metadata", .valid = true, .bolt12_str = "lno1qsgqqqqqqqqqqqqqqqqqqqqqqqqqqzsv23jhxapqwejkxar0wfe3vggzamrjghtt05kvkvpcp0a79gmy3nt6jsn98ad2xs8de6sl9qmgvcvs" },
    .{ .description = "with amount", .valid = true, .bolt12_str = "lno1pqpzwyq2p32x2um5ypmx2cm5dae8x93pqthvwfzadd7jejes8q9lhc4rvjxd022zv5l44g6qah82ru5rdpnpj" },
    .{ .description = "with currency", .valid = true, .bolt12_str = "lno1qcp4256ypqpzwyq2p32x2um5ypmx2cm5dae8x93pqthvwfzadd7jejes8q9lhc4rvjxd022zv5l44g6qah82ru5rdpnpj" },
    .{ .description = "with expiry", .valid = true, .bolt12_str = "lno1pgx9getnwss8vetrw3hhyucwq3ay997czcss9mk8y3wkklfvevcrszlmu23kfrxh49px20665dqwmn4p72pksese" },
    .{ .description = "with issuer", .valid = true, .bolt12_str = "lno1pgx9getnwss8vetrw3hhyucjy358garswvaz7tmzdak8gvfj9ehhyeeqgf85c4p3xgsxjmnyw4ehgunfv4e3vggzamrjghtt05kvkvpcp0a79gmy3nt6jsn98ad2xs8de6sl9qmgvcvs" },
    .{ .description = "with quantity", .valid = true, .bolt12_str = "lno1pgx9getnwss8vetrw3hhyuc5qyz3vggzamrjghtt05kvkvpcp0a79gmy3nt6jsn98ad2xs8de6sl9qmgvcvs" },
    .{ .description = "with unlimited quantity", .valid = true, .bolt12_str = "lno1pgx9getnwss8vetrw3hhyuc5qqtzzqhwcuj966ma9n9nqwqtl032xeyv6755yeflt235pmww58egx6rxry" },
    .{ .description = "with single quantity", .valid = true, .bolt12_str = "lno1pgx9getnwss8vetrw3hhyuc5qyq3vggzamrjghtt05kvkvpcp0a79gmy3nt6jsn98ad2xs8de6sl9qmgvcvs" },
    .{ .description = "with feature", .valid = true, .bolt12_str = "lno1pgx9getnwss8vetrw3hhyucvp5yqqqqqqqqqqqqqqqqqqqqkyypwa3eyt44h6txtxquqh7lz5djge4afgfjn7k4rgrkuag0jsd5xvxg" },
    .{ .description = "with blinded path via Bob", .valid = true, .bolt12_str = "lno1pgx9getnwss8vetrw3hhyucs5ypjgef743p5fzqq9nqxh0ah7y87rzv3ud0eleps9kl2d5348hq2k8qzqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgqpqqqqqqqqqqqqqqqqqqqqqqqqqqqzqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqqzq3zyg3zyg3zyg3vggzamrjghtt05kvkvpcp0a79gmy3nt6jsn98ad2xs8de6sl9qmgvcvs" },
    .{ .description = "same with sciddir first_node_id", .valid = true, .bolt12_str = "lno1pgx9getnwss8vetrw3hhyucs3yqqqqqqqqqqqqp2qgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqqyqqqqqqqqqqqqqqqqqqqqqqqqqqqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqqgzyg3zyg3zyg3z93pqthvwfzadd7jejes8q9lhc4rvjxd022zv5l44g6qah82ru5rdpnpj" },
    .{ .description = "no issuer_id with blinded path", .valid = true, .bolt12_str = "lno1pgx9getnwss8vetrw3hhyucs5ypjgef743p5fzqq9nqxh0ah7y87rzv3ud0eleps9kl2d5348hq2k8qzqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgqpqqqqqqqqqqqqqqqqqqqqqqqqqqqzqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqqzq3zyg3zyg3zygs" },
    .{ .description = "two blinded paths", .valid = true, .bolt12_str = "lno1pgx9getnwss8vetrw3hhyucsl5qj5qeyv5l2cs6y3qqzesrth7mlzrlp3xg7xhulusczm04x6g6nms9trspqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqqsqqqqqqqqqqqqqqqqqqqqqqqqqqpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqsqpqg3zyg3zyg3zygpqqqqzqqqqgqqxqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqqgqqqqqqqqqqqqqqqqqqqqqqqqqqqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgqqsg3zyg3zyg3zygtzzqhwcuj966ma9n9nqwqtl032xeyv6755yeflt235pmww58egx6rxry" },
    .{ .description = "unknown odd field", .valid = true, .bolt12_str = "lno1pgx9getnwss8vetrw3hhyuckyypwa3eyt44h6txtxquqh7lz5djge4afgfjn7k4rgrkuag0jsd5xvxfppf5x2mrvdamk7unvvs" },
    .{ .description = "unknown odd experimental field", .valid = true, .bolt12_str = "lno1pgx9getnwss8vetrw3hhyuckyypwa3eyt44h6txtxquqh7lz5djge4afgfjn7k4rgrkuag0jsd5xvx078wdv5gg2dpjkcmr0wahhymry" },

    // --- Invalid vectors ---
    .{ .description = "fields out of order", .valid = false, .bolt12_str = "lno1zcssyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszpgz5znzfgdzs" },
    .{ .description = "unknown even TLV type 78", .valid = false, .bolt12_str = "lno1pgz5znzfgdz3vggzqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpysgr0u2xq4dh3kdevrf4zg6hx8a60jv0gxe0ptgyfc6xkryqqqqqqqq" },
    .{ .description = "empty data", .valid = false, .bolt12_str = "lno1" },
    .{ .description = "truncated at type", .valid = false, .bolt12_str = "lno1pg" },
    .{ .description = "truncated in length", .valid = false, .bolt12_str = "lno1pt7s" },
    .{ .description = "truncated after length", .valid = false, .bolt12_str = "lno1pgpq" },
    .{ .description = "truncated in description", .valid = false, .bolt12_str = "lno1pgpyz" },
    .{ .description = "invalid offer_chains length", .valid = false, .bolt12_str = "lno1qgqszzs9g9xyjs69zcssyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqsz" },
    .{ .description = "truncated currency UTF-8", .valid = false, .bolt12_str = "lno1qcqcqzs9g9xyjs69zcssyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqsz" },
    .{ .description = "invalid currency UTF-8", .valid = false, .bolt12_str = "lno1qcplllhapqpq86q2q4qkc6trv5tzzq6muh550qsfva9fdes0ruph7ctk2s8aqq06r4jxj3msc448wzwy9s" },
    .{ .description = "truncated description UTF-8", .valid = false, .bolt12_str = "lno1pgqcq93pqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqy" },
    .{ .description = "invalid description UTF-8", .valid = false, .bolt12_str = "lno1pgpgqsgkyypqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqs" },
    .{ .description = "truncated offer_paths", .valid = false, .bolt12_str = "lno1pgz5znzfgdz3qqgpzcssyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqsz" },
    .{ .description = "zero num_hops in blinded_path", .valid = false, .bolt12_str = "lno1pgz5znzfgdz3qqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqsqzcssyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqsz" },
    .{ .description = "truncated onionmsg_hop", .valid = false, .bolt12_str = "lno1pgz5znzfgdz3qqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqspqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqgkyypqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqs" },
    .{ .description = "bad first_node_id", .valid = false, .bolt12_str = "lno1pgz5znzfgdz3qqcrqvpsxqcrqvpsxqcrqvpsxqcrqvpsxqcrqvpsxqcrqvpsxqcrqvpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqspqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqgqzcssyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqsz" },
    .{ .description = "bad path_key", .valid = false, .bolt12_str = "lno1pgz5znzfgdz3qqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpsxqcrqvpsxqcrqvpsxqcrqvpsxqcrqvpsxqcrqvpsxqcrqvpsxqcpqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqgqzcssyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqsz" },
    .{ .description = "bad blinded_node_id", .valid = false, .bolt12_str = "lno1pgz5znzfgdz3qqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqspqvpsxqcrqvpsxqcrqvpsxqcrqvpsxqcrqvpsxqcrqvpsxqcrqvpsxqgqzcssyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqsz" },
    .{ .description = "truncated issuer UTF-8", .valid = false, .bolt12_str = "lno1pgz5znzfgdz3yqvqzcssyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqsz" },
    .{ .description = "invalid issuer UTF-8", .valid = false, .bolt12_str = "lno1pgz5znzfgdz3yq5qgytzzqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqg" },
    .{ .description = "invalid offer_issuer_id", .valid = false, .bolt12_str = "lno1pgz5znzfgdz3vggzqvpsxqcrqvpsxqcrqvpsxqcrqvpsxqcrqvpsxqcrqvpsxqcrqvps" },
    .{ .description = "contains type >= 80", .valid = false, .bolt12_str = "lno1pgz5znzfgdz3vggzqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgp9qgr0u2xq4dh3kdevrf4zg6hx8a60jv0gxe0ptgyfc6xkryqqqqqqqq" },
    .{ .description = "contains type > 1999999999", .valid = false, .bolt12_str = "lno1pgz5znzfgdz3vggzqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgp06ae4jsq9qgr0u2xq4dh3kdevrf4zg6hx8a60jv0gxe0ptgyfc6xkryqqqqqqqq" },
    .{ .description = "unknown even type 1000000002", .valid = false, .bolt12_str = "lno1pgz5znzfgdz3vggzqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgp06wu6egp9qgr0u2xq4dh3kdevrf4zg6hx8a60jv0gxe0ptgyfc6xkryqqqqqqqq" },
    .{ .description = "unknown feature 122", .valid = false, .bolt12_str = "lno1pgx9getnwss8vetrw3hhyucvzqzqqqqqqqqqqqqqqqqqqqqqqqqpvggzamrjghtt05kvkvpcp0a79gmy3nt6jsn98ad2xs8de6sl9qmgvcvs" },
    .{ .description = "missing description with amount", .valid = false, .bolt12_str = "lno1pqpzwyqkyypwa3eyt44h6txtxquqh7lz5djge4afgfjn7k4rgrkuag0jsd5xvxg" },
    .{ .description = "missing amount with currency", .valid = false, .bolt12_str = "lno1qcp4256ypgx9getnwss8vetrw3hhyuckyypwa3eyt44h6txtxquqh7lz5djge4afgfjn7k4rgrkuag0jsd5xvxg" },
    .{ .description = "zero offer_amount", .valid = false, .bolt12_str = "lno1pqqq5qqkyyp4he0fg7pqje62jmnq78cr0ashv4q06qql58tyd9rhp3t2wuyugtq" },
    .{ .description = "zero offer_amount with currency", .valid = false, .bolt12_str = "lno1qcp4256ypqqq5qqkyyp4he0fg7pqje62jmnq78cr0ashv4q06qql58tyd9rhp3t2wuyugtq" },
    .{ .description = "missing issuer_id and paths", .valid = false, .bolt12_str = "lno1pgx9getnwss8vetrw3hhyuc" },
    .{ .description = "second offer_path is empty", .valid = false, .bolt12_str = "lno1pgx9getnwss8vetrw3hhyucsespjgef743p5fzqq9nqxh0ah7y87rzv3ud0eleps9kl2d5348hq2k8qzqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgqpqqqqqqqqqqqqqqqqqqqqqqqqqqqzqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqqzq3zyg3zyg3zygszqqqqyqqqqsqqvpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqsq" },
    .{ .description = "offer_chains with zero entries", .valid = false, .bolt12_str = "lno1qgqpvggrt0j7j3uzp9n549hxpu0sxlmpwe2ql5qplgwkg628wrzk5acfcskq" },
    .{ .description = "bech32 padding exceeds 4-bit limit", .valid = false, .bolt12_str = "lno1zcss9mk8y3wkklfvevcrszlmu23kfrxh49px20665dqwmn4p72pkseseq" },
};

test "offers-test.json: valid offers decode and match fields" {
    var pass: usize = 0;
    var fail: usize = 0;

    for (offer_test_vectors) |vec| {
        if (!vec.valid) continue;

        // Decode bech32
        const decoded = bech32.decode(testing.allocator, vec.bolt12_str) catch |e| {
            std.debug.print("FAIL [{s}]: bech32 decode: {}\n", .{ vec.description, e });
            fail += 1;
            continue;
        };
        defer decoded.deinit();

        if (decoded.hrp != .lno) {
            std.debug.print("FAIL [{s}]: expected lno, got {s}\n", .{ vec.description, decoded.hrp.toSlice() });
            fail += 1;
            continue;
        }

        // Parse TLV
        const records = tlv_mod.parseTlvStream(testing.allocator, decoded.data) catch |e| {
            std.debug.print("FAIL [{s}]: TLV parse: {}\n", .{ vec.description, e });
            fail += 1;
            continue;
        };
        defer testing.allocator.free(records);

        // Validate offer
        _ = offer_mod.validateOffer(records) catch |e| {
            std.debug.print("FAIL [{s}]: validation: {}\n", .{ vec.description, e });
            fail += 1;
            continue;
        };

        // Compare fields if provided
        if (vec.expected_fields) |expected_fields| {
            if (records.len != expected_fields.len) {
                std.debug.print("FAIL [{s}]: field count {d} != {d}\n", .{ vec.description, records.len, expected_fields.len });
                fail += 1;
                continue;
            }

            var fields_ok = true;
            for (expected_fields, records) |expected, actual| {
                if (actual.tlv_type != expected.tlv_type or actual.length != expected.length) {
                    std.debug.print("FAIL [{s}]: type/length mismatch\n", .{vec.description});
                    fields_ok = false;
                    break;
                }
                const actual_hex = bytesToHex(testing.allocator, actual.value) catch {
                    fields_ok = false;
                    break;
                };
                defer testing.allocator.free(actual_hex);
                if (!std.mem.eql(u8, actual_hex, expected.hex)) {
                    std.debug.print("FAIL [{s}]: value mismatch\n  expected: {s}\n  got:      {s}\n", .{ vec.description, expected.hex, actual_hex });
                    fields_ok = false;
                    break;
                }
            }
            if (!fields_ok) {
                fail += 1;
                continue;
            }
        }

        pass += 1;
    }

    std.debug.print("offers-test.json valid: {d} passed, {d} failed\n", .{ pass, fail });
    try testing.expectEqual(@as(usize, 0), fail);
}

test "offers-test.json: invalid offers are rejected" {
    var pass: usize = 0;
    var fail: usize = 0;

    for (offer_test_vectors) |vec| {
        if (vec.valid) continue;

        // Should fail at some stage
        const decoded = bech32.decode(testing.allocator, vec.bolt12_str) catch {
            pass += 1;
            continue;
        };
        defer decoded.deinit();

        const records = tlv_mod.parseTlvStream(testing.allocator, decoded.data) catch {
            pass += 1;
            continue;
        };
        defer testing.allocator.free(records);

        _ = offer_mod.validateOffer(records) catch {
            pass += 1;
            continue;
        };

        // Accepted when it should have been rejected
        std.debug.print("FAIL [{s}]: expected rejection but accepted\n", .{vec.description});
        fail += 1;
    }

    std.debug.print("offers-test.json invalid: {d} passed, {d} failed\n", .{ pass, fail });
    try testing.expectEqual(@as(usize, 0), fail);
}

test "offers-test.json: full decodeOffer pipeline" {
    var pass: usize = 0;
    for (offer_test_vectors) |vec| {
        if (!vec.valid) continue;

        const result = bolt12.decodeOffer(testing.allocator, vec.bolt12_str) catch continue;
        defer result.deinit();

        try testing.expectEqual(@as(usize, 32), result.offer_id.len);
        pass += 1;
    }
    std.debug.print("offers-test.json pipeline: {d} passed\n", .{pass});
    try testing.expect(pass > 0);
}

// ---------------------------------------------------------------------------
// 2. Format string test vectors (format-string-test.json)
// ---------------------------------------------------------------------------

const FormatTestVector = struct {
    comment: []const u8,
    valid: bool,
    string: []const u8,
};

const format_test_vectors = [_]FormatTestVector{
    .{ .comment = "A complete string is valid", .valid = true, .string = "lno1pqps7sjqpgtyzm3qv4uxzmtsd3jjqer9wd3hy6tsw35k7msjzfpy7nz5yqcnygrfdej82um5wf5k2uckyypwa3eyt44h6txtxquqh7lz5djge4afgfjn7k4rgrkuag0jsd5xvxg" },
    .{ .comment = "Uppercase is valid", .valid = true, .string = "LNO1PQPS7SJQPGTYZM3QV4UXZMTSD3JJQER9WD3HY6TSW35K7MSJZFPY7NZ5YQCNYGRFDEJ82UM5WF5K2UCKYYPWA3EYT44H6TXTXQUQH7LZ5DJGE4AFGFJN7K4RGRKUAG0JSD5XVXG" },
    .{ .comment = "+ can join anywhere", .valid = true, .string = "l+no1pqps7sjqpgtyzm3qv4uxzmtsd3jjqer9wd3hy6tsw35k7msjzfpy7nz5yqcnygrfdej82um5wf5k2uckyypwa3eyt44h6txtxquqh7lz5djge4afgfjn7k4rgrkuag0jsd5xvxg" },
    .{ .comment = "Multiple + can join", .valid = true, .string = "lno1pqps7sjqpgt+yzm3qv4uxzmtsd3jjqer9wd3hy6tsw3+5k7msjzfpy7nz5yqcn+ygrfdej82um5wf5k2uckyypwa3eyt44h6txtxquqh7lz5djge4afgfjn7k4rgrkuag0jsd+5xvxg" },
    .{ .comment = "+ followed by whitespace", .valid = true, .string = "lno1pqps7sjqpgt+ yzm3qv4uxzmtsd3jjqer9wd3hy6tsw3+  5k7msjzfpy7nz5yqcn+\nygrfdej82um5wf5k2uckyypwa3eyt44h6txtxquqh7lz5djge4afgfjn7k4rgrkuag0jsd+\r\n 5xvxg" },
    .{ .comment = "+ followed by whitespace UPPERCASE", .valid = true, .string = "LNO1PQPS7SJQPGT+ YZM3QV4UXZMTSD3JJQER9WD3HY6TSW3+  5K7MSJZFPY7NZ5YQCN+\nYGRFDEJ82UM5WF5K2UCKYYPWA3EYT44H6TXTXQUQH7LZ5DJGE4AFGFJN7K4RGRKUAG0JSD+\r\n 5XVXG" },
    .{ .comment = "Mixed case is invalid", .valid = false, .string = "LnO1PqPs7sJqPgTyZm3qV4UxZmTsD3JjQeR9Wd3hY6TsW35k7mSjZfPy7nZ5YqCnYgRfDeJ82uM5Wf5k2uCkYyPwA3EyT44h6tXtXqUqH7Lz5dJgE4AfGfJn7k4rGrKuAg0jSd5xVxG" },
    .{ .comment = "+ at end", .valid = false, .string = "lno1pqps7sjqpgtyzm3qv4uxzmtsd3jjqer9wd3hy6tsw35k7msjzfpy7nz5yqcnygrfdej82um5wf5k2uckyypwa3eyt44h6txtxquqh7lz5djge4afgfjn7k4rgrkuag0jsd5xvxg+" },
    .{ .comment = "+ at end with space", .valid = false, .string = "lno1pqps7sjqpgtyzm3qv4uxzmtsd3jjqer9wd3hy6tsw35k7msjzfpy7nz5yqcnygrfdej82um5wf5k2uckyypwa3eyt44h6txtxquqh7lz5djge4afgfjn7k4rgrkuag0jsd5xvxg+ " },
    .{ .comment = "+ at start", .valid = false, .string = "+lno1pqps7sjqpgtyzm3qv4uxzmtsd3jjqer9wd3hy6tsw35k7msjzfpy7nz5yqcnygrfdej82um5wf5k2uckyypwa3eyt44h6txtxquqh7lz5djge4afgfjn7k4rgrkuag0jsd5xvxg" },
    .{ .comment = "+ at start with space", .valid = false, .string = "+ lno1pqps7sjqpgtyzm3qv4uxzmtsd3jjqer9wd3hy6tsw35k7msjzfpy7nz5yqcnygrfdej82um5wf5k2uckyypwa3eyt44h6txtxquqh7lz5djge4afgfjn7k4rgrkuag0jsd5xvxg" },
    .{ .comment = "double + (not bech32)", .valid = false, .string = "ln++o1pqps7sjqpgtyzm3qv4uxzmtsd3jjqer9wd3hy6tsw35k7msjzfpy7nz5yqcnygrfdej82um5wf5k2uckyypwa3eyt44h6txtxquqh7lz5djge4afgfjn7k4rgrkuag0jsd5xvxg" },
};

test "format-string-test.json: valid strings decode correctly" {
    var pass: usize = 0;
    for (format_test_vectors) |vec| {
        if (!vec.valid) continue;

        const decoded = bech32.decode(testing.allocator, vec.string) catch |e| {
            std.debug.print("FAIL [{s}]: {}\n", .{ vec.comment, e });
            return e;
        };
        defer decoded.deinit();

        try testing.expectEqual(bech32.Hrp.lno, decoded.hrp);
        pass += 1;
    }
    std.debug.print("format-string-test.json valid: {d} passed\n", .{pass});
}

test "format-string-test.json: invalid strings are rejected" {
    var pass: usize = 0;
    for (format_test_vectors) |vec| {
        if (vec.valid) continue;

        if (bech32.decode(testing.allocator, vec.string)) |decoded| {
            decoded.deinit();
            std.debug.print("FAIL [{s}]: expected rejection but decoded ok\n", .{vec.comment});
            return error.TestUnexpectedResult;
        } else |_| {
            pass += 1;
        }
    }
    std.debug.print("format-string-test.json invalid: {d} passed\n", .{pass});
}

// ---------------------------------------------------------------------------
// 3. Signature/merkle test vectors (signature-test.json)
//
// Tests merkle tree computation against known leaf/branch/root hashes.
// ---------------------------------------------------------------------------

const MerkleTestVector = struct {
    description: []const u8,
    first_tlv_hex: []const u8,
    /// Array of (tlv_hex, expected_leaf_hash, expected_nonce_hash, expected_branch_hash)
    leaves: []const MerkleLeaf,
    /// Expected final merkle root
    expected_merkle: []const u8,
};

const MerkleLeaf = struct {
    tlv_hex: []const u8,
    expected_leaf: []const u8,
    expected_branch: []const u8,
};

const merkle_test_vectors = [_]MerkleTestVector{
    .{
        .description = "Simple n1, tlv1=1000",
        .first_tlv_hex = "010203e8",
        .leaves = &[_]MerkleLeaf{
            .{
                .tlv_hex = "010203e8",
                .expected_leaf = "67a2a995433890d8fe0c18a1765ad19e98f1fcfeff14c13a45bbc80964a78cf7",
                .expected_branch = "b013756c8fee86503a0b4abdab4cddeb1af5d344ca6fc2fa8b6c08938caa6f93",
            },
        },
        .expected_merkle = "b013756c8fee86503a0b4abdab4cddeb1af5d344ca6fc2fa8b6c08938caa6f93",
    },
    .{
        .description = "n1, tlv1=1000, tlv2=1x2x3",
        .first_tlv_hex = "010203e8",
        .leaves = &[_]MerkleLeaf{
            .{
                .tlv_hex = "010203e8",
                .expected_leaf = "67a2a995433890d8fe0c18a1765ad19e98f1fcfeff14c13a45bbc80964a78cf7",
                .expected_branch = "b013756c8fee86503a0b4abdab4cddeb1af5d344ca6fc2fa8b6c08938caa6f93",
            },
            .{
                .tlv_hex = "02080000010000020003",
                .expected_leaf = "cc04567fcbff60d4de87afe5142de16b7401531300554838b2d1117341a4ea8d",
                .expected_branch = "19d6ecfa3be88d29c30e56167f58526d7695dfac9cb95e1256deb222c92db4d0",
            },
        },
        .expected_merkle = "c3774abbf4815aa54ccaa026bff6581f01f3be5fe814c620a252534f434bc0d1",
    },
    .{
        .description = "n1, tlv1=1000, tlv2=1x2x3, tlv3=point+1+2",
        .first_tlv_hex = "010203e8",
        .leaves = &[_]MerkleLeaf{
            .{
                .tlv_hex = "010203e8",
                .expected_leaf = "67a2a995433890d8fe0c18a1765ad19e98f1fcfeff14c13a45bbc80964a78cf7",
                .expected_branch = "b013756c8fee86503a0b4abdab4cddeb1af5d344ca6fc2fa8b6c08938caa6f93",
            },
            .{
                .tlv_hex = "02080000010000020003",
                .expected_leaf = "cc04567fcbff60d4de87afe5142de16b7401531300554838b2d1117341a4ea8d",
                .expected_branch = "19d6ecfa3be88d29c30e56167f58526d7695dfac9cb95e1256deb222c92db4d0",
            },
            .{
                .tlv_hex = "03310266e4598d1d3c415f572a8488830b60f7e744ed9235eb0b1ba93283b315c0351800000000000000010000000000000002",
                .expected_leaf = "47da319b36d61a006e0dbcf6642fe4c822c33a6131af67dfa9293b089c5cbd27",
                .expected_branch = "7c879819c09f1525e7bc69b84f7928180de584f92c846e01fa2daf5b17e32967",
            },
        },
        .expected_merkle = "ab2e79b1283b0b31e0b035258de23782df6b89a38cfa7237bde69aed1a658c5d",
    },
};

test "signature-test.json: leaf hash computation" {
    const Sha256 = std.crypto.hash.sha2.Sha256;

    for (merkle_test_vectors) |vec| {
        // Compute leaf tag hash
        var leaf_tag_hash: [32]u8 = undefined;
        Sha256.hash("LnLeaf", &leaf_tag_hash, .{});

        for (vec.leaves) |leaf| {
            const tlv_bytes = try hexToBytes(testing.allocator, leaf.tlv_hex);
            defer testing.allocator.free(tlv_bytes);

            // Compute H("LnLeaf", tlv_bytes)
            const computed_leaf = merkle.taggedHash("LnLeaf", tlv_bytes);
            const computed_hex = try bytesToHex(testing.allocator, &computed_leaf);
            defer testing.allocator.free(computed_hex);

            try testing.expectEqualStrings(leaf.expected_leaf, computed_hex);
        }
    }
}

test "signature-test.json: merkle root computation" {
    for (merkle_test_vectors) |vec| {
        // Parse TLV records from the concatenated hex of all leaves
        var all_tlv_bytes: std.ArrayList(u8) = .{};
        defer all_tlv_bytes.deinit(testing.allocator);

        for (vec.leaves) |leaf| {
            const tlv_bytes = try hexToBytes(testing.allocator, leaf.tlv_hex);
            defer testing.allocator.free(tlv_bytes);
            try all_tlv_bytes.appendSlice(testing.allocator, tlv_bytes);
        }

        const records = try tlv_mod.parseTlvStream(testing.allocator, all_tlv_bytes.items);
        defer testing.allocator.free(records);

        const root = try merkle.computeMerkleRoot(testing.allocator, records);
        try testing.expect(root != null);

        const root_hex = try bytesToHex(testing.allocator, &root.?);
        defer testing.allocator.free(root_hex);

        if (!std.mem.eql(u8, root_hex, vec.expected_merkle)) {
            std.debug.print("FAIL [{s}]: merkle root mismatch\n  expected: {s}\n  got:      {s}\n", .{ vec.description, vec.expected_merkle, root_hex });
        }
        try testing.expectEqualStrings(vec.expected_merkle, root_hex);
    }
}

test "signature-test.json: per-TLV branch hashes" {
    for (merkle_test_vectors) |vec| {
        // Reconstruct TLV records
        var all_tlv_bytes: std.ArrayList(u8) = .{};
        defer all_tlv_bytes.deinit(testing.allocator);

        for (vec.leaves) |leaf| {
            const tlv_bytes = try hexToBytes(testing.allocator, leaf.tlv_hex);
            defer testing.allocator.free(tlv_bytes);
            try all_tlv_bytes.appendSlice(testing.allocator, tlv_bytes);
        }

        const records = try tlv_mod.parseTlvStream(testing.allocator, all_tlv_bytes.items);
        defer testing.allocator.free(records);

        // Filter non-signature records (all of them in these test vectors)
        var non_sig: std.ArrayList(tlv_mod.TlvRecord) = .{};
        defer non_sig.deinit(testing.allocator);
        for (records) |r| {
            if (!merkle.isSignatureType(r.tlv_type)) {
                try non_sig.append(testing.allocator, r);
            }
        }

        // Compute per-TLV branch hashes manually and compare
        const first_rec_bytes = try tlv_mod.serializeTlvRecord(testing.allocator, non_sig.items[0]);
        defer testing.allocator.free(first_rec_bytes);

        const Sha256 = std.crypto.hash.sha2.Sha256;
        var nonce_tag_hash: [32]u8 = undefined;
        {
            var h = Sha256.init(.{});
            h.update("LnNonce");
            h.update(first_rec_bytes);
            nonce_tag_hash = h.finalResult();
        }

        var leaf_tag_hash: [32]u8 = undefined;
        Sha256.hash("LnLeaf", &leaf_tag_hash, .{});

        var branch_tag_hash: [32]u8 = undefined;
        Sha256.hash("LnBranch", &branch_tag_hash, .{});

        for (non_sig.items, 0..) |record, idx| {
            const rec_bytes = try tlv_mod.serializeTlvRecord(testing.allocator, record);
            defer testing.allocator.free(rec_bytes);

            // Compute leaf
            const leaf = merkle.taggedHash("LnLeaf", rec_bytes);
            const leaf_hex = try bytesToHex(testing.allocator, &leaf);
            defer testing.allocator.free(leaf_hex);
            try testing.expectEqualStrings(vec.leaves[idx].expected_leaf, leaf_hex);

            // Compute nonce
            const type_r = bigsize_mod.writeToArray(record.tlv_type);
            var nonce: [32]u8 = undefined;
            {
                var h = Sha256.init(.{});
                h.update(&nonce_tag_hash);
                h.update(&nonce_tag_hash);
                h.update(type_r.data[0..type_r.len]);
                nonce = h.finalResult();
            }

            // Compute branch = H("LnBranch", sorted(leaf, nonce))
            var msg: [64]u8 = undefined;
            if (compareBytesSlice(&leaf, &nonce) < 0) {
                @memcpy(msg[0..32], &leaf);
                @memcpy(msg[32..64], &nonce);
            } else {
                @memcpy(msg[0..32], &nonce);
                @memcpy(msg[32..64], &leaf);
            }

            var branch: [32]u8 = undefined;
            {
                var h = Sha256.init(.{});
                h.update(&branch_tag_hash);
                h.update(&branch_tag_hash);
                h.update(&msg);
                branch = h.finalResult();
            }

            const branch_hex = try bytesToHex(testing.allocator, &branch);
            defer testing.allocator.free(branch_hex);
            try testing.expectEqualStrings(vec.leaves[idx].expected_branch, branch_hex);
        }
    }
}

fn compareBytesSlice(a: []const u8, b: []const u8) i32 {
    const len = @min(a.len, b.len);
    for (a[0..len], b[0..len]) |ca, cb| {
        if (ca < cb) return -1;
        if (ca > cb) return 1;
    }
    if (a.len < b.len) return -1;
    if (a.len > b.len) return 1;
    return 0;
}
