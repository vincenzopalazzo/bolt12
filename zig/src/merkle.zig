/// Merkle tree computation for BOLT12 signature verification.
///
/// Each TLV record is paired with a nonce derived from the first TLV:
///   leaf    = H("LnLeaf", tlv_bytes)
///   nonce   = H(SHA256("LnNonce" || first_tlv_bytes), type_bytes)
///   branch  = H("LnBranch", sorted(leaf, nonce))
///
/// These branches are then paired up in a binary tree:
///   parent  = H("LnBranch", sorted(left, right))
///
/// The root of the tree is the merkle root (offer_id for offers).
///
/// Signature verification uses:
///   msg = H("lightning" || messagename || "signature", merkle_root)

const std = @import("std");
const Sha256 = std.crypto.hash.sha2.Sha256;

const bigsize = @import("bigsize.zig");
const tlv = @import("tlv.zig");

/// BIP-341 style tagged hash: H(tag, msg) = SHA256(SHA256(tag) || SHA256(tag) || msg)
pub fn taggedHash(tag: []const u8, msg: []const u8) [32]u8 {
    var tag_hash: [32]u8 = undefined;
    Sha256.hash(tag, &tag_hash, .{});
    return taggedHashWithHash(tag_hash, msg);
}

/// Tagged hash using a pre-computed tag hash.
fn taggedHashWithHash(tag_hash: [32]u8, msg: []const u8) [32]u8 {
    var h = Sha256.init(.{});
    h.update(&tag_hash);
    h.update(&tag_hash);
    h.update(msg);
    return h.finalResult();
}

/// Serialize a single TLV record to its wire format (type + length + value).
/// Uses a stack buffer. Returns the number of bytes written.
fn tlvToBytesInline(record: tlv.TlvRecord, out: []u8) usize {
    const type_r = bigsize.writeToArray(record.tlv_type);
    const length_r = bigsize.writeToArray(record.length);
    const total = type_r.len + length_r.len + record.value.len;

    @memcpy(out[0..type_r.len], type_r.data[0..type_r.len]);
    @memcpy(out[type_r.len .. type_r.len + length_r.len], length_r.data[0..length_r.len]);
    @memcpy(out[type_r.len + length_r.len .. total], record.value);

    return total;
}

/// Serialize a TLV record to an allocated buffer.
pub fn tlvToBytes(allocator: std.mem.Allocator, record: tlv.TlvRecord) ![]u8 {
    return tlv.serializeTlvRecord(allocator, record);
}

/// Compare two byte slices lexicographically. Returns < 0, 0, or > 0.
fn compareBytes(a: []const u8, b: []const u8) i32 {
    const len = @min(a.len, b.len);
    for (a[0..len], b[0..len]) |ca, cb| {
        if (ca < cb) return -1;
        if (ca > cb) return 1;
    }
    if (a.len < b.len) return -1;
    if (a.len > b.len) return 1;
    return 0;
}

/// Check if a TLV type is a signature element (240-1000 inclusive).
pub fn isSignatureType(typ: u64) bool {
    return typ >= 240 and typ <= 1000;
}

/// Compute a branch hash from two nodes, ordering them lexicographically.
pub fn branchHash(a: [32]u8, b: [32]u8) [32]u8 {
    var branch_tag_hash: [32]u8 = undefined;
    Sha256.hash("LnBranch", &branch_tag_hash, .{});

    var msg: [64]u8 = undefined;
    if (compareBytes(&a, &b) < 0) {
        @memcpy(msg[0..32], &a);
        @memcpy(msg[32..64], &b);
    } else {
        @memcpy(msg[0..32], &b);
        @memcpy(msg[32..64], &a);
    }
    return taggedHashWithHash(branch_tag_hash, &msg);
}

/// Compute the merkle root from an array of TLV records.
/// Excludes signature TLVs (types 240-1000) from the tree.
pub fn computeMerkleRoot(allocator: std.mem.Allocator, records: []const tlv.TlvRecord) !?[32]u8 {
    // Filter non-signature records
    var non_sig: std.ArrayList(tlv.TlvRecord) = .{};
    defer non_sig.deinit(allocator);

    for (records) |r| {
        if (!isSignatureType(r.tlv_type)) {
            try non_sig.append(allocator, r);
        }
    }

    if (non_sig.items.len == 0) {
        return null;
    }

    // Compute per-TLV branch hashes
    const branches = try computePerTlvBranches(allocator, non_sig.items);
    defer allocator.free(branches);

    // Build merkle tree bottom-up
    return try buildMerkleTree(allocator, branches);
}

/// Compute per-TLV branch hashes (leaf+nonce combined).
fn computePerTlvBranches(allocator: std.mem.Allocator, non_sig: []const tlv.TlvRecord) ![][32]u8 {
    // Serialize first record for nonce computation
    const first_rec_bytes = try tlv.serializeTlvRecord(allocator, non_sig[0]);
    defer allocator.free(first_rec_bytes);

    // Nonce tag: SHA256("LnNonce" || first_record_bytes)
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

    var branches = try allocator.alloc([32]u8, non_sig.len);
    errdefer allocator.free(branches);

    for (non_sig, 0..) |record, idx| {
        const rec_bytes = try tlv.serializeTlvRecord(allocator, record);
        defer allocator.free(rec_bytes);

        const type_r = bigsize.writeToArray(record.tlv_type);

        const leaf = taggedHashWithHash(leaf_tag_hash, rec_bytes);
        const nonce = taggedHashWithHash(nonce_tag_hash, type_r.data[0..type_r.len]);

        // Combine leaf and nonce with lexicographic ordering
        var msg: [64]u8 = undefined;
        if (compareBytes(&leaf, &nonce) < 0) {
            @memcpy(msg[0..32], &leaf);
            @memcpy(msg[32..64], &nonce);
        } else {
            @memcpy(msg[0..32], &nonce);
            @memcpy(msg[32..64], &leaf);
        }
        branches[idx] = taggedHashWithHash(branch_tag_hash, &msg);
    }

    return branches;
}

/// Build merkle tree from per-TLV branch hashes, bottom-up.
fn buildMerkleTree(allocator: std.mem.Allocator, initial_nodes: [][32]u8) ![32]u8 {
    var branch_tag_hash: [32]u8 = undefined;
    Sha256.hash("LnBranch", &branch_tag_hash, .{});

    // Copy nodes so we can work in-place
    var nodes = try allocator.alloc([32]u8, initial_nodes.len);
    defer allocator.free(nodes);
    @memcpy(nodes, initial_nodes);

    while (nodes.len > 1) {
        var parents: std.ArrayList([32]u8) = .{};
        defer parents.deinit(allocator);

        var i: usize = 0;
        while (i < nodes.len) {
            if (i + 1 < nodes.len) {
                var msg: [64]u8 = undefined;
                if (compareBytes(&nodes[i], &nodes[i + 1]) < 0) {
                    @memcpy(msg[0..32], &nodes[i]);
                    @memcpy(msg[32..64], &nodes[i + 1]);
                } else {
                    @memcpy(msg[0..32], &nodes[i + 1]);
                    @memcpy(msg[32..64], &nodes[i]);
                }
                try parents.append(allocator, taggedHashWithHash(branch_tag_hash, &msg));
                i += 2;
            } else {
                try parents.append(allocator, nodes[i]);
                i += 1;
            }
        }

        allocator.free(nodes);
        nodes = try parents.toOwnedSlice(allocator);
    }

    const result = nodes[0];
    return result;
}

/// Compute the signature verification message.
/// tag = "lightning" + messagename + "signature"
pub fn signatureMessage(message_name: []const u8, merkle_root: [32]u8) [32]u8 {
    // Build the tag string
    var tag_buf: [256]u8 = undefined;
    const tag_len = 9 + message_name.len + 9; // "lightning" + name + "signature"
    @memcpy(tag_buf[0..9], "lightning");
    @memcpy(tag_buf[9 .. 9 + message_name.len], message_name);
    @memcpy(tag_buf[9 + message_name.len .. tag_len], "signature");

    return taggedHash(tag_buf[0..tag_len], &merkle_root);
}

// ---- Tests ----

const testing = std.testing;

test "merkle: tagged hash produces 32 bytes" {
    const result = taggedHash("test-tag", "test-message");
    try testing.expectEqual(@as(usize, 32), result.len);
}

test "merkle: tagged hash is deterministic" {
    const a = taggedHash("LnLeaf", "hello");
    const b = taggedHash("LnLeaf", "hello");
    try testing.expectEqualSlices(u8, &a, &b);
}

test "merkle: branch hash is commutative" {
    var a: [32]u8 = undefined;
    @memset(&a, 0x01);
    var b: [32]u8 = undefined;
    @memset(&b, 0x02);

    const ab = branchHash(a, b);
    const ba = branchHash(b, a);
    try testing.expectEqualSlices(u8, &ab, &ba);
}

test "merkle: compute root from single record" {
    const record = tlv.TlvRecord{
        .tlv_type = 10,
        .length = 3,
        .value = "abc",
    };
    const records = [_]tlv.TlvRecord{record};

    const root = try computeMerkleRoot(testing.allocator, &records);
    try testing.expect(root != null);
}

test "merkle: compute root from multiple records" {
    const records = [_]tlv.TlvRecord{
        .{ .tlv_type = 10, .length = 12, .value = "Test vectors" },
        .{ .tlv_type = 22, .length = 33, .value = &([_]u8{0x02} ++ [_]u8{0xee} ** 32) },
    };

    const root = try computeMerkleRoot(testing.allocator, &records);
    try testing.expect(root != null);
}

test "merkle: signature types are excluded" {
    const records = [_]tlv.TlvRecord{
        .{ .tlv_type = 10, .length = 3, .value = "abc" },
        .{ .tlv_type = 240, .length = 64, .value = &[_]u8{0} ** 64 }, // signature type
    };

    // With signature
    const root_with_sig = try computeMerkleRoot(testing.allocator, &records);
    // Without signature
    const root_without_sig = try computeMerkleRoot(testing.allocator, records[0..1]);

    try testing.expect(root_with_sig != null);
    try testing.expect(root_without_sig != null);
    try testing.expectEqualSlices(u8, &root_with_sig.?, &root_without_sig.?);
}
