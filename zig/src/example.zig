/// Example: decode a BOLT12 offer from the command line.
///
/// Usage:
///   zig-out/bin/bolt12-decode <bolt12-string>
///   zig-out/bin/bolt12-decode lno1zcss9mk8y3wkklfvevcrszlmu23kfrxh49px20665dqwmn4p72pksese

const std = @import("std");
const bolt12 = @import("bolt12");

fn writeStr(file: std.fs.File, s: []const u8) void {
    file.writeAll(s) catch {};
}

pub fn main() !void {
    const allocator = std.heap.page_allocator;
    const out = std.fs.File.stdout();

    var args = std.process.args();
    _ = args.skip(); // skip program name

    const input = args.next() orelse {
        writeStr(out, "Usage: bolt12-decode <bolt12-string>\n\n");
        writeStr(out, "Example:\n  bolt12-decode lno1zcss9mk8y3wkklfvevcrszlmu23kfrxh49px20665dqwmn4p72pksese\n");
        return;
    };

    const result = bolt12.decodeOffer(allocator, input) catch |e| {
        writeStr(out, "Error decoding offer: ");
        writeStr(out, @errorName(e));
        writeStr(out, "\n");
        return;
    };
    defer result.deinit();

    const offer_id_hex = result.offerIdHex();
    writeStr(out, "Offer decoded successfully!\n");
    writeStr(out, "  HRP: ");
    writeStr(out, result.hrp.toSlice());
    writeStr(out, "\n  Offer ID: ");
    writeStr(out, &offer_id_hex);
    writeStr(out, "\n");

    if (result.description()) |desc| {
        writeStr(out, "  Description: ");
        writeStr(out, desc);
        writeStr(out, "\n");
    }

    if (result.issuerId()) |id| {
        const hex = bolt12.toHex(allocator, id) catch "???";
        defer allocator.free(hex);
        writeStr(out, "  Issuer ID: ");
        writeStr(out, hex);
        writeStr(out, "\n");
    }

    writeStr(out, "\nAll TLV records:\n");
    for (result.records) |r| {
        const hex = bolt12.toHex(allocator, r.value) catch continue;
        defer allocator.free(hex);
        writeStr(out, "  type=");
        // Simple integer formatting
        var num_buf: [20]u8 = undefined;
        const num_str = std.fmt.bufPrint(&num_buf, "{d}", .{r.tlv_type}) catch "?";
        writeStr(out, num_str);
        writeStr(out, " length=");
        const len_str = std.fmt.bufPrint(&num_buf, "{d}", .{r.length}) catch "?";
        writeStr(out, len_str);
        writeStr(out, " value=");
        writeStr(out, hex);
        writeStr(out, "\n");
    }
}
