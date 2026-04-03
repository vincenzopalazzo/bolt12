# bolt12-zig

Pure Zig implementation of [BOLT12](https://github.com/lightning/bolts/blob/master/12-offer-encoding.md) offer decoding and validation for the Lightning Network. Zero external dependencies -- uses only the Zig standard library (`std.crypto`).

Ported from the [TypeScript reference implementation](https://github.com/rustyrussell/bolt12/tree/master/js) (`bolt12-utils`).

## Features

- Bech32 decoding/encoding (no checksum, `+` continuation support)
- BigSize variable-length integer encoding (BOLT 1)
- TLV stream parsing with ascending order validation
- Offer semantic validation (all BOLT12 rules)
- secp256k1 point-on-curve validation via `std.crypto.ecc.Secp256k1`
- Merkle tree computation for `offer_id` (tagged hashes per BIP-341)
- High-level `decodeOffer()` API with typed field accessors

## Requirements

- Zig 0.15+

## Build

```sh
zig build
```

## Test

Runs all unit tests and the official [BOLT12 test vectors](https://github.com/lightning/bolts/tree/master/bolt12):

```sh
zig build test
```

Test suites:
- `offers-test.json` -- 53 vectors (20 valid + 33 invalid offers)
- `format-string-test.json` -- 12 vectors (bech32 format parsing)
- `signature-test.json` -- 3 vectors (merkle tree computation)

## Example

```sh
zig build run -- lno1pgx9getnwss8vetrw3hhyuckyypwa3eyt44h6txtxquqh7lz5djge4afgfjn7k4rgrkuag0jsd5xvxg
```

Output:

```
Offer decoded successfully!
  HRP: lno
  Offer ID: e64a8c3f9b7d27014c54a31fba6e5a1dfb3946af41d1a3881c92aa0af19e302a
  Description: Test vectors
  Issuer ID: 02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619
```

## Usage as a library

Import the `bolt12` module in your `build.zig`:

```zig
const bolt12_dep = b.dependency("bolt12", .{
    .target = target,
    .optimize = optimize,
});
exe.root_module.addImport("bolt12", bolt12_dep.module("bolt12"));
```

Then in your code:

```zig
const bolt12 = @import("bolt12");

const offer = try bolt12.decodeOffer(allocator, "lno1zcss9mk8y3wkkl...");
defer offer.deinit();

if (offer.description()) |desc| {
    // "Test vectors"
}

if (offer.amount()) |msat| {
    // amount in millisatoshis
}

// Access the raw offer_id (32-byte merkle root)
const id_hex = offer.offerIdHex();
```

## Modules

| File | Purpose |
|------|---------|
| `bigsize.zig` | Variable-length integer encoding per BOLT 1 |
| `bech32.zig` | BOLT12 bech32 encoding/decoding (no checksum) |
| `tlv.zig` | TLV stream parsing with ascending order validation |
| `merkle.zig` | Tagged hash merkle tree for `offer_id` computation |
| `offer.zig` | Semantic validation of offer TLV fields |
| `bolt12.zig` | High-level `decodeOffer` API and utilities |

## License

Same as the parent [bolt12](https://github.com/rustyrussell/bolt12) repository.
