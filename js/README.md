# bolt12-utils

Pure TypeScript BOLT12 library for the Lightning Network. Decode, validate, and create BOLT12 offers, invoice requests, invoices, and payer proofs — with zero native dependencies.

**[Live Playground](https://vincenzopalazzo.github.io/bolt12/)**

## Install

```bash
npm install bolt12-utils
```

## Quick Start

### Decode an Offer

```ts
import { decodeOffer } from 'bolt12-utils';

const offer = decodeOffer('lno1pgx9getnwss8vetrw3hhyuc...');

console.log(offer.hrp);          // 'lno'
console.log(offer.description);  // 'Test vectors'
console.log(offer.issuer_id);    // hex-encoded 33-byte compressed pubkey
console.log(offer.offer_id);     // Uint8Array (merkle root)
```

### Low-Level Decoding

If you need more control, use the building blocks directly:

```ts
import { decodeBolt12, parseTlvStream, validateOffer } from 'bolt12-utils';

// Step 1: Bech32 decode
const { hrp, data } = decodeBolt12('lno1pgx9getnwss8vetrw3hhyuc...');
console.log(hrp); // 'lno'

// Step 2: Parse TLV stream
const records = parseTlvStream(data);
for (const rec of records) {
  console.log(`type=${rec.type} length=${rec.length}`);
}

// Step 3: Validate offer semantics (throws on invalid)
validateOffer(records);
```

### Extract Typed Fields (Generated from Spec)

The library auto-generates types from the [BOLT12 spec CSV](https://github.com/lightning/bolts/blob/master/12-offer-encoding.md). These cover all four message types:

```ts
import {
  decodeBolt12,
  parseTlvStream,
  extractGeneratedOfferFields,
  extractInvoiceRequestFields,
  extractInvoiceFields,
  extractInvoiceErrorFields,
  type GeneratedOfferFields,
  type InvoiceRequestFields,
  type InvoiceFields,
  type InvoiceErrorFields,
} from 'bolt12-utils';

const { data } = decodeBolt12('lno1...');
const records = parseTlvStream(data);

// Spec-compliant field names (offer_description, not description)
const offer: GeneratedOfferFields = extractGeneratedOfferFields(records);
console.log(offer.offer_description);    // string | undefined
console.log(offer.offer_amount);         // bigint | undefined
console.log(offer.offer_issuer_id);      // string (hex) | undefined
console.log(offer.offer_chains);         // Uint8Array[] | undefined
console.log(offer.offer_absolute_expiry); // bigint | undefined
```

### TLV Constants and Lookups

Every TLV type is exported as a `bigint` constant, and lookup maps let you resolve type numbers to names:

```ts
import {
  OFFER_DESCRIPTION,
  OFFER_AMOUNT,
  INVOICE_PAYMENT_HASH,
  SIGNATURE,
  OFFER_TLV_NAMES,
  INVOICE_TLV_NAMES,
  KNOWN_OFFER_TYPES,
} from 'bolt12-utils';

// Constants
console.log(OFFER_DESCRIPTION);     // 10n
console.log(INVOICE_PAYMENT_HASH);  // 168n
console.log(SIGNATURE);             // 240n

// Name lookups
console.log(OFFER_TLV_NAMES.get(10n));   // 'offer_description'
console.log(INVOICE_TLV_NAMES.get(168n)); // 'invoice_payment_hash'

// Known type sets (useful for validation)
console.log(KNOWN_OFFER_TYPES.has(10n)); // true
console.log(KNOWN_OFFER_TYPES.has(99n)); // false
```

### Merkle Root and Signature Verification

BOLT12 uses BIP-340 Schnorr signatures over a Merkle tree of TLV fields:

```ts
import {
  decodeBolt12,
  parseTlvStream,
  computeMerkleRoot,
  verifySignature,
} from 'bolt12-utils';

const { data } = decodeBolt12('lni1...');
const records = parseTlvStream(data);

// Compute the merkle root (= offer_id for offers)
const merkleRoot = computeMerkleRoot(records);

// Verify a signature (64-byte Schnorr sig, 32-byte x-only pubkey)
const valid = verifySignature('invoice', merkleRoot, pubkey32, sig64);
```

### Payer Proofs

Payer proofs (`lnp`) let a payer prove they paid an invoice while selectively disclosing only certain fields:

#### Decode and Verify

```ts
import { decodePayerProof, verifyPayerProof } from 'bolt12-utils';

const { proof } = decodePayerProof('lnp1...');

// Inspect disclosed fields
console.log(proof.includedRecords);   // TlvRecord[]
console.log(proof.preimage);          // Uint8Array | undefined
console.log(proof.payerNote);         // string (e.g. "Payment for coffee")
console.log(proof.omittedTlvs);       // bigint[] (marker numbers)

// Verify both invoice and payer signatures
const result = verifyPayerProof(proof);
console.log(result.valid);      // true/false
console.log(result.merkleRoot); // Uint8Array
console.log(result.error);      // string | undefined
```

#### Create a Payer Proof

```ts
import { createPayerProof } from 'bolt12-utils';

const result = createPayerProof({
  invoiceHex: '...',         // hex-encoded invoice TLV stream
  preimageHex: '...',        // 32-byte payment preimage (hex)
  payerSecretKeyHex: '...',  // 32-byte BIP-340 secret key (hex)
  note: 'Payment for coffee',
  includedTlvTypes: [174],   // optional: extra types to disclose
});

console.log(result.proofBech32); // 'lnp1...'
console.log(result.proofHex);   // hex-encoded proof TLV stream
console.log(result.merkleRoot); // Uint8Array
```

### Bech32 Encoding

Encode raw TLV bytes back to a BOLT12 string:

```ts
import { encodeBolt12 } from 'bolt12-utils';

const bolt12String = encodeBolt12('lno', tlvBytes);
// 'lno1pgx9getnwss8...'
```

## API Reference

### High-Level Functions

| Function | Description |
|---|---|
| `decodeOffer(str)` | Decode, validate, and extract fields from a BOLT12 offer string. Returns `DecodedOffer`. |
| `decodePayerProof(str)` | Decode and parse a payer proof string. Returns `DecodedPayerProof`. |
| `createPayerProof(params)` | Create a payer proof from an invoice, preimage, and payer key. |
| `verifyPayerProof(proof)` | Verify both the invoice signature and payer signature of a proof. |

### Building Blocks

| Function | Description |
|---|---|
| `decodeBolt12(str)` | Bech32-decode a BOLT12 string into `{ hrp, data }`. Handles `+` continuation. |
| `encodeBolt12(hrp, data)` | Bech32-encode raw bytes into a BOLT12 string. |
| `parseTlvStream(data)` | Parse raw bytes into `TlvRecord[]`. Enforces ascending type order. |
| `validateOffer(records)` | Validate offer TLV records against BOLT12 semantic rules. |
| `computeMerkleRoot(records)` | Compute the Merkle root of TLV records (= `offer_id` for offers). |
| `verifySignature(name, root, pubkey, sig)` | Verify a BIP-340 Schnorr signature on a BOLT12 message. |
| `taggedHash(tag, msg)` | Compute `SHA256(SHA256(tag) \|\| SHA256(tag) \|\| msg)`. |

### Generated Field Extractors

| Function | Returns | Message Type |
|---|---|---|
| `extractGeneratedOfferFields(records)` | `GeneratedOfferFields` | Offer (`lno`) |
| `extractInvoiceRequestFields(records)` | `InvoiceRequestFields` | Invoice Request (`lnr`) |
| `extractInvoiceFields(records)` | `InvoiceFields` | Invoice (`lni`) |
| `extractInvoiceErrorFields(records)` | `InvoiceErrorFields` | Invoice Error |

### Types

```ts
interface TlvRecord {
  type: bigint;
  length: bigint;
  value: Uint8Array;
}

interface DecodedOffer extends OfferFields {
  hrp: 'lno' | 'lnr' | 'lni' | 'lnp';
  offer_id: Uint8Array;
}

interface GeneratedOfferFields {
  offer_chains?: Uint8Array[];
  offer_metadata?: Uint8Array;
  offer_currency?: string;
  offer_amount?: bigint;
  offer_description?: string;
  offer_features?: Uint8Array;
  offer_absolute_expiry?: bigint;
  offer_paths?: Uint8Array;
  offer_issuer?: string;
  offer_quantity_max?: bigint;
  offer_issuer_id?: string;
  records: TlvRecord[];
}

interface InvoiceRequestFields extends GeneratedOfferFields {
  invreq_metadata?: Uint8Array;
  invreq_chain?: Uint8Array;
  invreq_amount?: bigint;
  invreq_features?: Uint8Array;
  invreq_quantity?: bigint;
  invreq_payer_id?: string;
  invreq_payer_note?: string;
  invreq_paths?: Uint8Array;
  invreq_bip_353_name?: string;
}

interface InvoiceFields extends InvoiceRequestFields {
  invoice_paths?: Uint8Array;
  invoice_blindedpay?: BlindedPayinfo[];
  invoice_created_at?: bigint;
  invoice_relative_expiry?: bigint;
  invoice_payment_hash?: Uint8Array;
  invoice_amount?: bigint;
  invoice_fallbacks?: FallbackAddress[];
  invoice_features?: Uint8Array;
  invoice_node_id?: string;
}

interface PayerProofFields {
  includedRecords: TlvRecord[];
  signature: Uint8Array;
  preimage: Uint8Array | undefined;
  omittedTlvs: bigint[];
  missingHashes: Uint8Array[];
  leafHashes: Uint8Array[];
  payerSignature: Uint8Array;
  payerNote: string;
  invoicePaymentHash: Uint8Array;
  invoiceNodeId: Uint8Array;
  payerId: Uint8Array;
}
```

### Constants

All TLV type numbers are exported as `bigint` constants:

**Offer:** `OFFER_CHAINS` (2), `OFFER_METADATA` (4), `OFFER_CURRENCY` (6), `OFFER_AMOUNT` (8), `OFFER_DESCRIPTION` (10), `OFFER_FEATURES` (12), `OFFER_ABSOLUTE_EXPIRY` (14), `OFFER_PATHS` (16), `OFFER_ISSUER` (18), `OFFER_QUANTITY_MAX` (20), `OFFER_ISSUER_ID` (22)

**Invoice Request:** `INVREQ_METADATA` (0), `INVREQ_CHAIN` (80), `INVREQ_AMOUNT` (82), `INVREQ_FEATURES` (84), `INVREQ_QUANTITY` (86), `INVREQ_PAYER_ID` (88), `INVREQ_PAYER_NOTE` (89), `INVREQ_PATHS` (90), `INVREQ_BIP_353_NAME` (91)

**Invoice:** `INVOICE_PATHS` (160), `INVOICE_BLINDEDPAY` (162), `INVOICE_CREATED_AT` (164), `INVOICE_RELATIVE_EXPIRY` (166), `INVOICE_PAYMENT_HASH` (168), `INVOICE_AMOUNT` (170), `INVOICE_FALLBACKS` (172), `INVOICE_FEATURES` (174), `INVOICE_NODE_ID` (176)

**Signature:** `SIGNATURE` (240)

## Browser Usage

The library ships a browser bundle for the [live playground](https://vincenzopalazzo.github.io/bolt12/):

```html
<script src="https://vincenzopalazzo.github.io/bolt12/bolt12-bundle.js"></script>
<script>
  const { decodeOffer } = bolt12;
  const offer = decodeOffer('lno1...');
  console.log(offer.description);
</script>
```

Build it yourself:

```bash
npm run build:web
# Output: website/bolt12-bundle.js
```

## Dependencies

Only two dependencies, both from the [noble](https://github.com/paulmillr/noble-curves) family (audited, pure JS):

- `@noble/curves` — secp256k1 / BIP-340 Schnorr
- `@noble/hashes` — SHA-256

## Regenerating Types from Spec

The generated types in `src/generated.ts` are produced from the BOLT12 spec CSV:

```bash
npm run generate
```

This runs `tools/generate-ts.ts` against `specs/bolt12.csv` (extracted from [lightning/bolts](https://github.com/lightning/bolts) `12-offer-encoding.md`).

## Support Development

If you find this library useful, consider donating. The following [BIP21/321](https://bips.dev/321/) URI supports on-chain (taproot), [ARK](https://ark-protocol.org), and [BOLT12](https://bolt12.org) payments:

```
bitcoin:bc1pyys36jag8qug09c36d9j6427kny3d0x08u3wf5l89sks5sxyq3fsp2vddt?ark=ark1qq4hfssprtcgnjzf8qlw2f78yvjau5kldfugg29k34y7j96q2w4t5fjuejh7a4eauna0vf2eegcw95w3dyjzl8gykpye50e9qneuwezqdfwupf&lno=lno1pgqppmsrse80qf0aara4slvcjxrvu6j2rp5ftmjy4yntlsmsutpkvkt6878sxn8g96fuzlhw75hendmuhjy0gp607tsgzaasdvjmstcwcgc6vgwyqgp6mv9u948ngt3j0urev4ga0vw06cpvasexgn00feez9vfgdkyykfgqxdaa8ysjuy8um26ekywlceecwalj0zvqu5h0dd486uhhzvj9m3qlnmaa9awj0cft7x95h7yn9vaep4gm055q8rsctl6lthka2htmk8pzxvgyzae72gnapuhg2v9rtgwfg4mlr56lqqerat2vv2u2aka8e592vqluf5erqqs2ve30snd2pr2d0h7fdfl9js6wyzjl4c66nu6d32nj4w2ft0um9q4q
```

| Method | Details |
|---|---|
| On-chain (Taproot) | `bc1pyys36jag8qug09c36d9j6427kny3d0x08u3wf5l89sks5sxyq3fsp2vddt` |
| ARK | `ark1qq4hfssprtcgnjzf8qlw2f78yvjau5kldfugg29k34y7j96q2w4t5fjuejh7a4eauna0vf2eegcw95w3dyjzl8gykpye50e9qneuwezqdfwupf` |
| BOLT12 Offer | `lno1pgqppmsrse80qf0aara4slvcjxrvu6j2rp5ftmjy4yntlsmsutpkvkt6878sxn8g96fuzlhw75hendmuhjy0gp607tsgzaasdvjmstcwcgc6vgwyqgp6mv9u948ngt3j0urev4ga0vw06cpvasexgn00feez9vfgdkyykfgqxdaa8ysjuy8um26ekywlceecwalj0zvqu5h0dd486uhhzvj9m3qlnmaa9awj0cft7x95h7yn9vaep4gm055q8rsctl6lthka2htmk8pzxvgyzae72gnapuhg2v9rtgwfg4mlr56lqqerat2vv2u2aka8e592vqluf5erqqs2ve30snd2pr2d0h7fdfl9js6wyzjl4c66nu6d32nj4w2ft0um9q4q` |

## License

MIT
