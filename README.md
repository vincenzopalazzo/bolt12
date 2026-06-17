# bolt12-decoder

Pure TypeScript BOLT12 implementation for the Lightning Network.

Decode, validate, and create BOLT12 offers, invoice requests, invoices,
and payer proofs. Zero native dependencies — runs in Node.js and browsers.

## Install

```bash
npm install bolt12-decoder
```

## Quick Start

```typescript
import { decodeOffer } from 'bolt12-decoder';

const { description, issuer, issuer_id, offer_id } = decodeOffer('lno1...');
console.log(description, issuer);
```

## Features

- Bech32 encoding/decoding (lno, lnr, lni, lnp)
- TLV stream parsing with BigSize integers
- Typed field extraction for offers
- Merkle root computation with BIP-340 Schnorr signature verification
- Payer proof creation and verification (experimental, PR #1295)
- Browser bundle (IIFE) for client-side use

## Website

See the interactive decoder and playground at `website/`.

## Authors

Rusty Russell (@rustyrussell), @adi2011, Vincenzo Palazzo (@vincenzopalazzo).

## Previous implementations

The `python/`, `javascript/`, and `bolt12/` directories contained earlier
implementations by Rusty Russell and contributors. They have been removed
in favor of the pure TypeScript rewrite in `js/`.
