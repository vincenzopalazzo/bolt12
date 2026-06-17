/**
 * Smoke tests for generated types and extractors.
 *
 * Verifies that the auto-generated code from specs/bolt12.csv
 * correctly decodes the same test vectors as the hand-written code.
 */

import { decodeBolt12 } from '../src/bech32.js';
import { parseTlvStream } from '../src/tlv.js';
import { extractOfferFields as extractHandWritten } from '../src/fields.js';
import {
  extractOfferFields as extractGenerated,
  extractInvoiceRequestFields,
  extractInvoiceErrorFields,
  OFFER_CHAINS, OFFER_DESCRIPTION, OFFER_ISSUER_ID, OFFER_AMOUNT,
  OFFER_ISSUER, OFFER_QUANTITY_MAX,
  KNOWN_OFFER_TYPES,
  OFFER_TLV_NAMES,
  INVOICE_REQUEST_TLV_NAMES,
  INVOICE_TLV_NAMES,
} from '../src/generated.js';

function toHex(buf: Uint8Array): string {
  let hex = '';
  for (let i = 0; i < buf.length; i++) {
    hex += buf[i].toString(16).padStart(2, '0');
  }
  return hex;
}

let passed = 0;
let failed = 0;

function assert(cond: boolean, msg: string) {
  if (cond) {
    console.log(`  PASS: ${msg}`);
    passed++;
  } else {
    console.log(`  FAIL: ${msg}`);
    failed++;
  }
}

// Test vectors from the spec
const testOffers = [
  {
    name: 'Minimal offer (issuer_id only)',
    bolt12: 'lno1pgx9getnwss8vetrw3hhyuckyypwa3eyt44h6txtxquqh7lz5djge4afgfjn7k4rgrkuag0jsd5xvxg',
    expectDescription: 'Test vectors',
    expectIssuerId: '02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619',
  },
];

console.log('Generated Types Smoke Tests\n');

// --- Test 1: Generated constants match spec ---
console.log('--- Constants ---');
assert(OFFER_CHAINS === 2n, 'OFFER_CHAINS = 2n');
assert(OFFER_DESCRIPTION === 10n, 'OFFER_DESCRIPTION = 10n');
assert(OFFER_ISSUER_ID === 22n, 'OFFER_ISSUER_ID = 22n');
assert(OFFER_AMOUNT === 8n, 'OFFER_AMOUNT = 8n');
assert(OFFER_ISSUER === 18n, 'OFFER_ISSUER = 18n');
assert(OFFER_QUANTITY_MAX === 20n, 'OFFER_QUANTITY_MAX = 20n');

// --- Test 2: Known types set ---
console.log('\n--- Known types ---');
assert(KNOWN_OFFER_TYPES.size === 11, `KNOWN_OFFER_TYPES has 11 entries (got ${KNOWN_OFFER_TYPES.size})`);
assert(KNOWN_OFFER_TYPES.has(2n), 'Contains offer_chains (2)');
assert(KNOWN_OFFER_TYPES.has(22n), 'Contains offer_issuer_id (22)');
assert(!KNOWN_OFFER_TYPES.has(240n), 'Does not contain signature (240)');

// --- Test 3: TLV name lookup ---
console.log('\n--- TLV name lookup ---');
assert(OFFER_TLV_NAMES.get(2n) === 'offer_chains', 'offer type 2 -> offer_chains');
assert(OFFER_TLV_NAMES.get(10n) === 'offer_description', 'offer type 10 -> offer_description');
assert(INVOICE_REQUEST_TLV_NAMES.get(88n) === 'invreq_payer_id', 'invreq type 88 -> invreq_payer_id');
assert(INVOICE_REQUEST_TLV_NAMES.get(91n) === 'invreq_bip_353_name', 'invreq type 91 -> invreq_bip_353_name');
assert(INVOICE_TLV_NAMES.get(168n) === 'invoice_payment_hash', 'invoice type 168 -> invoice_payment_hash');
assert(INVOICE_TLV_NAMES.get(176n) === 'invoice_node_id', 'invoice type 176 -> invoice_node_id');

// --- Test 4: Generated extractor matches hand-written ---
console.log('\n--- Extractor parity ---');
for (const tv of testOffers) {
  const { data } = decodeBolt12(tv.bolt12);
  const records = parseTlvStream(data);

  const handWritten = extractHandWritten(records);
  const generated = extractGenerated(records);

  // Compare description
  if (tv.expectDescription) {
    assert(
      handWritten.description === generated.offer_description,
      `${tv.name}: description matches ("${generated.offer_description}")`,
    );
  }

  // Compare issuer_id
  if (tv.expectIssuerId && handWritten.issuer_id && generated.offer_issuer_id) {
    assert(
      handWritten.issuer_id === toHex(generated.offer_issuer_id),
      `${tv.name}: issuer_id matches`,
    );
  }

  // Compare amount (if present)
  if (tv.expectAmount !== undefined) {
    assert(
      generated.offer_amount === tv.expectAmount,
      `${tv.name}: amount = ${generated.offer_amount}`,
    );
  }

  // Verify records are included
  assert(
    generated.records.length > 0,
    `${tv.name}: records array is populated (${generated.records.length} records)`,
  );
}

// --- Test 5: Field naming follows spec (offer_ prefix) ---
console.log('\n--- Spec-compliant naming ---');
{
  const { data } = decodeBolt12(testOffers[0].bolt12);
  const records = parseTlvStream(data);
  const fields = extractGenerated(records);

  assert('offer_description' in fields, 'Uses spec name offer_description (not just description)');
  assert('offer_issuer_id' in fields, 'Uses spec name offer_issuer_id (not just issuer_id)');
  assert('records' in fields, 'Includes raw records');
}

// --- Summary ---
console.log(`\n${'='.repeat(60)}`);
console.log(`Results: ${passed} passed, ${failed} failed out of ${passed + failed}\n`);

if (failed > 0) {
  process.exit(1);
} else {
  console.log('All generated type tests passed!');
}
