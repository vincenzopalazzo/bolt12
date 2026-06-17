/**
 * Offer payment verification tests.
 *
 * Mirrors the verification logic and test vectors from:
 *   https://github.com/vincenzopalazzo/ocean-ln/blob/main/ocean-offer-cli/src/verify.rs#L108
 *
 * The verification flow checks:
 *   1. Issuer signing pubkey matches invoice signing pubkey
 *   2. Offer ID (merkle root of offer TLVs) matches between offer and invoice
 *   3. Invoice signature is valid
 *   4. SHA256(preimage) == invoice payment_hash  (Proof of Payment)
 */

import { sha256 } from '@noble/hashes/sha2';
import { decodeBolt12 } from '../src/bech32.js';
import { parseTlvStream, type TlvRecord } from '../src/tlv.js';
import {
  extractInvoiceFields,
  extractOfferFields as extractGeneratedOfferFields,
} from '../src/generated.js';
import { computeMerkleRoot, verifySignature } from '../src/merkle.js';
import { toHex } from '../src/utils.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}

/** Check whether a TLV type belongs to the offer namespace (types 1-79). */
function isOfferTlvType(type: bigint): boolean {
  return type >= 1n && type <= 79n;
}

/**
 * Extract the last blinded_node_id from raw offer_paths bytes.
 *
 * Format per path:
 *   first_node_id: 33-byte point (02/03 prefix) or 9-byte sciddir (00/01 prefix)
 *   path_key:      33-byte point
 *   num_hops:      u8
 *   per hop:
 *     blinded_node_id: 33-byte point
 *     enclen:          u16
 *     encrypted_data:  enclen bytes
 */
function extractLastBlindedNodeId(pathsRaw: Uint8Array): Uint8Array | null {
  let offset = 0;
  let lastBlindedNodeId: Uint8Array | null = null;

  while (offset < pathsRaw.length) {
    // first_node_id
    const firstByte = pathsRaw[offset];
    const firstNodeIdLen =
      firstByte === 0x00 || firstByte === 0x01
        ? 9 // sciddir
        : 33; // compressed point
    offset += firstNodeIdLen;

    // path_key: 33 bytes
    offset += 33;

    // num_hops: u8
    const numHops = pathsRaw[offset];
    offset += 1;

    for (let h = 0; h < numHops; h++) {
      // blinded_node_id: 33 bytes
      const blindedNodeId = pathsRaw.slice(offset, offset + 33);
      offset += 33;

      // enclen: u16
      const enclen = (pathsRaw[offset] << 8) | pathsRaw[offset + 1];
      offset += 2;

      // encrypted_data
      offset += enclen;

      // Keep the last hop's blinded_node_id
      if (h === numHops - 1) {
        lastBlindedNodeId = blindedNodeId;
      }
    }
  }

  return lastBlindedNodeId;
}

/**
 * Verify an offer-based payment.
 *
 * Steps:
 *   1. Decode offer -> extract issuer signing pubkey (from offer_issuer_id
 *      or fallback to last blinded hop's blinded_node_id)
 *   2. Decode invoice -> extract invoice_node_id, signature, payment_hash
 *   3. Compare signing pubkeys
 *   4. Compare offer IDs (merkle root of offer TLVs)
 *   5. Verify invoice signature
 *   6. Verify proof of payment: SHA256(preimage) == payment_hash
 */
function verifyOfferPayment(
  offerStr: string,
  invoiceStr: string,
  preimageHex: string,
): { ok: boolean; error?: string } {
  // --- 1. Parse the offer ---
  const offerDecoded = decodeBolt12(offerStr);
  if (offerDecoded.hrp !== 'lno') {
    return { ok: false, error: `Expected offer (lno), got ${offerDecoded.hrp}` };
  }
  const offerRecords = parseTlvStream(offerDecoded.data);
  const offerFields = extractGeneratedOfferFields(offerRecords);

  // --- 2. Parse the invoice ---
  const invoiceDecoded = decodeBolt12(invoiceStr);
  if (invoiceDecoded.hrp !== 'lni') {
    return { ok: false, error: `Expected invoice (lni), got ${invoiceDecoded.hrp}` };
  }
  const invoiceRecords = parseTlvStream(invoiceDecoded.data);
  const invoiceFields = extractInvoiceFields(invoiceRecords);

  // --- 3. Extract issuer signing pubkey ---
  let issuerSigningPubkey: Uint8Array | null = null;

  if (offerFields.offer_issuer_id) {
    issuerSigningPubkey = offerFields.offer_issuer_id;
  } else if (offerFields.offer_paths) {
    // Fallback: last blinded hop's blinded_node_id
    issuerSigningPubkey = extractLastBlindedNodeId(offerFields.offer_paths);
  }

  if (!issuerSigningPubkey) {
    return { ok: false, error: 'Cannot determine issuer signing pubkey' };
  }

  // --- 4. Compare signing pubkeys ---
  const invoiceNodeId = invoiceFields.invoice_node_id;
  if (!invoiceNodeId) {
    return { ok: false, error: 'Invoice missing invoice_node_id' };
  }

  if (toHex(issuerSigningPubkey) !== toHex(invoiceNodeId)) {
    return {
      ok: false,
      error: `Signing pubkey mismatch: offer=${toHex(issuerSigningPubkey)}, invoice=${toHex(invoiceNodeId)}`,
    };
  }

  // --- 5. Compare offer IDs ---
  // Offer ID from the standalone offer
  const offerMerkleRoot = computeMerkleRoot(offerRecords);

  // Offer ID from the invoice (computed from offer-namespace TLVs in the invoice)
  const invoiceOfferRecords = invoiceRecords.filter((r) => isOfferTlvType(r.type));
  const invoiceOfferMerkleRoot = computeMerkleRoot(invoiceOfferRecords);

  if (toHex(offerMerkleRoot) !== toHex(invoiceOfferMerkleRoot)) {
    return {
      ok: false,
      error: `Offer ID mismatch: offer=${toHex(offerMerkleRoot)}, invoice=${toHex(invoiceOfferMerkleRoot)}`,
    };
  }

  // --- 6. Verify invoice signature ---
  const signature = invoiceFields.signature;
  if (!signature) {
    return { ok: false, error: 'Invoice missing signature' };
  }

  const invoiceMerkleRoot = computeMerkleRoot(invoiceRecords);
  // verifySignature expects x-only pubkey (32 bytes), strip the 02/03 prefix
  const xOnlyPubkey = invoiceNodeId.slice(1);
  const sigValid = verifySignature('invoice', invoiceMerkleRoot, xOnlyPubkey, signature);
  if (!sigValid) {
    return { ok: false, error: 'Invoice signature verification failed' };
  }

  // --- 7. Proof of Payment ---
  const preimageBytes = hexToBytes(preimageHex);
  if (preimageBytes.length !== 32) {
    return { ok: false, error: `Invalid preimage length: expected 32 bytes, got ${preimageBytes.length}` };
  }

  const paymentHash = sha256(preimageBytes);
  const invoicePaymentHash = invoiceFields.invoice_payment_hash;
  if (!invoicePaymentHash) {
    return { ok: false, error: 'Invoice missing payment_hash' };
  }

  if (toHex(paymentHash) !== toHex(invoicePaymentHash)) {
    return {
      ok: false,
      error: `Payment hash mismatch: SHA256(preimage)=${toHex(paymentHash)}, invoice=${toHex(invoicePaymentHash)}`,
    };
  }

  return { ok: true };
}

// ---------------------------------------------------------------------------
// Test data (from ocean-ln verify.rs)
// ---------------------------------------------------------------------------

const TEST_PREIMAGE = 'a71dceaa4f2b86713834d6362035adf0eb7eab6c6c61ae3c8b68baffd9072cfc';

// CLN offer with offer_issuer_id — all fields consistent
const CLN_OFFER =
  'lno1pg7y7s69g98zq5rp09hh2arnypnx7u3qvf3nzutc8q6xcdphve4r2emjvucrsdejwqmkv73cvymnxmthw3cngcmnvcmrgum5d4j3vggrufqg5j0s05h5pqaywdzp8rhcnemp0e3eryszey4234ym2a99vzhq';
const CLN_INVOICE =
  'lni1qqg9sr0tna8ljw0tp9zk9uehh7s8vz3ufap52s2wypgxz7t0w468xgrxdaezqcnrx9chswp5ds6rwen2x4nhyees8qmnyuphvearscfhxdkhwar3x33hxe3kx3ehgmt9zcss8cjq3fylqlf0gzp6gu6yzw8038nkzlnrjxfq9jf24r2fk4622c9w2gpsz28qtqssxstnfpsaqtgdhchfv70shwvganrwuk28gwz9f6v5nlt37s0xh7hp5zvq8cjq3fylqlf0gzp6gu6yzw8038nkzlnrjxfq9jf24r2fk4622c9wq27sqsf52x7pdt5432aztt8ee3s5l20g3u0whwudkk5asanadjzz5qgzhgehdw5jyjf6m83awzntjkxykywzxycduph6gp5crv29qjf9gsasqv394jhcqgta9q4cr975hw4vl5nzekvuzujxv0u7rngsse707e0pq4duexv3930unvay593kd38t6z8em29zrsqqqqqqqqqqqqqqzgqqqqqqqqqqqqqayjedltzjqqqqqq9yq359nfhm4qst3qczk7fkkjhhqs6syjuygh3q87t8jsmtg04xvzu6vsys3fggzt92qvqj3c9wqvpqqq9syyp7ysy2f8c86t6qswj8x3qn3mufuashucu3jgpvj24g6jd4wjjkpthsgqtas84k74uvj2uvxh32exre34mu4vsc5cnmqpftru4cw0s6wujsk8ggn30v3jll8rn98r3xmlymy850udw2smfmse0amens93mk6fzt';

// Phoenix wallet offer — uses blinded paths, no offer_issuer_id
const PHOENIX_OFFER =
  'lno1pgd57cm9v9hzqnmxvejhygzrd35jqanpd35kgct5d9hkugqsacpcvnhsyh77376c0kvfrpkwdf9ps6y4aez2jf4lcdcw9smxt9arlrczf6ycmt3ftr363p6f3fm08epd84y0lkz4t5zphpuygjqnwxzklltqyqnv4q7rx9lc4k8zjcyy7jdxaupjyuhfu7j7jkrdszh9xah04npkysqrxka4j4yxve6j8czdzcr56f5m5hku3uy0zlqn3genn8pszptkms5u6vv6u7qjej4sg4r00r8lpkeuk9allsgz2gqhm8qmj9cuwcfttex5366yvcma274gtaysskp5nmxrl9h3gsdsqv38tquert0z9py4uadrnuceanv26ytqw2pwys6909szlpw562u5lw8gv0ne7jnz52w9903vfv28pdpswrq';
const PHOENIX_INVOICE =
  'lni1qqgpllwtmnmv6xspe70m78ptxrr5vzsmfa3k2ctwyp8kven9wgsyxmrfypmxzmrfv3shg6t0dcsppmsrse80qf0aara4slvcjxrvu6j2rp5ftmjy4yntlsmsutpkvkt6878syn5f3khzjk8r4zr5nznk70jz602gllv92hgyrwrcg3ypxuv9dl7kqgpxe2puxvtl3tvw99sgfay6dmcryfewnea9a9vxmq9w2dmwltxrvfqqxddmt92gven4y0sy69s8f5nfhf0dercg797p8z3n8xwrqyzhdhpfe5ce4eup9n9tq32x77x07rdnevtmllqsy5sp0kwphyt3casjkhjdfr45ge3h64a2sh6fppvrf8kv87t0z3qmqqezwkpejxk7y2zfte6688e3nmxc45gkqu5zufp527tq97zaf54ef7uwscl8na9x9g5u22lzcjc5wz6rqux9yqc0gfq9gqzcyypaauxsjgg80qzvfrysks88du2s78vme6neec3jt5axdcrj4yj8a99ql5qm2quxfmcztl0gldv8mxy3sm8x5jscdz27u39fy6luxu8zcdn9j73l3upfh49ulj5edehzplt3t9fyw9m2j63x9nmey3r8204yfqpj0y5zzlqzqv5wvsgcqc463wtwd2npxp2t953yqp5vj7j829em3apsnt56chhx2qz9rl9mszedhld2xpuzgthfx007d585x4nfxtdefz74f355mua8wwnnr0weqkgeyj8fa72saljsa0kjzhys9w3dt60k9jxqjddkttw5x50l99smn9grg39v0up6s83lvf5x3nxs3knpvm7qpz8vtl7gj78q9jv7yt8cw0nqpecrvfcy4a0tq2z7560lys4tzp3j2586awqv2pgm66plh4a0q73jw3fq3yzl0tje4u5emck0p3x5p5w9gr74xshtkplmk9p68qwa6uz4m3ez4gv35ldgnl3zytpnm6fszejm4rk4f8g6vrknh7cuas5qq6tgt3f0grshlxxzkcyyzm6jp60p9mym870h2nuk9cl2cz3urvd0qksyegf6lq6gquzy0xumkwge00066l8yyss5wh44hz7vr5nssx0ywst5ju5escm85qwyv4jjs8qdlg2llun2zfymp4qqu8u30avlt52879nsfwgvskvvv3hrmggelcjysxnegcgfxexeaz2k6zttq9vdf4pwfy7qfwcnf88j5gwqqqqraqqqqqryqysqqqqqqqqqqqlgqqqqqqqqr6zgqqqq5szxshfdu6nqxq23sz5zqcu908d9dzgtmzva3vh28mpjz4hggyja3r8d48x6cuhxky628xjp4gps7sjq4cpsyqqqkqssy5sp0kwphyt3casjkhjdfr45ge3h64a2sh6fppvrf8kv87t0z3qm7pqx6pt4td9rrz7ek6gpfzner0dmq9zz92md57cnee4mfv7mktgjj7c3vqn66pdzy80fzgu9sarhtdgd3sy6fl0pzq2dac6m5p87qd393q';

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

let passed = 0;
let failed = 0;
const failures: string[] = [];

function assert(condition: boolean, label: string, detail?: string) {
  if (condition) {
    passed++;
    console.log(`  PASS ${label}`);
  } else {
    failed++;
    const msg = `FAIL ${label}${detail ? ': ' + detail : ''}`;
    failures.push(msg);
    console.log(`  ${msg}`);
  }
}

console.log('=== Offer payment verification tests ===\n');

// Test 1: Valid CLN offer + invoice + preimage
{
  console.log('--- test_verify_offer_payment (CLN, expect OK) ---');
  const result = verifyOfferPayment(CLN_OFFER, CLN_INVOICE, TEST_PREIMAGE);
  assert(result.ok, 'CLN offer verification succeeds', result.error);
}

// Test 2: Phoenix offer — signing pubkey mismatch
{
  console.log('\n--- test_verify_phoenix_offer_fail (expect error) ---');
  const result = verifyOfferPayment(PHOENIX_OFFER, PHOENIX_INVOICE, TEST_PREIMAGE);
  assert(!result.ok, 'Phoenix offer verification fails (signing pubkey mismatch)', result.ok ? 'expected failure' : undefined);
  if (!result.ok) {
    console.log(`    error: ${result.error}`);
  }
}

// Test 3: Phoenix offer — proof of payment failure (same data, same outcome)
{
  console.log('\n--- test_verify_phoenix_offer_fail_pop (expect error) ---');
  const result = verifyOfferPayment(PHOENIX_OFFER, PHOENIX_INVOICE, TEST_PREIMAGE);
  assert(!result.ok, 'Phoenix offer verification fails (PoP check)', result.ok ? 'expected failure' : undefined);
  if (!result.ok) {
    console.log(`    error: ${result.error}`);
  }
}

// ---------------------------------------------------------------------------
// Summary
// ---------------------------------------------------------------------------

console.log(`\n${'='.repeat(60)}`);
console.log(`Results: ${passed} passed, ${failed} failed out of ${passed + failed}`);

if (failures.length > 0) {
  console.log(`\nFailures:`);
  for (const f of failures) {
    console.log(`  - ${f}`);
  }
  process.exit(1);
} else {
  console.log('\nAll verification tests passed!');
}
