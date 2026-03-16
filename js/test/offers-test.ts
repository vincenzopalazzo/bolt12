/**
 * Test harness for BOLT12 offers test vectors.
 *
 * Loads offers-test.json from the bolts repository and validates
 * that our implementation correctly handles all test vectors.
 */

import * as fs from 'fs';
import * as path from 'path';
import { decodeBolt12 } from '../src/bech32.js';
import { parseTlvStream, type TlvRecord } from '../src/tlv.js';
import { validateOffer } from '../src/offer.js';

interface TestField {
  type: number;
  length: number;
  hex: string;
}

interface TestVector {
  description: string;
  valid: boolean;
  bolt12: string;
  'field info'?: string;
  fields?: TestField[];
}

function toHex(buf: Uint8Array): string {
  return Buffer.from(buf).toString('hex');
}

function runTests() {
  const testFile = path.resolve(__dirname, '../../test-vectors/offers-bolt-test.json');
  const vectors: TestVector[] = JSON.parse(fs.readFileSync(testFile, 'utf-8'));

  let passed = 0;
  let failed = 0;
  const failures: string[] = [];

  for (let i = 0; i < vectors.length; i++) {
    const v = vectors[i];
    const label = `#${i + 1}: ${v.description}`;

    try {
      if (v.valid) {
        // Should decode successfully
        const { hrp, data } = decodeBolt12(v.bolt12);

        if (hrp !== 'lno') {
          throw new Error(`Expected lno prefix, got ${hrp}`);
        }

        // Parse TLV stream
        const records = parseTlvStream(data);

        // Validate offer semantics
        validateOffer(records);

        // Compare fields if provided
        if (v.fields) {
          if (records.length !== v.fields.length) {
            throw new Error(
              `Field count mismatch: expected ${v.fields.length}, got ${records.length}`
            );
          }

          for (let j = 0; j < v.fields.length; j++) {
            const expected = v.fields[j];
            const actual = records[j];

            if (Number(actual.type) !== expected.type) {
              throw new Error(
                `Field ${j} type mismatch: expected ${expected.type}, got ${actual.type}`
              );
            }

            if (Number(actual.length) !== expected.length) {
              throw new Error(
                `Field ${j} length mismatch: expected ${expected.length}, got ${actual.length}`
              );
            }

            const actualHex = toHex(actual.value);
            if (actualHex !== expected.hex) {
              throw new Error(
                `Field ${j} value mismatch:\n  expected: ${expected.hex}\n  got:      ${actualHex}`
              );
            }
          }
        }

        passed++;
        console.log(`  PASS ${label}`);
      } else {
        // Should fail to decode or validate
        try {
          const { data } = decodeBolt12(v.bolt12);
          const records = parseTlvStream(data);
          validateOffer(records);

          // If we get here, it didn't throw - that's a failure
          failed++;
          const msg = `FAIL ${label}: expected rejection but decoded successfully`;
          failures.push(msg);
          console.log(`  ${msg}`);
        } catch {
          // Expected to fail
          passed++;
          console.log(`  PASS ${label} (correctly rejected)`);
        }
      }
    } catch (e: any) {
      failed++;
      const msg = `FAIL ${label}: ${e.message}`;
      failures.push(msg);
      console.log(`  ${msg}`);
    }
  }

  console.log(`\n${'='.repeat(60)}`);
  console.log(`Results: ${passed} passed, ${failed} failed out of ${vectors.length}`);

  if (failures.length > 0) {
    console.log(`\nFailures:`);
    for (const f of failures) {
      console.log(`  - ${f}`);
    }
    process.exit(1);
  } else {
    console.log('\nAll test vectors passed!');
  }
}

runTests();
