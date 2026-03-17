/**
 * @fileoverview Auto-generated BOLT12 TLV types, constants, and field extractors.
 * @generated from specs/bolt12.csv by tools/generate-ts.ts
 *
 * DO NOT EDIT — changes will be overwritten on next generation.
 *
 * Re-generate with:
 *   npx tsx tools/generate-ts.ts --spec specs/bolt12.csv --output js/src/generated.ts
 *
 * Source: lightning-rfc/12-offer-encoding.md (https://github.com/lightning/bolts)
 */

/* eslint-disable */

import type { TlvRecord } from './tlv.js';

// ---------------------------------------------------------------------------
// Wire encoding/decoding helpers
// ---------------------------------------------------------------------------

const utf8Encoder = new TextEncoder();
const utf8Decoder = new TextDecoder('utf-8', { fatal: false });

/** Read a truncated big-endian unsigned integer. */
function readTU(data: Uint8Array): bigint {
  if (data.length === 0) return 0n;
  let val = 0n;
  for (let i = 0; i < data.length; i++) {
    val = (val << 8n) | BigInt(data[i]);
  }
  return val;
}

/** Write a truncated unsigned integer (variable length, big-endian). */
function writeTU(val: bigint): Uint8Array {
  if (val === 0n) return new Uint8Array(0);
  const bytes: number[] = [];
  let v = val;
  while (v > 0n) {
    bytes.unshift(Number(v & 0xffn));
    v >>= 8n;
  }
  return new Uint8Array(bytes);
}

/** Read a fixed-width big-endian unsigned integer. */
function readU(data: Uint8Array, offset: number, len: number): [bigint, number] {
  let val = 0n;
  for (let i = 0; i < len; i++) {
    val = (val << 8n) | BigInt(data[offset + i]);
  }
  return [val, offset + len];
}

/** Convert bytes to lowercase hex string. */
function toHex(buf: Uint8Array): string {
  let hex = '';
  for (let i = 0; i < buf.length; i++) {
    hex += buf[i].toString(16).padStart(2, '0');
  }
  return hex;
}

/** Subtype: blinded_payinfo */
export interface BlindedPayinfo {
  fee_base_msat: number;
  fee_proportional_millionths: number;
  cltv_expiry_delta: number;
  htlc_minimum_msat: bigint;
  htlc_maximum_msat: bigint;
  features: Uint8Array;
}

/** Subtype: fallback_address */
export interface FallbackAddress {
  version: number;
  address: Uint8Array;
}

// ---------------------------------------------------------------------------
// offer TLV type constants
// ---------------------------------------------------------------------------

export const OFFER_CHAINS = 2n;
export const OFFER_METADATA = 4n;
export const OFFER_CURRENCY = 6n;
export const OFFER_AMOUNT = 8n;
export const OFFER_DESCRIPTION = 10n;
export const OFFER_FEATURES = 12n;
export const OFFER_ABSOLUTE_EXPIRY = 14n;
export const OFFER_PATHS = 16n;
export const OFFER_ISSUER = 18n;
export const OFFER_QUANTITY_MAX = 20n;
export const OFFER_ISSUER_ID = 22n;

export const KNOWN_OFFER_TYPES = new Set<bigint>([
  OFFER_CHAINS,
  OFFER_METADATA,
  OFFER_CURRENCY,
  OFFER_AMOUNT,
  OFFER_DESCRIPTION,
  OFFER_FEATURES,
  OFFER_ABSOLUTE_EXPIRY,
  OFFER_PATHS,
  OFFER_ISSUER,
  OFFER_QUANTITY_MAX,
  OFFER_ISSUER_ID,
]);

/** Map from TLV type number to field name for offer. */
export const OFFER_TLV_NAMES: ReadonlyMap<bigint, string> = new Map([
  [2n, 'offer_chains'],
  [4n, 'offer_metadata'],
  [6n, 'offer_currency'],
  [8n, 'offer_amount'],
  [10n, 'offer_description'],
  [12n, 'offer_features'],
  [14n, 'offer_absolute_expiry'],
  [16n, 'offer_paths'],
  [18n, 'offer_issuer'],
  [20n, 'offer_quantity_max'],
  [22n, 'offer_issuer_id'],
]);

/** Typed fields for a decoded offer. */
export interface OfferFields {
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
  offer_issuer_id?: Uint8Array;
  /** Raw TLV records for advanced access. */
  records: TlvRecord[];
}

/**
 * Extract typed fields from offer TLV records.
 */
export function extractOfferFields(records: TlvRecord[]): OfferFields {
  const fields: Partial<Omit<OfferFields, 'records'>> = {};

  for (const rec of records) {
    switch (rec.type) {
      case OFFER_CHAINS: {
        {
          const chains: Uint8Array[] = [];
          for (let i = 0; i < rec.value.length; i += 32) {
            chains.push(rec.value.slice(i, i + 32));
          }
          fields.offer_chains = chains;
        }
        break;
      }
      case OFFER_METADATA: {
        fields.offer_metadata = rec.value;
        break;
      }
      case OFFER_CURRENCY: {
        fields.offer_currency = utf8Decoder.decode(rec.value);
        break;
      }
      case OFFER_AMOUNT: {
        fields.offer_amount = readTU(rec.value);
        break;
      }
      case OFFER_DESCRIPTION: {
        fields.offer_description = utf8Decoder.decode(rec.value);
        break;
      }
      case OFFER_FEATURES: {
        fields.offer_features = rec.value;
        break;
      }
      case OFFER_ABSOLUTE_EXPIRY: {
        fields.offer_absolute_expiry = readTU(rec.value);
        break;
      }
      case OFFER_PATHS: {
        fields.offer_paths = rec.value; // blinded_path[] — raw bytes
        break;
      }
      case OFFER_ISSUER: {
        fields.offer_issuer = utf8Decoder.decode(rec.value);
        break;
      }
      case OFFER_QUANTITY_MAX: {
        fields.offer_quantity_max = readTU(rec.value);
        break;
      }
      case OFFER_ISSUER_ID: {
        fields.offer_issuer_id = rec.value.slice(0, 33);
        break;
      }
    }
  }

  return { ...fields, records } as OfferFields;
}

// ---------------------------------------------------------------------------
// invoice_request TLV type constants
// ---------------------------------------------------------------------------

export const INVREQ_METADATA = 0n;
export const INVREQ_CHAIN = 80n;
export const INVREQ_AMOUNT = 82n;
export const INVREQ_FEATURES = 84n;
export const INVREQ_QUANTITY = 86n;
export const INVREQ_PAYER_ID = 88n;
export const INVREQ_PAYER_NOTE = 89n;
export const INVREQ_PATHS = 90n;
export const INVREQ_BIP_353_NAME = 91n;
export const SIGNATURE = 240n;

export const KNOWN_INVOICE_REQUEST_TYPES = new Set<bigint>([
  INVREQ_METADATA,
  INVREQ_CHAIN,
  INVREQ_AMOUNT,
  INVREQ_FEATURES,
  INVREQ_QUANTITY,
  INVREQ_PAYER_ID,
  INVREQ_PAYER_NOTE,
  INVREQ_PATHS,
  INVREQ_BIP_353_NAME,
  SIGNATURE,
]);

/** Map from TLV type number to field name for invoice_request. */
export const INVOICE_REQUEST_TLV_NAMES: ReadonlyMap<bigint, string> = new Map([
  [0n, 'invreq_metadata'],
  [2n, 'offer_chains'],
  [4n, 'offer_metadata'],
  [6n, 'offer_currency'],
  [8n, 'offer_amount'],
  [10n, 'offer_description'],
  [12n, 'offer_features'],
  [14n, 'offer_absolute_expiry'],
  [16n, 'offer_paths'],
  [18n, 'offer_issuer'],
  [20n, 'offer_quantity_max'],
  [22n, 'offer_issuer_id'],
  [80n, 'invreq_chain'],
  [82n, 'invreq_amount'],
  [84n, 'invreq_features'],
  [86n, 'invreq_quantity'],
  [88n, 'invreq_payer_id'],
  [89n, 'invreq_payer_note'],
  [90n, 'invreq_paths'],
  [91n, 'invreq_bip_353_name'],
  [240n, 'signature'],
]);

/** Typed fields for a decoded invoice_request. */
export interface InvoiceRequestFields {
  invreq_metadata?: Uint8Array;
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
  offer_issuer_id?: Uint8Array;
  invreq_chain?: Uint8Array;
  invreq_amount?: bigint;
  invreq_features?: Uint8Array;
  invreq_quantity?: bigint;
  invreq_payer_id?: Uint8Array;
  invreq_payer_note?: string;
  invreq_paths?: Uint8Array;
  invreq_bip_353_name?: {
    name: Uint8Array;
    domain: Uint8Array;
  };
  signature?: Uint8Array;
  /** Raw TLV records for advanced access. */
  records: TlvRecord[];
}

/**
 * Extract typed fields from invoice_request TLV records.
 */
export function extractInvoiceRequestFields(records: TlvRecord[]): InvoiceRequestFields {
  const fields: Partial<Omit<InvoiceRequestFields, 'records'>> = {};

  for (const rec of records) {
    switch (rec.type) {
      case INVREQ_METADATA: {
        fields.invreq_metadata = rec.value;
        break;
      }
      case OFFER_CHAINS: {
        {
          const chains: Uint8Array[] = [];
          for (let i = 0; i < rec.value.length; i += 32) {
            chains.push(rec.value.slice(i, i + 32));
          }
          fields.offer_chains = chains;
        }
        break;
      }
      case OFFER_METADATA: {
        fields.offer_metadata = rec.value;
        break;
      }
      case OFFER_CURRENCY: {
        fields.offer_currency = utf8Decoder.decode(rec.value);
        break;
      }
      case OFFER_AMOUNT: {
        fields.offer_amount = readTU(rec.value);
        break;
      }
      case OFFER_DESCRIPTION: {
        fields.offer_description = utf8Decoder.decode(rec.value);
        break;
      }
      case OFFER_FEATURES: {
        fields.offer_features = rec.value;
        break;
      }
      case OFFER_ABSOLUTE_EXPIRY: {
        fields.offer_absolute_expiry = readTU(rec.value);
        break;
      }
      case OFFER_PATHS: {
        fields.offer_paths = rec.value; // blinded_path[] — raw bytes
        break;
      }
      case OFFER_ISSUER: {
        fields.offer_issuer = utf8Decoder.decode(rec.value);
        break;
      }
      case OFFER_QUANTITY_MAX: {
        fields.offer_quantity_max = readTU(rec.value);
        break;
      }
      case OFFER_ISSUER_ID: {
        fields.offer_issuer_id = rec.value.slice(0, 33);
        break;
      }
      case INVREQ_CHAIN: {
        fields.invreq_chain = rec.value.slice(0, 32);
        break;
      }
      case INVREQ_AMOUNT: {
        fields.invreq_amount = readTU(rec.value);
        break;
      }
      case INVREQ_FEATURES: {
        fields.invreq_features = rec.value;
        break;
      }
      case INVREQ_QUANTITY: {
        fields.invreq_quantity = readTU(rec.value);
        break;
      }
      case INVREQ_PAYER_ID: {
        fields.invreq_payer_id = rec.value.slice(0, 33);
        break;
      }
      case INVREQ_PAYER_NOTE: {
        fields.invreq_payer_note = utf8Decoder.decode(rec.value);
        break;
      }
      case INVREQ_PATHS: {
        fields.invreq_paths = rec.value; // blinded_path[] — raw bytes
        break;
      }
      case INVREQ_BIP_353_NAME: {
        let _off = 0;
        const name_len = rec.value[_off]; _off += 1;
        const _name = rec.value.slice(_off, _off + name_len); _off += name_len;
        const domain_len = rec.value[_off]; _off += 1;
        const _domain = rec.value.slice(_off, _off + domain_len); _off += domain_len;
        fields.invreq_bip_353_name = { name: _name, domain: _domain };
        break;
      }
      case SIGNATURE: {
        fields.signature = rec.value.slice(0, 64);
        break;
      }
    }
  }

  return { ...fields, records } as InvoiceRequestFields;
}

// ---------------------------------------------------------------------------
// invoice TLV type constants
// ---------------------------------------------------------------------------

export const INVOICE_PATHS = 160n;
export const INVOICE_BLINDEDPAY = 162n;
export const INVOICE_CREATED_AT = 164n;
export const INVOICE_RELATIVE_EXPIRY = 166n;
export const INVOICE_PAYMENT_HASH = 168n;
export const INVOICE_AMOUNT = 170n;
export const INVOICE_FALLBACKS = 172n;
export const INVOICE_FEATURES = 174n;
export const INVOICE_NODE_ID = 176n;

export const KNOWN_INVOICE_TYPES = new Set<bigint>([
  INVOICE_PATHS,
  INVOICE_BLINDEDPAY,
  INVOICE_CREATED_AT,
  INVOICE_RELATIVE_EXPIRY,
  INVOICE_PAYMENT_HASH,
  INVOICE_AMOUNT,
  INVOICE_FALLBACKS,
  INVOICE_FEATURES,
  INVOICE_NODE_ID,
]);

/** Map from TLV type number to field name for invoice. */
export const INVOICE_TLV_NAMES: ReadonlyMap<bigint, string> = new Map([
  [0n, 'invreq_metadata'],
  [2n, 'offer_chains'],
  [4n, 'offer_metadata'],
  [6n, 'offer_currency'],
  [8n, 'offer_amount'],
  [10n, 'offer_description'],
  [12n, 'offer_features'],
  [14n, 'offer_absolute_expiry'],
  [16n, 'offer_paths'],
  [18n, 'offer_issuer'],
  [20n, 'offer_quantity_max'],
  [22n, 'offer_issuer_id'],
  [80n, 'invreq_chain'],
  [82n, 'invreq_amount'],
  [84n, 'invreq_features'],
  [86n, 'invreq_quantity'],
  [88n, 'invreq_payer_id'],
  [89n, 'invreq_payer_note'],
  [90n, 'invreq_paths'],
  [91n, 'invreq_bip_353_name'],
  [160n, 'invoice_paths'],
  [162n, 'invoice_blindedpay'],
  [164n, 'invoice_created_at'],
  [166n, 'invoice_relative_expiry'],
  [168n, 'invoice_payment_hash'],
  [170n, 'invoice_amount'],
  [172n, 'invoice_fallbacks'],
  [174n, 'invoice_features'],
  [176n, 'invoice_node_id'],
  [240n, 'signature'],
]);

/** Typed fields for a decoded invoice. */
export interface InvoiceFields {
  invreq_metadata?: Uint8Array;
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
  offer_issuer_id?: Uint8Array;
  invreq_chain?: Uint8Array;
  invreq_amount?: bigint;
  invreq_features?: Uint8Array;
  invreq_quantity?: bigint;
  invreq_payer_id?: Uint8Array;
  invreq_payer_note?: string;
  invreq_paths?: Uint8Array;
  invreq_bip_353_name?: {
    name: Uint8Array;
    domain: Uint8Array;
  };
  invoice_paths?: Uint8Array;
  invoice_blindedpay?: Uint8Array;
  invoice_created_at?: bigint;
  invoice_relative_expiry?: bigint;
  invoice_payment_hash?: Uint8Array;
  invoice_amount?: bigint;
  invoice_fallbacks?: Uint8Array;
  invoice_features?: Uint8Array;
  invoice_node_id?: Uint8Array;
  signature?: Uint8Array;
  /** Raw TLV records for advanced access. */
  records: TlvRecord[];
}

/**
 * Extract typed fields from invoice TLV records.
 */
export function extractInvoiceFields(records: TlvRecord[]): InvoiceFields {
  const fields: Partial<Omit<InvoiceFields, 'records'>> = {};

  for (const rec of records) {
    switch (rec.type) {
      case INVREQ_METADATA: {
        fields.invreq_metadata = rec.value;
        break;
      }
      case OFFER_CHAINS: {
        {
          const chains: Uint8Array[] = [];
          for (let i = 0; i < rec.value.length; i += 32) {
            chains.push(rec.value.slice(i, i + 32));
          }
          fields.offer_chains = chains;
        }
        break;
      }
      case OFFER_METADATA: {
        fields.offer_metadata = rec.value;
        break;
      }
      case OFFER_CURRENCY: {
        fields.offer_currency = utf8Decoder.decode(rec.value);
        break;
      }
      case OFFER_AMOUNT: {
        fields.offer_amount = readTU(rec.value);
        break;
      }
      case OFFER_DESCRIPTION: {
        fields.offer_description = utf8Decoder.decode(rec.value);
        break;
      }
      case OFFER_FEATURES: {
        fields.offer_features = rec.value;
        break;
      }
      case OFFER_ABSOLUTE_EXPIRY: {
        fields.offer_absolute_expiry = readTU(rec.value);
        break;
      }
      case OFFER_PATHS: {
        fields.offer_paths = rec.value; // blinded_path[] — raw bytes
        break;
      }
      case OFFER_ISSUER: {
        fields.offer_issuer = utf8Decoder.decode(rec.value);
        break;
      }
      case OFFER_QUANTITY_MAX: {
        fields.offer_quantity_max = readTU(rec.value);
        break;
      }
      case OFFER_ISSUER_ID: {
        fields.offer_issuer_id = rec.value.slice(0, 33);
        break;
      }
      case INVREQ_CHAIN: {
        fields.invreq_chain = rec.value.slice(0, 32);
        break;
      }
      case INVREQ_AMOUNT: {
        fields.invreq_amount = readTU(rec.value);
        break;
      }
      case INVREQ_FEATURES: {
        fields.invreq_features = rec.value;
        break;
      }
      case INVREQ_QUANTITY: {
        fields.invreq_quantity = readTU(rec.value);
        break;
      }
      case INVREQ_PAYER_ID: {
        fields.invreq_payer_id = rec.value.slice(0, 33);
        break;
      }
      case INVREQ_PAYER_NOTE: {
        fields.invreq_payer_note = utf8Decoder.decode(rec.value);
        break;
      }
      case INVREQ_PATHS: {
        fields.invreq_paths = rec.value; // blinded_path[] — raw bytes
        break;
      }
      case INVREQ_BIP_353_NAME: {
        let _off = 0;
        const name_len = rec.value[_off]; _off += 1;
        const _name = rec.value.slice(_off, _off + name_len); _off += name_len;
        const domain_len = rec.value[_off]; _off += 1;
        const _domain = rec.value.slice(_off, _off + domain_len); _off += domain_len;
        fields.invreq_bip_353_name = { name: _name, domain: _domain };
        break;
      }
      case INVOICE_PATHS: {
        fields.invoice_paths = rec.value; // blinded_path[] — raw bytes
        break;
      }
      case INVOICE_BLINDEDPAY: {
        fields.invoice_blindedpay = rec.value; // blinded_payinfo[] — raw bytes
        break;
      }
      case INVOICE_CREATED_AT: {
        fields.invoice_created_at = readTU(rec.value);
        break;
      }
      case INVOICE_RELATIVE_EXPIRY: {
        fields.invoice_relative_expiry = readTU(rec.value);
        break;
      }
      case INVOICE_PAYMENT_HASH: {
        fields.invoice_payment_hash = rec.value.slice(0, 32);
        break;
      }
      case INVOICE_AMOUNT: {
        fields.invoice_amount = readTU(rec.value);
        break;
      }
      case INVOICE_FALLBACKS: {
        fields.invoice_fallbacks = rec.value; // fallback_address[] — raw bytes
        break;
      }
      case INVOICE_FEATURES: {
        fields.invoice_features = rec.value;
        break;
      }
      case INVOICE_NODE_ID: {
        fields.invoice_node_id = rec.value.slice(0, 33);
        break;
      }
      case SIGNATURE: {
        fields.signature = rec.value.slice(0, 64);
        break;
      }
    }
  }

  return { ...fields, records } as InvoiceFields;
}

// ---------------------------------------------------------------------------
// invoice_error TLV type constants
// ---------------------------------------------------------------------------

export const ERRONEOUS_FIELD = 1n;
export const SUGGESTED_VALUE = 3n;
export const ERROR = 5n;

export const KNOWN_INVOICE_ERROR_TYPES = new Set<bigint>([
  ERRONEOUS_FIELD,
  SUGGESTED_VALUE,
  ERROR,
]);

/** Map from TLV type number to field name for invoice_error. */
export const INVOICE_ERROR_TLV_NAMES: ReadonlyMap<bigint, string> = new Map([
  [1n, 'erroneous_field'],
  [3n, 'suggested_value'],
  [5n, 'error'],
]);

/** Typed fields for a decoded invoice_error. */
export interface InvoiceErrorFields {
  erroneous_field?: bigint;
  suggested_value?: Uint8Array;
  error?: string;
  /** Raw TLV records for advanced access. */
  records: TlvRecord[];
}

/**
 * Extract typed fields from invoice_error TLV records.
 */
export function extractInvoiceErrorFields(records: TlvRecord[]): InvoiceErrorFields {
  const fields: Partial<Omit<InvoiceErrorFields, 'records'>> = {};

  for (const rec of records) {
    switch (rec.type) {
      case ERRONEOUS_FIELD: {
        fields.erroneous_field = readTU(rec.value);
        break;
      }
      case SUGGESTED_VALUE: {
        fields.suggested_value = rec.value;
        break;
      }
      case ERROR: {
        fields.error = utf8Decoder.decode(rec.value);
        break;
      }
    }
  }

  return { ...fields, records } as InvoiceErrorFields;
}

