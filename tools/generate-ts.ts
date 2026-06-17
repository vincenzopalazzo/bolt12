#!/usr/bin/env npx tsx
/**
 * TypeScript code generator for BOLT12 TLV types.
 *
 * Reads CSV spec files (produced by lightning-rfc/tools/extract-formats.py)
 * and generates pure TypeScript types, constants, and wire functions.
 *
 * Usage:
 *   npx tsx tools/generate-ts.ts [--spec FILE ...] [--output FILE] [containers...]
 *
 * Examples:
 *   npx tsx tools/generate-ts.ts --spec specs/bolt12.csv
 *   npx tsx tools/generate-ts.ts --spec specs/bolt12.csv offer invoice_request invoice
 */

import * as fs from 'fs';
import * as path from 'path';

// ---------------------------------------------------------------------------
// CSV parsing
// ---------------------------------------------------------------------------

interface TlvField {
  /** Field name within the TLV (e.g. "chains", "amount") */
  name: string;
  /** Wire type (e.g. "chain_hash", "tu64", "utf8", "byte", "point") */
  wireType: string;
  /** If present, this is a variable-length array sized by another field */
  lengthField?: string;
  /** If the CSV ends with "...", the field is a trailing variable-length array */
  isVariableArray: boolean;
}

interface TlvType {
  /** Container name (e.g. "offer", "invoice_request", "invoice") */
  container: string;
  /** TLV field name (e.g. "offer_chains", "invreq_amount") */
  name: string;
  /** TLV type number */
  typeNum: number;
  /** Sub-fields within this TLV value */
  fields: TlvField[];
}

interface SubtypeField {
  name: string;
  wireType: string;
  lengthField?: string;
}

interface Subtype {
  name: string;
  fields: SubtypeField[];
}

interface ParsedSpec {
  /** TLV types grouped by container */
  containers: Map<string, TlvType[]>;
  /** Subtypes (complex embedded types like blinded_path) */
  subtypes: Map<string, Subtype>;
}

function parseCSV(csvContent: string): ParsedSpec {
  const containers = new Map<string, TlvType[]>();
  const subtypes = new Map<string, Subtype>();

  const lines = csvContent.split('\n').filter(l => l.trim().length > 0);

  let currentTlv: TlvType | null = null;
  let currentSubtype: Subtype | null = null;

  for (const line of lines) {
    const parts = line.split(',').map(s => s.trim());
    const directive = parts[0];

    switch (directive) {
      case 'tlvtype': {
        const container = parts[1];
        const name = parts[2];
        const typeNum = parseInt(parts[3], 10);

        currentTlv = { container, name, typeNum, fields: [] };
        currentSubtype = null;

        if (!containers.has(container)) {
          containers.set(container, []);
        }
        containers.get(container)!.push(currentTlv);
        break;
      }

      case 'tlvdata': {
        if (!currentTlv) throw new Error(`tlvdata without preceding tlvtype: ${line}`);
        // parts: tlvdata, container, tlvname, fieldname, wiretype, [lengthfield|...]
        const fieldName = parts[3];
        const wireType = parts[4];
        const extra = parts[5] || '';

        currentTlv.fields.push({
          name: fieldName,
          wireType,
          isVariableArray: extra === '...',
          lengthField: extra && extra !== '...' ? extra : undefined,
        });
        break;
      }

      case 'subtype': {
        const name = parts[1];
        currentSubtype = { name, fields: [] };
        currentTlv = null;
        subtypes.set(name, currentSubtype);
        break;
      }

      case 'subtypedata': {
        if (!currentSubtype) throw new Error(`subtypedata without preceding subtype: ${line}`);
        const fieldName = parts[2];
        const wireType = parts[3];
        const extra = parts[4] || '';

        currentSubtype.fields.push({
          name: fieldName,
          wireType,
          lengthField: extra && extra !== '...' ? extra : undefined,
        });
        break;
      }
    }
  }

  return { containers, subtypes };
}

// ---------------------------------------------------------------------------
// Type mapping: wire types -> TypeScript types
// ---------------------------------------------------------------------------

function wireTypeToTS(wireType: string, isArray: boolean): string {
  switch (wireType) {
    case 'tu64':
    case 'tu32':
      return 'bigint';
    case 'u64':
    case 'bigsize':
      return isArray ? 'bigint[]' : 'bigint';
    case 'u32':
    case 'u16':
    case 'u8':
    case 'byte':
      return isArray ? 'Uint8Array' : 'number';
    case 'utf8':
      return 'string';
    case 'chain_hash':
    case 'sha256':
      return isArray ? 'Uint8Array[]' : 'Uint8Array';
    case 'point':
    case 'point32':
    case 'bip340sig':
      return 'Uint8Array';
    default:
      // Complex subtypes (blinded_path, fallback_address, etc.)
      return `${pascalCase(wireType)}`;
  }
}

function wireTypeByteSize(wireType: string): number | null {
  switch (wireType) {
    case 'u8':
    case 'byte':
      return 1;
    case 'u16':
      return 2;
    case 'u32':
    case 'tu32':
      return 4;
    case 'u64':
    case 'tu64':
      return 8;
    case 'chain_hash':
    case 'sha256':
    case 'point32':
    case 'bip340sig':
      return 32;
    case 'point':
      return 33;
    default:
      return null;
  }
}

// ---------------------------------------------------------------------------
// String helpers
// ---------------------------------------------------------------------------

function pascalCase(s: string): string {
  return s.replace(/(^|_)([a-z])/g, (_, __, c) => c.toUpperCase());
}

function screamingSnake(s: string): string {
  return s.toUpperCase();
}

function camelCase(s: string): string {
  return s.replace(/_([a-z])/g, (_, c) => c.toUpperCase());
}

// ---------------------------------------------------------------------------
// Code generation
// ---------------------------------------------------------------------------

function generateHeader(): string {
  return `/**
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

`;
}

function generateImports(): string {
  return `import type { TlvRecord } from './tlv.js';
import { readBigSize } from './bigsize.js';

`;
}

function generateUtilFunctions(): string {
  return `// ---------------------------------------------------------------------------
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

`;
}

function generateSubtypeInterface(sub: Subtype): string {
  const name = pascalCase(sub.name);
  let out = `/** Subtype: ${sub.name} */\nexport interface ${name} {\n`;
  for (const f of sub.fields) {
    // Skip length fields — they're implicit
    if (sub.fields.some(other => other.lengthField === f.name)) continue;
    const tsType = wireTypeToTS(f.wireType, !!f.lengthField);
    out += `  ${f.name}: ${tsType};\n`;
  }
  out += `}\n\n`;
  return out;
}

function generateConstants(containerName: string, types: TlvType[]): string {
  const prefix = screamingSnake(containerName);
  let out = `// ---------------------------------------------------------------------------\n`;
  out += `// ${containerName} TLV type constants\n`;
  out += `// ---------------------------------------------------------------------------\n\n`;

  // Only output constants for types that are unique to this container
  // (skip offer_ types that are duplicated in invoice_request and invoice)
  for (const t of types) {
    const constName = screamingSnake(t.name);
    out += `export const ${constName} = ${t.typeNum}n;\n`;
  }
  out += '\n';

  // Known types set
  out += `export const KNOWN_${prefix}_TYPES = new Set<bigint>([\n`;
  for (const t of types) {
    out += `  ${screamingSnake(t.name)},\n`;
  }
  out += `]);\n\n`;

  return out;
}

function isComplexSubtype(wireType: string, subtypes: Map<string, Subtype>): boolean {
  // Any subtype that contains variable-length fields or nested subtypes
  // needs a custom parser and should be stored as raw bytes
  if (['blinded_path', 'blinded_path_hop', 'sciddir_or_pubkey'].includes(wireType)) {
    return true;
  }
  const sub = subtypes.get(wireType);
  if (!sub) return false;
  // If any field is variable-length or references another subtype, it's complex
  return sub.fields.some(f => !!f.lengthField || subtypes.has(f.wireType));
}

function generateFieldsInterface(containerName: string, types: TlvType[], subtypes: Map<string, Subtype>): string {
  const ifaceName = `${pascalCase(containerName)}Fields`;
  let out = `/** Typed fields for a decoded ${containerName}. */\n`;
  out += `export interface ${ifaceName} {\n`;

  for (const t of types) {
    const fieldName = t.name;
    if (t.fields.length === 0) {
      // Flag-type TLV (no data, e.g. send_invoice)
      out += `  ${fieldName}?: boolean;\n`;
    } else if (t.fields.length === 1) {
      const f = t.fields[0];
      const isArray = f.isVariableArray || !!f.lengthField;
      let tsType: string;

      if (f.wireType === 'chain_hash' && isArray) {
        tsType = 'Uint8Array[]'; // array of 32-byte hashes
      } else if (f.wireType === 'bip340sig') {
        tsType = 'Uint8Array';
      } else if (f.wireType === 'sha256') {
        tsType = isArray ? 'Uint8Array[]' : 'Uint8Array';
      } else if (f.wireType === 'point' || f.wireType === 'point32') {
        tsType = 'Uint8Array';
      } else if (isArray && subtypes.has(f.wireType) && !isComplexSubtype(f.wireType, subtypes)) {
        tsType = `${pascalCase(f.wireType)}[]`;
      } else if (isComplexSubtype(f.wireType, subtypes) || (isArray && subtypes.has(f.wireType))) {
        // Complex subtypes stored as raw bytes — parse with dedicated functions
        tsType = 'Uint8Array';
      } else {
        tsType = wireTypeToTS(f.wireType, isArray);
      }

      out += `  ${fieldName}?: ${tsType};\n`;
    } else {
      // Multi-field TLV — generate inline type
      out += `  ${fieldName}?: {\n`;
      for (const f of t.fields) {
        if (t.fields.some(other => other.lengthField === f.name)) continue;
        const tsType = wireTypeToTS(f.wireType, !!f.lengthField);
        out += `    ${f.name}: ${tsType};\n`;
      }
      out += `  };\n`;
    }
  }

  out += `  /** Raw TLV records for advanced access. */\n`;
  out += `  records: TlvRecord[];\n`;
  out += `}\n\n`;

  return out;
}

function generateFieldExtractor(containerName: string, types: TlvType[]): string {
  const funcName = `extract${pascalCase(containerName)}Fields`;
  const ifaceName = `${pascalCase(containerName)}Fields`;

  let out = `/**\n * Extract typed fields from ${containerName} TLV records.\n */\n`;
  out += `export function ${funcName}(records: TlvRecord[]): ${ifaceName} {\n`;
  out += `  const fields: Partial<Omit<${ifaceName}, 'records'>> = {};\n\n`;
  out += `  for (const rec of records) {\n`;
  out += `    switch (rec.type) {\n`;

  for (const t of types) {
    const constName = screamingSnake(t.name);
    out += `      case ${constName}: {\n`;

    if (t.fields.length === 0) {
      // Flag type
      out += `        fields.${t.name} = true;\n`;
    } else if (t.fields.length === 1) {
      const f = t.fields[0];
      out += `        ${generateSingleFieldDecode(t.name, f)}`;
    } else {
      // Multi-field: parse sequentially
      out += generateMultiFieldDecode(t.name, t.fields);
    }

    out += `        break;\n`;
    out += `      }\n`;
  }

  out += `    }\n`;
  out += `  }\n\n`;
  out += `  return { ...fields, records } as ${ifaceName};\n`;
  out += `}\n\n`;

  return out;
}

function generateSingleFieldDecode(tlvName: string, f: TlvField): string {
  const isArray = f.isVariableArray || !!f.lengthField;

  switch (f.wireType) {
    case 'tu64':
    case 'tu32':
      return `fields.${tlvName} = readTU(rec.value);\n`;

    case 'bigsize':
      if (isArray) {
        return `{\n` +
          `          const values: bigint[] = [];\n` +
          `          let offset = 0;\n` +
          `          while (offset < rec.value.length) {\n` +
          `            const { value, bytesRead } = readBigSize(rec.value, offset);\n` +
          `            values.push(value);\n` +
          `            offset += bytesRead;\n` +
          `          }\n` +
          `          fields.${tlvName} = values;\n` +
          `        }\n`;
      }
      return `fields.${tlvName} = readBigSize(rec.value, 0).value;\n`;

    case 'utf8':
      return `fields.${tlvName} = utf8Decoder.decode(rec.value);\n`;

    case 'byte':
      if (isArray) {
        return `fields.${tlvName} = rec.value;\n`;
      }
      return `fields.${tlvName} = rec.value[0];\n`;

    case 'chain_hash':
      if (isArray) {
        return `{\n` +
          `          const chains: Uint8Array[] = [];\n` +
          `          for (let i = 0; i < rec.value.length; i += 32) {\n` +
          `            chains.push(rec.value.slice(i, i + 32));\n` +
          `          }\n` +
          `          fields.${tlvName} = chains;\n` +
          `        }\n`;
      }
      return `fields.${tlvName} = rec.value.slice(0, 32);\n`;

    case 'sha256':
      if (isArray) {
        return `{\n` +
          `          const hashes: Uint8Array[] = [];\n` +
          `          for (let i = 0; i < rec.value.length; i += 32) {\n` +
          `            hashes.push(rec.value.slice(i, i + 32));\n` +
          `          }\n` +
          `          fields.${tlvName} = hashes;\n` +
          `        }\n`;
      }
      return `fields.${tlvName} = rec.value.slice(0, 32);\n`;

    case 'point':
    case 'point32':
      return `fields.${tlvName} = rec.value.slice(0, ${f.wireType === 'point' ? 33 : 32});\n`;

    case 'bip340sig':
      return `fields.${tlvName} = rec.value.slice(0, 64);\n`;

    default:
      // Complex subtype or unknown — store raw bytes
      return `fields.${tlvName} = rec.value; // ${f.wireType}${isArray ? '[]' : ''} — raw bytes\n`;
  }
}

function generateMultiFieldDecode(tlvName: string, fields: TlvField[]): string {
  let out = `        let _off = 0;\n`;
  const resultFields: string[] = [];

  for (const f of fields) {
    // Skip length fields that are used by other fields
    const isLengthFor = fields.some(other => other.lengthField === f.name);

    switch (f.wireType) {
      case 'u8':
      case 'byte':
        if (isLengthFor) {
          out += `        const ${f.name} = rec.value[_off]; _off += 1;\n`;
        } else if (f.lengthField) {
          out += `        const _${f.name} = rec.value.slice(_off, _off + ${f.lengthField}); _off += ${f.lengthField};\n`;
          resultFields.push(f.name);
        } else {
          out += `        const _${f.name} = rec.value[_off]; _off += 1;\n`;
          resultFields.push(f.name);
        }
        break;

      case 'u16':
        if (isLengthFor) {
          out += `        const ${f.name} = (rec.value[_off] << 8) | rec.value[_off + 1]; _off += 2;\n`;
        } else {
          out += `        const _${f.name} = (rec.value[_off] << 8) | rec.value[_off + 1]; _off += 2;\n`;
          resultFields.push(f.name);
        }
        break;

      case 'u32':
        out += `        const [_${f.name}_big, _${f.name}_next] = readU(rec.value, _off, 4); _off = _${f.name}_next;\n`;
        out += `        const _${f.name} = Number(_${f.name}_big);\n`;
        resultFields.push(f.name);
        break;

      case 'tu32':
      case 'tu64':
        // Truncated uint — rest of buffer or specific size
        out += `        const _${f.name} = readTU(rec.value.slice(_off)); _off = rec.value.length;\n`;
        resultFields.push(f.name);
        break;

      default:
        out += `        const _${f.name} = rec.value.slice(_off); // ${f.wireType}\n`;
        resultFields.push(f.name);
        break;
    }
  }

  out += `        fields.${tlvName} = { ${resultFields.map(n => `${n}: _${n}`).join(', ')} };\n`;
  return out;
}

// ---------------------------------------------------------------------------
// TLV type number -> name lookup table
// ---------------------------------------------------------------------------

function generateLookupTable(containerName: string, types: TlvType[]): string {
  let out = `/** Map from TLV type number to field name for ${containerName}. */\n`;
  out += `export const ${screamingSnake(containerName)}_TLV_NAMES: ReadonlyMap<bigint, string> = new Map([\n`;
  for (const t of types) {
    out += `  [${t.typeNum}n, '${t.name}'],\n`;
  }
  out += `]);\n\n`;
  return out;
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

function main() {
  const args = process.argv.slice(2);
  const specFiles: string[] = [];
  let outputFile: string | null = null;
  const requestedContainers: string[] = [];

  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--spec' && i + 1 < args.length) {
      specFiles.push(args[++i]);
    } else if (args[i] === '--output' && i + 1 < args.length) {
      outputFile = args[++i];
    } else if (!args[i].startsWith('-')) {
      requestedContainers.push(args[i]);
    }
  }

  if (specFiles.length === 0) {
    specFiles.push(path.join(__dirname, '..', 'specs', 'bolt12.csv'));
  }

  // Parse all CSV files
  let allCsv = '';
  for (const f of specFiles) {
    allCsv += fs.readFileSync(f, 'utf-8') + '\n';
  }

  const spec = parseCSV(allCsv);

  // Filter containers if requested
  const containerNames = requestedContainers.length > 0
    ? requestedContainers
    : [...spec.containers.keys()];

  // Deduplicate TLV types: if the same type number + name appears in multiple
  // containers, only generate the constant once. But each container gets its
  // own fields interface and extractor.
  const generatedConstants = new Set<string>();

  let output = '';
  output += generateHeader();
  output += generateImports();
  output += generateUtilFunctions();

  // Generate subtypes
  for (const [, sub] of spec.subtypes) {
    output += generateSubtypeInterface(sub);
  }

  // Generate per-container code
  for (const containerName of containerNames) {
    const types = spec.containers.get(containerName);
    if (!types) {
      console.error(`Warning: container '${containerName}' not found in spec`);
      continue;
    }

    // Constants — deduplicate across containers
    const uniqueTypes = types.filter(t => {
      const key = `${t.name}_${t.typeNum}`;
      if (generatedConstants.has(key)) return false;
      generatedConstants.add(key);
      return true;
    });

    if (uniqueTypes.length > 0) {
      output += generateConstants(containerName, uniqueTypes);
    }

    // Lookup table
    output += generateLookupTable(containerName, types);

    // Fields interface
    output += generateFieldsInterface(containerName, types, spec.subtypes);

    // Field extractor function
    output += generateFieldExtractor(containerName, types);
  }

  if (outputFile) {
    fs.mkdirSync(path.dirname(outputFile), { recursive: true });
    fs.writeFileSync(outputFile, output, 'utf-8');
    console.log(`Generated ${outputFile}`);
  } else {
    process.stdout.write(output);
  }
}

main();
