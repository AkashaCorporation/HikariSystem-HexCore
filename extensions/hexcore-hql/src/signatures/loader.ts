import * as fs from 'fs';
import * as path from 'path';
import { BUILTIN_SIGNATURES } from './builtin.js';
import type { HQLSignature } from '../types/hql.js';

const SEVERITIES = new Set(['info', 'low', 'medium', 'high', 'critical']);

function isSignature(value: unknown): value is HQLSignature {
  if (!value || typeof value !== 'object' || Array.isArray(value)) { return false; }
  const v = value as Record<string, unknown>;
  return typeof v.id === 'string' && v.id.length > 0 &&
    typeof v.name === 'string' && typeof v.description === 'string' &&
    typeof v.severity === 'string' && SEVERITIES.has(v.severity) &&
    Array.isArray(v.queries) && v.queries.length > 0 &&
    v.queries.every(query => query !== null && typeof query === 'object' && !Array.isArray(query));
}

function collectSignatureFiles(root: string): string[] {
  if (!fs.existsSync(root)) { return []; }
  const files: string[] = [];
  const visit = (dir: string): void => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })
      .sort((a, b) => a.name.localeCompare(b.name))) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) { visit(full); }
      else if (entry.isFile() && entry.name.endsWith('.hql.json')) { files.push(full); }
    }
  };
  visit(root);
  return files;
}

/** Load valid on-disk signatures in deterministic path order. */
export function loadSignatureDirectory(root: string): HQLSignature[] {
  const signatures: HQLSignature[] = [];
  for (const file of collectSignatureFiles(root)) {
    try {
      const parsed: unknown = JSON.parse(fs.readFileSync(file, 'utf8'));
      if (!isSignature(parsed)) {
        console.warn(`[HQL] Ignoring invalid signature schema: ${file}`);
        continue;
      }
      signatures.push(parsed);
    } catch (error) {
      console.warn(`[HQL] Ignoring unreadable signature ${file}: ${(error as Error).message}`);
    }
  }
  return signatures;
}

/** Merge libraries by ID. Earlier entries win, so builtins remain authoritative. */
export function mergeSignatureLibraries(
  ...libraries: ReadonlyArray<ReadonlyArray<HQLSignature>>
): HQLSignature[] {
  const byId = new Map<string, HQLSignature>();
  for (const library of libraries) {
    for (const signature of library) {
      if (!byId.has(signature.id)) { byId.set(signature.id, signature); }
    }
  }
  return [...byId.values()];
}

let cachedDefault: HQLSignature[] | undefined;

/** Builtins plus the packaged recursive .hql.json signature library. */
export function getDefaultSignatures(): HQLSignature[] {
  if (cachedDefault) { return cachedDefault; }
  const configured = process.env.HEXCORE_HQL_SIGNATURE_DIR;
  const candidates = configured
    ? [configured]
    : [
        path.resolve(__dirname, '../../signatures'),
        path.resolve(process.cwd(), 'signatures'),
      ];
  const root = candidates.find(candidate => fs.existsSync(candidate));
  const onDisk = root ? loadSignatureDirectory(root) : [];
  cachedDefault = mergeSignatureLibraries(BUILTIN_SIGNATURES, onDisk);
  return cachedDefault;
}
