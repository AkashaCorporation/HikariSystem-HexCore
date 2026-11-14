import * as fs from 'fs';
import * as path from 'path';
import { BUILTIN_SIGNATURES } from './builtin.js';
import type { HQLSignature } from '../types/hql.js';
import { assertValidSignature } from './schema.js';
import { loadReleasedAtlasSignatures } from '../atlas/runtime.js';
import { compileHql } from '../text/compiler.js';

function collectSignatureFiles(root: string): string[] {
  if (!fs.existsSync(root)) { return []; }
  const files: string[] = [];
  const visit = (dir: string): void => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })
      .sort((a, b) => a.name.localeCompare(b.name))) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) { visit(full); }
      else if (entry.isFile() && (entry.name.endsWith('.hql.json') || entry.name.endsWith('.hql'))) { files.push(full); }
    }
  };
  visit(root);
  return files;
}

/** Load valid on-disk signatures in deterministic path order. */
export function loadSignatureDirectory(root: string): HQLSignature[] {
  const signatures: HQLSignature[] = [];
  const failures: string[] = [];
  const sourcesById = new Map<string, string>();
  for (const file of collectSignatureFiles(root)) {
    try {
      const text = fs.readFileSync(file, 'utf8');
      const parsed: unknown = file.endsWith('.hql.json') ? JSON.parse(text) : compileHql(text, { filename: file });
      assertValidSignature(parsed, file);
      const previous = sourcesById.get(parsed.id);
      if (previous) throw new Error(`HQL duplicate signature ID ${parsed.id}: ${previous} and ${file}`);
      sourcesById.set(parsed.id, file);
      signatures.push(parsed);
    } catch (error) {
      failures.push((error as Error).message);
    }
  }
  if (failures.length > 0) {
    throw new Error(`HQL signature library rejected ${failures.length} file(s):\n${failures.join('\n')}`);
  }
  return signatures;
}

/** Merge libraries by ID. Duplicate IDs fail closed. */
export function mergeSignatureLibraries(
  ...libraries: ReadonlyArray<ReadonlyArray<HQLSignature>>
): HQLSignature[] {
  const byId = new Map<string, HQLSignature>();
  for (const library of libraries) {
    for (const signature of library) {
      if (byId.has(signature.id)) throw new Error(`HQL duplicate signature ID: ${signature.id}`);
      byId.set(signature.id, signature);
    }
  }
  return [...byId.values()];
}

let cachedDefault: HQLSignature[] | undefined;

/** Builtins plus the packaged recursive .hql.json signature library. */
export function getDefaultSignatures(): HQLSignature[] {
  if (cachedDefault) { return cachedDefault; }
  const configured = process.env.HEXCORE_HQL_SIGNATURE_DIR;
  const configuredAtlas = process.env.HEXCORE_HQL_ATLAS_PATH;
  const atlasCandidates = configuredAtlas ? [configuredAtlas] : [
    path.resolve(__dirname, '../hql-atlas.sqlite'),
    path.resolve(__dirname, '../../dist/hql-atlas.sqlite'),
  ];
  const atlasPath = atlasCandidates.find(candidate => fs.existsSync(candidate));
  cachedDefault = (configured
    ? loadSignatureDirectory(configured)
    : atlasPath ? loadReleasedAtlasSignatures(atlasPath) : [...BUILTIN_SIGNATURES])
    .filter(signature => signature.status === undefined || signature.status === 'released');
  return cachedDefault;
}
