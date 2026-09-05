// Backwards-compatible export name for the packaged canonical rule library.
// The source of truth is signatures/**/*.hql.json; no rules live in TypeScript.

import * as fs from 'fs';
import * as path from 'path';
import type { HQLSignature } from '../types/hql.js';
import { assertValidSignature } from './schema.js';

function collect(root: string): string[] {
  const files: string[] = [];
  const visit = (dir: string): void => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true }).sort((left, right) => left.name < right.name ? -1 : left.name > right.name ? 1 : 0)) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) visit(full);
      else if (entry.isFile() && entry.name.endsWith('.hql.json')) files.push(full);
    }
  };
  visit(root);
  return files;
}

function canonicalRoot(): string {
  const candidates = [
    path.resolve(__dirname, '../../signatures'),
    path.resolve(process.cwd(), 'signatures'),
  ];
  const root = candidates.find(candidate => fs.existsSync(candidate));
  if (!root) throw new Error(`HQL canonical signature directory not found: ${candidates.join(', ')}`);
  return root;
}

function loadCanonicalLibrary(): HQLSignature[] {
  const byId = new Map<string, HQLSignature>();
  for (const file of collect(canonicalRoot())) {
    const parsed: unknown = JSON.parse(fs.readFileSync(file, 'utf8'));
    assertValidSignature(parsed, file);
    if (byId.has(parsed.id)) throw new Error(`HQL duplicate canonical rule ID ${parsed.id}: ${file}`);
    byId.set(parsed.id, parsed);
  }
  return [...byId.values()].filter(signature => signature.status === 'released');
}

export const BUILTIN_SIGNATURES: HQLSignature[] = loadCanonicalLibrary();
