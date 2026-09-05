import * as fs from 'fs';
import * as crypto from 'crypto';
import * as path from 'path';
import { loadPdbProvider } from '../../src/pdbProvider';

const manifestPath = path.resolve(process.argv[2] ?? '');
const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8').replace(/^\uFEFF/, '')) as any;
const source = fs.readFileSync(manifest.sourcePath, 'utf8');
const functions = [...source.matchAll(/^\/\/ HXGT (\{.+\})$/gm)].map(match => JSON.parse(match[1]));
const sourceRecords = [...source.matchAll(/^\/\/ HXGT_RECORD (\{.+\})$/gm)].map(match => JSON.parse(match[1]));
const configurations: any[] = [];
for (const entry of manifest.entries) {
  const expectedFunctions = Object.fromEntries(functions.map(item => [item.function, {
    ...item,
    expectedCallingConvention: entry.architecture === 'x64' ? item.x64Convention ?? 'win64' : item.x86Convention ?? 'cdecl',
    export: entry.exports.find((candidate: any) => candidate.name === item.function),
  }]));
  let pdb: any = null;
  if (entry.pdbPath) {
    pdb = loadPdbProvider({ pdbPath: entry.pdbPath, imageBase: entry.architecture === 'x86' ? 0x10000000 : 0x180000000 });
    if (pdb.status === 'error' || !pdb.identityValidated) throw new Error(`${entry.id}: PDB provider failed`);
    for (const [name, expected] of Object.entries(expectedFunctions) as any) {
      const symbol = pdb.functions.find((fn: any) => fn.name === name);
      if (!symbol) throw new Error(`${entry.id}: PDB missing ${name}`);
      expected.pdb = { address: symbol.address, size: symbol.size, prototype: symbol.prototype, locals: symbol.locals };
    }
  }
  configurations.push({ id: entry.id, binarySha256: entry.binarySha256, pdbSha256: entry.pdbSha256, functions: expectedFunctions, pdbIdentity: pdb?.identity ?? null, pdbContentHash: pdb?.contentHash ?? null,
    records: pdb ? Object.fromEntries(sourceRecords.map(record => [record.name, pdb.debugTypes.structs[record.name] ?? null])) : null });
}
const logical = { schemaVersion: 1, corpusId: manifest.corpusId, sourceSha256: manifest.sourceSha256, sourceAnnotationsSha256: crypto.createHash('sha256').update(JSON.stringify({functions,sourceRecords})).digest('hex'), configurations };
const output = { ...logical, contentHash: crypto.createHash('sha256').update(JSON.stringify(logical)).digest('hex') };
fs.writeFileSync(path.join(path.dirname(manifestPath), 'ground-truth.json'), JSON.stringify(output, null, 2) + '\n');
console.log(`Ground truth: ${configurations.length} configurations, ${functions.length} functions, ${sourceRecords.length} records, ${output.contentHash}`);
