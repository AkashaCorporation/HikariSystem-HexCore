import * as assert from 'assert';
import * as fs from 'fs';
import * as path from 'path';
import { scanHAST } from '../src/scan.js';
import type { HQLUpstreamQuality } from '../src/scan.js';
import type { HQLSignature } from '../src/types/hql.js';

const bytes = fs.readFileSync(path.join(__dirname, 'fixtures', 'semantic-quality-v1_1.fb'));
const signature: HQLSignature = {
  id: 'test.upstream', name: 'Upstream contract', description: 'Synthetic root query',
  severity: 'info', evidenceLevel: 'proven', condition: { query: { target: 'CFunctionDecl' } },
};
const complete = scanHAST(bytes, [signature], undefined, { upstream: { architecture: 'arm64', status: 'ok' } })[0];
assert.strictEqual(complete.status, 'ok');
assert.strictEqual(complete.hast.architecture, 'aarch64');
assert.strictEqual(complete.hast.semanticEligible, true);
assert.strictEqual(complete.evaluatedSignatureCount, 1);

const incompleteInputs: HQLUpstreamQuality[] = [
  { architecture: 'arm64', status: 'partial', warning: 'function boundary not reached' },
  { architecture: 'x64', status: 'ok' },
  { architecture: 'arm64', status: 'ok', semanticEligible: false },
  { architecture: 'arm64', status: 'ok', qualityIssues: ['placeholder variables'] },
  { architecture: 'arm64', status: 'ok', qualityIssues: [{ kind: 'incomplete-lift', count: 1, detail: 'requested byte coverage is 9.4%' }] },
  { architecture: 'arm64', status: 'error' },
  { architecture: 'arm64' },
];
for (const upstream of incompleteInputs) {
  const result = scanHAST(bytes, [signature], undefined, { upstream })[0];
  assert.strictEqual(result.status, 'partial');
  assert.strictEqual(result.adapterCoverage.coverage, 1, 'adapter coverage must retain its original meaning');
  assert.strictEqual(result.hast.semanticEligible, false);
  assert.strictEqual(result.hast.architecture, 'aarch64', 'do not rewrite conflicting serialized metadata');
  assert.strictEqual(result.evaluatedSignatureCount, 0);
  assert.strictEqual(result.findings.length, 0);
  assert.ok(result.partialReasons.length > 0);
  assert.notStrictEqual(result.cacheKey, complete.cacheKey);
  assert.deepStrictEqual(scanHAST(bytes, [signature], undefined, { upstream })[0], result);
}
const structured = scanHAST(bytes, [signature], undefined, {
  upstream: { architecture: 'arm64', status: 'ok', qualityIssues: [{ kind: 'incomplete-lift', count: 1, detail: 'requested byte coverage is 9.4%' }] },
})[0];
assert.ok(structured.partialReasons.includes('Upstream quality issue: requested byte coverage is 9.4%'));
assert.ok(!structured.partialReasons.some(reason => reason.includes('[object Object]')));
assert.strictEqual(structured.signatureSetScope, 'active-rule-set');
console.log('upstreamQuality: architecture, partial-state, eligibility and deterministic cache gates - OK');
