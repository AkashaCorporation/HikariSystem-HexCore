/*---------------------------------------------------------------------------------------------
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import * as assert from 'assert';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { assessAuditInputQuality, readAuditInputQuality } from './auditInputQuality';

const source = Buffer.from('int sample(void) { return 1; }');
const inputPath = 'sample.c';
const digest = crypto.createHash('sha256').update(source).digest('hex');
function entry(status = 'ok') {
	return { artifact: { path: inputPath, sha256: digest }, step: { semanticStatus: status },
		analysisContract: { status, target: { id: 'target:fixture' }, artifact: { id: `artifact:sha256:${digest}` } }, inputs: [] as any[] };
}

suite('audit input quality', () => {
	test('retains exact consumed ancestry even when the original manifest changes', () => {
		const root = fs.mkdtempSync(path.join(os.tmpdir(), 'hexcore-audit-snapshot-'));
		try {
			const input = path.join(root, 'sample.c');
			const metadata = path.join(root, '.hexcore-meta');
			const manifestPath = path.join(metadata, 'provenance.json');
			fs.mkdirSync(metadata);
			const ancestor = entry('partial'); ancestor.artifact.path = input;
			const original = JSON.stringify({ artifacts: [ancestor] });
			fs.writeFileSync(manifestPath, original);
			const result = readAuditInputQuality(input, source, [root], path.join(root, 'out', '.hexcore-meta', 'inputs'));
			assert.strictEqual(result.status, 'partial');
			assert.ok(result.reasons.includes('upstream-not-ok'));
			assert.strictEqual(result.provenanceSha256, crypto.createHash('sha256').update(original).digest('hex'));
			assert.strictEqual(result.provenanceSnapshot?.sha256, result.provenanceSha256);
			fs.writeFileSync(manifestPath, '{}');
			assert.strictEqual(fs.readFileSync(result.provenanceSnapshot!.path, 'utf8'), original);
		} finally { fs.rmSync(root, { recursive: true, force: true }); }
	});
	test('snapshot collisions cannot silently overwrite evidence or permit negatives', () => {
		const root = fs.mkdtempSync(path.join(os.tmpdir(), 'hexcore-audit-snapshot-'));
		try {
			const input = path.join(root, 'sample.c');
			fs.mkdirSync(path.join(root, '.hexcore-meta'));
			const ancestor = entry(); ancestor.artifact.path = input;
			fs.writeFileSync(path.join(root, '.hexcore-meta', 'provenance.json'), JSON.stringify({ artifacts: [ancestor] }));
			const snapshots = path.join(root, 'snapshots');
			const first = readAuditInputQuality(input, source, [root], snapshots);
			assert.strictEqual(first.status, 'ok');
			const repeat = readAuditInputQuality(input, source, [root], snapshots);
			assert.deepStrictEqual(first.provenanceSnapshot, repeat.provenanceSnapshot);
			fs.writeFileSync(first.provenanceSnapshot!.path, 'corrupt');
			const corrupt = readAuditInputQuality(input, source, [root], snapshots);
			assert.strictEqual(corrupt.status, 'partial');
			assert.strictEqual(corrupt.negativeEvidenceUsable, false);
			assert.strictEqual(corrupt.provenanceSnapshot, undefined);
			assert.strictEqual(fs.readFileSync(first.provenanceSnapshot!.path, 'utf8'), 'corrupt');
		} finally { fs.rmSync(root, { recursive: true, force: true }); }
	});
	test('permits scoped negative evidence only for the exact accepted input', () => {
		const result = assessAuditInputQuality(inputPath, source, { artifacts: [entry()] });
		assert.strictEqual(result.status, 'ok');
		assert.strictEqual(result.negativeEvidenceUsable, true);
		assert.strictEqual(result.scope, 'patterns-in-provided-source');
	});
	test('partial upstream, missing provenance and tampered input are inconclusive', () => {
		for (const result of [
			assessAuditInputQuality(inputPath, source, { artifacts: [entry('partial')] }),
			assessAuditInputQuality(inputPath, source, undefined),
			assessAuditInputQuality(inputPath, Buffer.from('int changed;'), { artifacts: [entry()] }),
		]) {
			assert.strictEqual(result.status, 'partial');
			assert.strictEqual(result.negativeEvidenceUsable, false);
		}
	});
	test('a successful child cannot hide a partial ancestor', () => {
		const child = entry();
		child.inputs = [{ id: 'parent' }];
		const parent = { ...entry('partial'), artifact: { path: 'sample.ll', sha256: 'parent-hash' },
			analysisContract: { status: 'partial', artifact: { id: 'parent' } } };
		assert.ok(assessAuditInputQuality(inputPath, source, { artifacts: [child, parent] }).reasons.includes('upstream-not-ok'));
	});
	test('cycles, unresolved parents and mismatched targets do not become clean', () => {
		const cycle = entry(); cycle.inputs.push({ id: `artifact:sha256:${digest}` });
		assert.ok(assessAuditInputQuality(inputPath, source, { artifacts: [cycle] }).reasons.includes('provenance-cycle'));
		const unresolved = entry(); unresolved.inputs.push({ id: 'missing' });
		assert.ok(assessAuditInputQuality(inputPath, source, { artifacts: [unresolved] }).reasons.includes('upstream-provenance-unresolved'));
		const child = entry(); child.inputs.push({ id: 'foreign' });
		const foreign = { ...entry(), artifact: { path: 'foreign.ll' }, analysisContract: { status: 'ok', target: { id: 'other' }, artifact: { id: 'foreign' } } };
		assert.ok(assessAuditInputQuality(inputPath, source, { artifacts: [child, foreign] }).reasons.includes('upstream-target-mismatch'));
	});
	test('Helix issue header remains a blocker even when provenance says ok', () => {
		const bytes = Buffer.from('// Issues: uninitialized return\nint f(void) { return x; }');
		const annotated = entry(); annotated.artifact.sha256 = crypto.createHash('sha256').update(bytes).digest('hex');
		assert.ok(assessAuditInputQuality(inputPath, bytes, { artifacts: [annotated] }).reasons.includes('decompiler-quality-warning'));
	});
});
