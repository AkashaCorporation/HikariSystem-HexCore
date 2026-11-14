/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Akasha Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as assert from 'assert';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { HQLMatcher } from '../src/engine/matcher.js';
import { canonicalJson, canonicalSha256 } from '../src/atlas/canonical.js';
import { loadHqlPackageAtlasSource } from '../src/atlas/gitSource.js';
import { loadSignatureDirectory } from '../src/signatures/loader.js';
import {
	compileHql,
	compileHqlDetailed,
	formatHql,
	formatHqlSignature,
	HqlCompileError,
} from '../src/text/index.js';
import type { CFunctionDecl, CNode } from '../src/types/ast.js';
import type { HQLSemanticFact, HQLSignature } from '../src/types/hql.js';

const fixtures = path.resolve(__dirname, 'fixtures', 'textual');
const sourcePath = path.join(fixtures, 'v1', 'memory-allocator.hql');
const jsonPath = path.join(fixtures, 'v1', 'memory-allocator.hql.json');
const source = fs.readFileSync(sourcePath, 'utf8');
const expected = JSON.parse(fs.readFileSync(jsonPath, 'utf8')) as HQLSignature;

const compiled = compileHqlDetailed(source, { filename: sourcePath });
assert.strictEqual(compiled.hqlVersion, '1.0');
assert.strictEqual(compiled.compilerVersion, '1.0.0');
assert.deepStrictEqual(compiled.signature, expected);
assert.strictEqual(compiled.signatureSha256, canonicalSha256(expected));
assert.strictEqual(compiled.canonicalJson, canonicalJson(expected));

const formatted = formatHql(source, { filename: sourcePath });
assert.strictEqual(formatHql(formatted, { filename: '<formatted>' }), formatted);
assert.deepStrictEqual(compileHql(formatted), expected);

const legacyQueries = JSON.parse(fs.readFileSync(
	path.resolve(__dirname, '..', 'signatures', 'memory-safety', 'refcount-uaf.hql.json'), 'utf8',
)) as HQLSignature;
const legacyText = formatHqlSignature(legacyQueries);
assert.deepStrictEqual(compileHql(legacyText), legacyQueries);
assert.strictEqual(formatHql(legacyText), legacyText);
assert.strictEqual(canonicalSha256(compileHql(legacyText)), canonicalSha256(legacyQueries));

const signatureRoot = path.resolve(__dirname, '..', 'signatures');
const signatureFiles: string[] = [];
const collectSignatures = (directory: string): void => {
	for (const entry of fs.readdirSync(directory, { withFileTypes: true }).sort((left, right) => left.name.localeCompare(right.name))) {
		const absolute = path.join(directory, entry.name);
		if (entry.isDirectory()) collectSignatures(absolute);
		else if (entry.isFile() && entry.name.endsWith('.hql.json')) signatureFiles.push(absolute);
	}
};
collectSignatures(signatureRoot);
for (const file of signatureFiles) {
	const jsonSignature = JSON.parse(fs.readFileSync(file, 'utf8')) as HQLSignature;
	const text = formatHqlSignature(jsonSignature);
	assert.deepStrictEqual(compileHql(text, { filename: `${file}.formatted.hql` }), jsonSignature, file);
	assert.strictEqual(formatHql(text), text, file);
}
assert.strictEqual(signatureFiles.length, 12);

const value = (name: string, type = 'void *') => ({ kind: 'CVarRefExpr' as const, name, type });
const field = { kind: 'CFieldAccessExpr' as const, object: value('ctx', 'struct context *'), field: 'buffer', arrow: true };
const cast = { kind: 'CCastExpr' as const, targetType: 'void *', operand: value('input') };
const call = { kind: 'CCallExpr' as const, callee: 'malloc', arguments: [value('count', 'size_t'), cast] };
const loop = { kind: 'CForStmt' as const, body: { kind: 'CBlockStmt' as const, body: [call] } };
const ast: CFunctionDecl = {
	kind: 'CFunctionDecl', name: 'allocate', returnType: 'void *', params: [],
	body: { kind: 'CBlockStmt', body: [loop, field] as CNode[] },
};
const provenance = [{ producer: 'fixture', source: 'debug-info', strength: 'debug', generation: 1 }];
const facts: HQLSemanticFact[] = [
	{ kind: 'summary-ownership', attributes: { ownershipKind: 'allocate', valueIdentity: 'value:1', objectIdentity: 'object:1', generation: 1 }, proofStatus: 'candidate', provenance },
	{ kind: 'summary-call', attributes: { callsiteIdentity: 'call:1', calleeIdentity: 'function:malloc', argumentCount: 2, indirectCandidateCount: 0, generation: 1 }, proofStatus: 'candidate', provenance },
];
const matcher = new HQLMatcher();
const textResult = matcher.evaluate(ast, compiled.signature, facts);
const jsonResult = matcher.evaluate(ast, expected, facts);
assert.deepStrictEqual(textResult, jsonResult);
assert.strictEqual(canonicalSha256(textResult), canonicalSha256(jsonResult));
assert.ok(textResult);

const scalarEdges = compileHql(`hql 1.0;
rule "edge.scalars" {
	name "Scalar edges";
	description "Exercises escaped regex and signed hexadecimal values.";
	severity info;
	where all {
		ast CCallExpr { callee == /api\\/v1/; };
		ast CIntLitExpr { value == -0x10; };
	}
}`);
const scalarConditions = scalarEdges.condition && 'all' in scalarEdges.condition ? scalarEdges.condition.all : [];
assert.strictEqual((scalarConditions[0] as any).query.attributes[0].value, 're:api/v1');
assert.strictEqual((scalarConditions[1] as any).query.attributes[0].value, -16);
const scalarText = formatHqlSignature(scalarEdges);
assert.strictEqual(formatHql(scalarText), scalarText);

const invalidExpectations: Record<string, { code: string; suggestion?: string }> = {
	'invalid-node.hql': { code: 'HQL1006', suggestion: 'CStringLitExpr' },
	'invalid-field.hql': { code: 'HQL1007', suggestion: "did you mean 'callee'?" },
	'invalid-operator.hql': { code: 'HQL1008' },
	'invalid-fact.hql': { code: 'HQL1009', suggestion: 'summary-ownership' },
	'invalid-fact-field.hql': { code: 'HQL1010', suggestion: 'ownershipKind' },
	'invalid-regex.hql': { code: 'HQL1011' },
	'invalid-version.hql': { code: 'HQL1003' },
	'mixed-any.hql': { code: 'HQL1012' },
	'arbitrary-code.hql': { code: 'HQL1002' },
};
for (const [file, expectation] of Object.entries(invalidExpectations)) {
	const filename = path.join(fixtures, 'invalid', file);
	let error: unknown;
	try { compileHql(fs.readFileSync(filename, 'utf8'), { filename }); } catch (caught) { error = caught; }
	assert.ok(error instanceof HqlCompileError, `${file} did not fail with HqlCompileError`);
	const diagnostic = (error as HqlCompileError).diagnostics[0];
	assert.strictEqual(diagnostic.code, expectation.code, `${file}: ${(error as Error).message}`);
	assert.strictEqual(diagnostic.filename, filename);
	assert.ok(diagnostic.span.start.line > 0 && diagnostic.span.start.column > 0);
	assert.ok(diagnostic.excerpt.length > 0);
	if (expectation.suggestion) assert.match((error as Error).message, new RegExp(expectation.suggestion.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
}

assert.throws(() => compileHql(source, { filename: sourcePath, hqlVersion: '9.0' }), /HQL1003/);
assert.throws(() => compileHql(source, { filename: sourcePath, maxSourceBytes: 32 }), /HQL1015/);
assert.throws(() => compileHql(source, { filename: sourcePath, maxTokens: 4 }), /HQL1015/);
assert.throws(() => compileHql(`hql 1.0; rule "deep.rule" { name "Deep"; description "Deep"; severity info; where not not not ast CCallExpr {} }`, { maxDepth: 2 }), /HQL1015/);
assert.throws(() => compileHql(`hql 1.0; rule "invalid.comparison" { name "Invalid"; description "Invalid"; severity info; where ast CCallExpr { callee != "malloc"; } }`), /HQL1008/);

const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'hql-text-loader-'));
try {
	fs.copyFileSync(sourcePath, path.join(temp, 'rule.hql'));
	const loaded = loadSignatureDirectory(temp);
	assert.strictEqual(loaded.length, 1);
	assert.deepStrictEqual(loaded[0], expected);
	fs.copyFileSync(path.join(fixtures, 'invalid', 'invalid-field.hql'), path.join(temp, 'invalid.hql'));
	assert.throws(() => loadSignatureDirectory(temp), /HQL1007/);
	fs.rmSync(path.join(temp, 'invalid.hql'));
	fs.copyFileSync(jsonPath, path.join(temp, 'duplicate.hql.json'));
	assert.throws(() => loadSignatureDirectory(temp), /duplicate signature ID/);
} finally {
	fs.rmSync(temp, { recursive: true, force: true });
}

const atlasTemp = fs.mkdtempSync(path.join(os.tmpdir(), 'hql-text-atlas-'));
try {
	const packageRoot = path.resolve(__dirname, '..');
	fs.cpSync(path.join(packageRoot, 'signatures'), path.join(atlasTemp, 'signatures'), { recursive: true });
	fs.cpSync(path.join(packageRoot, 'atlas', 'fixtures'), path.join(atlasTemp, 'atlas', 'fixtures'), { recursive: true });
	fs.mkdirSync(path.join(atlasTemp, 'benchmarks'), { recursive: true });
	fs.copyFileSync(path.join(packageRoot, 'benchmarks', 'third_party.lock.json'), path.join(atlasTemp, 'benchmarks', 'third_party.lock.json'));
	const timingJson = path.join(atlasTemp, 'signatures', 'anti-analysis', 'timing-check.hql.json');
	const timing = JSON.parse(fs.readFileSync(timingJson, 'utf8')) as HQLSignature;
	fs.writeFileSync(timingJson.slice(0, -'.json'.length), formatHqlSignature(timing), 'utf8');
	fs.rmSync(timingJson);
	const atlas = loadHqlPackageAtlasSource(atlasTemp);
	const timingRecord = atlas.records.find(record => record.record.recordType === 'rule' && record.record.id === timing.id);
	assert.ok(timingRecord && timingRecord.record.recordType === 'rule');
	assert.deepStrictEqual(timingRecord.record.signature, timing);
	assert.ok(atlas.files.some(file => file.path.endsWith('timing-check.hql')));
} finally {
	fs.rmSync(atlasTemp, { recursive: true, force: true });
}

for (let iteration = 0; iteration < 100; iteration++) {
	const repeat = compileHqlDetailed(source, { filename: sourcePath });
	assert.strictEqual(repeat.signatureSha256, compiled.signatureSha256);
	assert.strictEqual(formatHql(source, { filename: sourcePath }), formatted);
}

let seed = 0x66c0ffee;
const mutationAlphabet = '{}[]();,=@`/"0123456789abcdefghijklmnopqrstuvwxyz\n';
for (let iteration = 0; iteration < 256; iteration++) {
	seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0;
	const offset = seed % source.length;
	const replacement = mutationAlphabet[(seed >>> 8) % mutationAlphabet.length];
	const mutated = source.slice(0, offset) + replacement + source.slice(offset + 1);
	try {
		compileHql(mutated, { filename: `mutation-${iteration}.hql` });
	} catch (error) {
		assert.ok(error instanceof HqlCompileError, `mutation ${iteration} escaped the typed diagnostic contract: ${String(error)}`);
	}
}

console.log(`textCompiler: parity, ${signatureFiles.length} corpus round-trips, diagnostics, loader/Atlas, 100 deterministic runs and 256 mutations - OK (${compiled.signatureSha256})`);
