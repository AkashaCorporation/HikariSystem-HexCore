import * as assert from 'assert';
import {
	buildScanTargets,
	mapWithConcurrency,
	preserveHqlFunctionFindings,
	flattenHqlFunctionFindings,
	summarizeHqlResults,
	type HqlFunctionFindings,
} from './hqlScanner';

const clean: HqlFunctionFindings = {
	function: 'clean_negative',
	address: '0x140001000',
	nodeCount: 12,
	adapterCoverage: { totalNodes: 12, lossyNodes: 0, coverage: 1, unsupportedNodeCounts: {} },
	hast: { schemaMajor: 1, schemaMinor: 0, capabilities: ['node-ids', 'symbol-identities', 'typed-child-roles'], architecture: 'x86_64', pointerBits: 64, semanticEligible: true },
	signatureSetSha256: 'a'.repeat(64),
	cacheKey: 'b'.repeat(64),
	status: 'ok',
	truncated: false,
	truncationReasons: [],
	partialReasons: [],
	evaluatedSignatureCount: 12,
	semanticFactCount: 0,
	semanticFactsSha256: 'c'.repeat(64),
	semanticReadErrors: [],
	findings: [],
};
const cleanResult = flattenHqlFunctionFindings([clean], 'fallback');
assert.strictEqual(cleanResult.function, 'clean_negative');
assert.strictEqual(cleanResult.status, 'ok');
assert.strictEqual(cleanResult.address, '0x140001000');
assert.strictEqual(cleanResult.nodeCount, 12);
	assert.strictEqual(cleanResult.findings.length, 0);
	assert.strictEqual(cleanResult.signatureSetSha256, 'a'.repeat(64));
	assert.strictEqual(cleanResult.semanticFactCount, 0);
	assert.strictEqual(cleanResult.semanticFactsSha256, 'c'.repeat(64));

const signal: HqlFunctionFindings = {
	...clean,
	function: 'xor_worker',
	address: '0x140002000',
	findings: [{
		signatureId: 'crypto.xor_present',
		matches: [{ kind: 'CBinaryExpr' }],
		structuralCompleteness: 1,
		evidenceLevel: 'signal',
		adapterCoverage: 1,
		semanticMatches: [{
			kind: 'function-prototype',
			attributes: { callingConventionId: 'win64' },
			proofStatus: 'proven',
			provenance: [{ producer: 'pdb:test', source: 'debug-info', strength: 'debug', generation: 3 }],
		}],
	}],
};
const signalResult = flattenHqlFunctionFindings([signal], 'fallback');
assert.deepStrictEqual(signalResult.findings[0], {
	signatureId: 'crypto.xor_present',
	structuralCompleteness: 1,
	evidenceLevel: 'signal',
	adapterCoverage: 1,
	semanticMatches: [{
		kind: 'function-prototype',
		attributes: { callingConventionId: 'win64' },
		proofStatus: 'proven',
		provenance: [{ producer: 'pdb:test', source: 'debug-info', strength: 'debug', generation: 3 }],
	}],
	matchCount: 1,
});
assert.ok(!('confidence' in signalResult.findings[0]));
const preserved = preserveHqlFunctionFindings([clean, signal], 'fallback', '<ir-text>');
assert.strictEqual(preserved.length, 2);
assert.deepStrictEqual(preserved.map(result => result.function), ['clean_negative', 'xor_worker']);
assert.deepStrictEqual(preserved.map(result => result.address), ['0x140001000', '0x140002000']);
assert.ok(preserved.every(result => result.requestedTarget === '<ir-text>'));

const empty = flattenHqlFunctionFindings([], '0xdead');
assert.match(empty.error ?? '', /no functions/);
assert.strictEqual(summarizeHqlResults([cleanResult]).status, 'ok');
assert.strictEqual(summarizeHqlResults([empty]).status, 'failed');
assert.deepStrictEqual(buildScanTargets({ file: 'x.exe', addresses: ['0x1', '0x1', '0x2'] }), [
	{ file: 'x.exe', address: '0x1' },
	{ file: 'x.exe', address: '0x2' },
]);
assert.deepStrictEqual(buildScanTargets({ irPath: 'sample.ll', addresses: ['0x1'] }), [{ irPath: 'sample.ll', irText: undefined }]);

void (async () => {
	let active = 0;
	let peak = 0;
	const ordered = await mapWithConcurrency([30, 5, 15, 1], 2, async (delay, index) => {
		active++;
		peak = Math.max(peak, active);
		await new Promise(resolve => setTimeout(resolve, delay));
		active--;
		return index;
	});
	assert.deepStrictEqual(ordered, [0, 1, 2, 3]);
	assert.strictEqual(peak, 2);
	await assert.rejects(() => mapWithConcurrency([], 0, async () => 0), /positive safe integer/);
	console.log('hqlScannerContract: clean identity, evidence contract, budgets, and bounded concurrency - OK');
})().catch(error => {
	console.error(error);
	process.exitCode = 1;
});
