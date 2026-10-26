import * as assert from 'assert';
import { analyzeConstantSanity } from './constantSanityChecker';
import type { Instruction } from './disassemblerEngine';

function instruction(address: number, opStr: string, comment?: string): Instruction {
	return {
		address,
		bytes: Buffer.from([0x90]),
		mnemonic: 'mov',
		opStr,
		size: 1,
		comment,
		isCall: false,
		isJump: false,
		isRet: false,
		isConditional: false,
	};
}

suite('constant sanity checker evidence contract', () => {
	test('empty analysis is partial and not negative evidence', () => {
		const result = analyzeConstantSanity([]);
		assert.strictEqual(result.status, 'partial');
		assert.strictEqual(result.conclusion, 'not-assessed');
		assert.strictEqual(result.evaluatedAnnotations, 0);
		assert.strictEqual(result.negativeEvidenceUsable, false);
		assert.deepStrictEqual(result.diagnostics.map(item => item.code), ['NO_INSTRUCTIONS']);
		assert.match(result.reportMarkdown, /absence of mismatches is not negative evidence/);
	});

	test('immediates without annotations do not produce a clean verdict', () => {
		const result = analyzeConstantSanity([instruction(0x1000, 'eax, 0x2a')]);
		assert.strictEqual(result.status, 'partial');
		assert.strictEqual(result.conclusion, 'not-assessed');
		assert.deepStrictEqual(result.diagnostics.map(item => item.code), ['NO_ANNOTATIONS']);
	});

	test('ambiguous annotations remain unevaluated', () => {
		const result = analyzeConstantSanity([
			instruction(0x1000, 'eax, 0x2a', 'expected 42 or 43'),
		]);
		assert.strictEqual(result.annotationsConsidered, 1);
		assert.strictEqual(result.ambiguousAnnotations, 1);
		assert.strictEqual(result.evaluatedAnnotations, 0);
		assert.strictEqual(result.status, 'partial');
		assert.deepStrictEqual(result.diagnostics.map(item => item.code), ['NO_EVALUABLE_ANNOTATIONS']);
	});

	test('a real match permits a bounded negative conclusion', () => {
		const result = analyzeConstantSanity([
			instruction(0x1000, 'eax, 0x2a', 'expected 42'),
		]);
		assert.strictEqual(result.status, 'ok');
		assert.strictEqual(result.conclusion, 'matched');
		assert.strictEqual(result.evaluatedAnnotations, 1);
		assert.strictEqual(result.negativeEvidenceUsable, true);
		assert.deepStrictEqual(result.diagnostics, []);
	});

	test('mismatches are assessed but never negative evidence', () => {
		const result = analyzeConstantSanity([
			instruction(0x1000, 'eax, 0x2a', 'expected 41'),
		]);
		assert.strictEqual(result.status, 'ok');
		assert.strictEqual(result.conclusion, 'mismatched');
		assert.strictEqual(result.mismatchedAnnotations, 1);
		assert.strictEqual(result.negativeEvidenceUsable, false);
		assert.strictEqual(result.findings.length, 1);
	});

	test('truncated mismatch output is visibly partial', () => {
		const result = analyzeConstantSanity([
			instruction(0x1000, 'eax, 1', 'expected 2'),
			instruction(0x1001, 'eax, 3', 'expected 4'),
		], { maxFindings: 1 });
		assert.strictEqual(result.status, 'partial');
		assert.strictEqual(result.conclusion, 'mismatched');
		assert.strictEqual(result.mismatchedAnnotations, 2);
		assert.strictEqual(result.findings.length, 1);
		assert.deepStrictEqual(result.diagnostics.map(item => item.code), ['FINDINGS_TRUNCATED']);
	});
});
