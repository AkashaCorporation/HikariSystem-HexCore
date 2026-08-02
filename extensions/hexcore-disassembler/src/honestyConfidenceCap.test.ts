/*---------------------------------------------------------------------------------------------
 * Issue #31 — honesty confidence cap unit tests
 *---------------------------------------------------------------------------------------------*/

import * as assert from 'assert';
import {
	applyHonestyConfidenceCap,
	countPostReturnLines,
	detectTextDamningDefects,
} from './honestyConfidenceCap';

suite('honestyConfidenceCap (#31)', () => {
	test('caps High when __helix_unhandled_cf_switch present', () => {
		const src = [
			'// Confidence: 87.5% (High)',
			'void sub_1(void) {',
			'  __helix_unhandled_cf_switch(v0);',
			'  return;',
			'}',
			'',
		].join('\n');
		const r = applyHonestyConfidenceCap(src);
		assert.strictEqual(r.capped, true);
		assert.strictEqual(r.newScore, 50);
		assert.ok(r.source.includes('Confidence: 50% (Low)'));
		assert.ok(r.source.includes('damning honesty defect'));
		assert.ok(r.reasons.some(x => x.includes('unrecovered control flow')));
	});

	test('does not raise or rewrite when already ≤50', () => {
		const src = [
			'// Confidence: 45% (Medium)',
			'void f(void) { __helix_unhandled_cf_switch(x); }',
		].join('\n');
		const r = applyHonestyConfidenceCap(src);
		assert.strictEqual(r.capped, false);
		assert.ok(r.source.includes('Confidence: 45%'));
	});

	test('no-op when body is clean', () => {
		const src = [
			'// Confidence: 92% (High)',
			'int f(int a) { return a + 1; }',
		].join('\n');
		const r = applyHonestyConfidenceCap(src);
		assert.strictEqual(r.capped, false);
		assert.deepStrictEqual(r.reasons, []);
		assert.strictEqual(r.source, src);
	});

	test('detects (void*)0x code-address leak', () => {
		const src = 'v = (void*)0x140005605;';
		const reasons = detectTextDamningDefects(src);
		assert.ok(reasons.some(r => r.includes('code-address leak')));
	});

	test('counts post-return executable lines', () => {
		const src = [
			'void f(void) {',
			'  int x = 1;',
			'  return;',
			'  x = 2;',
			'  x = 3;',
			'}',
		].join('\n');
		assert.strictEqual(countPostReturnLines(src), 2);
		const r = applyHonestyConfidenceCap(
			'// Confidence: 80% (High)\n' + src,
		);
		assert.strictEqual(r.capped, true);
		assert.ok(r.reasons.some(x => x.includes('after return')));
	});

	test('does not count post-return across nested if without sibling junk', () => {
		const src = [
			'void f(int c) {',
			'  if (c) {',
			'    return;',
			'  } else {',
			'    c = 1;',
			'  }',
			'}',
		].join('\n');
		// return is nested; else is sibling of if, not after return at depth 1
		assert.strictEqual(countPostReturnLines(src), 0);
	});

	test('D1 residual: cluster of bare 0x4xxxxxxx assigns caps High', () => {
		// Mirrors #31 rev_ffmodule evidence (truncated block entries as data)
		const src = [
			'// Confidence: 55% (Medium)',
			'void sub_140005510(void) {',
			'  var_0 = 0x40005605;',
			'  var_0 = 0x40005617;',
			'  var_0 = 0x40005634;',
			'  var_0 = 0x40005655;',
			'  return;',
			'}',
		].join('\n');
		const r = applyHonestyConfidenceCap(src);
		assert.strictEqual(r.capped, true);
		assert.strictEqual(r.newScore, 50);
		assert.ok(r.reasons.some(x => x.includes('bare code-address')));
	});

	test('D1 residual: single magic constant does not cap', () => {
		const src = [
			'// Confidence: 90% (High)',
			'int f(void) { int x = 0xdeadbeef; return x; }',
		].join('\n');
		const r = applyHonestyConfidenceCap(src);
		assert.strictEqual(r.capped, false);
	});

	test('#56 caps a bare-return empty stub', () => {
		const src = '// Confidence: 85% (High)\nvoid entry_point(void) {\n  return;\n}\n';
		const r = applyHonestyConfidenceCap(src);
		assert.strictEqual(r.capped, true);
		assert.ok(r.reasons.some(x => x.includes('stub/empty body')));
	});

	test('#56 caps measured under-lift', () => {
		const src = '// Confidence: 85% (High)\nint f(void) {\n  return sub_1();\n}\n';
		const r = applyHonestyConfidenceCap(src, {
			bytesConsumed: 41,
			knownFunctionSize: 389,
			cLines: 4,
		});
		assert.strictEqual(r.capped, true);
		assert.ok(r.reasons.some(x => x.includes('under-lift')));
	});

	test('#56 keeps a genuine small call wrapper', () => {
		const src = '// Confidence: 90% (High)\nint thunk(void) {\n  return real_target();\n}\n';
		const r = applyHonestyConfidenceCap(src, {
			bytesConsumed: 12,
			knownFunctionSize: 12,
			cLines: 4,
		});
		assert.strictEqual(r.capped, false);
	});

	test('#56 caps a large function collapsed to call/return even at full coverage', () => {
		const src = '// Confidence: 85% (High)\nint f(void) {\n  return sub_1();\n}\n';
		const r = applyHonestyConfidenceCap(src, {
			bytesConsumed: 389,
			knownFunctionSize: 389,
			cLines: 4,
		});
		assert.strictEqual(r.capped, true);
		assert.ok(r.reasons.some(x => x.includes('stub-shaped body')));
	});
});
