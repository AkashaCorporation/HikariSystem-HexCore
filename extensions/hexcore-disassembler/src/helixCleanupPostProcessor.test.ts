/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

// Feature: v3.8.0 Helix Cleanup Post-Processor
// Target: helixCleanupPostProcessor.ts (4 passes — literal-cast strip, intrinsic
// normalize, logical-op fix on negations, dead-decl prune with register allowlist)

import * as assert from 'assert';
import 'mocha';
// eslint-disable-next-line local/code-import-patterns
import * as fc from 'fast-check';
import { cleanupHelixSource, type CleanupOptions } from './helixCleanupPostProcessor';

suite('helixCleanupPostProcessor', () => {

	// -----------------------------------------------------------------------
	// 1. Literal-cast strip — BigInt range check
	// -----------------------------------------------------------------------

	suite('stripLiteralCasts', () => {

		test('removes (int32_t)1 → 1', () => {
			const r = cleanupHelixSource('x = (int32_t)1;');
			assert.strictEqual(r.source, 'x = 1;');
			assert.strictEqual(r.stats.redundantCasts, 1);
		});

		test('removes (uint8_t)0xFF → 0xFF (in-range)', () => {
			const r = cleanupHelixSource('x = (uint8_t)0xFF;');
			assert.strictEqual(r.source, 'x = 0xFF;');
		});

		test('KEEPS (uint8_t)0x100 — out of range (truncation is load-bearing)', () => {
			const r = cleanupHelixSource('x = (uint8_t)0x100;');
			// Regression: the cast mathematically truncates — MUST preserve.
			assert.ok(r.source.includes('(uint8_t)0x100'));
			assert.strictEqual(r.stats.redundantCasts, 0);
		});

		test('KEEPS (int8_t)128 — overflow from signed range', () => {
			const r = cleanupHelixSource('x = (int8_t)128;');
			assert.ok(r.source.includes('(int8_t)128'));
			assert.strictEqual(r.stats.redundantCasts, 0);
		});

		test('KEEPS (int32_t)var — non-literal operand', () => {
			// Cast of non-literal expression may be load-bearing (sign-extension etc).
			const r = cleanupHelixSource('x = (int32_t)var;');
			assert.ok(r.source.includes('(int32_t)var'));
			assert.strictEqual(r.stats.redundantCasts, 0);
		});

		test('KEEPS (int64_t)(x + 1) — expression operand', () => {
			const r = cleanupHelixSource('x = (int64_t)(x + 1);');
			assert.ok(r.source.includes('(int64_t)'));
		});

		// PBT: for any in-range integer literal, strip leaves the value intact.
		test('PBT: in-range literals are stripped AND value preserved', () => {
			fc.assert(
				fc.property(
					fc.constantFrom(
						{ ty: 'int8_t', min: -128n, max: 127n },
						{ ty: 'int16_t', min: -32768n, max: 32767n },
						{ ty: 'int32_t', min: -(2n ** 31n), max: 2n ** 31n - 1n },
						{ ty: 'int64_t', min: -(2n ** 63n), max: 2n ** 63n - 1n },
						{ ty: 'uint8_t', min: 0n, max: 255n },
						{ ty: 'uint16_t', min: 0n, max: 65535n },
						{ ty: 'uint32_t', min: 0n, max: 2n ** 32n - 1n },
						{ ty: 'uint64_t', min: 0n, max: 2n ** 64n - 1n },
					),
					fc.bigInt({ min: -(2n ** 63n), max: 2n ** 64n - 1n }),
					({ ty, min, max }, vRaw) => {
						// Clamp to the type range (simulate in-range literal).
						if (vRaw < min || vRaw > max) { return; }
						// Use decimal literal — avoids hex sign ambiguity.
						const expr = `x = (${ty})${vRaw.toString()};`;
						const r = cleanupHelixSource(expr);
						assert.strictEqual(r.source, `x = ${vRaw.toString()};`);
						assert.strictEqual(r.stats.redundantCasts, 1);
					},
				),
				{ seed: 42, numRuns: 500 },
			);
		});
	});

	// -----------------------------------------------------------------------
	// 2. Intrinsic normalization
	// -----------------------------------------------------------------------

	suite('normalizeIntrinsics', () => {

		test('rewrites __unknown_llvm.intr.fabs → fabs', () => {
			const r = cleanupHelixSource('y = __unknown_llvm.intr.fabs(x);');
			assert.strictEqual(r.source, 'y = fabs(x);');
			assert.strictEqual(r.stats.intrinsicsNormalized, 1);
		});

		test('rewrites bit intrinsics to __builtin_* equivalents', () => {
			const src = 'a = __unknown_llvm.intr.ctpop(r1); b = __unknown_llvm.intr.bswap(r2);';
			const r = cleanupHelixSource(src);
			assert.ok(r.source.includes('__builtin_popcount(r1)'));
			assert.ok(r.source.includes('__builtin_bswap32(r2)'));
			assert.strictEqual(r.stats.intrinsicsNormalized, 2);
		});

		test('leaves unknown intrinsics alone', () => {
			const src = 'z = __unknown_llvm.intr.someNewBuiltin(q);';
			const r = cleanupHelixSource(src);
			assert.ok(r.source.includes('__unknown_llvm.intr.someNewBuiltin'));
			assert.strictEqual(r.stats.intrinsicsNormalized, 0);
		});
	});

	// -----------------------------------------------------------------------
	// 3. Logical-op fix on negations
	// -----------------------------------------------------------------------

	suite('fixLogicalOps', () => {

		test('upgrades !a | !b to !a || !b', () => {
			const r = cleanupHelixSource('if (!a | !b) return 0;');
			assert.strictEqual(r.source, 'if (!a || !b) return 0;');
			assert.strictEqual(r.stats.logicalOpsFixed, 1);
		});

		test('upgrades !a & !b to !a && !b', () => {
			const r = cleanupHelixSource('if (!a & !b) return 0;');
			assert.strictEqual(r.source, 'if (!a && !b) return 0;');
		});

		test('KEEPS a | b (no negation — could be genuine bitmask)', () => {
			// Regression: the fix MUST NOT rewrite `a | b` — that may be a real
			// bitwise operation (flag merge etc). Only `!a | !b` is safe.
			const r = cleanupHelixSource('flags = a | b;');
			assert.strictEqual(r.source, 'flags = a | b;');
			assert.strictEqual(r.stats.logicalOpsFixed, 0);
		});

		test('KEEPS !a | b (only one side negated)', () => {
			const r = cleanupHelixSource('x = !a | b;');
			assert.strictEqual(r.source, 'x = !a | b;');
			assert.strictEqual(r.stats.logicalOpsFixed, 0);
		});

		test('KEEPS (cond) | (cond) — could be wide-integer mask', () => {
			// Documented in the source: "we do NOT replace (cond) | (cond)"
			const r = cleanupHelixSource('x = (rax_2 & 1) | (rbx_2 & 1);');
			assert.strictEqual(r.stats.logicalOpsFixed, 0);
		});
	});

	// -----------------------------------------------------------------------
	// 4. Dead-decl pruning — register allowlist
	// -----------------------------------------------------------------------

	suite('pruneDeadDeclarations', () => {

		test('removes unused register shadow: int64_t rax;', () => {
			const src = [
				'int main() {',
				'  int64_t rax;',
				'  int32_t x = 5;',
				'  return x;',
				'}'
			].join('\n');
			const r = cleanupHelixSource(src);
			assert.ok(!r.source.includes('int64_t rax;'));
			assert.strictEqual(r.stats.deadDeclarations, 1);
		});

		test('KEEPS register shadow when referenced later', () => {
			const src = [
				'int main() {',
				'  int64_t rax;',
				'  rax = 5;',
				'  return (int)rax;',
				'}'
			].join('\n');
			const r = cleanupHelixSource(src);
			assert.ok(r.source.includes('int64_t rax;'));
			assert.strictEqual(r.stats.deadDeclarations, 0);
		});

		test('KEEPS user-like names even when unused (conservative)', () => {
			// Documented: we don't delete names that "a human reader might want to
			// see even unused". `myLocal` is not a register name.
			const src = [
				'int main() {',
				'  int64_t myLocal;',
				'  return 0;',
				'}'
			].join('\n');
			const r = cleanupHelixSource(src);
			assert.ok(r.source.includes('int64_t myLocal;'));
			assert.strictEqual(r.stats.deadDeclarations, 0);
		});

		test('KEEPS declarations with initializers (side effects)', () => {
			const src = [
				'int main() {',
				'  int64_t rax = callHasSideEffect();',
				'  return 0;',
				'}'
			].join('\n');
			const r = cleanupHelixSource(src);
			// SIMPLE_DECL_PATTERN rejects `=` so initializer lines never match.
			assert.ok(r.source.includes('rax = callHasSideEffect()'));
			assert.strictEqual(r.stats.deadDeclarations, 0);
		});

		test('removes xmm shadow: double xmm0;', () => {
			const src = 'int main() {\n  double xmm0;\n  return 0;\n}';
			const r = cleanupHelixSource(src);
			assert.ok(!r.source.includes('double xmm0;'));
		});
	});

	// -----------------------------------------------------------------------
	// Idempotence — running cleanup twice gives same result as once
	// -----------------------------------------------------------------------

	suite('idempotence (apply 2x == apply 1x)', () => {

		test('PBT: cleanup is idempotent across arbitrary short C fragments', () => {
			const lineArb = fc.oneof(
				fc.constantFrom(
					'x = (int32_t)1;',
					'y = (uint8_t)0xFF;',
					'if (!a | !b) goto L;',
					'z = __unknown_llvm.intr.fabs(w);',
					'q = (int8_t)200;',               // out-of-range, untouched
					'flags = a | b;',                 // untouched
					'int64_t rax;',
					'int32_t user_var;',
				),
			);
			fc.assert(
				fc.property(
					fc.array(lineArb, { minLength: 1, maxLength: 10 }),
					(lines) => {
						const src = ['int fn(){', ...lines, 'return 0;', '}'].join('\n');
						const first = cleanupHelixSource(src);
						const second = cleanupHelixSource(first.source);
						// Idempotent: a second pass must not rewrite anything.
						assert.strictEqual(second.stats.totalRewrites, 0,
							`expected 0 rewrites on 2nd pass, got ${second.stats.totalRewrites}. 1st pass output:\n${first.source}`);
						assert.strictEqual(second.source, first.source);
					},
				),
				{ seed: 1337, numRuns: 300 },
			);
		});
	});

	// -----------------------------------------------------------------------
	// Opt-out — options.cleanup=false via helixWrapper wiring
	// -----------------------------------------------------------------------

	suite('options gating', () => {

		test('disabling stripLiteralCasts leaves casts intact', () => {
			const opts: CleanupOptions = { stripLiteralCasts: false };
			const r = cleanupHelixSource('x = (int32_t)1;', opts);
			assert.ok(r.source.includes('(int32_t)1'));
		});

		test('disabling all passes leaves source unchanged', () => {
			const opts: CleanupOptions = {
				stripLiteralCasts: false,
				normalizeIntrinsics: false,
				fixLogicalOps: false,
				pruneDeadDeclarations: false,
			};
			const src = 'int main() {\n  int64_t rax;\n  x = (int32_t)1;\n  if (!a | !b) return 0;\n}';
			const r = cleanupHelixSource(src, opts);
			assert.strictEqual(r.source, src);
			assert.strictEqual(r.stats.totalRewrites, 0);
		});
	});
});
