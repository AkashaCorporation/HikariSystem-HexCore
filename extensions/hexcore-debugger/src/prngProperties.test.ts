/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

// Feature: v3.7.1, Properties P2.1–P2.5: PRNG Determinism & Isolation

import * as assert from 'assert';
import * as fc from 'fast-check';
import { createPRNG, GlibcPRNG, MsvcrtPRNG } from './prng';

suite('Property P2: PRNG Determinism', () => {

	/**
	 * P2.1: createPRNG('stub') returns undefined → rand() should return 0n.
	 * Since stub returns undefined, the caller (linuxApiHooks) returns 0n.
	 */
	test('stub PRNG always returns undefined (caller returns 0n)', () => {
		fc.assert(
			fc.property(fc.integer({ min: 0, max: 1000 }), (_iteration) => {
				const prng = createPRNG('stub');
				assert.strictEqual(prng, undefined, 'stub mode must return undefined');
			}),
			{ numRuns: 100 }
		);
	});

	/**
	 * P2.2: Glibc PRNG with same seed produces identical sequence.
	 */
	test('glibc PRNG deterministic with same seed', () => {
		fc.assert(
			fc.property(
				fc.nat({ max: 0x7FFFFFFF }),
				fc.integer({ min: 1, max: 50 }),
				(seed, count) => {
					const a = createPRNG('glibc')!;
					const b = createPRNG('glibc')!;
					a.seed(seed);
					b.seed(seed);

					for (let i = 0; i < count; i++) {
						const va = a.rand();
						const vb = b.rand();
						assert.strictEqual(va, vb, `Mismatch at iteration ${i} with seed ${seed}`);
					}
				}
			),
			{ numRuns: 100 }
		);
	});

	/**
	 * P2.3: MSVCRT PRNG with same seed produces identical sequence.
	 */
	test('msvcrt PRNG deterministic with same seed', () => {
		fc.assert(
			fc.property(
				fc.nat({ max: 0x7FFFFFFF }),
				fc.integer({ min: 1, max: 50 }),
				(seed, count) => {
					const a = createPRNG('msvcrt')!;
					const b = createPRNG('msvcrt')!;
					a.seed(seed);
					b.seed(seed);

					for (let i = 0; i < count; i++) {
						const va = a.rand();
						const vb = b.rand();
						assert.strictEqual(va, vb, `Mismatch at iteration ${i} with seed ${seed}`);
					}
				}
			),
			{ numRuns: 100 }
		);
	});

	/**
	 * P2.4: Invalid prngMode falls back to stub (returns undefined).
	 */
	test('invalid prngMode falls back to stub', () => {
		fc.assert(
			fc.property(
				fc.string({ minLength: 1, maxLength: 20 }).filter(s => !['stub', 'glibc', 'msvcrt'].includes(s)),
				(invalidMode) => {
					const prng = createPRNG(invalidMode as any);
					assert.strictEqual(prng, undefined, `Invalid mode "${invalidMode}" should return undefined (stub fallback)`);
				}
			),
			{ numRuns: 100 }
		);
	});

	/**
	 * P2.5: PRNG state is isolated between separate createPRNG() calls.
	 */
	test('PRNG state isolation between runs', () => {
		fc.assert(
			fc.property(
				fc.nat({ max: 0x7FFFFFFF }),
				fc.nat({ max: 0x7FFFFFFF }),
				fc.integer({ min: 1, max: 20 }),
				(seedA, seedB, advanceCount) => {
					fc.pre(seedA !== seedB);

					const a = createPRNG('glibc')!;
					const b = createPRNG('glibc')!;
					a.seed(seedA);
					b.seed(seedB);

					// Advance a
					for (let i = 0; i < advanceCount; i++) { a.rand(); }

					// b should still produce its own sequence from seedB
					const bFresh = createPRNG('glibc')!;
					bFresh.seed(seedB);
					for (let i = 0; i < advanceCount; i++) {
						assert.strictEqual(b.rand(), bFresh.rand(),
							`b was contaminated by a at iteration ${i}`);
					}
				}
			),
			{ numRuns: 100 }
		);
	});
});
