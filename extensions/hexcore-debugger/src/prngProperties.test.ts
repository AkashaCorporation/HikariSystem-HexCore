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
	 * P2.6: GlibcPRNG must match native glibc rand() bit-for-bit.
	 *
	 * Reference values captured from native glibc (gcc, WSL):
	 *   srand(SEED); for (i=0;i<8;i++) printf("%d ", rand());
	 * This guards against the pre-v3.8.2 344-entry approximation that returned
	 * 0x0fa2e13e for seed 1337 instead of the correct 0x1170f9e9 (292616681).
	 * glibc maps seed 0 → 1, so both produce the same sequence.
	 */
	test('glibc PRNG matches native glibc rand() bit-for-bit (10+ seeds)', () => {
		const native: Record<number, number[]> = {
			0:          [1804289383, 846930886, 1681692777, 1714636915, 1957747793, 424238335, 719885386, 1649760492],
			1:          [1804289383, 846930886, 1681692777, 1714636915, 1957747793, 424238335, 719885386, 1649760492],
			2:          [1505335290, 1738766719, 190686788, 260874575, 747983061, 906156498, 1502820864, 142559277],
			42:         [71876166, 708592740, 1483128881, 907283241, 442951012, 537146758, 1366999021, 1854614940],
			1337:       [292616681, 1638893262, 255706927, 995816787, 588263094, 1540293802, 343418821, 903681492],
			12345:      [383100999, 858300821, 357768173, 455528251, 133005921, 116285904, 591987137, 102557902],
			2147483646: [1320593690, 1199968952, 1432693999, 317934276, 69604050, 522196235, 1290561954, 354237423],
			99999:      [1268809316, 1366423099, 1000818142, 2078760739, 905264172, 1538814804, 425552616, 242719814],
			314159:     [414777680, 2009630532, 102799611, 1785840038, 1157731385, 59849040, 2016895726, 1169205285],
			1000000007: [110759905, 1327133856, 601025079, 673070893, 996726755, 1835848883, 2940937, 75760567],
			777:        [947371799, 2013380011, 1359686060, 1503739543, 459541900, 1184792193, 2114725554, 435210838],
			65536:      [553316596, 1748907888, 680492731, 191440832, 1061163313, 953167306, 1813102830, 422412382],
		};
		for (const [seedStr, expected] of Object.entries(native)) {
			const seed = Number(seedStr);
			const prng = new GlibcPRNG();
			prng.seed(seed);
			for (let i = 0; i < expected.length; i++) {
				assert.strictEqual(prng.rand(), expected[i],
					`glibc mismatch at index ${i} for seed ${seed}`);
			}
		}
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
