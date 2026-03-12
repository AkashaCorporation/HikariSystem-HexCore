/*---------------------------------------------------------------------------------------------
 *  HexCore Debugger - PRNG Implementations
 *  Accurate glibc and MSVCRT pseudo-random number generators for emulation.
 *  Copyright (c) HikariSystem. All rights reserved.
 *--------------------------------------------------------------------------------------------*/

export type PrngMode = 'glibc' | 'msvcrt' | 'stub';

export interface PRNG {
	seed(s: number): void;
	rand(): number;
}

/**
 * glibc TYPE_3 random() implementation.
 *
 * Uses a 31-element state array with additive feedback (trinomial LFSR).
 * This matches the behavior of glibc's random()/rand() with default
 * TYPE_3 state (initstate not called, or called with statesize >= 32).
 *
 * Algorithm:
 *   state[0] = seed
 *   state[i] = (16807 * state[i-1]) % 2147483647   for i in [1..30]
 *   state[i] = state[i - 31]                         for i in [31..33]  (warmup)
 *   state[i] = state[i - 31] + state[i - 3]          for i in [34..343] (warmup)
 *
 *   rand():
 *     if idx >= 344 → regenerate all 344 entries
 *     result = state[idx++]
 *     return (result >>> 1) & 0x7FFFFFFF
 *
 * Reference: glibc/stdlib/random_r.c (TYPE_3, DEG=31, SEP=3)
 */
export class GlibcPRNG implements PRNG {
	private state: number[] = new Array(344);
	private idx: number = 344;

	constructor(initialSeed?: number) {
		if (initialSeed !== undefined) {
			this.seed(initialSeed);
		}
	}

	seed(s: number): void {
		// Ensure 32-bit unsigned
		s = s >>> 0;

		this.state[0] = s;

		// Initialize first 31 elements with LCG (matching glibc __srandom_r)
		for (let i = 1; i < 31; i++) {
			// glibc: state[i] = (16807 * state[i-1]) % 2147483647
			// Use BigInt to avoid overflow in JS
			const prev = BigInt(this.state[i - 1]);
			this.state[i] = Number((16807n * prev) % 2147483647n);
		}

		// Warmup: extend state with trinomial feedback
		for (let i = 31; i < 34; i++) {
			this.state[i] = this.state[i - 31];
		}
		for (let i = 34; i < 344; i++) {
			this.state[i] = (this.state[i - 31] + this.state[i - 3]) | 0;
		}

		this.idx = 344;
	}

	rand(): number {
		if (this.idx >= 344) {
			// Regenerate state array
			for (let i = 0; i < 344; i++) {
				this.state[i] = (this.state[(i + 31) % 344] + this.state[(i + 3) % 344]) | 0;
			}
			this.idx = 0;
		}

		const result = this.state[this.idx++];
		return (result >>> 1) & 0x7FFFFFFF;
	}
}

/**
 * MSVCRT rand() implementation.
 *
 * Simple LCG used by Microsoft Visual C Runtime:
 *   seed = seed * 214013 + 2531011
 *   rand() = (seed >> 16) & 0x7FFF
 *
 * Range: [0, 32767] (RAND_MAX = 0x7FFF)
 */
export class MsvcrtPRNG implements PRNG {
	private _seed: number = 1; // MSVCRT default seed

	constructor(initialSeed?: number) {
		if (initialSeed !== undefined) {
			this.seed(initialSeed);
		}
	}

	seed(s: number): void {
		this._seed = s >>> 0;
	}

	rand(): number {
		// seed = seed * 214013 + 2531011 (mod 2^32)
		this._seed = ((this._seed * 214013 + 2531011) & 0xFFFFFFFF) >>> 0;
		return (this._seed >>> 16) & 0x7FFF;
	}
}

/**
 * Factory: create a PRNG instance based on mode.
 * Returns undefined for 'stub' mode (caller should return 0).
 */
export function createPRNG(mode: PrngMode): PRNG | undefined {
	switch (mode) {
		case 'glibc':
			return new GlibcPRNG();
		case 'msvcrt':
			return new MsvcrtPRNG();
		case 'stub':
			return undefined;
	}
}
