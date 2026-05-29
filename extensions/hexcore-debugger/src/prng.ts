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
 * glibc TYPE_3 random() / rand() implementation.
 *
 * Bit-for-bit faithful port of glibc's __srandom_r / __random_r
 * (glibc/stdlib/random_r.c) for the default TYPE_3 generator that rand()
 * uses when initstate is not called: an additive feedback (lagged-Fibonacci)
 * generator with DEG_3 = 31 state words and SEP_3 = 3.
 *
 * Verified against native glibc (gcc, WSL):
 *   srand(1337); rand() → 292616681 (0x1170f9e9), then
 *   1638893262, 255706927, 995816787, 588263094, 1540293802, ...
 *
 * Algorithm (random_r.c):
 *   1. __srandom_r: r[0] = seed (seed 0 is forced to 1). Then for i in [1..30]
 *      r[i] = (16807 * r[i-1]) mod 2147483647, computed via Schrage's method
 *      (hi/lo split, add 2^31-1 when negative) exactly as glibc does so the
 *      sign/overflow behavior matches int32_t arithmetic.
 *   2. fptr = &r[SEP_3] (3), rptr = &r[0]. Discard 10*DEG_3 = 310 outputs
 *      (the warmup loop in __srandom_r).
 *   3. __random_r: *fptr += *rptr (uint32 wraparound); result = (*fptr >> 1)
 *      & 0x7fffffff; advance fptr and rptr cyclically (mod 31).
 *
 * The previous 344-entry flat-array "approximation" did NOT match glibc for
 * any seed (it returned 0x0fa2e13e for seed 1337). This port is exact.
 *
 * Reference: https://sourceware.org/git/?p=glibc.git;a=blob;f=stdlib/random_r.c
 *   (TYPE_3: DEG_3 = 31, SEP_3 = 3; __random_r additive feedback).
 */
export class GlibcPRNG implements PRNG {
	private static readonly DEG = 31;
	private static readonly SEP = 3;
	// int32_t state words (glibc stores them as int32_t; arithmetic wraps in 32 bits).
	private state: Int32Array = new Int32Array(GlibcPRNG.DEG);
	private fptr: number = GlibcPRNG.SEP;
	private rptr: number = 0;

	constructor(initialSeed?: number) {
		if (initialSeed !== undefined) {
			this.seed(initialSeed);
		}
	}

	seed(s: number): void {
		const { DEG, SEP } = GlibcPRNG;

		// glibc: "if (seed == 0) seed = 1;" — a 0 seed is mapped to 1 so the
		// generator never degenerates to all-zero state.
		let seed = s | 0;
		if (seed === 0) {
			seed = 1;
		}

		this.state[0] = seed;

		// r[i] = (16807 * r[i-1]) % 2147483647 via Schrage's method, matching
		// glibc __srandom_r's int32_t computation (handles the negative branch).
		for (let i = 1; i < DEG; i++) {
			const word = BigInt(this.state[i - 1]);
			const hi = word / 127773n;
			const lo = word % 127773n;
			let v = 16807n * lo - 2836n * hi;
			if (v < 0n) {
				v += 2147483647n;
			}
			this.state[i] = Number(v) | 0;
		}

		this.fptr = SEP;
		this.rptr = 0;

		// Warmup: glibc discards the first 10 * DEG_3 outputs after seeding.
		for (let i = 0; i < 10 * DEG; i++) {
			this.next();
		}
	}

	/**
	 * One step of __random_r: *fptr += *rptr; result = (*fptr >> 1) & 0x7fffffff.
	 * The addition wraps as uint32 (glibc uses uint32_t accumulation), and the
	 * stored value is reinterpreted as int32_t. We keep the >> 1 on the unsigned
	 * value to match glibc's "(uint32_t)*fptr >> 1".
	 */
	private next(): number {
		const { DEG } = GlibcPRNG;
		// uint32 wraparound addition; Int32Array store reinterprets as int32_t.
		const sum = ((this.state[this.fptr] >>> 0) + (this.state[this.rptr] >>> 0)) >>> 0;
		this.state[this.fptr] = sum | 0;
		const result = (sum >>> 1) & 0x7fffffff;
		this.fptr = (this.fptr + 1) % DEG;
		this.rptr = (this.rptr + 1) % DEG;
		return result;
	}

	rand(): number {
		return this.next();
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
