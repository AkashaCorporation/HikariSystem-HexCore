/*---------------------------------------------------------------------------------------------
 * Helix packaging helpers (FIX-QUALITY-001)
 *
 * Pure (no vscode import). Used by extension.ts helix.decompile / decompileIR
 * to match engine-direct harness quality:
 *
 *   1. useCastLayer defaults ON (harness always setUseCastLayer(true)).
 *
 *   2. functionStarts / D2 registry:
 *      analyzeAll alone is incomplete on PE (thunks, JMP tails, register-target
 *      CALLI). Installing that sparse table flips Helix authoritative and
 *      mis-gates real callees → (*(void(*)())0xADDR) + honesty conf cap
 *      (observed 64% → 49% on mbamchameleon @ 0x14002641c).
 *
 *      DEFAULT: omit functionStarts (non-authoritative) = engine-direct quality.
 *      OPT-IN honesty: options.functionStarts === true → enriched registry
 *      (analyzeAll ∪ IR @sub_/@lifted_ ∪ CALLI immediates ∪ imports/exports ∪
 *      Remill callTargets). Still best-effort — register-indirect CALLI targets
 *      cannot be mined from IR text.
 *---------------------------------------------------------------------------------------------*/

import type { DisassemblerEngine } from './disassemblerEngine';

/** Image-like VA window used when mining CALLI immediates from IR text. */
const IMAGE_VA_MIN = 0x10000;
const IMAGE_VA_MAX = 0x00007FFFFFFFFFFF;

/** Inputs that make helix.decompileIR a non-interactive/headless call. */
export function hasHeadlessHelixIrInput(value: unknown): value is Record<string, unknown> {
	return value !== null && typeof value === 'object'
		&& ('file' in value || 'irText' in value || 'irPath' in value);
}

/**
 * Extract absolute VAs of named / immediate callees from Remill LLVM IR text.
 * Covers:
 *   - `@sub_<hex>` / `@lifted_<decimal>` (when present)
 *   - `i64 <decimal>` immediates on lines that invoke Remill `CALLI` helpers
 *     (the common PE form — Remill rarely emits @sub_ for direct calls)
 */
export function extractCalleeAddressesFromIr(ir: string): number[] {
	if (!ir) {
		return [];
	}
	const set = new Set<number>();
	const add = (n: number): void => {
		if (Number.isFinite(n) && n >= IMAGE_VA_MIN && n <= IMAGE_VA_MAX) {
			set.add(Math.trunc(n));
		}
	};

	for (const m of ir.matchAll(/@sub_([0-9a-fA-F]{4,})\b/g)) {
		add(Number.parseInt(m[1], 16));
	}
	for (const m of ir.matchAll(/@lifted_(\d+)\b/g)) {
		add(Number.parseInt(m[1], 10));
	}

	// Remill CALLI: `call ptr @_ZN12_GLOBAL__N_14CALLI2InImE...(..., i64 TARGET, ...)`
	// Mine every image-range i64 on those lines (target + return-PC both useful
	// for the registry; extra leaders are harmless).
	for (const line of ir.split('\n')) {
		if (!line.includes('CALLI')) {
			continue;
		}
		for (const m of line.matchAll(/\bi64\s+(\d+)\b/g)) {
			add(Number.parseInt(m[1], 10));
		}
	}

	return [...set];
}

/**
 * Whether the caller asked for the D2 honesty function-start registry.
 * Default is OFF (quality / engine-direct parity). Explicit `true` opts in;
 * also accepts legacy-ish `honesty: true` / `honestyMode: true`.
 */
export function wantsHelixFunctionStarts(options: Record<string, unknown>): boolean {
	if (options.functionStarts === true) {
		return true;
	}
	if (options.functionStarts === false) {
		return false;
	}
	if (options.honesty === true || options.honestyMode === true) {
		return true;
	}
	return false;
}

export interface HelixFunctionStartsExtras {
	/** Remill Phase-3 callTargets (may be incomplete — IR parse is the authority). */
	callTargets?: ReadonlyArray<number>;
	/** liftToIR internalCallTargets (in-.text filter). */
	internalCallTargets?: ReadonlyArray<number>;
	/** Full IR text — mined for @sub_/@lifted_ callees. */
	irText?: string;
	/** Entry VA of the function being decompiled. */
	entryAddress?: number;
}

/**
 * Build the Helix function-start registry for the D2 callee gate.
 * Returns `undefined` when empty (caller should omit the option so Helix
 * stays non-authoritative rather than installing a hollow table).
 */
export function buildHelixFunctionStarts(
	eng: Pick<DisassemblerEngine, 'getFunctions' | 'getImports' | 'getExports'>,
	extra?: HelixFunctionStartsExtras,
): number[] | undefined {
	const set = new Set<number>();
	const add = (n: unknown): void => {
		if (typeof n !== 'number' || !Number.isFinite(n) || n <= 0) {
			return;
		}
		set.add(Math.trunc(n));
	};

	try {
		for (const f of eng.getFunctions()) {
			add(f.address);
		}
	} catch { /* engine not ready */ }

	try {
		for (const lib of eng.getImports()) {
			for (const fn of lib.functions ?? []) {
				add(fn.address); // IAT slot VA
			}
		}
	} catch { /* no imports */ }

	try {
		for (const exp of eng.getExports()) {
			add(exp.address);
		}
	} catch { /* no exports */ }

	if (extra?.callTargets) {
		for (const t of extra.callTargets) {
			add(t);
		}
	}
	if (extra?.internalCallTargets) {
		for (const t of extra.internalCallTargets) {
			add(t);
		}
	}
	if (extra?.entryAddress !== undefined) {
		add(extra.entryAddress);
	}
	if (extra?.irText) {
		for (const t of extractCalleeAddressesFromIr(extra.irText)) {
			add(t);
		}
	}

	if (set.size === 0) {
		return undefined;
	}
	return [...set].sort((a, b) => a - b);
}

/**
 * Resolve Helix base flags. Cast layer defaults ON (quality); pass
 * `useCastLayer: false` to opt out. `optimizeIR` only set when the caller
 * specifies it (engine default otherwise).
 */
export function resolveHelixBaseOptions(options: Record<string, unknown>): {
	useCastLayer: boolean;
	optimizeIR?: boolean;
} {
	const base: { useCastLayer: boolean; optimizeIR?: boolean } = {
		// Explicit false → off; undefined / true / anything else → on.
		useCastLayer: options.useCastLayer !== false,
	};
	if (options.optimizeIR !== undefined) {
		base.optimizeIR = options.optimizeIR !== false;
	}
	return base;
}

/**
 * Authoritative function extent for a VA.
 *
 * The function table (prologue scan) often UNDERRSIZES real PE functions:
 *   - maxInstructions=1000 → size≈4800 before .pdata reconcile
 *   - engine instance that only loadFile'd (no analyzeAll) keeps the short stub
 *
 * .pdata RUNTIME_FUNCTION [begin,end) is the ground truth for non-leaf PE
 * functions. Prefer the larger of (table size, containing pdata span).
 *
 * Observed on mbamchameleon @ 0x14002641c:
 *   table size=4800  |  pdata end=0x140027e85 → 6761  |  pathfinder agrees
 */
export function getAuthoritativeFunctionExtent(
	eng: {
		getFunctionAt(address: number): { address: number; size: number; endAddress: number } | undefined;
		getPdataEntries(): ReadonlyArray<{ beginAddress: number; endAddress: number }>;
		getBaseAddress(): number;
		getRecommendedLiftSize(address: number, fallback?: number): number;
	},
	address: number,
): { size: number; end: number; start: number; source: 'function-table' | 'pdata' | 'recommended' | 'none' } {
	const fn = eng.getFunctionAt(address);
	let start = fn && fn.address > 0 ? fn.address : address;
	let size = fn && fn.size > 0 ? fn.size : 0;
	let end = fn && fn.endAddress > address ? fn.endAddress : 0;
	let source: 'function-table' | 'pdata' | 'recommended' | 'none' =
		size > 0 ? 'function-table' : 'none';

	try {
		const base = eng.getBaseAddress();
		for (const p of eng.getPdataEntries()) {
			const b = p.beginAddress + base;
			const e = p.endAddress + base;
			if (b <= address && address < e && e > b) {
				// Full function span from pdata begin (preferred when we own the entry)
				const fullSize = e - b;
				const toEnd = e - address;
				// Prefer pdata when it extends past the table size (the common undersize case)
				if (fullSize > size || toEnd > size) {
					// If the function table entry starts at the same begin, use full span
					if (!fn || fn.address === b || address === b) {
						start = b;
						size = fullSize;
						end = e;
					} else {
						// Mid-function hit: lift from address to pdata end
						size = toEnd;
						end = e;
					}
					source = 'pdata';
				} else if (end < e) {
					end = e;
				}
				break;
			}
		}
	} catch { /* no pdata / not PE */ }

	if (size <= 0) {
		const rec = eng.getRecommendedLiftSize(address, 0);
		if (rec > 0) {
			size = rec;
			end = address + rec;
			source = 'recommended';
		}
	}

	if (end <= address && size > 0) {
		end = address + size;
	}

	return { size, end, start, source };
}

/**
 * Coerce job/UI args that should be positive integers. Headless JSON is
 * usually fine, but `$step` interpolation and hand-edited jobs sometimes
 * deliver `"65536"` (string) — and `typeof x === 'number'` then silently
 * drops `size`, falling back to count*15 or the whole buffer.
 */
export function coercePositiveInt(value: unknown): number | undefined {
	if (typeof value === 'number' && Number.isFinite(value) && value > 0) {
		return Math.trunc(value);
	}
	if (typeof value === 'string') {
		const s = value.trim();
		if (!s) {
			return undefined;
		}
		const n = /^0x/i.test(s) ? Number.parseInt(s, 16) : Number.parseInt(s, 10);
		if (Number.isFinite(n) && n > 0) {
			return n;
		}
	}
	return undefined;
}

/**
 * Whether a caller-provided byte window must survive the single-function
 * clamp. PE `.pdata` is authoritative, but ET_REL symbol/analyzeAll extents
 * can describe only a hot fragment while branches target cold fragments
 * later in `.text`. In that format an explicit job `size` is intentional.
 */
export function shouldHonorExplicitLiftWindow(
	options: { size?: unknown; allowOversizedLift?: unknown },
	isRelocatable: boolean,
): boolean {
	return options.allowOversizedLift === true ||
		(isRelocatable && coercePositiveInt(options.size) !== undefined);
}

export interface ResolveLiftByteSizeArgs {
	/** Explicit size from job/UI (bytes). */
	size?: unknown;
	/** Explicit instruction-count heuristic (bytes ≈ count*15). */
	count?: unknown;
	/** analyzeAll / symbol size at the resolved entry (0 if unknown). */
	knownFunctionSize: number;
	/** Whole-file fallback when nothing else is known. */
	bufferSize: number;
	/**
	 * When true, honour an oversized explicit `size` (multi-function windows).
	 * Default false — clamp huge windows to the known function (engine-direct
	 * parity; avoids 64KB neighbour soup on single-fn decompiles).
	 */
	allowOversizedLift?: boolean;
}

export interface ResolvedLiftByteSize {
	size: number;
	/** Why this size was chosen (for logs / C header diagnostics). */
	reason: string;
	clampedFrom?: number;
}

/**
 * FIX-QUALITY-002: pick the Remill byte window for a single-function lift.
 *
 * Priority:
 *   1. explicit size (number or numeric string)
 *   2. max(count*15, knownFunctionSize)
 *   3. knownFunctionSize + 16
 *   4. whole buffer
 *
 * Then, unless allowOversizedLift: if we know the function size and the
 * window is > 2× that, clamp to knownSize+64. Never under-lift a known fn.
 */
export function resolveLiftByteSize(args: ResolveLiftByteSizeArgs): ResolvedLiftByteSize {
	const known = args.knownFunctionSize > 0 ? Math.trunc(args.knownFunctionSize) : 0;
	const sizeOpt = coercePositiveInt(args.size);
	const countOpt = coercePositiveInt(args.count);
	let size: number;
	let reason: string;

	if (sizeOpt !== undefined) {
		size = sizeOpt;
		reason = 'explicit-size';
	} else if (countOpt !== undefined) {
		const est = countOpt * 15;
		size = known > 0 ? Math.max(est, known) : est;
		reason = known > 0 ? 'count*15|knownSize' : 'count*15';
	} else if (known > 0) {
		size = known + 16;
		reason = 'knownFunctionSize+pad';
	} else {
		size = Math.max(1, Math.trunc(args.bufferSize) || 4096);
		reason = 'whole-buffer-fallback';
	}

	if (known > 0 && args.allowOversizedLift !== true) {
		const maxSane = known + 64;
		if (size > known * 2 && size > maxSane) {
			return { size: maxSane, reason: `${reason}|clamped-to-fn`, clampedFrom: size };
		}
		if (size < known) {
			return { size: known + 16, reason: `${reason}|raised-to-known`, clampedFrom: size };
		}
	}
	return { size, reason };
}
