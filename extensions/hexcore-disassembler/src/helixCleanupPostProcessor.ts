/*---------------------------------------------------------------------------------------------
 *  HexCore Helix Cleanup Post-Processor (v3.8.0)
 *
 *  Safe, text-level cleanup of Helix pseudo-C output. Addresses residual
 *  emitter artifacts that are well-understood but expensive to fix inside
 *  the MLIR pipeline (see MEMORY.md: "band-aid filters" + "register names"
 *  + "unused local declarations").
 *
 *  DESIGN RULES
 *  ------------
 *  - Never rewrite semantics. When in doubt, leave the line untouched.
 *  - Only act on patterns that are provably no-ops or pure syntactic
 *    redundancy (cast of integer literal to the LHS type, etc).
 *  - Track every transformation so the disassemblerEngine can surface
 *    a summary ("applied 12 cleanups").
 *  - Zero dependencies on other Helix internals — operates purely on
 *    the emitted C source string.
 *
 *  TRANSFORMATIONS
 *  ---------------
 *  1. Redundant integer-literal casts
 *     `field = (int32_t)1;`            -> `field = 1;`
 *     `(int8_t)0`                      -> `0`
 *     Cast is dropped when the literal is an untyped decimal/hex integer
 *     and the cast target is an integer width <= 32 bits. A 64-bit cast is
 *     KEPT: a bare literal is `int` (32-bit), so the widening is load-bearing
 *     (e.g. `(int64_t)1 << 40` must not become a 32-bit `1 << 40`).
 *
 *  2. LLVM intrinsic namespace cleanup
 *     `__unknown_llvm.intr.fabs`       -> `fabs`
 *     `__unknown_llvm.intr.trunc`      -> `trunc`
 *     These are math.h equivalents that the emitter already knows but
 *     leaves prefixed for diagnostic visibility.
 *
 *  3. Logical-vs-bitwise disambiguation on boolean operands
 *     `!x | !y`                        -> `!x || !y`
 *     `!x & !y`                        -> `!x && !y`
 *     Pattern is unambiguous: `!expr` always produces a 0/1 value, so a
 *     bitwise `|`/`&` between two negations is semantically identical to
 *     the logical form but confuses readers and short-circuit reasoning.
 *
 *  4. Unused local-variable declaration pruning
 *     Drops top-of-function declarations whose name NEVER appears again
 *     in the function body. Limited to simple `<type> <name>;` lines so
 *     we don't accidentally strip declarations that carry side effects
 *     (initializers, call expressions). Register-named placeholders
 *     (`rax`, `rbx`, `xmm0`, ...) that Helix injects as shadow state
 *     are the primary target — they're declared but only assigned to,
 *     never read, in 90%+ of outputs.
 *
 *  NON-GOALS
 *  ---------
 *  - Structural transforms (goto elimination, if-flattening). That belongs
 *    inside Helix CAstOptimizer — fighting it from here creates drift.
 *  - Renaming variables for readability. `structFieldPostProcessor.ts`
 *    already covers the DWARF/BTF/PDB naming case.
 *---------------------------------------------------------------------------------------------*/

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface CleanupStats {
	/** Total count of transformations applied */
	totalRewrites: number;
	/** Redundant integer-literal casts removed */
	redundantCasts: number;
	/** `__unknown_llvm.intr.*` prefixes stripped */
	intrinsicsNormalized: number;
	/** Bitwise ops between negations upgraded to logical ops */
	logicalOpsFixed: number;
	/** Unused local declarations removed */
	deadDeclarations: number;
}

export interface CleanupResult {
	source: string;
	stats: CleanupStats;
}

export interface CleanupOptions {
	/** Enable integer-literal cast removal (default: true) */
	stripLiteralCasts?: boolean;
	/** Enable `__unknown_llvm.intr.*` -> math.h cleanup (default: true) */
	normalizeIntrinsics?: boolean;
	/** Enable `| -> ||` on negated operands (default: true) */
	fixLogicalOps?: boolean;
	/** Enable unused-declaration pruning (default: true) */
	pruneDeadDeclarations?: boolean;
}

// ---------------------------------------------------------------------------
// Transformation 1: Redundant integer-literal casts
// ---------------------------------------------------------------------------

/**
 * A cast is redundant when:
 *   - Target type is a known fixed-width integer (int8_t, int16_t, int32_t,
 *     int64_t, uint8_t, etc).
 *   - Operand is a plain integer literal, optionally negated
 *     (e.g. `0`, `1`, `-1`, `0xff`, `42`).
 *
 * We DO NOT strip casts of non-literal expressions — those may be load-bearing
 * (sign extension, truncation, etc).
 *
 * Edge case: we keep the cast when the literal value is out of range for the
 * target type (e.g. `(int8_t)256`), since the cast mathematically truncates.
 */
const INT_CAST_PATTERN = /\((u?int(?:8|16|32|64)_t)\)(-?\s*(?:0x[0-9a-fA-F]+|[0-9]+))\b/g;

function isLiteralInRange(typeName: string, valueStr: string): boolean {
	const cleaned = valueStr.replace(/\s+/g, '');
	let value: bigint;
	try {
		if (cleaned.startsWith('-0x') || cleaned.startsWith('-')) {
			// BigInt supports negative decimals but not negative hex directly
			if (cleaned.startsWith('-0x')) {
				value = -BigInt('0x' + cleaned.slice(3));
			} else {
				value = BigInt(cleaned);
			}
		} else {
			value = BigInt(cleaned);
		}
	} catch {
		return false;
	}

	const bits = parseInt(typeName.match(/(\d+)/)?.[1] ?? '0', 10);
	if (bits === 0) { return false; }

	if (typeName.startsWith('u')) {
		const max = (1n << BigInt(bits)) - 1n;
		return value >= 0n && value <= max;
	} else {
		const max = (1n << BigInt(bits - 1)) - 1n;
		const min = -(1n << BigInt(bits - 1));
		return value >= min && value <= max;
	}
}

function stripLiteralCasts(source: string): { source: string; count: number } {
	let count = 0;
	const out = source.replace(INT_CAST_PATTERN, (match, typeName: string, literal: string) => {
		// A 64-bit cast on a bare integer literal is NOT redundant: an unsuffixed
		// integer literal is `int` (32-bit), so the widening is load-bearing in a
		// width-sensitive context like `(int64_t)1 << 40` -- dropping the cast makes
		// the shift operate on a 32-bit int (UB / wrong value, e.g. a 64-bit bitmask).
		// Narrow casts (8/16/32) are promotion-safe to drop: the operand promotes to
		// int before arithmetic either way, so the value is unchanged.
		if (typeName === 'int64_t' || typeName === 'uint64_t') {
			return match;
		}
		if (isLiteralInRange(typeName, literal)) {
			count++;
			// Preserve sign spacing: "(int32_t)- 1" -> "-1" (collapse whitespace)
			return literal.replace(/\s+/g, '');
		}
		return match;
	});
	return { source: out, count };
}

// ---------------------------------------------------------------------------
// Transformation 2: LLVM intrinsic namespace cleanup
// ---------------------------------------------------------------------------

/**
 * Map of `__unknown_llvm.intr.<name>` -> canonical C name.
 * Only includes intrinsics that have 1:1 math.h / stdint equivalents and
 * leave the call-site signature unchanged.
 */
const INTRINSIC_MAP: Record<string, string> = {
	fabs: 'fabs',
	trunc: 'trunc',
	floor: 'floor',
	ceil: 'ceil',
	round: 'round',
	sqrt: 'sqrt',
	sin: 'sin',
	cos: 'cos',
	exp: 'exp',
	log: 'log',
	pow: 'pow',
	// Math only here — bit intrinsics are width-aware (issue #46).
};

/**
 * Map Helix-leaked LLVM bit intrinsics to the correct GCC/Clang builtin.
 * FIX #46: bare `ctpop`/`bswap` → 32-bit builtins was width-lossy on i64
 * operands (wrong result for 64-bit popcount / byteswap). Honour an optional
 * `.iN` / `_iN` suffix from the emitter; default remains 32-bit only when no
 * width is present (legacy Helix emit path).
 */
function mapBitIntrinsic(name: string, widthBits: number | undefined): string | undefined {
	const base = name.replace(/[._]?i\d+$/i, '').toLowerCase();
	// Parse width from suffix: ctpop.i64 / ctpop_i64 / llvm.ctpop.i64 style tail
	let w = widthBits;
	if (w === undefined) {
		const m = name.match(/[._]i(\d+)$/i);
		if (m) { w = Number.parseInt(m[1], 10); }
	}
	const width = (w !== undefined && Number.isFinite(w) && w > 0) ? w : 32;

	switch (base) {
		case 'ctpop':
			return width > 32 ? '__builtin_popcountll' : '__builtin_popcount';
		case 'ctlz':
			return width > 32 ? '__builtin_clzll' : '__builtin_clz';
		case 'cttz':
			return width > 32 ? '__builtin_ctzll' : '__builtin_ctz';
		case 'bswap':
			if (width <= 16) { return '__builtin_bswap16'; }
			if (width >= 64) { return '__builtin_bswap64'; }
			return '__builtin_bswap32';
		default:
			return undefined;
	}
}

// Captures: name + optional `.i64` / `_i64` width suffix
const INTRINSIC_PATTERN = /__unknown_llvm\.intr\.([a-zA-Z_][a-zA-Z0-9_.]*)/g;

function normalizeIntrinsics(source: string): { source: string; count: number } {
	let count = 0;
	const out = source.replace(INTRINSIC_PATTERN, (match, name: string) => {
		// Math map first (fabs, sqrt, …)
		const simple = name.replace(/[._]i\d+$/i, '');
		const math = INTRINSIC_MAP[simple] ?? INTRINSIC_MAP[name];
		if (math) {
			count++;
			return math;
		}
		// Width-aware bit ops (#46)
		const bit = mapBitIntrinsic(name, undefined);
		if (bit) {
			count++;
			return bit;
		}
		return match;
	});
	return { source: out, count };
}

// ---------------------------------------------------------------------------
// Transformation 3: Logical vs bitwise disambiguation on negations
// ---------------------------------------------------------------------------

/**
 * Helix emits `!a | !b` for certain `or i1 %a, %b` patterns in Remill IR.
 * Although `!expr` always evaluates to 0 or 1 (so bitwise vs logical give
 * the same numeric result), the logical form short-circuits and reads far
 * better. This rewrite is value-preserving because:
 *
 *   !a | !b   <-> !a || !b     when both sides are in {0,1}
 *   !a & !b   <-> !a && !b     when both sides are in {0,1}
 *
 * We only rewrite when BOTH operands are `!<ident-or-call-or-literal>` so
 * we don't accidentally upgrade a genuine bitmask calculation.
 *
 * Note: we do NOT replace `(cond) | (cond)` because `(cond)` could be a
 * wide integer (e.g. `(rax_2 & 1)`) where bitwise-vs-logical is not
 * equivalent.
 */
const NEGATED_BITWISE_PATTERN = /(!\w+|!\([^)]+\))\s*([|&])\s*(!\w+|!\([^)]+\))(?!\w)/g;

function fixLogicalOps(source: string): { source: string; count: number } {
	let count = 0;
	const out = source.replace(NEGATED_BITWISE_PATTERN, (match, lhs: string, op: string, rhs: string) => {
		count++;
		return `${lhs} ${op}${op} ${rhs}`;
	});
	return { source: out, count };
}

// ---------------------------------------------------------------------------
// Transformation 4: Unused local-declaration pruning
// ---------------------------------------------------------------------------

/**
 * Matches a simple `<type> <name>;` declaration line. We accept:
 *   - Primitive types (int*_t, uint*_t, float, double, bool, void*)
 *   - Optional pointer / space noise
 *   - Optional trailing comment `/* stack[N] *\/`
 *
 * We reject anything with `=` (initializer — must keep, side effect),
 * anything with `(` (function declaration), and anything with brackets.
 */
const SIMPLE_DECL_PATTERN =
	/^(\s*)(u?int(?:8|16|32|64)_t|float|double|bool|void\s*\*|int64_t|int32_t|int16_t|int8_t)\s+(\*?\s*[A-Za-z_][A-Za-z0-9_]*)\s*;(\s*\/\*[^*]*(?:\*(?!\/)[^*]*)*\*\/)?\s*$/;

/**
 * Register-like identifiers that Helix emits as shadow declarations. These
 * are the primary targets of dead-decl pruning — when they're declared but
 * never read OR assigned, they are pure noise.
 */
const REGISTER_NAME_PATTERN = /^(?:r?(?:ax|bx|cx|dx|si|di|bp|sp|ip|8|9|10|11|12|13|14|15)(?:_\d+)?|[rex][a-d]x(?:_\d+)?|xmm\d+(?:_\d+)?|ymm\d+(?:_\d+)?|[re][bs]p(?:_\d+)?)$/;

/**
 * Count how many times `name` appears in `body` as a standalone identifier
 * (word-boundary match). We don't distinguish read from write — any mention
 * is enough to keep the declaration.
 */
function countIdentifierUses(body: string, name: string): number {
	const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
	const re = new RegExp(`\\b${escaped}\\b`, 'g');
	const matches = body.match(re);
	return matches ? matches.length : 0;
}

/**
 * Find the body of a C function in `source`. Returns the start/end of
 * everything between the opening `{` of the function and its matching
 * closing `}`. Returns null if we can't confidently locate the function.
 */
interface FunctionBody {
	bodyStart: number; // index after '{'
	bodyEnd: number;   // index of matching '}'
}

function findFunctionBody(source: string): FunctionBody | null {
	// Find the first '{' after a ')' on the same or prior line, indicating a
	// function opener. This is heuristic but robust for Helix output which
	// has exactly one top-level function per emission.
	const openBrace = source.indexOf('{');
	if (openBrace === -1) { return null; }

	// Find matching close brace at depth 0. We naively count but ignore
	// braces inside strings and comments.
	let depth = 1;
	let i = openBrace + 1;
	while (i < source.length && depth > 0) {
		const ch = source[i];
		if (ch === '/' && source[i + 1] === '/') {
			// line comment
			while (i < source.length && source[i] !== '\n') { i++; }
		} else if (ch === '/' && source[i + 1] === '*') {
			i += 2;
			while (i < source.length - 1 && !(source[i] === '*' && source[i + 1] === '/')) { i++; }
			i += 2;
		} else if (ch === '"' || ch === '\'') {
			const quote = ch;
			i++;
			while (i < source.length && source[i] !== quote) {
				if (source[i] === '\\') { i++; }
				i++;
			}
			i++;
		} else if (ch === '{') {
			depth++;
			i++;
		} else if (ch === '}') {
			depth--;
			if (depth === 0) { break; }
			i++;
		} else {
			i++;
		}
	}

	if (depth !== 0) { return null; }
	return { bodyStart: openBrace + 1, bodyEnd: i };
}

function pruneDeadDeclarations(source: string): { source: string; count: number } {
	const body = findFunctionBody(source);
	if (!body) { return { source, count: 0 }; }

	const fnBody = source.substring(body.bodyStart, body.bodyEnd);
	const lines = fnBody.split('\n');

	// Find the prologue: contiguous block of declaration-looking lines at the
	// top of the function (possibly separated by blank lines). Stop at the
	// first non-declaration statement.
	const prologueEnd = findPrologueEnd(lines);
	if (prologueEnd === 0) { return { source, count: 0 }; }

	// Rest-of-function body used for usage counting
	const restBody = lines.slice(prologueEnd).join('\n');

	let removed = 0;
	const kept: string[] = [];
	for (let i = 0; i < prologueEnd; i++) {
		const line = lines[i];
		const m = line.match(SIMPLE_DECL_PATTERN);
		if (!m) {
			kept.push(line);
			continue;
		}
		const rawName = m[3].replace(/[\s*]/g, '');
		// A declaration is considered unused if `rawName` does not appear as a
		// standalone identifier anywhere in the function body EXCEPT on its own
		// declaration line. We check the prologue (excluding line `i`) + rest.
		const prologueExcludingSelf = lines
			.slice(0, prologueEnd)
			.filter((_, idx) => idx !== i)
			.join('\n');
		const inPrologue = countIdentifierUses(prologueExcludingSelf, rawName);
		const inRest = countIdentifierUses(restBody, rawName);
		const totalOtherUses = inPrologue + inRest;

		// Only prune if unused AND looks like a register-shadow / clearly noise.
		// Conservative default: skip user-looking names (vN, var_N, param_N) so we
		// don't delete things a human reader might want to see even unused.
		const looksLikeRegister = REGISTER_NAME_PATTERN.test(rawName);
		if (totalOtherUses === 0 && looksLikeRegister) {
			removed++;
			continue;
		}
		kept.push(line);
	}

	if (removed === 0) { return { source, count: 0 }; }

	const newBody = kept.join('\n') + '\n' + lines.slice(prologueEnd).join('\n');
	const rebuilt = source.substring(0, body.bodyStart) + newBody + source.substring(body.bodyEnd);
	return { source: rebuilt, count: removed };
}

/**
 * Returns the line index where the declaration prologue ends. The prologue
 * contains only: declaration lines, blank lines, and single-line comments.
 * The first line with an assignment (=), call (()), control flow keyword,
 * or other statement ends the prologue.
 */
function findPrologueEnd(lines: string[]): number {
	for (let i = 0; i < lines.length; i++) {
		const trimmed = lines[i].trim();
		if (trimmed === '') { continue; }
		if (trimmed.startsWith('//') || trimmed.startsWith('/*')) { continue; }
		if (SIMPLE_DECL_PATTERN.test(lines[i])) { continue; }
		// First non-declaration, non-empty, non-comment line ends the prologue.
		return i;
	}
	return lines.length;
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

export function cleanupHelixSource(source: string, options?: CleanupOptions): CleanupResult {
	const opts = {
		stripLiteralCasts: options?.stripLiteralCasts !== false,
		normalizeIntrinsics: options?.normalizeIntrinsics !== false,
		fixLogicalOps: options?.fixLogicalOps !== false,
		pruneDeadDeclarations: options?.pruneDeadDeclarations !== false,
	};

	const stats: CleanupStats = {
		totalRewrites: 0,
		redundantCasts: 0,
		intrinsicsNormalized: 0,
		logicalOpsFixed: 0,
		deadDeclarations: 0,
	};

	let current = source;

	if (opts.stripLiteralCasts) {
		const r = stripLiteralCasts(current);
		current = r.source;
		stats.redundantCasts = r.count;
	}

	if (opts.normalizeIntrinsics) {
		const r = normalizeIntrinsics(current);
		current = r.source;
		stats.intrinsicsNormalized = r.count;
	}

	if (opts.fixLogicalOps) {
		const r = fixLogicalOps(current);
		current = r.source;
		stats.logicalOpsFixed = r.count;
	}

	if (opts.pruneDeadDeclarations) {
		const r = pruneDeadDeclarations(current);
		current = r.source;
		stats.deadDeclarations = r.count;
	}

	stats.totalRewrites =
		stats.redundantCasts +
		stats.intrinsicsNormalized +
		stats.logicalOpsFixed +
		stats.deadDeclarations;

	return { source: current, stats };
}
