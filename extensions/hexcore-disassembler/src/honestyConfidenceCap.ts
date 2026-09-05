/*---------------------------------------------------------------------------------------------
 * Issue #31 — packaging honesty safety net for Helix Confidence headers
 *
 * Helix C++ owns the authoritative score (CAstOptimizer::reanalyzeConfidence +
 * DamningDefect.h). Until a rebuilt hexcore-helix .node ships engine-side caps
 * (post-return damning, etc.), the IDE path must still refuse to present
 * Medium/High confidence when the *body text* still shows damning patterns.
 *
 * Pure (no vscode). Never invents defects — only *caps* an already-emitted
 * Confidence line when the body proves non-faithful. Prefer engine when the
 * .node already capped (idempotent: score ≤ 50 left alone).
 *---------------------------------------------------------------------------------------------*/

export interface HonestyCapResult {
	/** Source with Confidence header rewritten when capped */
	source: string;
	/** True when we lowered the score */
	capped: boolean;
	/** Original score from the header (undefined if none) */
	originalScore?: number;
	/** Score after cap (undefined if no header / no change) */
	newScore?: number;
	/** Human reasons (ASCII) that triggered the cap */
	reasons: string[];
}

export interface HonestyEvidence {
	bytesConsumed?: number;
	knownFunctionSize?: number;
	cLines?: number;
	semanticCoverage?: number;
	unsupportedInstructions?: number;
	decodeFailureInstructions?: number;
	scopeLimited?: {
		instructionLimit?: number;
		byteLimit?: number;
	};
	callfuscation?: {
		detected: boolean;
		gadgetCount: number;
		callCount: number;
		ratio: number;
	};
}

const CONF_RE = /\/\/\s*Confidence:\s*([\d.]+)%\s*\((High|Medium|Low)\)/i;

/** Match Helix CAstPrinter: >80 High, >50 Medium, else Low (50% damning → Low). */
function bandFor(score: number): 'High' | 'Medium' | 'Low' {
	if (score > 80) { return 'High'; }
	if (score > 50) { return 'Medium'; }
	return 'Low';
}

/**
 * Detect damning patterns that survive in emitted Pseudo-C text.
 * Keep this conservative: only patterns already treated as damning in Helix.
 */
export function detectTextDamningDefects(
	source: string,
	evidence: HonestyEvidence = {},
): string[] {
	const reasons: string[] = [];
	if (!source) { return reasons; }

	// FIX-110: unrecovered control flow
	const unhandled = source.match(/__helix_unhandled_[A-Za-z0-9_]+/g);
	if (unhandled && unhandled.length > 0) {
		const uniq = [...new Set(unhandled)];
		reasons.push(`unrecovered control flow (${uniq.slice(0, 3).join(', ')})`);
	}

	// D1: surviving code-address leak cast form
	if (/\(void\s*\*\s*\)\s*0x[0-9a-fA-F]{4,}/.test(source)) {
		reasons.push('surviving code-address leak (void*)0x…');
	}

	// D1 residual (#31): bare `var = 0xBLOCK;` clusters — Helix failed to tag
	// isCodeAddrLeak (folded/truncated immediates). Single magic constants are
	// common; a *cluster* of image-like hex assigns is the #31 symptom.
	const bareLeaks = countBareCodeAddrAssigns(source);
	if (bareLeaks.count >= 3) {
		reasons.push(
			`${bareLeaks.count} bare code-address-like assignments (e.g. 0x${bareLeaks.sample.toString(16)})`,
		);
	}

	// D3: post-return junk — crude same-function sequential scan on body lines.
	// Looks for a bare `return …;` then a later non-blank/non-brace/non-comment
	// statement before the function's closing.  Conservative: only fires when
	// ≥2 executable lines appear after the first return at brace-depth 1.
	const post = countPostReturnLines(source);
	if (post > 0) {
		reasons.push(`${post} unreachable statement(s) after return`);
	}

	// #56: a bare return/empty body proves that no behavior was recovered.
	// A return-of-call wrapper can be legitimate, so only classify that shape
	// when lift coverage is short or the authoritative function is far larger
	// than a real thunk/wrapper.
	const body = source.match(/\{([\s\S]*)\}\s*$/)?.[1] ?? '';
	const executable = body
		.split(/\r?\n/)
		.map(line => line.trim())
		.filter(line => line && !line.startsWith('//') && line !== '{' && line !== '}');
	const bareReturnOnly = executable.length === 0 ||
		(executable.length === 1 && /^return\s*;\s*$/.test(executable[0]));
	if (bareReturnOnly) {
		reasons.push('stub/empty body; no recovered behavior');
	}

	const known = evidence.knownFunctionSize ?? 0;
	const consumed = evidence.bytesConsumed ?? 0;
	const underLift = known > 0 && consumed > 0 && consumed < known * 0.85;
	if (underLift) {
		reasons.push(`under-lift (${consumed}/${known} bytes consumed)`);
	}

	if (evidence.scopeLimited) {
		const detail = evidence.scopeLimited.instructionLimit !== undefined
			? `${evidence.scopeLimited.instructionLimit} instruction(s)`
			: evidence.scopeLimited.byteLimit !== undefined
				? `${evidence.scopeLimited.byteLimit} byte(s)`
				: 'caller-provided boundary';
		reasons.push(`explicit scoped fragment (${detail}); confidence is not whole-function confidence`);
	}

	const unsupported = evidence.unsupportedInstructions ?? 0;
	const decodeFailures = evidence.decodeFailureInstructions ?? 0;
	if (unsupported > 0 || decodeFailures > 0) {
		const coverage = typeof evidence.semanticCoverage === 'number'
			? `, ${(evidence.semanticCoverage * 100).toFixed(1)}% semantic coverage`
			: '';
		reasons.push(
			`incomplete source IR (${unsupported} unsupported, ${decodeFailures} decode failures${coverage})`,
		);
	}

	const returnCallOnly = executable.length <= 2 &&
		/return\s+[A-Za-z_$][\w$]*(?:\s*\([^;]*\))?\s*;/.test(body);
	const suspiciouslyLargeWrapper = known >= 96 && returnCallOnly;
	if (!underLift && suspiciouslyLargeWrapper) {
		reasons.push(
			`stub-shaped body for ${known}-byte function (only call/return recovered)`,
		);
	}

	const cf = evidence.callfuscation;
	if (cf?.detected && cf.gadgetCount >= 16 && cf.ratio >= 0.5) {
		reasons.push(
			`callfuscation detected (${cf.gadgetCount}/${cf.callCount} call-as-jump gadgets); recovered semantics may be flattened`,
		);
	}

	return reasons;
}

/**
 * Bare hex immediates that look like leaked code addresses (not small masks).
 * Returns count of unique values + one sample for the reason string.
 *
 * Conservative gates (avoid false-high→false-low on magic numbers):
 *  - hex width ≥ 6 digits (and ≤ 16)
 *  - numeric value ≥ 0x10000
 *  - not all-bits masks (0xff…f of length 2/4/8)
 *  - for clusters: ≥3 values sharing the same high 16 bits (same image region)
 *    OR ≥3 full PE/ELF-looking bases (0x14… / 0x55… / 0x7F… style)
 */
export function countBareCodeAddrAssigns(source: string): { count: number; sample: number } {
	const empty = { count: 0, sample: 0 };
	if (!source) { return empty; }

	const re = /(?:=\s*|\(\s*)0x([0-9a-fA-F]{6,16})\b/g;
	const values: number[] = [];
	let m: RegExpExecArray | null;
	while ((m = re.exec(source)) !== null) {
		const hex = m[1];
		// all-F masks / small nibble patterns
		if (/^f+$/i.test(hex) || /^0+$/i.test(hex)) { continue; }
		const n = Number.parseInt(hex, 16);
		if (!Number.isFinite(n) || n < 0x10000) { continue; }
		// Skip tiny power-of-two-ish page sizes that are often real data
		if (n === 0x10000 || n === 0x100000 || n === 0x1000000) { continue; }
		values.push(n);
	}
	if (values.length === 0) { return empty; }

	const unique = [...new Set(values)];
	// Group by high 16 bits (region family)
	const byHi = new Map<number, number[]>();
	for (const v of unique) {
		const hi = (v >>> 16) & 0xffff;
		const arr = byHi.get(hi) ?? [];
		arr.push(v);
		byHi.set(hi, arr);
	}
	let best = 0;
	let sample = unique[0];
	for (const arr of byHi.values()) {
		if (arr.length > best) {
			best = arr.length;
			sample = arr[0];
		}
	}

	// Full-width PE/ELF code bases count even if high-16 differs slightly
	const imageLike = unique.filter(v => {
		// PE default image base region / user-space high
		if (v >= 0x140000000 && v < 0x150000000) { return true; }
		if (v >= 0x7ff000000000 && v < 0x800000000000) { return true; }
		// ELF PIE typical (low 48-bit with 0x55… prefix) — JS safe integers OK
		if (v >= 0x555555550000 && v < 0x555555560000) { return true; }
		// Truncated low-32 of PE code (0x4xxxxxxx with code-looking mid)
		if (v >= 0x40000000 && v < 0x50000000 && (v & 0xfff) !== 0) { return true; }
		return false;
	});

	const count = Math.max(best, imageLike.length >= 3 ? imageLike.length : 0);
	if (count < 3) { return empty; }
	return { count, sample: imageLike[0] ?? sample };
}

/**
 * Count executable lines that appear after a top-level `return` inside the
 * first function-like body.  Brace-depth tracking avoids counting nested
 * returns' siblings outside the function.
 */
export function countPostReturnLines(source: string): number {
	const lines = source.split(/\r?\n/);
	let depth = 0;
	let sawReturnAtDepth1 = false;
	let after = 0;
	for (const raw of lines) {
		const line = raw.trim();
		// Track braces roughly (ignore braces in strings — good enough for honesty gate)
		const opens = (raw.match(/\{/g) || []).length;
		const closes = (raw.match(/\}/g) || []).length;

		if (sawReturnAtDepth1 && depth >= 1) {
			if (line && !line.startsWith('//') && line !== '{' && line !== '}' &&
				!line.startsWith('#')) {
				// Don't count a second return / labels-only as heavily — still unreachable
				after++;
			}
		}

		if (depth === 1 && /^return\b/.test(line)) {
			sawReturnAtDepth1 = true;
		}

		depth += opens - closes;
		if (depth < 1) {
			// left the function
			if (sawReturnAtDepth1) { break; }
			sawReturnAtDepth1 = false;
		}
	}
	return after;
}

/**
 * Cap Confidence header to ≤50% when text damning defects are present and
 * the current score is above 50.  Appends an Issues-style note after the
 * Confidence line when missing.
 */
export function applyHonestyConfidenceCap(
	source: string,
	evidence: HonestyEvidence = {},
): HonestyCapResult {
	const reasons = detectTextDamningDefects(source, evidence);
	const m = source.match(CONF_RE);
	if (!m) {
		return { source, capped: false, reasons };
	}
	const originalScore = Number.parseFloat(m[1]);
	if (!Number.isFinite(originalScore)) {
		return { source, capped: false, reasons, originalScore };
	}
	if (reasons.length === 0 || originalScore <= 50) {
		return { source, capped: false, reasons, originalScore, newScore: originalScore };
	}

	const newScore = 50;
	const band = bandFor(newScore);
	const newHeader = `// Confidence: ${newScore}% (${band})`;
	let out = source.replace(CONF_RE, newHeader);

	const issueNote =
		`// Issues: damning honesty defect (${reasons.join('; ')}) - confidence capped at 50% (packaging safety net / #31/#56)`;
	// Insert after Confidence (+ optional LiftDiag) if no damning Issues already present
	if (!/damning honesty defect/i.test(out)) {
		out = out.replace(
			/(\/\/\s*Confidence:\s*50(?:\.\d+)?%\s*\((?:Low|Medium|High)\)[^\n]*\n)((?:\/\/\s*LiftDiag:[^\n]*\n)?)/,
			`$1$2${issueNote}\n`,
		);
	}

	return { source: out, capped: true, originalScore, newScore, reasons };
}
