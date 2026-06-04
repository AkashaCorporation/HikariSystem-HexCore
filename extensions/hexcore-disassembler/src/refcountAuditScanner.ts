/*---------------------------------------------------------------------------------------------
 *  HexCore Refcount Audit Scanner v0.1 — Milestone 2.1 (P0)
 *
 *  Automates four recurring kernel vulnerability patterns (refcount
 *  mismanagement, force-variant refcount bypass, dereference-after-failed-get,
 *  reachable crash primitive) surfaced during HexCore battle-testing on Linux
 *  GPU kernel drivers and Windows kernel drivers.
 *
 *  Scans decompiled C output (from Helix or any C-like source) for:
 *    - Pattern A — "get()" before error check without matching "put()" on error path
 *    - Pattern B — `_force` variants that bypass refcounting
 *    - Pattern C — unconditional operation after a failed refcount get()
 *    - Pattern E — reachable BUG_ON / panic / WARN_ON in error paths
 *
 *  Pattern D (lock-drop-reacquire with stale pointer) requires proper CFG
 *  dataflow analysis and is deferred to v0.2.
 *
 *  The scanner is regex + label-tracking based, not a full AST parser. That
 *  matches the doc's "AST-level or regex-based" contract and keeps the module
 *  zero-dep. False positives are filtered via heuristic confidence scoring.
 *
 *  Copyright (c) HikariSystem. All rights reserved.
 *--------------------------------------------------------------------------------------------*/

export type RefcountPattern = 'A' | 'B' | 'C' | 'E' | 'F';

export interface RefcountAuditFinding {
	/** Which detection pattern fired */
	pattern: RefcountPattern;
	/** 'high' | 'medium' | 'low' — qualitative triage weight */
	severity: 'high' | 'medium' | 'low';
	/** Confidence 0-100 — factoring in pattern specificity and surrounding heuristics */
	confidence: number;
	/** Human-readable summary */
	title: string;
	/** Detailed description referencing the pattern from the HexCore.3.8.0 spec */
	description: string;
	/** Function name containing the finding (or '<anonymous>' if unparseable) */
	functionName: string;
	/** 1-based line number within the input file */
	line: number;
	/** Code snippet (up to 4 lines around the hit) */
	snippet: string;
	/** Variable / symbol / API involved in the finding (best-effort) */
	affectedSymbol?: string;
	/** Suggested mitigation / root cause note */
	suggestion?: string;
	/** Reference to the vulnerability class (CWE) that matched this pattern (when applicable) */
	referenceBug?: string;
}

export interface RefcountAuditReport {
	inputFile: string;
	fileSize: number;
	scannedLines: number;
	functionsScanned: number;
	findings: RefcountAuditFinding[];
	summary: {
		total: number;
		byPattern: Record<RefcountPattern, number>;
		bySeverity: { high: number; medium: number; low: number };
		highestConfidence: number;
	};
	/** Scan duration in milliseconds */
	scanTimeMs: number;
}

// ---------------------------------------------------------------------------
// Constants — curated from Linux kernel + Windows driver refcount APIs
// ---------------------------------------------------------------------------

/**
 * get-like APIs that INCREMENT a refcount. Finding one of these followed by
 * an error-path exit WITHOUT the matching put is Pattern A. Names are split
 * into (incrementing, decrementing) pairs so we can look up "what put() cancels
 * this get()?".
 */
const REFCOUNT_PAIRS: ReadonlyArray<{ get: RegExp; put: RegExp; family: string }> = [
	// Linux kernel
	{ get: /\bkref_get(?:_unless_zero)?\s*\(/, put: /\bkref_put(?:_mutex)?\s*\(/, family: 'kref' },
	{ get: /\brefcount_inc(?:_not_zero)?\s*\(/, put: /\brefcount_dec(?:_and_test|_and_mutex_lock)?\s*\(/, family: 'refcount' },
	{ get: /\batomic_inc(?:_not_zero)?\s*\(/, put: /\batomic_dec(?:_and_test|_return)?\s*\(/, family: 'atomic' },
	{ get: /\bget_task_struct\s*\(/, put: /\bput_task_struct\s*\(/, family: 'task' },
	{ get: /\bget_device\s*\(/, put: /\bput_device\s*\(/, family: 'device' },
	{ get: /\bdget\s*\(/, put: /\bdput\s*\(/, family: 'dentry' },
	{ get: /\bmodule_get\s*\(|\btry_module_get\s*\(/, put: /\bmodule_put\s*\(/, family: 'module' },
	{ get: /\bfget(?:_light|_raw)?\s*\(/, put: /\bfput(?:_light)?\s*\(/, family: 'file' },
	{ get: /\bmntget\s*\(/, put: /\bmntput\s*\(/, family: 'mount' },
	{ get: /\bigrab\s*\(/, put: /\biput\s*\(/, family: 'inode' },
	{ get: /\bdma_buf_get\s*\(/, put: /\bdma_buf_put\s*\(/, family: 'dma_buf' },
	// GPU driver refcount families (Linux DRM/GPU subsystems)
	{ get: /\bkbase_[a-z_]*_(?:get|acquire|pin)\s*\(/, put: /\bkbase_[a-z_]*_(?:put|release|unpin)\s*\(/, family: 'kbase' },
	{ get: /\bkgsl_[a-z_]*_(?:get|acquire|pin)\s*\(/, put: /\bkgsl_[a-z_]*_(?:put|release|unpin)\s*\(/, family: 'kgsl' },
	// Windows KM
	{ get: /\bObReferenceObject(?:ByHandle|ByPointer)?\s*\(/, put: /\bObDereferenceObject\s*\(/, family: 'obj' },
];

/**
 * Names suggesting refcount-bypass / force variants. Finding a caller using
 * `*_force` OR a definition named `*_force` that doesn't call any put() is
 * Pattern B. Not inherently a bug but a strong smell worth flagging.
 */
const FORCE_VARIANT_NAMES: RegExp = /\b[a-zA-Z_][a-zA-Z0-9_]*_force(?:_release|_unmap|_put|_kill|_drop)?\s*\(/g;

/**
 * BUG_ON / panic / WARN_ON patterns — used in Pattern E.
 */
const CRASH_PRIMITIVES: RegExp = /\b(BUG_ON|BUG|panic|KeBugCheck(?:Ex)?|WARN_ON_ONCE|WARN_ON|assert|__builtin_trap)\s*\(/;

/**
 * Heuristic: words that signal an error-path label in decompiled C.
 */
const ERROR_LABEL_PATTERN: RegExp = /^\s*(err|error|fail|cleanup|unwind|rollback|out_err|bad|oom|abort)[a-z_0-9]*\s*:/i;

/**
 * Pattern A (raw): a refcount FIELD being incremented directly (`x->count++`,
 * `x.refcount += 1`) rather than through a get()-family call. Pattern A's
 * REFCOUNT_PAIRS are call-based and CANNOT match a raw increment (e.g.
 * `obj->...usage_count++`). The field must be a struct member (contains
 * `.`/`->`) whose tail looks like a reference counter.
 */
const RAW_INC_POST: RegExp = /([A-Za-z_]\w*(?:\s*(?:\.|->)\s*[A-Za-z_]\w*)+)\s*(?:\+\+|\+=\s*1\b)/;
const RAW_INC_PRE: RegExp = /\+\+\s*([A-Za-z_]\w*(?:\s*(?:\.|->)\s*[A-Za-z_]\w*)+)/;
/**
 * ReDoS guard (CWE-1333). RAW_INC_POST/PRE are unanchored and their member-chain
 * group backtracks ~O(n^2) against a very long member-access line that does NOT
 * end in `++`/`+= 1`. Real decompiled C never carries a refcount expression on a
 * line this wide, so any per-line regex is skipped beyond this width.
 */
const MAX_SCAN_LINE_LEN = 2000;
function isRefcountField(path: string): boolean {
	return /[.\->]/.test(path) && /(?:count|refcnt|refcount|usage|users|nref|_ref)\b/i.test(path);
}

/**
 * Pattern F (locking asymmetry): a lock-acquire primitive on a NAMED object.
 * Used to compare paired enable/disable (etc.) functions — if one acquires a
 * lock the other does not, the pair can race (CWE-667 / CWE-362).
 */
const LOCK_ACQUIRE: RegExp = /\b(?:mutex_lock(?:_interruptible|_nested|_killable)?|spin_lock(?:_irqsave|_irq|_bh)?|raw_spin_lock\w*|read_lock\w*|write_lock\w*|down_read|down_write|down_interruptible|down)\s*\(\s*&?([A-Za-z_][\w\s.\->]*?)[,)]/g;
/** Curated antonym pairs (strong, low-noise — short/common ones like on/off, up/down are intentionally excluded). */
const ANTONYM_PAIRS: ReadonlyArray<readonly [string, string]> = [
	['enable', 'disable'], ['lock', 'unlock'], ['acquire', 'release'],
	['start', 'stop'], ['suspend', 'resume'], ['open', 'close'], ['create', 'destroy'],
];

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

export function auditRefcount(source: string, filePath: string): RefcountAuditReport {
	if (typeof source !== 'string') {
		// Public-API surface: a non-string input previously threw an unguarded
		// TypeError ("Cannot read properties of undefined (reading 'split')").
		return {
			inputFile: filePath, fileSize: 0, scannedLines: 0, functionsScanned: 0,
			findings: [],
			summary: { total: 0, byPattern: { A: 0, B: 0, C: 0, E: 0, F: 0 }, bySeverity: { high: 0, medium: 0, low: 0 }, highestConfidence: 0 },
			scanTimeMs: 0,
		};
	}
	const startedAt = Date.now();
	const lines = source.split(/\r?\n/);
	const fns = extractFunctions(source);
	const findings: RefcountAuditFinding[] = [];

	for (const fn of fns) {
		findings.push(...detectPatternA(fn, source, lines));
		findings.push(...detectPatternARaw(fn, source, lines));
		findings.push(...detectPatternB(fn, source, lines));
		findings.push(...detectPatternC(fn, source, lines));
		findings.push(...detectPatternE(fn, source, lines));
	}

	// Pattern F is pairwise (cross-function), so it runs once over all functions.
	findings.push(...detectPatternF(fns, lines));

	// Also scan lines outside any detected function — covers hand-written
	// helpers whose boundaries the brace-matcher misses.
	if (fns.length === 0) {
		const synthetic: Fn = { name: '<top-level>', startLine: 1, endLine: lines.length, bodyLines: lines };
		findings.push(...detectPatternA(synthetic, source, lines));
		findings.push(...detectPatternARaw(synthetic, source, lines));
		findings.push(...detectPatternB(synthetic, source, lines));
		findings.push(...detectPatternC(synthetic, source, lines));
		findings.push(...detectPatternE(synthetic, source, lines));
	}

	// Deduplicate — two patterns can catch the same line, keep the highest-
	// severity/confidence one.
	const deduped = dedupeFindings(findings);

	const byPattern: Record<RefcountPattern, number> = { A: 0, B: 0, C: 0, E: 0, F: 0 };
	const bySeverity = { high: 0, medium: 0, low: 0 };
	let highestConfidence = 0;
	for (const f of deduped) {
		byPattern[f.pattern]++;
		bySeverity[f.severity]++;
		if (f.confidence > highestConfidence) { highestConfidence = f.confidence; }
	}

	return {
		inputFile: filePath,
		fileSize: source.length,
		scannedLines: lines.length,
		functionsScanned: fns.length,
		findings: deduped.sort((a, b) => b.confidence - a.confidence),
		summary: {
			total: deduped.length,
			byPattern,
			bySeverity,
			highestConfidence,
		},
		scanTimeMs: Date.now() - startedAt,
	};
}

// ---------------------------------------------------------------------------
// Function extraction — simple brace-matcher. Good enough for Helix output
// which has a predictable shape.
// ---------------------------------------------------------------------------

interface Fn {
	name: string;
	startLine: number; // 1-based line of the opening brace (or signature)
	endLine: number;
	bodyLines: string[]; // slice of the original source lines, inclusive
}

function extractFunctions(source: string): Fn[] {
	const fns: Fn[] = [];
	const lines = source.split(/\r?\n/);

	// Two-phase: find `signature { ... }` blocks where the line containing
	// `{` can be identified. Handles `int foo(x) {`, `static void bar() {`,
	// multi-line signatures, etc.
	const sigRe = /^\s*(?:[A-Za-z_][\w\s\*\(\)]*?)\s+([A-Za-z_]\w*)\s*\([^;]*\)\s*$/;
	const braceOpenOnly = /^\s*\{\s*$/;
	const inlineBrace = /^\s*(?:[A-Za-z_][\w\s\*\(\)]*?)\s+([A-Za-z_]\w*)\s*\([^;]*\)\s*\{/;

	for (let i = 0; i < lines.length; i++) {
		let name: string | null = null;
		let braceOpenLine = -1;

		const inlineMatch = inlineBrace.exec(lines[i]);
		if (inlineMatch) {
			name = inlineMatch[1];
			braceOpenLine = i;
		} else if (sigRe.test(lines[i]) && i + 1 < lines.length && braceOpenOnly.test(lines[i + 1])) {
			const m = sigRe.exec(lines[i]);
			if (m) { name = m[1]; braceOpenLine = i + 1; }
		}

		if (name === null || braceOpenLine === -1) { continue; }

		// Walk to matching close brace
		let depth = 0;
		let endLine = -1;
		for (let j = braceOpenLine; j < lines.length; j++) {
			for (const ch of lines[j]) {
				if (ch === '{') { depth++; }
				else if (ch === '}') {
					depth--;
					if (depth === 0) { endLine = j; break; }
				}
			}
			if (endLine !== -1) { break; }
			// Safety cap
			if (j - braceOpenLine > 5000) { endLine = j; break; }
		}
		if (endLine === -1) { continue; }

		fns.push({
			name,
			startLine: braceOpenLine + 1,
			endLine: endLine + 1,
			bodyLines: lines.slice(braceOpenLine, endLine + 1),
		});
		i = endLine; // jump past this function
	}

	return fns;
}

// ---------------------------------------------------------------------------
// Pattern A — Increment before error check without matching put on error
// ---------------------------------------------------------------------------

function detectPatternA(fn: Fn, _source: string, lines: string[]): RefcountAuditFinding[] {
	const findings: RefcountAuditFinding[] = [];

	for (const pair of REFCOUNT_PAIRS) {
		const getHits: Array<{ line: number; text: string; symbol: string }> = [];
		for (let i = 0; i < fn.bodyLines.length; i++) {
			const ln = fn.bodyLines[i];
			const m = pair.get.exec(ln);
			if (m) {
				// Try to extract the variable name being got
				const varMatch = /(?:get|inc|acquire|pin|grab|grab)[A-Za-z0-9_]*\s*\(\s*&?([A-Za-z_][\w\.\-\>]*)/.exec(ln);
				const symbol = varMatch ? varMatch[1] : m[0].trim();
				getHits.push({ line: fn.startLine + i, text: ln.trim(), symbol });
			}
		}
		if (getHits.length === 0) { continue; }

		// Any put() matching this family inside the function?
		const putHits: number[] = [];
		for (let i = 0; i < fn.bodyLines.length; i++) {
			if (pair.put.test(fn.bodyLines[i])) {
				putHits.push(fn.startLine + i);
			}
		}

		// For each get, check: is there an error-path goto/return between the
		// get and the function end that DOESN'T have a put before it?
		for (const g of getHits) {
			const bodyStartIdx = g.line - fn.startLine;
			let riskyExits = 0;
			let exitLine = 0;
			let exitText = '';
			for (let i = bodyStartIdx + 1; i < fn.bodyLines.length; i++) {
				const ln = fn.bodyLines[i];
				// Early exit primitives in error paths
				if (/\b(goto\s+(err|error|fail|out_err|cleanup|rollback|bad|abort))|return\s*-[A-Z]|return\s+NULL/i.test(ln)) {
					// Was there a matching put between g.line and this exit?
					let putBetween = false;
					for (const p of putHits) {
						if (p > g.line && p <= fn.startLine + i) { putBetween = true; break; }
					}
					if (!putBetween) {
						riskyExits++;
						if (exitLine === 0) { exitLine = fn.startLine + i; exitText = ln.trim(); }
					}
				}
			}

			if (riskyExits > 0) {
				const confidence = Math.min(95, 60 + riskyExits * 10 + (getHits.length > putHits.length ? 15 : 0));
				findings.push({
					pattern: 'A',
					severity: confidence >= 80 ? 'high' : 'medium',
					confidence,
					title: `Possible refcount leak: ${pair.family} get without matching put on error path`,
					description:
						`Function \`${fn.name}\` calls \`${pair.family}\`-family get() at line ${g.line} ` +
						`(${getHits.length} get vs ${putHits.length} put), followed by ${riskyExits} risky exit ` +
						`path(s) (e.g. \`${exitText}\` at line ${exitLine}) without intermediate put(). ` +
						`If the error path is hit, the refcount is never released.`,
					functionName: fn.name,
					line: g.line,
					snippet: snippetAround(lines, g.line, 2),
					affectedSymbol: g.symbol,
					suggestion: `Add \`${pair.family}\`-put() on all error paths reachable between the get() and the function exit, or restructure to acquire the reference only on the success branch.`,
					referenceBug: 'CWE-911 (refcount leak on error path)',
				});
			}
		}
	}

	return findings;
}

// ---------------------------------------------------------------------------
// Pattern A (raw) — raw refcount-FIELD increment before an error exit without
// a matching decrement. Pattern A above is call-based and cannot see this -- a
// real-world shape is a raw `obj->...usage_count++` left unbalanced on error.
// ---------------------------------------------------------------------------

function detectPatternARaw(fn: Fn, _source: string, lines: string[]): RefcountAuditFinding[] {
	const findings: RefcountAuditFinding[] = [];

	const incHits: Array<{ line: number; field: string }> = [];
	for (let i = 0; i < fn.bodyLines.length; i++) {
		const ln = fn.bodyLines[i];
		if (ln.length > MAX_SCAN_LINE_LEN) { continue; } // ReDoS guard (CWE-1333)
		if (/^\s*(?:\/\/|\*|\/\*)/.test(ln)) { continue; } // skip comment lines
		const m = RAW_INC_POST.exec(ln) ?? RAW_INC_PRE.exec(ln);
		if (!m) { continue; }
		const field = m[1].replace(/\s+/g, '');
		if (!isRefcountField(field)) { continue; }
		incHits.push({ line: fn.startLine + i, field });
	}
	if (incHits.length === 0) { return findings; }

	for (const g of incHits) {
		const bodyStartIdx = g.line - fn.startLine;
		const f = escapeRegex(g.field);
		const decRe = new RegExp(`${f}\\s*(?:--|-=\\s*1\\b)|--\\s*${f}`);
		let riskyExits = 0;
		let exitLine = 0;
		let exitText = '';
		for (let i = bodyStartIdx + 1; i < fn.bodyLines.length; i++) {
			const ln = fn.bodyLines[i];
			if (/\b(goto\s+(err|error|fail|out_err|cleanup|rollback|bad|abort)\w*)|return\s*-[A-Z]|return\s+NULL/i.test(ln)) {
				let decBetween = false;
				for (let j = bodyStartIdx + 1; j <= i; j++) {
					if (decRe.test(fn.bodyLines[j].replace(/\s+/g, ''))) { decBetween = true; break; }
				}
				if (!decBetween) {
					riskyExits++;
					if (exitLine === 0) { exitLine = fn.startLine + i; exitText = ln.trim(); }
				}
			}
		}

		if (riskyExits > 0) {
			const confidence = Math.min(92, 65 + riskyExits * 8);
			findings.push({
				pattern: 'A',
				severity: confidence >= 80 ? 'high' : 'medium',
				confidence,
				title: `Possible refcount corruption: raw increment of \`${g.field}\` not unwound on error path`,
				description:
					`Function \`${fn.name}\` increments refcount field \`${g.field}\` at line ${g.line} ` +
					`(raw \`++\`/\`+= 1\`, NOT a get()-family call), then takes ${riskyExits} error exit path(s) ` +
					`(e.g. \`${exitText}\` at line ${exitLine}) with no matching decrement of \`${g.field}\`. ` +
					`If the error path runs, the counter stays incremented -> corrupted refcount -> later ` +
					`use-after-free or double-free.`,
				functionName: fn.name,
				line: g.line,
				snippet: snippetAround(lines, g.line, 2),
				affectedSymbol: g.field,
				suggestion:
					`Move the increment AFTER the success check, or decrement \`${g.field}\` on every error ` +
					`path before exit.`,
				referenceBug: 'CWE-911 (refcount mismanagement on error path)',
			});
		}
	}

	return findings;
}

// ---------------------------------------------------------------------------
// Pattern B — _force variant ignoring refcount entirely
// ---------------------------------------------------------------------------

function detectPatternB(fn: Fn, _source: string, lines: string[]): RefcountAuditFinding[] {
	const findings: RefcountAuditFinding[] = [];

	// Case 1: this function's NAME ends in _force and it doesn't call any put()
	const nameIsForce = /_force(?:_release|_unmap|_put|_kill|_drop)?$/.test(fn.name);
	if (nameIsForce) {
		const body = fn.bodyLines.join('\n');
		const callsAnyPut = REFCOUNT_PAIRS.some(p => p.put.test(body));
		if (!callsAnyPut) {
			findings.push({
				pattern: 'B',
				severity: 'high',
				confidence: 80,
				title: `\`_force\` variant ignores refcounting`,
				description:
					`Function \`${fn.name}\` has the \`_force\` suffix typical of refcount-bypass helpers ` +
					`and does not call any known put/release primitive. Callers may release resources while ` +
					`other paths still hold a live reference, producing a use-after-free on the other path.`,
				functionName: fn.name,
				line: fn.startLine,
				snippet: snippetAround(lines, fn.startLine, 2),
				affectedSymbol: fn.name,
				suggestion: `Verify every caller of \`${fn.name}\` has exclusive ownership. If not, route those callers through the refcount-aware variant instead.`,
				referenceBug: 'CWE-911 (refcount-bypass via force variant)',
			});
		}
	}

	// Case 2: this function CALLS a _force variant
	for (let i = 0; i < fn.bodyLines.length; i++) {
		const ln = fn.bodyLines[i];
		FORCE_VARIANT_NAMES.lastIndex = 0;
		const m = FORCE_VARIANT_NAMES.exec(ln);
		if (m && !m[0].startsWith('//') && !/\bstatic\b/.test(ln)) {
			// Skip if the match IS our own function's name (self-call)
			const calledName = m[0].replace(/\s*\($/, '');
			if (calledName === fn.name) { continue; }
			findings.push({
				pattern: 'B',
				severity: 'medium',
				confidence: 60,
				title: `Caller invokes \`_force\` variant`,
				description:
					`\`${fn.name}\` calls \`${calledName}\` which bypasses refcounting. Confirm this call path ` +
					`holds the only reference to the target object; otherwise a concurrent put() can race into ` +
					`a use-after-free.`,
				functionName: fn.name,
				line: fn.startLine + i,
				snippet: snippetAround(lines, fn.startLine + i, 2),
				affectedSymbol: calledName,
				suggestion: `Audit the caller's locking discipline: if \`${calledName}\` is called from a path where other threads can still see the object, switch to the non-force variant.`,
			});
		}
	}

	return findings;
}

// ---------------------------------------------------------------------------
// Pattern C — Unconditional operation after failed refcount get
// ---------------------------------------------------------------------------

function detectPatternC(fn: Fn, _source: string, lines: string[]): RefcountAuditFinding[] {
	const findings: RefcountAuditFinding[] = [];

	for (let i = 0; i < fn.bodyLines.length; i++) {
		const ln = fn.bodyLines[i];
		// Match patterns like `if (!kref_get_unless_zero(...)) { ... } <continues>`
		// or `if (kref_get_unless_zero(...) == 0)` or `if (... == NULL)` where the
		// get() appears in the condition and the "ok we proceed" branch then
		// dereferences the returned object without checking its validity.
		for (const pair of REFCOUNT_PAIRS) {
			if (!pair.get.test(ln)) { continue; }

			// Is it inside an if-condition?
			const ifMatch = /if\s*\(\s*(!?)(.+)\)\s*(\{)?/.exec(ln);
			if (!ifMatch) { continue; }
			if (!pair.get.test(ifMatch[2])) { continue; }

			const negated = ifMatch[1] === '!';
			// Extract the symbol being refcounted
			const varMatch = /(?:get|inc|acquire|pin|grab|grab)[A-Za-z0-9_]*\s*\(\s*&?([A-Za-z_][\w\.\-\>]*)/.exec(ln);
			const symbol = varMatch ? varMatch[1] : 'object';

			// Scan the following block for derefs of that symbol
			const scanEnd = Math.min(i + 20, fn.bodyLines.length);
			const derefRe = new RegExp(`\\b${escapeRegex(symbol.split(/[\.\->]/)[0])}\\b`);
			let derefLine = -1;
			let derefText = '';
			for (let j = i + 1; j < scanEnd; j++) {
				const nxt = fn.bodyLines[j];
				// If we left the if-block via } before we see a deref, stop
				if (/^\s*\}\s*$/.test(nxt)) {
					// The success branch is likely BEFORE this }. If `negated`,
					// the code BELOW the } is the "get succeeded" path.
					if (negated) { continue; } else { break; }
				}
				if (derefRe.test(nxt) && /[-\>\.]/.test(nxt)) {
					derefLine = fn.startLine + j;
					derefText = nxt.trim();
					break;
				}
			}

			if (derefLine > 0) {
				findings.push({
					pattern: 'C',
					severity: 'high',
					confidence: 75,
					title: `Possible UAF: dereference after failed refcount get`,
					description:
						`Function \`${fn.name}\` calls \`${pair.family}\`-get() inside a conditional at line ${fn.startLine + i} ` +
						`and then dereferences \`${symbol}\` at line ${derefLine} (\`${derefText}\`) without ` +
						`verifying the get succeeded. If the get returns zero (object already destroyed), the ` +
						`subsequent access is a use-after-free.`,
					functionName: fn.name,
					line: fn.startLine + i,
					snippet: snippetAround(lines, fn.startLine + i, 3),
					affectedSymbol: symbol,
					suggestion: `Bail out on failure with \`return -ESTALE;\` / \`goto err;\` before touching \`${symbol}\`.`,
					referenceBug: 'CWE-416 (dereference after failed get)',
				});
			}
		}
	}

	return findings;
}

// ---------------------------------------------------------------------------
// Pattern E — Reachable BUG_ON / panic in error paths
// ---------------------------------------------------------------------------

function detectPatternE(fn: Fn, _source: string, lines: string[]): RefcountAuditFinding[] {
	const findings: RefcountAuditFinding[] = [];

	for (let i = 0; i < fn.bodyLines.length; i++) {
		const ln = fn.bodyLines[i];
		const m = CRASH_PRIMITIVES.exec(ln);
		if (!m) { continue; }
		// Skip obvious sanity checks on build-time constants (`BUILD_BUG_ON`)
		if (/\bBUILD_BUG_ON\b/.test(ln)) { continue; }

		// Heuristic: is this BUG_ON gated by a condition that checks something
		// attacker-controlled? Look upward for the nearest if() and see what it
		// tests. If it's a NULL/allocation check, this is reachable via OOM or
		// corrupted input.
		let reachability: 'high' | 'medium' | 'low' = 'medium';
		let context = '';
		for (let k = i - 1; k >= Math.max(0, i - 8); k--) {
			const prev = fn.bodyLines[k].trim();
			if (!prev || prev.startsWith('//')) { continue; }
			if (/\bif\s*\(/.test(prev)) {
				context = prev;
				// Patterns that make the BUG_ON user-reachable
				if (/==\s*NULL|!\s*[A-Za-z_]|kmalloc|kzalloc|kmem_cache_alloc|vmalloc|copy_from_user/.test(prev)) {
					reachability = 'high';
				} else if (/BUG_ON|WARN_ON/.test(prev)) {
					reachability = 'low';
				}
				break;
			}
			// Error label above means this BUG_ON is in cleanup — generally reachable
			if (ERROR_LABEL_PATTERN.test(prev)) { reachability = 'high'; break; }
		}

		const crashName = m[1];
		const confidence = reachability === 'high' ? 85 : reachability === 'medium' ? 55 : 30;
		findings.push({
			pattern: 'E',
			severity: reachability === 'high' ? 'high' : 'medium',
			confidence,
			title: `Reachable ${crashName} in error-handling path`,
			description:
				`Function \`${fn.name}\` contains \`${crashName}\` at line ${fn.startLine + i} ` +
				`${context ? `gated by \`${context}\` — ` : ''}` +
				`this may be reachable from userspace input or OOM conditions. Kernel ${crashName} ` +
				`results in system crash (DoS or privilege escalation via panic-handler races).`,
			functionName: fn.name,
			line: fn.startLine + i,
			snippet: snippetAround(lines, fn.startLine + i, 3),
			affectedSymbol: crashName,
			suggestion: `Replace \`${crashName}\` with a soft error return (\`-ENOMEM\` / \`-EINVAL\`) and let the caller handle the failure.`,
			referenceBug: reachability === 'high' ? 'CWE-617 (reachable crash primitive)' : undefined,
		});
	}

	return findings;
}

// ---------------------------------------------------------------------------
// Pattern F — locking asymmetry between paired functions (enable/disable etc.)
// One sibling acquires a named lock around shared state; the antonym sibling
// touches the same state WITHOUT it -> race (CWE-667 / CWE-362), which patterns
// A-E do not model.
// ---------------------------------------------------------------------------

/** Strip block and line comments so commented-out / mentioned APIs are ignored. */
function stripComments(s: string): string {
	return s.replace(/\/\*[\s\S]*?\*\//g, ' ').replace(/\/\/[^\n]*/g, ' ');
}

function locksAcquiredBy(fn: Fn): Set<string> {
	const set = new Set<string>();
	const body = stripComments(fn.bodyLines.join('\n'));
	const re = new RegExp(LOCK_ACQUIRE.source, 'g');
	let m: RegExpExecArray | null;
	while ((m = re.exec(body)) !== null) {
		const obj = m[1].replace(/\s+/g, '');
		// normalize to the last member token so `&a->state_lock` and
		// `&b->state_lock` compare equal across siblings.
		const tail = obj.split(/[.\->]+/).filter(Boolean).pop();
		if (tail) { set.add(tail); }
	}
	return set;
}

function roleOf(name: string): { role: string; anti: string } | null {
	const lower = name.toLowerCase();
	for (const [a, b] of ANTONYM_PAIRS) {
		if (new RegExp(`(?:^|_)${a}(?:_|$)`).test(lower)) { return { role: a, anti: b }; }
		if (new RegExp(`(?:^|_)${b}(?:_|$)`).test(lower)) { return { role: b, anti: a }; }
	}
	return null;
}

function longestCommonSubstr(a: string, b: string): string {
	let best = '';
	const dp: number[] = new Array(b.length + 1).fill(0);
	for (let i = 1; i <= a.length; i++) {
		let prev = 0;
		for (let j = 1; j <= b.length; j++) {
			const tmp = dp[j];
			if (a[i - 1] === b[j - 1]) {
				dp[j] = prev + 1;
				if (dp[j] > best.length) { best = a.slice(i - dp[j], i); }
			} else {
				dp[j] = 0;
			}
			prev = tmp;
		}
	}
	return best;
}

function detectPatternF(fns: Fn[], lines: string[]): RefcountAuditFinding[] {
	const findings: RefcountAuditFinding[] = [];
	const info = fns.map(fn => ({ fn, locks: locksAcquiredBy(fn), role: roleOf(fn.name) }));

	// Bucket by role so each A scans only its ANTONYM bucket instead of all-pairs.
	// The prior `for A for B` over every function was O(n^2) in function count — a
	// large decompiled .c (thousands of fns) would stall the scanner. Grouping is
	// O(n) and each anti-role bucket is usually tiny.
	const byRole = new Map<string, typeof info>();
	for (const it of info) {
		if (!it.role) { continue; }
		const bucket = byRole.get(it.role.role);
		if (bucket) { bucket.push(it); } else { byRole.set(it.role.role, [it]); }
	}

	for (const A of info) {
		// A must hold at least one named lock and have a recognizable role.
		if (!A.role || A.locks.size === 0) { continue; }
		const candidates = byRole.get(A.role.anti);
		if (!candidates) { continue; }
		for (const B of candidates) {
			if (B.fn === A.fn || !B.role) { continue; } // B.role is non-null by bucket; the check also narrows the type for TS
			const stem = longestCommonSubstr(A.fn.name.toLowerCase(), B.fn.name.toLowerCase());
			// The shared subject must dominate the names, not just a common library
			// prefix (e.g. `drv_`) — require it to cover >= half the shorter name.
			const minLen = Math.min(A.fn.name.length, B.fn.name.length);
			if (stem.length < Math.max(10, minLen * 0.5)) { continue; }
			if (B.fn.bodyLines.length < 4) { continue; } // skip trivial stubs
			const missing = [...A.locks].filter(l => !B.locks.has(l));
			if (missing.length === 0) { continue; } // B locks everything A does -> symmetric
			const lock = missing[0];
			findings.push({
				pattern: 'F',
				severity: 'high',
				confidence: 78,
				title: `Locking asymmetry: \`${B.fn.name}\` omits \`${lock}\` held by sibling \`${A.fn.name}\``,
				description:
					`\`${A.fn.name}\` acquires \`${lock}\` around its critical section, but its ${B.role.role} ` +
					`counterpart \`${B.fn.name}\` (shared subject \`${stem}\`) manipulates the same shared state ` +
					`WITHOUT acquiring \`${lock}\`${missing.length > 1 ? ` (and ${missing.length - 1} more)` : ''}. ` +
					`The two paths can run concurrently and corrupt shared state (e.g. double-release of resources, ` +
					`torn transition state).`,
				functionName: B.fn.name,
				line: B.fn.startLine,
				snippet: snippetAround(lines, B.fn.startLine, 2),
				affectedSymbol: lock,
				suggestion:
					`Acquire \`${lock}\` in \`${B.fn.name}\` to match \`${A.fn.name}\`, and hold it across the ` +
					`check-then-act in the common caller to close the TOCTOU window.`,
				referenceBug: 'CWE-667 (locking asymmetry)',
			});
		}
	}

	return findings;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function snippetAround(lines: string[], lineNumber: number, before = 2, after = 2): string {
	const start = Math.max(0, lineNumber - 1 - before);
	const end = Math.min(lines.length, lineNumber + after);
	const out: string[] = [];
	for (let i = start; i < end; i++) {
		const marker = (i === lineNumber - 1) ? '>>> ' : '    ';
		out.push(`${marker}${i + 1}: ${lines[i]}`);
	}
	return out.join('\n');
}

function dedupeFindings(findings: RefcountAuditFinding[]): RefcountAuditFinding[] {
	// Key = function + line — keep highest confidence
	const best = new Map<string, RefcountAuditFinding>();
	for (const f of findings) {
		const key = `${f.functionName}:${f.line}:${f.pattern}`;
		const cur = best.get(key);
		if (!cur || f.confidence > cur.confidence) { best.set(key, f); }
	}
	return [...best.values()];
}

function escapeRegex(s: string): string {
	return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
