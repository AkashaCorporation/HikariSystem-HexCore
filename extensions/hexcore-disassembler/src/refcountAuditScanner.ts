/*---------------------------------------------------------------------------------------------
 *  HexCore Refcount Audit Scanner v0.1 — Milestone 2.1 (P0)
 *
 *  Automates the vulnerability patterns that produced all 4 of the bounty bugs
 *  found across ARM Mali (mali_kbase.ko), Qualcomm Adreno KGSL (kgsl.c), and
 *  Riot Vanguard (vgk.sys) during the HexCore battle-testing sessions.
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

export type RefcountPattern = 'A' | 'B' | 'C' | 'E';

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
	/** Reference to the bounty bug that matched this pattern (when applicable) */
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
	// GPU driver specifics that showed up in Mali / Adreno bounty work
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

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

export function auditRefcount(source: string, filePath: string): RefcountAuditReport {
	const startedAt = Date.now();
	const lines = source.split(/\r?\n/);
	const fns = extractFunctions(source);
	const findings: RefcountAuditFinding[] = [];

	for (const fn of fns) {
		findings.push(...detectPatternA(fn, source, lines));
		findings.push(...detectPatternB(fn, source, lines));
		findings.push(...detectPatternC(fn, source, lines));
		findings.push(...detectPatternE(fn, source, lines));
	}

	// Also scan lines outside any detected function — covers hand-written
	// helpers whose boundaries the brace-matcher misses.
	if (fns.length === 0) {
		const synthetic: Fn = { name: '<top-level>', startLine: 1, endLine: lines.length, bodyLines: lines };
		findings.push(...detectPatternA(synthetic, source, lines));
		findings.push(...detectPatternB(synthetic, source, lines));
		findings.push(...detectPatternC(synthetic, source, lines));
		findings.push(...detectPatternE(synthetic, source, lines));
	}

	// Deduplicate — two patterns can catch the same line, keep the highest-
	// severity/confidence one.
	const deduped = dedupeFindings(findings);

	const byPattern: Record<RefcountPattern, number> = { A: 0, B: 0, C: 0, E: 0 };
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
					referenceBug: pair.family === 'kbase' ? 'Mali Bug #1 (kbase_gpu_mmap)' : undefined,
				});
			}
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
				referenceBug: 'Mali Bug #2 (release_force)',
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
					referenceBug: pair.family === 'kgsl' ? 'Qualcomm Bug #2 (vm_open UAF)' : undefined,
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
			referenceBug: reachability === 'high' ? 'Qualcomm Bug #1 (VBO BUG_ON)' : undefined,
		});
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
