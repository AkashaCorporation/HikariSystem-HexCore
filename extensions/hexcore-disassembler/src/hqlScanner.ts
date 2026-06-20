/*---------------------------------------------------------------------------------------------
 *  HexCore HQL Scanner -- VS Code surface for the Helix Query Language semantic scanner.
 *
 *  The CORE (signature matching over a hydrated Helix HAST) lives in the sibling
 *  `hexcore-hql` extension (pure TS/JS, no native binding). This module is the thin
 *  glue that wires it into:
 *    - the interactive command  `hexcore.hql.scanFunction`
 *    - the headless capability   `hexcore.hql.scanHeadless`  (pipeline-addressable)
 *
 *  It does NOT re-implement the lift/decompile orchestration. It calls the existing
 *  `hexcore.helix.decompile` (binary+address) / `hexcore.helix.decompileIR` (IR text/
 *  file) commands -- which already handle file load, Remill lift, Souper, data sections,
 *  function-start tables, struct info and session renames -- and reads back the raw HAST
 *  FlatBuffer (`astBuffer`) those commands now expose on their headless/quiet return.
 *  scanHAST() then evaluates the built-in signature library over every function.
 *---------------------------------------------------------------------------------------------*/

import * as path from 'path';

// ---------------------------------------------------------------------------
// hexcore-hql module surface (typed locally to avoid coupling the disassembler
// tsconfig to the sibling's build output; hexcore-hql is pure JS in dist/).
// ---------------------------------------------------------------------------

/** Mirror of hexcore-hql's HQLMatchResult (dist/types/hql.d.ts). */
export interface HqlMatchResult {
	signatureId: string;
	/** Matched AST nodes (opaque here -- we only surface the count). */
	matches: unknown[];
	confidence: number;
}

/** Mirror of hexcore-hql's HQLFunctionFindings (dist/scan.d.ts). */
export interface HqlFunctionFindings {
	function: string;
	findings: HqlMatchResult[];
}

interface HqlModule {
	scanHAST(astBuffer: Uint8Array): HqlFunctionFindings[];
}

let cachedHql: HqlModule | undefined;
let cachedHqlError: string | undefined;

/**
 * Lazily resolve the sibling hexcore-hql library. Matches the relative-path
 * convention used by the native wrappers (`__dirname` is the compiled `out/`
 * dir, so `../../hexcore-hql` == `extensions/hexcore-hql`). Returns undefined
 * and records the error if the library cannot be loaded.
 */
export function loadHql(): HqlModule | undefined {
	if (cachedHql) { return cachedHql; }
	if (cachedHqlError) { return undefined; }
	const candidates = [
		path.join(__dirname, '..', '..', 'hexcore-hql', 'dist', 'index.js'),
		path.join(__dirname, '..', '..', '..', 'hexcore-hql', 'dist', 'index.js'),
	];
	for (const candidate of candidates) {
		try {
			// eslint-disable-next-line @typescript-eslint/no-var-requires
			const mod = require(candidate) as Partial<HqlModule>;
			if (mod && typeof mod.scanHAST === 'function') {
				cachedHql = mod as HqlModule;
				return cachedHql;
			}
		} catch {
			// try next candidate
		}
	}
	cachedHqlError = `hexcore-hql not found (looked in: ${candidates.join(', ')})`;
	console.warn('[hexcore-hql]', cachedHqlError);
	return undefined;
}

export function getHqlLoadError(): string | undefined {
	return cachedHqlError;
}

// ---------------------------------------------------------------------------
// Decompile-result shape (subset of the headless/quiet return of the
// hexcore.helix.decompile / .decompileIR commands, now carrying astBuffer).
// ---------------------------------------------------------------------------

export interface HelixDecompileQuietResult {
	success: boolean;
	code: string;
	address: string;
	error: string;
	astBuffer?: Buffer | null;
}

/** A `runHqlScan` callback that invokes the right Helix decompile command. */
export type DecompileFn = (target: HqlScanTarget) => Promise<HelixDecompileQuietResult | undefined>;

export interface HqlScanTarget {
	/** Binary file path (for the helix.decompile lift path). */
	file?: string;
	/** Single function entry address (binary path). */
	address?: string | number;
	/** Pre-lifted LLVM IR file path (helix.decompileIR path -- used by fixtures/tests). */
	irPath?: string;
	/** Raw LLVM IR text (helix.decompileIR path). */
	irText?: string;
}

/** Per-target HQL scan result included in the headless report. */
export interface HqlAddressResult {
	address: string;
	function: string;
	findings: Array<{ signatureId: string; confidence: number; matchCount: number }>;
	error?: string;
}

export interface HqlHeadlessReport {
	success: boolean;
	command: 'hexcore.hql.scanHeadless';
	file?: string;
	targetCount: number;
	matchedFunctionCount: number;
	totalFindings: number;
	results: HqlAddressResult[];
	error?: string;
}

// ---------------------------------------------------------------------------
// Core: decompile one target -> scanHAST -> flatten to findings.
// ---------------------------------------------------------------------------

/**
 * Decompile a single target and run the HQL signature library over its HAST.
 * Returns one HqlAddressResult. Never throws for an expected failure (no AST,
 * decompile error, hql unavailable) -- the failure is encoded in the result so
 * a batch scan reports partial success instead of aborting.
 */
export async function scanOneTarget(
	target: HqlScanTarget,
	decompile: DecompileFn
): Promise<HqlAddressResult> {
	const addrLabel =
		target.address !== undefined ? String(target.address)
			: target.irPath !== undefined ? target.irPath
				: target.irText !== undefined ? '<ir-text>'
					: '<unknown>';

	const hql = loadHql();
	if (!hql) {
		return { address: addrLabel, function: '', findings: [], error: getHqlLoadError() ?? 'hexcore-hql unavailable' };
	}

	let dr: HelixDecompileQuietResult | undefined;
	try {
		dr = await decompile(target);
	} catch (err) {
		const msg = err instanceof Error ? err.message : String(err);
		return { address: addrLabel, function: '', findings: [], error: `decompile threw: ${msg}` };
	}

	if (!dr || !dr.success) {
		return { address: addrLabel, function: '', findings: [], error: dr?.error || 'decompile failed' };
	}

	const ab = dr.astBuffer;
	if (!ab || ab.length === 0) {
		return { address: dr.address || addrLabel, function: '', findings: [], error: 'no AST (decompile produced no functions)' };
	}

	let perFunction: HqlFunctionFindings[];
	try {
		perFunction = hql.scanHAST(Uint8Array.from(ab));
	} catch (err) {
		const msg = err instanceof Error ? err.message : String(err);
		return { address: dr.address || addrLabel, function: '', findings: [], error: `scanHAST threw: ${msg}` };
	}

	// scanHAST returns one entry per function with >=1 finding. A single decompiled
	// target is one function, but be defensive and flatten all of them.
	const flatFindings: Array<{ signatureId: string; confidence: number; matchCount: number }> = [];
	let functionName = '';
	for (const fn of perFunction) {
		if (!functionName) { functionName = fn.function; }
		for (const f of fn.findings) {
			flatFindings.push({
				signatureId: f.signatureId,
				confidence: f.confidence,
				matchCount: Array.isArray(f.matches) ? f.matches.length : 0,
			});
		}
	}

	return { address: dr.address || addrLabel, function: functionName, findings: flatFindings };
}

/**
 * Run the HQL scan over a batch of targets and assemble the headless report.
 * Partial failures (one address fails to decompile) are captured per-result;
 * the overall report is `success: true` as long as the scan machinery ran.
 */
export async function runHqlScanBatch(
	file: string | undefined,
	targets: HqlScanTarget[],
	decompile: DecompileFn
): Promise<HqlHeadlessReport> {
	if (!loadHql()) {
		return {
			success: false,
			command: 'hexcore.hql.scanHeadless',
			file,
			targetCount: targets.length,
			matchedFunctionCount: 0,
			totalFindings: 0,
			results: [],
			error: getHqlLoadError() ?? 'hexcore-hql unavailable',
		};
	}

	const results: HqlAddressResult[] = [];
	for (const target of targets) {
		results.push(await scanOneTarget(target, decompile));
	}

	const matchedFunctionCount = results.filter(r => r.findings.length > 0).length;
	const totalFindings = results.reduce((acc, r) => acc + r.findings.length, 0);

	return {
		success: true,
		command: 'hexcore.hql.scanHeadless',
		file,
		targetCount: targets.length,
		matchedFunctionCount,
		totalFindings,
		results,
	};
}

/**
 * Normalize the `address` + `addresses` headless args into an ordered, de-duped
 * list of scan targets. When an IR fixture (`irPath`/`irText`) is supplied it is
 * the single target (no binary addresses). Each address becomes one target that
 * carries the binary `file` for the lift.
 */
export function buildScanTargets(args: {
	file?: string;
	address?: string | number;
	addresses?: Array<string | number>;
	irPath?: string;
	irText?: string;
}): HqlScanTarget[] {
	if (args.irText !== undefined || args.irPath !== undefined) {
		return [{ irPath: args.irPath, irText: args.irText }];
	}
	const addrs: Array<string | number> = [];
	if (args.address !== undefined) { addrs.push(args.address); }
	if (Array.isArray(args.addresses)) {
		for (const a of args.addresses) { addrs.push(a); }
	}
	// De-dupe while preserving order (string form as the key).
	const seen = new Set<string>();
	const targets: HqlScanTarget[] = [];
	for (const a of addrs) {
		const key = String(a);
		if (seen.has(key)) { continue; }
		seen.add(key);
		targets.push({ file: args.file, address: a });
	}
	return targets;
}
