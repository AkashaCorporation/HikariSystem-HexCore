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
import * as crypto from 'crypto';
import type { SessionStore } from './sessionStore';

// ---------------------------------------------------------------------------
// hexcore-hql module surface (typed locally to avoid coupling the disassembler
// tsconfig to the sibling's build output; hexcore-hql is pure JS in dist/).
// ---------------------------------------------------------------------------

/** Mirror of hexcore-hql's HQLMatchResult (dist/types/hql.d.ts). */
export interface HqlMatchResult {
	signatureId: string;
	/** Matched AST nodes (opaque here -- we only surface the count). */
	matches: unknown[];
	structuralCompleteness: number;
	evidenceLevel: 'signal' | 'candidate' | 'proven';
	confidence?: number;
	adapterCoverage?: number;
	adapterLossAffected?: boolean;
	semanticMatches?: Array<{
		kind: string;
		attributes: Record<string, string | number | boolean>;
		proofStatus: 'signal' | 'candidate' | 'proven';
		provenance: Array<{ producer: string; source: string; strength: string; generation: number }>;
	}>;
}

/** Mirror of hexcore-hql's HQLFunctionFindings (dist/scan.d.ts). */
export interface HqlFunctionFindings {
	function: string;
	address: string;
	nodeCount: number;
	adapterCoverage: {
		totalNodes: number;
		lossyNodes: number;
		coverage: number;
		unsupportedNodeCounts: Record<string, number>;
	};
	hast: {
		schemaMajor: number;
		schemaMinor: number;
		capabilities: string[];
		producer?: string;
		producerVersion?: string;
		architecture?: string;
		pointerBits?: number;
		semanticEligible: boolean;
	};
	signatureSetSha256: string;
	cacheKey: string;
	status: 'ok' | 'partial';
	truncated: boolean;
	truncationReasons: string[];
	partialReasons: string[];
	evaluatedSignatureCount: number;
	findings: HqlMatchResult[];
	semanticFactCount: number;
	semanticFactsSha256: string;
	semanticReadErrors: string[];
}

interface HqlModule {
	SessionDbReader: new (dbPath: string, sqliteModule: HqlSqliteModule) => HqlSessionReader;
	scanHAST(
		astBuffer: Uint8Array,
		signatures?: unknown,
		session?: unknown,
		options?: { maxFunctions?: number; maxNodesPerFunction?: number; maxFindingsPerFunction?: number; signal?: AbortSignal },
	): HqlFunctionFindings[];
}

interface HqlSqliteModule {
	openDatabase(filename: string, options?: { readonly?: boolean; fileMustExist?: boolean }): unknown;
}

interface HqlSessionReader {
	getTargetIdentity(): string | undefined;
	getFunctionName(address: string): string | undefined;
	getFunctionReturnType(address: string): string | undefined;
	getVariableRenames(address: string): Array<{ original_name: string; new_name: string | null; new_type: string | null }>;
	getSemanticFacts(address: string): unknown[];
	getSemanticReadErrors(): string[];
	dispose(): void;
}

export interface HqlSessionBinding {
	dbPath: string;
	expectedTargetIdentity: string;
}

export type HqlSessionBindingProvider = HqlSessionBinding | (() => HqlSessionBinding | HqlSessionReader | undefined);

function isHqlSessionReader(value: HqlSessionBinding | HqlSessionReader): value is HqlSessionReader {
	return typeof (value as Partial<HqlSessionReader>).getSemanticFacts === 'function';
}

let cachedHql: HqlModule | undefined;
let cachedHqlError: string | undefined;
let cachedSqlite: HqlSqliteModule | undefined;

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
			if (mod && typeof mod.scanHAST === 'function' && typeof mod.SessionDbReader === 'function') {
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

function loadHqlSqlite(): HqlSqliteModule {
	if (cachedSqlite) { return cachedSqlite; }
	const candidates = [
		path.join(__dirname, '..', '..', 'hexcore-better-sqlite3', 'index.js'),
		path.join(__dirname, '..', '..', '..', 'hexcore-better-sqlite3', 'index.js'),
		'hexcore-better-sqlite3',
	];
	for (const candidate of candidates) {
		try {
			// eslint-disable-next-line @typescript-eslint/no-var-requires
			const mod = require(candidate) as Partial<HqlSqliteModule>;
			if (typeof mod.openDatabase === 'function') {
				cachedSqlite = mod as HqlSqliteModule;
				return cachedSqlite;
			}
		} catch {
			// Try the next packaged/native location.
		}
	}
	throw new Error(`hexcore-better-sqlite3 not found (looked in: ${candidates.join(', ')})`);
}

function openBoundHqlSession(hql: HqlModule, provider: HqlSessionBindingProvider | undefined): HqlSessionReader | undefined {
	const binding = typeof provider === 'function' ? provider() : provider;
	if (!binding) { return undefined; }
	if (isHqlSessionReader(binding)) {
		return binding;
	}
	const reader = new hql.SessionDbReader(binding.dbPath, loadHqlSqlite());
	const actualTargetIdentity = reader.getTargetIdentity();
	if (actualTargetIdentity !== binding.expectedTargetIdentity) {
		reader.dispose();
		throw new Error(`HXDB target mismatch: expected ${binding.expectedTargetIdentity}, got ${actualTargetIdentity ?? 'missing'}`);
	}
	return reader;
}

type HqlSemanticFact = NonNullable<HqlMatchResult['semanticMatches']>[number];

/**
 * Installed scans already own a target-bound SemanticStore. Read that accepted
 * generation directly instead of reopening the same HXDB through Electron's
 * native SQLite statement wrapper.
 */
export function createLiveHqlSessionReader(session: SessionStore): HqlSessionReader {
	const semanticStore = session.getSemanticStore();
	let semanticReadErrors: string[] = [];
	const proofStatus = (strength: string): HqlSemanticFact['proofStatus'] =>
		strength === 'definitive' || strength === 'debug' ? 'proven'
			: strength === 'signature' || strength === 'derived' ? 'candidate' : 'signal';
	const evidence = (record: any) => {
		const evidenceSet = Array.isArray(record?.evidenceSet) && record.evidenceSet.length > 0
			? record.evidenceSet : record?.evidence ? [record.evidence] : [];
		const provenance = evidenceSet.map((item: any) => ({
			producer: String(item?.producer ?? 'unknown'),
			source: String(item?.source ?? 'unknown'),
			strength: String(item?.strength ?? 'unknown'),
			generation: Number(item?.generation ?? 0),
		}));
		return { provenance, proofStatus: provenance[0] ? proofStatus(provenance[0].strength) : 'candidate' as const };
	};
	const append = (
		facts: HqlSemanticFact[], kind: string,
		attributes: Record<string, string | number | boolean>, record: any,
		fallback: HqlSemanticFact['proofStatus'] = 'candidate',
	): void => {
		const derived = evidence(record);
		facts.push({ kind, attributes, proofStatus: derived.provenance.length > 0 ? derived.proofStatus : fallback, provenance: derived.provenance });
	};
	return {
		getTargetIdentity: () => semanticStore.targetIdentity,
		getFunctionName: address => session.getFunction(address)?.name ?? undefined,
		getFunctionReturnType: address => session.getFunction(address)?.return_type ?? undefined,
		getVariableRenames: address => session.getVariables(address).map(item => ({
			original_name: item.original_name,
			new_name: item.new_name,
			new_type: item.new_type,
		})),
		getSemanticFacts: addressInput => {
			semanticReadErrors = [];
			const address = addressInput.toLowerCase();
			const functionIdentity = `function:${address}`;
			const facts: HqlSemanticFact[] = [];
			try {
				const prototype = semanticStore.getPrototype(functionIdentity) ?? semanticStore.getPrototypeAtAddress(address);
				if (prototype) {
					append(facts, 'function-prototype', {
						functionIdentity: prototype.functionIdentity,
						callingConventionId: prototype.callingConventionId,
						returnTypeId: prototype.returnTypeId,
						variadic: prototype.variadic,
						noreturn: prototype.noreturn,
						method: prototype.method,
						provider: prototype.evidence.producer,
						evidenceStrength: prototype.evidence.strength,
						generation: prototype.evidence.generation,
					}, prototype);
				}
				for (const binding of semanticStore.findTypeBindings(functionIdentity)) {
					append(facts, 'type-binding', {
						bindingId: binding.bindingId, scope: binding.scope,
						valueIdentity: binding.valueIdentity, typeId: binding.typeId,
						functionIdentity, provider: binding.evidence.producer,
						evidenceStrength: binding.evidence.strength, generation: binding.evidence.generation,
					}, binding);
				}
				for (const edge of semanticStore.getReferenceGraph().query({ direction: 'both', functionIdentity })) {
					append(facts, 'xref', {
						relation: edge.relation, family: edge.family,
						sourceAddress: edge.source.address, targetKind: edge.target.kind,
						targetIdentity: edge.target.identity,
						...(edge.target.address ? { targetAddress: edge.target.address } : {}),
						...(edge.accessWidthBits !== null ? { accessWidthBits: edge.accessWidthBits } : {}),
						provider: edge.evidence.producer, evidenceStrength: edge.evidence.strength,
						generation: edge.generation,
					}, edge);
					for (const resolution of edge.indirectResolutionSet) {
						append(facts, 'indirect-target', {
							relation: edge.relation, sourceAddress: edge.source.address,
							targetIdentity: edge.target.identity, status: resolution.status,
							resolutionSource: resolution.source, candidateSetId: resolution.candidateSetId,
							provider: edge.evidence.producer, generation: edge.generation,
						}, edge, resolution.status === 'resolved' ? 'proven' : 'candidate');
					}
				}
				const summary = semanticStore.getWholeProgramPropagationStore().getSummary(functionIdentity);
				if (summary) {
					for (const call of summary.calls) append(facts, 'summary-call', {
						callsiteIdentity: call.callsiteIdentity, calleeIdentity: call.calleeIdentity,
						argumentCount: call.arguments.length, indirectCandidateCount: call.indirectCandidates?.length ?? 0,
						generation: summary.generation,
					}, summary);
					for (const global of summary.globalEffects) append(facts, 'summary-global', {
						globalIdentity: global.globalIdentity, access: global.access, generation: summary.generation,
					}, summary);
					for (const ownership of summary.ownershipEffects) append(facts, 'summary-ownership', {
						ownershipKind: ownership.kind, valueIdentity: ownership.value.identity,
						...(ownership.objectIdentity ? { objectIdentity: ownership.objectIdentity } : {}),
						generation: summary.generation,
					}, summary);
					for (const field of summary.fieldAccesses) append(facts, 'summary-field', {
						fieldIdentity: field.fieldIdentity, baseIdentity: field.base.identity,
						offsetBytes: field.offsetBytes, access: field.access,
						...(field.typeId ? { typeId: field.typeId } : {}), generation: summary.generation,
					}, summary);
					for (const barrier of summary.barriers) append(facts, 'summary-barrier', {
						barrierIdentity: barrier.identity, reason: barrier.reason,
						lossy: barrier.lossy, generation: summary.generation,
					}, summary, 'signal');
				}
				for (const conflict of semanticStore.listConflicts().filter(item => item.factKey === functionIdentity || item.factKey === address)) {
					facts.push({
						kind: 'semantic-conflict',
						attributes: {
							factKind: conflict.factKind, factKey: conflict.factKey, reason: conflict.reason,
							winnerHash: conflict.winnerHash, loserHash: conflict.loserHash,
						},
						proofStatus: 'signal', provenance: [],
					});
				}
			} catch (error) {
				semanticReadErrors.push(error instanceof Error ? error.message : String(error));
			}
			return facts.sort((left, right) => JSON.stringify(left).localeCompare(JSON.stringify(right)));
		},
		getSemanticReadErrors: () => [...semanticReadErrors],
		dispose: () => undefined,
	};
}

// ---------------------------------------------------------------------------
// Decompile-result shape (subset of the headless/quiet return of the
// hexcore.helix.decompile / .decompileIR commands, now carrying astBuffer).
// ---------------------------------------------------------------------------

export interface HelixDecompileQuietResult {
	success: boolean;
	status?: 'ok' | 'partial' | 'error';
	code: string;
	address: string;
	error: string;
	confidence?: number;
	qualityIssues?: string[];
	warning?: string;
	astBuffer?: Buffer | null;
}

/** A `runHqlScan` callback that invokes the right Helix decompile command. */
export type DecompileFn = (target: HqlScanTarget) => Promise<HelixDecompileQuietResult | undefined>;

export interface HqlScanTarget {
	/** Binary file path (for the helix.decompile lift path). */
	file?: string;
	/** Single function entry address (binary path). */
	address?: string | number;
	/** Pre-lifted Remill-compatible LLVM IR file path (helix.decompileIR path). */
	irPath?: string;
	/** Raw Remill-compatible LLVM IR text (helix.decompileIR path). */
	irText?: string;
}

/** Per-target HQL scan result included in the headless report. */
export interface HqlAddressResult {
	status: 'ok' | 'partial' | 'error';
	requestedTarget?: string;
	address: string;
	function: string;
	nodeCount?: number;
	adapterCoverage?: HqlFunctionFindings['adapterCoverage'];
	hast?: HqlFunctionFindings['hast'];
	signatureSetSha256?: string;
	cacheKey?: string;
	truncated?: boolean;
	truncationReasons?: string[];
	partialReasons?: string[];
	evaluatedSignatureCount?: number;
	semanticFactCount?: number;
	semanticFactsSha256?: string;
	semanticReadErrors?: string[];
	findings: Array<{
		signatureId: string;
		structuralCompleteness: number;
		evidenceLevel: 'signal' | 'candidate' | 'proven';
		confidence?: number;
		adapterCoverage?: number;
		adapterLossAffected?: boolean;
		matchCount: number;
		semanticMatches?: HqlMatchResult['semanticMatches'];
	}>;
	error?: string;
}

function mapHqlFunctionFinding(fn: HqlFunctionFindings, fallbackAddress: string, requestedTarget?: string): HqlAddressResult {
	return {
		status: fn.status,
		...(requestedTarget ? { requestedTarget } : {}),
		address: fn.address || fallbackAddress,
		function: fn.function,
		nodeCount: fn.nodeCount,
		adapterCoverage: fn.adapterCoverage,
		hast: fn.hast,
		signatureSetSha256: fn.signatureSetSha256,
		cacheKey: fn.cacheKey,
		truncated: fn.truncated,
		truncationReasons: [...fn.truncationReasons],
		partialReasons: [...fn.partialReasons],
		evaluatedSignatureCount: fn.evaluatedSignatureCount,
		semanticFactCount: fn.semanticFactCount,
		semanticFactsSha256: fn.semanticFactsSha256,
		semanticReadErrors: [...fn.semanticReadErrors],
		findings: fn.findings.map(finding => ({
			signatureId: finding.signatureId,
			structuralCompleteness: finding.structuralCompleteness,
			evidenceLevel: finding.evidenceLevel,
			...(finding.confidence !== undefined ? { confidence: finding.confidence } : {}),
			...(finding.adapterCoverage !== undefined ? { adapterCoverage: finding.adapterCoverage } : {}),
			...(finding.adapterLossAffected ? { adapterLossAffected: true } : {}),
			...(finding.semanticMatches ? { semanticMatches: finding.semanticMatches.map(fact => ({
				...fact,
				attributes: { ...fact.attributes },
				provenance: fact.provenance.map(item => ({ ...item })),
			})) } : {}),
			matchCount: Array.isArray(finding.matches) ? finding.matches.length : 0,
		})),
	};
}

export function preserveHqlFunctionFindings(
	perFunction: readonly HqlFunctionFindings[],
	fallbackAddress: string,
	requestedTarget?: string,
): HqlAddressResult[] {
	return perFunction.map(fn => mapHqlFunctionFinding(fn, fallbackAddress, requestedTarget));
}

export interface HqlHeadlessReport {
	success: boolean;
	status: 'ok' | 'partial' | 'failed';
	command: 'hexcore.hql.scanHeadless';
	file?: string;
	targetCount: number;
	completedTargetCount: number;
	failedTargetCount: number;
	partialTargetCount: number;
	matchedFunctionCount: number;
	totalFindings: number;
	results: HqlAddressResult[];
	error?: string;
	budget: {
		maxTargets: number;
		maxConcurrency: number;
		maxFunctionsPerHast: number;
		maxNodesPerFunction: number;
		maxFindingsPerFunction: number;
	};
}

export interface HqlBatchOptions {
	maxTargets?: number;
	maxConcurrency?: number;
	maxFunctionsPerHast?: number;
	maxNodesPerFunction?: number;
	maxFindingsPerFunction?: number;
	signal?: AbortSignal;
	/** Target-bound read-only HXDB used by HQL semantic conditions. */
	session?: HqlSessionBindingProvider;
}

export const DEFAULT_HQL_BATCH_BUDGET = Object.freeze({
	maxTargets: 256,
	maxConcurrency: 2,
	maxFunctionsPerHast: 64,
	maxNodesPerFunction: 250_000,
	maxFindingsPerFunction: 1024,
});

export async function mapWithConcurrency<T, R>(
	items: readonly T[],
	maxConcurrency: number,
	mapper: (item: T, index: number) => Promise<R>,
): Promise<R[]> {
	if (!Number.isSafeInteger(maxConcurrency) || maxConcurrency <= 0) throw new Error('maxConcurrency must be a positive safe integer');
	const results = new Array<R>(items.length);
	let nextIndex = 0;
	const worker = async (): Promise<void> => {
		while (true) {
			const index = nextIndex++;
			if (index >= items.length) return;
			results[index] = await mapper(items[index], index);
		}
	};
	await Promise.all(Array.from({ length: Math.min(maxConcurrency, Math.max(1, items.length)) }, () => worker()));
	return results;
}

export function summarizeHqlResults(results: readonly HqlAddressResult[]): {
	status: 'ok' | 'partial' | 'failed';
	success: boolean;
	completedTargetCount: number;
	failedTargetCount: number;
	partialTargetCount: number;
} {
	const failedTargetCount = results.filter(result => result.status === 'error' || (typeof result.error === 'string' && result.error.length > 0)).length;
	const partialTargetCount = results.filter(result => result.status === 'partial').length;
	const completedTargetCount = results.length - failedTargetCount;
	const status = failedTargetCount === 0 && partialTargetCount === 0
		? 'ok'
		: completedTargetCount === 0 ? 'failed' : 'partial';
	return {
		status,
		// `success` retains the transport-level convention for partial batches;
		// `status` carries the stricter semantic outcome consumed by the runner.
		success: status !== 'failed',
		completedTargetCount,
		failedTargetCount,
		partialTargetCount,
	};
}

export function flattenHqlFunctionFindings(
	perFunction: readonly HqlFunctionFindings[],
	fallbackAddress: string,
): HqlAddressResult {
	if (perFunction.length === 0) {
		return { status: 'error', address: fallbackAddress, function: '', findings: [], error: 'HAST hydration produced no functions' };
	}
	if (perFunction.length === 1) return mapHqlFunctionFinding(perFunction[0], fallbackAddress);
	const flatFindings: HqlAddressResult['findings'] = [];
	const unsupportedNodeCounts: Record<string, number> = {};
	let nodeCount = 0;
	let lossyNodes = 0;
	let evaluatedSignatureCount = 0;
	let semanticFactCount = 0;
	const semanticFactIdentities: Array<{ address: string; sha256: string }> = [];
	const semanticReadErrors: string[] = [];
	const truncationReasons: string[] = [];
	const partialReasons: string[] = [];
	truncationReasons.push(`Compatibility aggregate contains ${perFunction.length} HAST functions; use headless per-function results for identity-preserving output`);
	for (const fn of perFunction) {
		nodeCount += fn.nodeCount;
		lossyNodes += fn.adapterCoverage.lossyNodes;
		evaluatedSignatureCount += fn.evaluatedSignatureCount;
		semanticFactCount += fn.semanticFactCount;
		semanticFactIdentities.push({ address: fn.address, sha256: fn.semanticFactsSha256 });
		semanticReadErrors.push(...fn.semanticReadErrors);
		truncationReasons.push(...fn.truncationReasons);
		partialReasons.push(...fn.partialReasons);
		for (const [kind, count] of Object.entries(fn.adapterCoverage.unsupportedNodeCounts)) {
			unsupportedNodeCounts[kind] = (unsupportedNodeCounts[kind] ?? 0) + count;
		}
		for (const finding of fn.findings) {
			flatFindings.push({
				signatureId: finding.signatureId,
				structuralCompleteness: finding.structuralCompleteness,
				evidenceLevel: finding.evidenceLevel,
				...(finding.confidence !== undefined ? { confidence: finding.confidence } : {}),
				...(finding.adapterCoverage !== undefined ? { adapterCoverage: finding.adapterCoverage } : {}),
				...(finding.adapterLossAffected ? { adapterLossAffected: true } : {}),
				...(finding.semanticMatches ? { semanticMatches: finding.semanticMatches.map(fact => ({
					...fact,
					attributes: { ...fact.attributes },
					provenance: fact.provenance.map(item => ({ ...item })),
				})) } : {}),
				matchCount: Array.isArray(finding.matches) ? finding.matches.length : 0,
			});
		}
	}
	return {
		status: truncationReasons.length > 0 || partialReasons.length > 0 ? 'partial' : 'ok',
		address: perFunction[0].address || fallbackAddress,
		function: perFunction[0].function,
		nodeCount,
		adapterCoverage: {
			totalNodes: nodeCount,
			lossyNodes,
			coverage: nodeCount === 0 ? 0 : (nodeCount - lossyNodes) / nodeCount,
			unsupportedNodeCounts,
		},
		signatureSetSha256: perFunction[0].signatureSetSha256,
		cacheKey: perFunction[0].cacheKey,
		truncated: truncationReasons.length > 0,
		truncationReasons,
		partialReasons,
		evaluatedSignatureCount,
		semanticFactCount,
		semanticFactsSha256: crypto.createHash('sha256').update(JSON.stringify(semanticFactIdentities)).digest('hex'),
		semanticReadErrors: [...new Set(semanticReadErrors)].sort(),
		findings: flatFindings,
	};
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
export async function scanTargetFunctions(
	target: HqlScanTarget,
	decompile: DecompileFn,
	options: HqlBatchOptions = {},
): Promise<HqlAddressResult[]> {
	const addrLabel =
		target.address !== undefined ? String(target.address)
			: target.irPath !== undefined ? target.irPath
				: target.irText !== undefined ? '<ir-text>'
					: '<unknown>';

	const hql = loadHql();
	if (!hql) {
		return [{ status: 'error', requestedTarget: addrLabel, address: addrLabel, function: '', findings: [], error: getHqlLoadError() ?? 'hexcore-hql unavailable' }];
	}
	if (options.signal?.aborted) return [{ status: 'error', requestedTarget: addrLabel, address: addrLabel, function: '', findings: [], error: 'HQL scan cancelled before decompile' }];

	let dr: HelixDecompileQuietResult | undefined;
	try {
		dr = await decompile(target);
	} catch (err) {
		const msg = err instanceof Error ? err.message : String(err);
		return [{ status: 'error', requestedTarget: addrLabel, address: addrLabel, function: '', findings: [], error: `decompile threw: ${msg}` }];
	}

	if (!dr || !dr.success) {
		return [{ status: 'error', requestedTarget: addrLabel, address: addrLabel, function: '', findings: [], error: dr?.error || 'decompile failed' }];
	}

	const ab = dr.astBuffer;
	if (!ab || ab.length === 0) {
		return [{ status: 'error', requestedTarget: addrLabel, address: dr.address || addrLabel, function: '', findings: [], error: 'no AST (decompile produced no functions)' }];
	}

	let perFunction: HqlFunctionFindings[];
	let session: HqlSessionReader | undefined;
	try {
		session = openBoundHqlSession(hql, options.session);
		perFunction = hql.scanHAST(Uint8Array.from(ab), undefined, session, {
			maxFunctions: options.maxFunctionsPerHast,
			maxNodesPerFunction: options.maxNodesPerFunction,
			maxFindingsPerFunction: options.maxFindingsPerFunction,
			signal: options.signal,
		});
	} catch (err) {
		const msg = err instanceof Error ? err.message : String(err);
		return [{ status: 'error', requestedTarget: addrLabel, address: dr.address || addrLabel, function: '', findings: [], error: `scanHAST threw: ${msg}` }];
	} finally {
		session?.dispose();
	}

	if (perFunction.length === 0) {
		return [{ status: 'error', requestedTarget: addrLabel, address: dr.address || addrLabel, function: '', findings: [], error: 'HAST hydration produced no functions' }];
	}
	return preserveHqlFunctionFindings(perFunction, dr!.address || addrLabel, addrLabel);
}

/** Compatibility wrapper for the interactive single-function command. */
export async function scanOneTarget(
	target: HqlScanTarget,
	decompile: DecompileFn,
	options: HqlBatchOptions = {},
): Promise<HqlAddressResult> {
	const functions = await scanTargetFunctions(target, decompile, options);
	return functions.length === 1
		? functions[0]
		: flattenHqlFunctionFindings(functions.map(result => ({
			function: result.function,
			address: result.address,
			nodeCount: result.nodeCount ?? 0,
			adapterCoverage: result.adapterCoverage ?? { totalNodes: 0, lossyNodes: 0, coverage: 0, unsupportedNodeCounts: {} },
			hast: result.hast ?? { schemaMajor: 0, schemaMinor: 0, capabilities: [], semanticEligible: false },
			signatureSetSha256: result.signatureSetSha256 ?? '',
			cacheKey: result.cacheKey ?? '',
			status: result.status === 'error' ? 'partial' : result.status,
			truncated: result.truncated ?? result.status !== 'ok',
			truncationReasons: result.truncationReasons ?? (result.error ? [result.error] : []),
			partialReasons: result.partialReasons ?? [],
			evaluatedSignatureCount: result.evaluatedSignatureCount ?? 0,
			semanticFactCount: result.semanticFactCount ?? 0,
			semanticFactsSha256: result.semanticFactsSha256 ?? crypto.createHash('sha256').update('[]').digest('hex'),
			semanticReadErrors: result.semanticReadErrors ?? [],
			findings: result.findings.map(finding => ({
				signatureId: finding.signatureId, matches: Array.from({ length: finding.matchCount }),
				structuralCompleteness: finding.structuralCompleteness, evidenceLevel: finding.evidenceLevel,
				...(finding.confidence !== undefined ? { confidence: finding.confidence } : {}),
				...(finding.adapterCoverage !== undefined ? { adapterCoverage: finding.adapterCoverage } : {}),
				...(finding.adapterLossAffected ? { adapterLossAffected: true } : {}),
				...(finding.semanticMatches ? { semanticMatches: finding.semanticMatches } : {}),
			})),
		})), functions[0]?.address ?? '<unknown>');
}

/**
 * Run the HQL scan over a batch of targets and assemble the headless report.
 * Partial failures (one address fails to decompile) are captured per-result;
 * the overall report is `success: true` as long as the scan machinery ran.
 */
export async function runHqlScanBatch(
	file: string | undefined,
	targets: HqlScanTarget[],
	decompile: DecompileFn,
	options: HqlBatchOptions = {},
): Promise<HqlHeadlessReport> {
	const budget = resolveBatchBudget(options);
	if (!loadHql()) {
		return {
			success: false,
			status: 'failed',
			command: 'hexcore.hql.scanHeadless',
			file,
			targetCount: targets.length,
			completedTargetCount: 0,
			failedTargetCount: targets.length,
			partialTargetCount: 0,
			matchedFunctionCount: 0,
			totalFindings: 0,
			results: [],
			budget,
			error: getHqlLoadError() ?? 'hexcore-hql unavailable',
		};
	}
	if (targets.length > budget.maxTargets) {
		return {
			success: false, status: 'failed', command: 'hexcore.hql.scanHeadless', file,
			targetCount: targets.length, completedTargetCount: 0, failedTargetCount: targets.length,
			partialTargetCount: 0, matchedFunctionCount: 0, totalFindings: 0, results: [], budget,
			error: `HQL target budget exceeded: ${targets.length} > ${budget.maxTargets}`,
		};
	}

	const targetResults = await mapWithConcurrency(targets, budget.maxConcurrency, target =>
		scanTargetFunctions(target, decompile, { ...budget, signal: options.signal, session: options.session }));
	const results = targetResults.flat();

	const matchedFunctionCount = results.filter(r => r.findings.length > 0).length;
	const totalFindings = results.reduce((acc, r) => acc + r.findings.length, 0);
	const targetStatuses = targetResults.map(group => summarizeHqlResults(group));
	const failedTargetCount = targetStatuses.filter(outcome => outcome.status === 'failed').length;
	const partialTargetCount = targetStatuses.filter(outcome => outcome.status === 'partial').length;
	const completedTargetCount = targets.length - failedTargetCount;
	const status = failedTargetCount === 0 && partialTargetCount === 0 ? 'ok'
		: completedTargetCount === 0 ? 'failed' : 'partial';

	return {
		success: status !== 'failed',
		status,
		command: 'hexcore.hql.scanHeadless',
		file,
		targetCount: targets.length,
		completedTargetCount,
		failedTargetCount,
		partialTargetCount,
		matchedFunctionCount,
		totalFindings,
		results,
		budget,
		...(status === 'failed'
			? { error: `All ${failedTargetCount} HQL target(s) failed; first error: ${results.find(result => result.error)?.error}` }
			: {}),
	};
}

function resolveBatchBudget(options: HqlBatchOptions): HqlHeadlessReport['budget'] {
	const positive = (value: number | undefined, fallback: number, name: string, maximum: number): number => {
		const resolved = value ?? fallback;
		if (!Number.isSafeInteger(resolved) || resolved <= 0 || resolved > maximum) {
			throw new Error(`HQL ${name} must be a positive safe integer <= ${maximum}`);
		}
		return resolved;
	};
	return {
		maxTargets: positive(options.maxTargets, DEFAULT_HQL_BATCH_BUDGET.maxTargets, 'maxTargets', 4096),
		maxConcurrency: positive(options.maxConcurrency, DEFAULT_HQL_BATCH_BUDGET.maxConcurrency, 'maxConcurrency', 8),
		maxFunctionsPerHast: positive(options.maxFunctionsPerHast, DEFAULT_HQL_BATCH_BUDGET.maxFunctionsPerHast, 'maxFunctionsPerHast', 4096),
		maxNodesPerFunction: positive(options.maxNodesPerFunction, DEFAULT_HQL_BATCH_BUDGET.maxNodesPerFunction, 'maxNodesPerFunction', 10_000_000),
		maxFindingsPerFunction: positive(options.maxFindingsPerFunction, DEFAULT_HQL_BATCH_BUDGET.maxFindingsPerFunction, 'maxFindingsPerFunction', 100_000),
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
