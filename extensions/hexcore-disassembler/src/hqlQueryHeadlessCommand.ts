/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import type { DisassemblerEngine } from './disassemblerEngine';
import { pipelineInputPartialReasons } from './pipelineArtifactInputs';
import { isTrustedPipelineArtifactBindings, type PipelineArtifactBinding } from './pipelineArtifactInputs';
import { openSemanticQueryView } from './semanticQueryView';
import { captureReadOnlyHelixInput } from './readOnlyHelixCapture';
import { prepareReadonlyNativeRequest } from './readonlyNativeRequest';
import { ReadonlyNativeProcess, type ReadonlyNativeExecution } from './readonlyNativeProcess';
import { hqlQueryRequiresHast, normalizeHqlSnapshotQuery, runHqlSnapshotQuery, type HqlQueryHastSource, type HqlQuerySelection } from './hqlQueryBridge';

interface NativeProducer { run(request: ReturnType<typeof prepareReadonlyNativeRequest>, options: { timeoutMs: number; signal?: AbortSignal }): Promise<ReadonlyNativeExecution> }
export type NativeProducerFactory = () => NativeProducer;

function positiveInteger(arg: Record<string, unknown>, name: string, fallback: number, maximum: number): number {
	const value = arg[name] ?? fallback;
	if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 1 || value > maximum) { throw new Error(`${name} must be a positive integer <= ${maximum}`); }
	return value;
}

/** Core command implementation. It neither opens targets nor writes artifacts. */
export async function runHqlQueryHeadlessCommand(
	engine: DisassemblerEngine,
	arg: Record<string, unknown> = {},
	producerFactory: NativeProducerFactory = () => new ReadonlyNativeProcess(),
	runtime: { signal?: AbortSignal; stepTimeoutMs?: number } = {},
): Promise<Record<string, unknown>> {
	try {
		if (arg.materialization !== undefined && arg.materialization !== 'never') { throw new Error('hexcore.hql.queryHeadless supports only materialization:"never" in 3.8.5'); }
		if (arg.query !== undefined && ['condition', 'addresses', 'functions', 'select'].some(key => arg[key] !== undefined)) { throw new Error('Use either args.query or top-level condition/filters, not both'); }
		if (arg.irText !== undefined) { throw new Error('Inline IR has no runner-bound artifact ancestry; use irPath from a prior pipeline step'); }
		if (!engine.isFileLoaded()) { throw new Error('No active analyzed binary is loaded'); }
		if (typeof arg.file === 'string' && path.resolve(arg.file).toLowerCase() !== path.resolve(engine.getFilePath()!).toLowerCase()) { throw new Error('Query target differs from the active binary; load/analyze it explicitly first'); }
		const session = engine.getSessionStore();
		if (!session) { throw new Error('Active target has no bound HXDB session'); }
		const rawQuery = arg.query && typeof arg.query === 'object' && !Array.isArray(arg.query)
			? arg.query : { schemaVersion: 1, condition: arg.condition,
				...(Array.isArray(arg.addresses) ? { addresses: arg.addresses } : {}),
				...(Array.isArray(arg.functions) ? { functions: arg.functions } : {}),
				...(Array.isArray(arg.select) ? { select: arg.select } : {}), materialization: 'never' };
		const normalized = normalizeHqlSnapshotQuery(rawQuery);
		const needsHast = hqlQueryRequiresHast(normalized);
		const irPath = typeof arg.irPath === 'string' ? path.resolve(arg.irPath) : undefined;
		let irText: string | undefined;
		let irBinding: PipelineArtifactBinding | undefined;
		if (irPath) {
			if (!needsHast) { throw new Error('irPath is only meaningful for a structural HAST condition'); }
			if (!isTrustedPipelineArtifactBindings(arg.pipelineArtifactBindings)) { throw new Error('IR query requires runner-minted artifact ancestry'); }
			irBinding = arg.pipelineArtifactBindings.find(binding => path.resolve(binding.path).toLowerCase() === irPath.toLowerCase());
			if (!irBinding || irBinding.artifactKind !== 'llvm-ir' || irBinding.status === 'error' || irBinding.status === 'skipped') { throw new Error('IR query producer is unavailable or is not LLVM IR'); }
			if (!fs.statSync(irPath).isFile() || fs.statSync(irPath).size > 32 * 1024 * 1024) { throw new Error('IR query input is missing or exceeds 32 MiB'); }
			irText = fs.readFileSync(irPath, 'utf8');
			const digest = crypto.createHash('sha256').update(irText).digest('hex');
			if (digest !== irBinding.sha256) { throw new Error('IR query artifact hash changed after runner validation'); }
		}
		const maxFunctions = positiveInteger(arg, 'maxFunctions', needsHast ? 16 : 256, needsHast ? 256 : 4096);
		const requestedTimeoutMs = positiveInteger(arg, 'timeoutMs', 180000, 300000);
		const stepTimeoutMs = runtime.stepTimeoutMs === undefined ? requestedTimeoutMs : Math.max(1, Math.min(requestedTimeoutMs, runtime.stepTimeoutMs - Math.min(1000, Math.floor(runtime.stepTimeoutMs / 4))));
		const timeoutMs = stepTimeoutMs;
		const queryLimits: Record<string, number> = {
			maxFunctions, maxNodes: positiveInteger(arg, 'maxNodes', 250000, 1000000), maxRows: positiveInteger(arg, 'maxRows', 256, 4096),
			maxEvidencePerRow: positiveInteger(arg, 'maxEvidencePerRow', 64, 1024), maxOperations: positiveInteger(arg, 'maxOperations', 2000000, 20000000),
			maxInputBytes: positiveInteger(arg, 'maxInputBytes', 16 * 1024 * 1024, 64 * 1024 * 1024),
			maxOutputBytes: positiveInteger(arg, 'maxOutputBytes', 4 * 1024 * 1024, 16 * 1024 * 1024), timeoutMs,
		};
		const view = openSemanticQueryView(session, { engineGeneration: engine.getAnalysisGeneration() });
		if (irBinding && (irBinding.targetIdentity !== view.identity.targetIdentity || irBinding.sessionId !== view.identity.sessionId || irBinding.generation !== view.identity.generation || irBinding.universeSha256 !== view.identity.universeSha256 || !irBinding.producerCommand)) { throw new Error('IR query artifact ancestry differs from the active snapshot'); }
		if (irPath && normalized.addresses?.length !== 1) { throw new Error('The 3.8.5 bound-IR lane requires exactly one function address'); }
		let candidates: HqlQuerySelection[];
		let requestedByScope = 0;
		let selectedNames = new Set<string>();
		const functionFilter = normalized.functions ? new Set(normalized.functions) : undefined;
		if (normalized.addresses?.length) {
			candidates = normalized.addresses.map(address => {
				const value = BigInt(address);
				if (value > BigInt(Number.MAX_SAFE_INTEGER)) { return { address, partialReasons: ['address exceeds the active engine precision'] }; }
				const fn = engine.getFunctionAt(Number(value));
				return { address, ...(fn ? { name: fn.name } : { partialReasons: ['function is not indexed in the active target'] }) };
			});
			requestedByScope = candidates.length;
			selectedNames = new Set(candidates.map(item => item.name).filter((name): name is string => !!name));
			candidates.sort((left, right) => BigInt(left.address) < BigInt(right.address) ? -1 : BigInt(left.address) > BigInt(right.address) ? 1 : 0);
			candidates = candidates.slice(0, maxFunctions);
		} else {
			const ready: HqlQuerySelection[] = [];
			const deferred: HqlQuerySelection[] = [];
			for (const fn of engine.getFunctions()) {
				if (functionFilter && !functionFilter.has(fn.name)) { continue; }
				requestedByScope++;
				selectedNames.add(fn.name);
				const selection = { address: `0x${fn.address.toString(16)}`, name: fn.name };
				if (!needsHast || engine.peekFunctionBodyCompleteness(fn.address)?.state === 'complete') {
					if (ready.length < maxFunctions) { ready.push(selection); }
				} else if (deferred.length < maxFunctions) { deferred.push(selection); }
			}
			candidates = [...ready, ...deferred].slice(0, maxFunctions);
		}
		const missingNames = (normalized.functions ?? []).filter(name => !selectedNames.has(name));
		const requestedFunctions = requestedByScope + missingNames.length;
		const globalPartialReasons = missingNames.map(name => `function name is not indexed: ${name}`);
		if (requestedFunctions > candidates.length) { globalPartialReasons.push(`selection limit: ${requestedFunctions - candidates.length} function(s) unevaluated`); }
		if (candidates.length === 0) { globalPartialReasons.push('no functions are available in the requested scope'); }
		const sources = new Map<string, HqlQueryHastSource>();
		const nativeProducers: unknown[] = [];
		const started = Date.now();
		if (needsHast) {
			const producer = producerFactory();
			for (const selection of candidates) {
				if (runtime.signal?.aborted) { globalPartialReasons.push('query cancelled'); break; }
				const address = BigInt(selection.address);
				const fn = address <= BigInt(Number.MAX_SAFE_INTEGER) ? engine.getFunctionAt(Number(address)) : undefined;
				if (!fn) { continue; }
				const completeness = engine.peekFunctionBodyCompleteness(fn.address);
				if (completeness?.state !== 'complete' || !completeness.boundaryReached) { selection.partialReasons = [...(selection.partialReasons ?? []), `function body is ${completeness?.state ?? 'unavailable'}`]; continue; }
				const remaining = timeoutMs - (Date.now() - started);
				if (remaining <= 0) { globalPartialReasons.push('native producer batch timeout'); break; }
				const capture = captureReadOnlyHelixInput(engine, view, fn.address);
				const request = prepareReadonlyNativeRequest(engine, capture, { maxOutputBytes: queryLimits.maxOutputBytes,
					...(irText && irBinding ? { irText, irAncestry: { artifactSha256: irBinding.sha256, targetIdentity: irBinding.targetIdentity!, sessionId: irBinding.sessionId!, generation: irBinding.generation!, universeSha256: irBinding.universeSha256!, producerCommand: irBinding.producerCommand! } } : {}) });
				const produced = await producer.run(request, { timeoutMs: Math.max(1, remaining), signal: runtime.signal });
				capture.assertCurrent(engine);
				nativeProducers.push({ address: selection.address, status: produced.status, success: produced.success, requestSha256: produced.requestSha256,
					contextSha256: produced.contextSha256, irSha256: produced.irSha256, hastSha256: produced.hastSha256,
					qualityIssues: produced.qualityIssues, error: produced.error, execution: { isolation: produced.execution.isolation,
						exited: produced.execution.exited, exitCode: produced.execution.exitCode, signal: produced.execution.signal } });
				if (!produced.success || !produced.hastSha256) { selection.partialReasons = [...(selection.partialReasons ?? []), produced.error ?? 'native producer failed']; continue; }
				sources.set(selection.address, { base64: produced.hastBase64, sha256: produced.hastSha256, identity: view.identity,
					targetArchitecture: view.identity.architecture, producerArchitecture: produced.architecture,
					producerStatus: produced.status, semanticEligible: produced.semanticEligible, qualityIssues: produced.qualityIssues });
			}
		}
		queryLimits.timeoutMs = Math.min(queryLimits.timeoutMs, Math.max(1, timeoutMs - (Date.now() - started)));
		const result = await runHqlSnapshotQuery(view, candidates, normalized, { sources, requestedFunctions, partialReasons: globalPartialReasons,
			inputPartialReasons: pipelineInputPartialReasons(arg.pipelineInputQuality), limits: queryLimits, signal: runtime.signal });
		return { ...(result as object), command: 'hexcore.hql.queryHeadless', targetIdentity: view.identity.targetIdentity,
			generation: view.identity.generation, universeSha256: view.identity.universeSha256, snapshotSha256: view.identity.snapshotSha256,
			materialization: 'never', nativeProducers };
	} catch (error) {
		return { success: false, status: 'error', command: 'hexcore.hql.queryHeadless', materialization: 'never', error: error instanceof Error ? error.message : String(error) };
	}
}
