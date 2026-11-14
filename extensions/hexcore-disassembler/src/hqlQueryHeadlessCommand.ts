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
import { hqlQueryRequiresHast, hqlQueryRequiresSemanticFacts, normalizeHqlSnapshotQuery, runHqlSnapshotQuery, type HqlQueryHastSource, type HqlQuerySelection } from './hqlQueryBridge';
import { planQueryMaterialization, type QueryMaterializationPlan } from './queryMaterialization';
import {
	QueryMaterializationProcessError,
	queryMaterializationProcessController,
	type QueryMaterializationProcessController,
	type StagedQueryMaterializationResult,
} from './queryMaterializationProcess';
import { syncWholeProgramPropagationIsolated } from './wholeProgramPropagationProducer';

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
	runtime: {
		signal?: AbortSignal;
		stepTimeoutMs?: number;
		materializationController?: Pick<QueryMaterializationProcessController, 'run'>;
	} = {},
): Promise<Record<string, unknown>> {
	const requestedMaterialization = arg.materialization ?? (
		arg.query && typeof arg.query === 'object' && !Array.isArray(arg.query)
			? (arg.query as Record<string, unknown>).materialization
			: undefined
	) ?? 'never';
	try {
		if (arg.query !== undefined && ['condition', 'addresses', 'functions', 'select', 'materialization'].some(key => arg[key] !== undefined)) { throw new Error('Use either args.query or top-level condition/filters, not both'); }
		if (arg.irText !== undefined) { throw new Error('Inline IR has no runner-bound artifact ancestry; use irPath from a prior pipeline step'); }
		if (!engine.isFileLoaded()) { throw new Error('No active analyzed binary is loaded'); }
		if (typeof arg.file === 'string' && path.resolve(arg.file).toLowerCase() !== path.resolve(engine.getFilePath()!).toLowerCase()) { throw new Error('Query target differs from the active binary; load/analyze it explicitly first'); }
		const session = engine.getSessionStore();
		if (!session) { throw new Error('Active target has no bound HXDB session'); }
		const rawQuery = arg.query && typeof arg.query === 'object' && !Array.isArray(arg.query)
			? arg.query : { schemaVersion: 1, condition: arg.condition,
				...(Array.isArray(arg.addresses) ? { addresses: arg.addresses } : {}),
				...(Array.isArray(arg.functions) ? { functions: arg.functions } : {}),
				...(Array.isArray(arg.select) ? { select: arg.select } : {}), materialization: arg.materialization ?? 'never' };
		const normalized = normalizeHqlSnapshotQuery(rawQuery);
		const needsHast = hqlQueryRequiresHast(normalized);
		const needsSemanticFacts = hqlQueryRequiresSemanticFacts(normalized);
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
		let view = openSemanticQueryView(session, { engineGeneration: engine.getAnalysisGeneration() });
		const initialIdentity = { ...view.identity };
		if (irBinding && (irBinding.targetIdentity !== view.identity.targetIdentity || irBinding.sessionId !== view.identity.sessionId || irBinding.generation !== view.identity.generation || irBinding.universeSha256 !== view.identity.universeSha256 || !irBinding.producerCommand)) { throw new Error('IR query artifact ancestry differs from the active snapshot'); }
		if (irPath && normalized.addresses?.length !== 1) { throw new Error('The 3.8.5 bound-IR lane requires exactly one function address'); }
		if (irPath && normalized.materialization !== 'never') { throw new Error('Query materialization cannot rebind a frozen runner-owned IR artifact; use the binary-bound query lane.'); }
		const materializationPartialReasons: string[] = [];
		let materializationBodyRequired = false;
		let materializationReport: unknown = 'never';
		if (normalized.materialization !== 'never') {
			const policy = normalized.materialization;
			const plan = planQueryMaterialization(engine, normalized, policy);
			materializationBodyRequired = plan.bodyRequired;
			const reportBase = {
				schemaVersion: 1,
				mode: policy.mode,
				planSha256: plan.planSha256,
				initialGeneration: initialIdentity.generation,
				initialUniverseSha256: initialIdentity.universeSha256,
				budgets: { maxFunctions: policy.maxFunctions, maxBytes: policy.maxBytes, maxMilliseconds: policy.maxMilliseconds, maxDepth: policy.maxDepth },
				requestedFunctions: plan.requested.length,
				estimatedBytes: plan.estimatedBytes,
				budgetExhausted: plan.budgetExhausted,
				...(plan.budgetReason ? { reason: plan.budgetReason } : {}),
			};
			for (const reason of plan.unknownReasons) materializationPartialReasons.push(`materialization:${reason.function}:${reason.reason}${reason.detail ? `:${reason.detail}` : ''}`);
			if (plan.requested.length === 0) {
				materializationReport = {
					...reportBase,
					status: materializationPartialReasons.length > 0 ? 'partial' : 'not-required',
					materializedFunctions: 0, partialFunctions: 0, decodeEmptyFunctions: 0, failedFunctions: 0,
					finalGeneration: initialIdentity.generation, finalUniverseSha256: initialIdentity.universeSha256,
					unknownReasons: plan.unknownReasons,
				};
			} else {
				const materializationStarted = Date.now();
				let staged: StagedQueryMaterializationResult | undefined;
				try {
					staged = await (runtime.materializationController ?? queryMaterializationProcessController).run(engine, plan, runtime.signal);
				} catch (error) {
					if (!(error instanceof QueryMaterializationProcessError)) throw error;
					materializationPartialReasons.push(`materialization-${error.execution.outcome}`);
					if (!error.execution.artifactsRemoved) materializationPartialReasons.push('materialization-staging-artifacts-not-removed');
					materializationReport = {
						...reportBase, status: error.execution.outcome, materializedFunctions: 0,
						partialFunctions: 0, decodeEmptyFunctions: 0, failedFunctions: plan.requested.length,
						finalGeneration: initialIdentity.generation, finalUniverseSha256: initialIdentity.universeSha256,
						unknownReasons: [
							...plan.unknownReasons,
							...plan.requested.map(entry => ({ function: entry.functionIdentity, reason: `materialization-${error.execution.outcome}` })),
						],
						nativeExecution: error.execution,
					};
				}
				if (staged) {
					if (!staged.nativeExecution.artifactsRemoved) materializationPartialReasons.push('materialization-staging-artifacts-not-removed');
					const planned = new Map(plan.requested.map(entry => [entry.addressHex, entry]));
					const stagedByAddress = new Map(staged.functions.map(entry => [entry.address.toLowerCase(), entry]));
					const completeAddresses: number[] = [];
					const stageUnknown = [...plan.unknownReasons];
					for (const entry of plan.requested) {
						const outcome = stagedByAddress.get(entry.addressHex);
						if (!outcome) {
							stageUnknown.push({ function: entry.functionIdentity, reason: 'dependency-body-unavailable', detail: 'staging worker returned no function outcome' });
							continue;
						}
						if (outcome.status === 'complete') completeAddresses.push(entry.address);
						else stageUnknown.push({ function: entry.functionIdentity, reason: 'dependency-body-unavailable', detail: outcome.status });
					}
					for (const outcome of staged.functions) if (!planned.has(outcome.address.toLowerCase())) throw new Error(`Materialization worker returned unplanned function ${outcome.address}.`);
					let closure: Record<string, unknown> | undefined;
					const remaining = policy.maxMilliseconds - (Date.now() - materializationStarted);
					if (completeAddresses.length > 0 && remaining > 0 && !runtime.signal?.aborted) {
						const before = engine.exportAnalysisSnapshot();
						let committedBatch = false;
						try {
							engine.importAnalysisSnapshot(staged.snapshot, { adopt: true });
							for (const address of completeAddresses) {
								const outcome = stagedByAddress.get(`0x${address.toString(16)}`)!;
								if (!outcome.bodySha256 || engine.getFunctionBodySha256(address) !== outcome.bodySha256) throw new Error(`Staged body hash mismatch for 0x${address.toString(16)}.`);
							}
							const committed = engine.commitStagedFunctionMaterializations(completeAddresses);
							committedBatch = true;
							const cancellationToken = runtime.signal ? { get isCancellationRequested() { return runtime.signal!.aborted; } } : undefined;
							try {
								const propagated = await syncWholeProgramPropagationIsolated(engine, {
									changedFunctions: committed.persistence.dirtyFunctions,
									maxMilliseconds: Math.max(1, remaining),
									...(cancellationToken ? { cancellationToken } : {}),
								});
								const recomputed = new Set(propagated.run.recomputedFunctions);
								const missingRecomputed = committed.persistence.dirtyFunctions.filter(identity => !recomputed.has(identity));
								const closureComplete = propagated.run.committed && propagated.references.status === 'ok'
									&& propagated.collection.status === 'ok' && missingRecomputed.length === 0;
								closure = {
									status: closureComplete ? 'committed' : propagated.run.committed ? 'partial' : propagated.run.status,
									runHash: propagated.run.runHash,
									recomputedFunctions: propagated.run.recomputedFunctions,
									missingRecomputedFunctions: missingRecomputed,
									referenceStatus: propagated.references.status,
									collectionStatus: propagated.collection.status,
									worker: propagated.worker,
								};
								if (!closureComplete) materializationPartialReasons.push(`materialization-closure:${propagated.run.committed ? 'partial' : propagated.run.status}`);
							} catch (error) {
								const message = error instanceof Error ? error.message : String(error);
								closure = { status: 'error', error: message };
								materializationPartialReasons.push(`materialization-closure-error:${message}`);
							}
						} catch (error) {
							if (!committedBatch) engine.importAnalysisSnapshot(before, { adopt: true });
							throw error;
						}
					} else if (completeAddresses.length > 0) {
						materializationPartialReasons.push(runtime.signal?.aborted ? 'materialization-cancelled-before-commit' : 'materialization-time-budget-before-commit');
						for (const address of completeAddresses) stageUnknown.push({ function: `function:0x${address.toString(16)}`, reason: 'dependency-body-unavailable', detail: 'staged body was not committed' });
					}
					view = openSemanticQueryView(session, { engineGeneration: engine.getAnalysisGeneration() });
					for (const reason of stageUnknown) materializationPartialReasons.push(`materialization:${reason.function}:${reason.reason}${reason.detail ? `:${reason.detail}` : ''}`);
					materializationReport = {
						...reportBase,
						status: completeAddresses.length > 0 && view.identity.generation > initialIdentity.generation && closure && closure.status === 'committed' && stageUnknown.length === 0 && materializationPartialReasons.length === 0 ? 'committed' : 'partial',
						materializedFunctions: view.identity.generation > initialIdentity.generation ? completeAddresses.length : 0,
						partialFunctions: staged.functions.filter(entry => entry.status === 'partial').length,
						decodeEmptyFunctions: staged.functions.filter(entry => entry.status === 'decode-empty').length,
						failedFunctions: staged.functions.filter(entry => entry.status === 'unknown-function').length,
						finalGeneration: view.identity.generation,
						finalUniverseSha256: view.identity.universeSha256,
						unknownReasons: stageUnknown,
						functions: staged.functions,
						nativeExecution: staged.nativeExecution,
						...(closure ? { closure } : {}),
					};
				}
			}
		}
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
		const globalPartialReasons = [...materializationPartialReasons, ...missingNames.map(name => `function name is not indexed: ${name}`)];
		if (requestedFunctions > candidates.length) { globalPartialReasons.push(`selection limit: ${requestedFunctions - candidates.length} function(s) unevaluated`); }
		if (candidates.length === 0) { globalPartialReasons.push('no functions are available in the requested scope'); }
		const semanticCompleteFunctions = new Set<string>();
		if (normalized.materialization !== 'never' && materializationBodyRequired && needsSemanticFacts && materializationPartialReasons.length === 0) {
			for (const selection of candidates) {
				const numeric = BigInt(selection.address);
				if (numeric > BigInt(Number.MAX_SAFE_INTEGER)) continue;
				const fn = engine.getFunctionAt(Number(numeric));
				const completeness = fn ? engine.peekFunctionBodyCompleteness(fn.address) : undefined;
				if (!fn || completeness?.state !== 'complete' || completeness.boundaryReached !== true) continue;
				const identity = `function:0x${fn.address.toString(16)}`;
				try {
					const summary = view.getPropagationSummary(identity);
					const unresolved = view.queryReferences({ direction: 'outgoing', functionIdentity: identity, relations: ['code-indirect-candidate'] });
					const blocked = !summary || unresolved.length > 0 || view.listBarriers(identity).length > 0
						|| view.listConflicts(identity).length > 0 || view.listPropagationConflicts(identity).length > 0;
					if (blocked) {
						globalPartialReasons.push(`materialization-semantic-closure-incomplete:${identity}`);
						continue;
					}
					semanticCompleteFunctions.add(selection.address);
				} catch (error) {
					globalPartialReasons.push(`materialization-semantic-closure-read-failed:${identity}:${error instanceof Error ? error.message : String(error)}`);
				}
			}
		}
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
			inputPartialReasons: pipelineInputPartialReasons(arg.pipelineInputQuality), semanticCompleteFunctions, limits: queryLimits, signal: runtime.signal });
		return { ...(result as object), command: 'hexcore.hql.queryHeadless', targetIdentity: view.identity.targetIdentity,
			generation: view.identity.generation, universeSha256: view.identity.universeSha256, snapshotSha256: view.identity.snapshotSha256,
			initialGeneration: initialIdentity.generation, finalGeneration: view.identity.generation,
			initialUniverseSha256: initialIdentity.universeSha256, finalUniverseSha256: view.identity.universeSha256,
			materialization: materializationReport, nativeProducers };
	} catch (error) {
		return {
			success: false, status: 'error', command: 'hexcore.hql.queryHeadless',
			materialization: requestedMaterialization === 'never' ? 'never' : { status: 'error', policy: requestedMaterialization },
			error: error instanceof Error ? error.message : String(error),
		};
	}
}
