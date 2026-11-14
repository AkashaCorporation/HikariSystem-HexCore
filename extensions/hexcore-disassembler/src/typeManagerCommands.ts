/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Akasha Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as crypto from 'crypto';
import type { DisassemblerEngine } from './disassemblerEngine';
import { exportStructInfoJson, type StructInfoJson } from './elfBtfLoader';
import { ingestDebugTypeInfo, reconcileDebugFunctionAddress, type DebugTypeIngestionOptions, type ExtendedStructInfoJson } from './debugTypeIngestion';
import { recoverRecordsFromPropagation } from './recordRecovery';
import { normalizeRecordRecoveryOptions, requireCurrentCommittedPropagation } from './recordRecoveryCommandOptions';
import { semanticPrototypeBatchCallbacks } from './semanticCommandIntegration';
import { SemanticCommandService } from './semanticCommandService';
import { canonicalSerialize, type CallingConventionId, type SemanticTypeSpec } from './semanticModel';
import { TypeManager, type TypeManagerExport } from './typeManager';
import { syncWholeProgramPropagationIsolated } from './wholeProgramPropagationProducer';

function storeFor(engine: DisassemblerEngine) {
	const session = engine.getSessionStore();
	if (!session) { throw new Error('Type-manager command requires a bound HXDB session.'); }
	return session.getSemanticStore();
}

function generation(engine: DisassemblerEngine, value?: number): number {
	const resolved = value ?? engine.getAnalysisGeneration();
	if (!Number.isSafeInteger(resolved) || resolved < 0) { throw new Error('Type-manager generation must be non-negative.'); }
	return resolved;
}

function contentHash(value: unknown): string {
	return crypto.createHash('sha256').update(canonicalSerialize(value)).digest('hex');
}

function debugCallingConvention(engine: DisassemblerEngine): CallingConventionId {
	const format = engine.getSessionStore()?.getAnalysisTarget()?.format;
	switch (engine.getArchitecture()) {
		case 'x64': return format === 'pe' ? 'win64' : 'sysv64';
		case 'x86': return 'cdecl';
		case 'arm64': return 'aapcs64';
		case 'arm': return 'aapcs32';
		default: throw new Error(`No canonical debug ABI is available for ${engine.getArchitecture()}.`);
	}
}

export function runTypeList(engine: DisassemblerEngine) {
	const manager = new TypeManager(storeFor(engine));
	return { ok: true, command: 'hexcore.typeManager.list', types: manager.list(), export: manager.export() };
}

export function runTypeCreate(engine: DisassemblerEngine, spec: SemanticTypeSpec, requestedGeneration?: number) {
	const type = new TypeManager(storeFor(engine)).create(spec, generation(engine, requestedGeneration));
	return { ok: true, command: 'hexcore.typeManager.create', changed: true, type };
}

export function runTypeUpdate(engine: DisassemblerEngine, typeId: string, patch: Partial<SemanticTypeSpec>, requestedGeneration?: number) {
	const type = new TypeManager(storeFor(engine)).update(typeId, patch, generation(engine, requestedGeneration));
	return { ok: true, command: 'hexcore.typeManager.update', changed: true, type };
}

export function runTypeRename(engine: DisassemblerEngine, typeId: string, name: string, requestedGeneration?: number) {
	const type = new TypeManager(storeFor(engine)).rename(typeId, name, generation(engine, requestedGeneration));
	return { ok: true, command: 'hexcore.typeManager.rename', changed: true, type };
}

export function runTypeDelete(engine: DisassemblerEngine, typeId: string, requestedGeneration?: number) {
	const result = new TypeManager(storeFor(engine)).delete(typeId, generation(engine, requestedGeneration));
	return { ok: result.status !== 'blocked', command: 'hexcore.typeManager.delete', ...result };
}

export function runTypeUndo(engine: DisassemblerEngine, typeId: string, requestedGeneration?: number) {
	const type = new TypeManager(storeFor(engine)).undo(typeId, generation(engine, requestedGeneration));
	return { ok: true, command: 'hexcore.typeManager.undo', changed: true, type };
}

export function runTypeExport(engine: DisassemblerEngine) {
	return new TypeManager(storeFor(engine)).export();
}

export function runTypeImport(engine: DisassemblerEngine, envelope: TypeManagerExport) {
	return { ok: true, command: 'hexcore.typeManager.import', ...new TypeManager(storeFor(engine)).import(envelope) };
}

export async function runDebugTypeIngest(
	engine: DisassemblerEngine,
	input?: ExtendedStructInfoJson,
	options?: Partial<DebugTypeIngestionOptions>,
) {
	await engine.ensureDebugInfoLoaded();
	const elf = engine.getELFAnalysis();
	let source: StructInfoJson | undefined = input;
	let provider = options?.provider;
	if (!source && elf?.btfData) {
		source = exportStructInfoJson(elf.btfData, engine.getArchitecture() === 'x86' || engine.getArchitecture() === 'arm' ? 4 : 8);
		provider = 'btf';
	} else if (!source && elf?.dwarfStructInfo) {
		source = elf.dwarfStructInfo;
		provider = 'dwarf';
	}
	if (!source || !provider) { throw new Error('No BTF/DWARF debug type payload is available for ingestion.'); }
	const resolvedGeneration = generation(engine, options?.generation);
	const unitIdentity = options?.unitIdentity ?? `${provider}:${engine.getFilePath() ?? 'active-target'}`;
	const pointerSizeBits = options?.pointerSizeBits ?? (engine.getArchitecture() === 'x86' || engine.getArchitecture() === 'arm' ? 32 : 64);
	const longSizeBits = options?.longSizeBits ?? (engine.getSessionStore()?.getAnalysisTarget()?.format === 'pe' ? 32 : pointerSizeBits);
	const types = ingestDebugTypeInfo(storeFor(engine), source as ExtendedStructInfoJson, {
		provider,
		unitIdentity,
		generation: resolvedGeneration,
		pointerSizeBits,
		longSizeBits,
	});
	const session = engine.getSessionStore();
	if (!session) { throw new Error('Debug type ingestion requires a bound HXDB session.'); }
	const batch = semanticPrototypeBatchCallbacks(session, engine);
	const service = new SemanticCommandService(session, {
		producer: `${provider}:${unitIdentity}`,
		typeNamespace: `${provider}:${unitIdentity}`,
		legacyCTypeOptions: { pointerSizeBits, longSizeBits, allowOpaquePointerBase: true },
		callbacks: batch.callbacks,
		computeStoreHash: false,
	});
	const evidence = { strength: 'debug' as const, source: 'debug-info' as const, producer: `${provider}:${unitIdentity}`, generation: resolvedGeneration };
	let applied = 0;
	let conflicts = 0;
	let failures = 0;
	const diagnostics: Array<{ functionName: string; status: 'unreconciled' | 'conflict' | 'error'; message: string }> = [];
	for (const functionName of Object.keys(source.functions).sort()) {
		const signature = source.functions[functionName];
		const owner = reconcileDebugFunctionAddress(functionName, source.boundaries, engine.getFunctions());
		if (owner.status === 'unreconciled') {
			diagnostics.push({ functionName, status: 'unreconciled', message: owner.reason });
			continue;
		}
		const address = `0x${owner.address.toString(16)}`;
		try {
			const result = service.applyPrototype({
				functionIdentity: `function:${address}`,
				functionAddress: address,
				returnType: signature.returnType,
				callingConventionId: debugCallingConvention(engine),
				parameters: [...signature.params].sort((left, right) => left.index - right.index).map((parameter, ordinal) => ({
					ordinal,
					name: parameter.name || `arg${ordinal}`,
					type: parameter.type,
					stableIdentity: `${provider}:${unitIdentity}:${address}:parameter:${parameter.index}`,
					...(parameter.abiValueClass ? { abiValueClass: parameter.abiValueClass } : {}),
					...(parameter.abiSizeBits ? { abiSizeBits: parameter.abiSizeBits } : {}),
					...(parameter.abiAlignBits ? { abiAlignBits: parameter.abiAlignBits } : {}),
				})),
				variadic: signature.variadic === true,
				evidence,
			});
			if (result.conflicts.length > 0 || /(?:rejected|peer)/.test(result.status)) {
				conflicts++;
				diagnostics.push({ functionName, status: 'conflict', message: `prototype arbitration=${result.status}; emitted context remains unknown` });
			} else {
				applied++;
			}
			if (result.callbackFailures.length > 0) {
				failures++;
				diagnostics.push({
					functionName,
					status: 'error',
					message: `semantic callbacks incomplete: ${result.callbackFailures.map(failure => `${failure.callback}:${failure.message}`).join('; ')}`,
				});
			}
		} catch (error) {
			failures++;
			diagnostics.push({ functionName, status: 'error', message: error instanceof Error ? error.message : String(error) });
		}
	}
	const propagation = await batch.finalize();
	const deferred = Object.keys(source.functions).length - applied;
	const status = types.opaqueFieldCount === 0 && deferred === 0 && failures === 0
		&& (propagation.status === 'ok' || propagation.status === 'not-required') ? 'ok' as const : 'partial' as const;
	const { contentHash: typeIngestionContentHash, ...typeIngestion } = types;
	const logical = {
		...typeIngestion,
		status,
		functionSignatureCount: Object.keys(source.functions).length,
		functionSignaturesApplied: applied,
		functionSignaturesDeferred: deferred,
		functionSignatureConflicts: conflicts,
		prototypeFailures: failures,
		diagnostics,
		propagation,
		typeIngestionContentHash,
		storeHash: session.getSemanticStore().exportHash(),
	};
	return { ...logical, contentHash: contentHash(logical) };
}

export async function runRecordRecovery(engine: DisassemblerEngine, rawOptions?: unknown) {
	const options = normalizeRecordRecoveryOptions(rawOptions);
	const store = storeFor(engine);
	if (options.refresh === true) {
		const { refresh: _refresh, ...solveOptions } = options;
		const closure = await syncWholeProgramPropagationIsolated(engine, solveOptions);
		if (!closure.run.committed) { throw new Error(`Record recovery requires committed propagation: ${closure.run.reason ?? closure.run.status}`); }
		const recovery = recoverRecordsFromPropagation(store, closure.collection.analysisGeneration);
		return { ok: true, semanticStatus: recovery.status, command: 'hexcore.records.recover', closure: {
			source: 'refreshed' as const,
			referenceGraphHash: closure.references.graphHash,
			collectionHash: closure.collection.collectionHash,
			propagationOutputHash: closure.run.outputHash,
			solverOptions: solveOptions,
		}, worker: closure.worker, recovery };
	}

	const propagation = store.getWholeProgramPropagationStore();
	const summaries = propagation.listSummaries();
	const dirty = propagation.listDirty();
	const committed = requireCurrentCommittedPropagation(
		engine.getAnalysisGeneration(), propagation.latestAcceptedGeneration(),
		summaries.length, dirty.length);
	const recovery = recoverRecordsFromPropagation(store, committed.analysisGeneration);
	return { ok: true, semanticStatus: recovery.status, command: 'hexcore.records.recover', closure: {
		source: 'committed' as const,
		...committed,
		referenceGraphHash: store.getReferenceGraph().exportHash(),
	}, recovery };
}
