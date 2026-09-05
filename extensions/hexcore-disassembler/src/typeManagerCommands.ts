/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Akasha Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import type { DisassemblerEngine } from './disassemblerEngine';
import { exportStructInfoJson, type StructInfoJson } from './elfBtfLoader';
import { ingestDebugTypeInfo, type DebugTypeIngestionOptions, type ExtendedStructInfoJson } from './debugTypeIngestion';
import { recoverRecordsFromPropagation } from './recordRecovery';
import type { SemanticTypeSpec } from './semanticModel';
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
	return ingestDebugTypeInfo(storeFor(engine), source as ExtendedStructInfoJson, {
		provider,
		unitIdentity: options?.unitIdentity ?? `${provider}:${engine.getFilePath() ?? 'active-target'}`,
		generation: generation(engine, options?.generation),
		pointerSizeBits: options?.pointerSizeBits ?? (engine.getArchitecture() === 'x86' || engine.getArchitecture() === 'arm' ? 32 : 64),
		longSizeBits: options?.longSizeBits ?? 32,
	});
}

export async function runRecordRecovery(engine: DisassemblerEngine) {
	const closure = await syncWholeProgramPropagationIsolated(engine);
	if (!closure.run.committed) { throw new Error(`Record recovery requires committed propagation: ${closure.run.reason ?? closure.run.status}`); }
	const recovery = recoverRecordsFromPropagation(storeFor(engine), closure.collection.analysisGeneration);
	return { ok: true, command: 'hexcore.records.recover', closure: {
		referenceGraphHash: closure.references.graphHash,
		collectionHash: closure.collection.collectionHash,
		propagationOutputHash: closure.run.outputHash,
	}, worker: closure.worker, recovery };
}
