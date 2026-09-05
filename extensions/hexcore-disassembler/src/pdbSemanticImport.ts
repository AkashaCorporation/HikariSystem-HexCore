/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Akasha Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as path from 'path';
import type { DisassemblerEngine } from './disassemblerEngine';
import { ingestDebugTypeInfo } from './debugTypeIngestion';
import { discoverPdbPath } from './pdbLoader';
import { loadPdbProvider, type PdbProviderOptions, type PdbProviderResult } from './pdbProvider';
import { SemanticCommandService, type SemanticPrototypeParameterInput } from './semanticCommandService';
import type { CallingConventionId, ParameterLocation } from './semanticModel';
import { canonicalSerialize, canonicalizeSemanticType, classifyAggregateReturn, getABIModel } from './semanticModel';

export interface PdbSemanticImportOptions {
	pdbPath?: string;
	maxFunctions?: number;
	provider?: Omit<PdbProviderOptions, 'pdbPath' | 'imageBase' | 'expectedGuid' | 'expectedAge'>;
}

function callingConvention(raw: string, architecture: string): CallingConventionId {
	if (architecture === 'x64') { return 'win64'; }
	const normalized = raw.trim().toLowerCase().replace(/^__/, '');
	if (['cdecl', 'stdcall', 'fastcall', 'thiscall', 'vectorcall'].includes(normalized)) { return normalized as CallingConventionId; }
	return architecture === 'x86' ? 'cdecl' : architecture === 'arm64' ? 'aapcs64' : 'aapcs32';
}

function undecoratedExportName(name: string): string {
	return name.replace(/^[@_]/, '').replace(/@@?\d+$/, '');
}

export async function importPdbSemantics(engine: DisassemblerEngine, options: PdbSemanticImportOptions = {}) {
	if (!engine.isFileLoaded() || !engine.getFilePath()) { throw new Error('PDB semantic import requires a loaded PE target.'); }
	const session = engine.getSessionStore();
	if (!session) { throw new Error('PDB semantic import requires a bound HXDB session.'); }
	const file = engine.getFilePath()!;
	const codeView = engine.getPEDataDirectories()?.debug?.find(entry => entry.type === 2 && entry.pdbGuid);
	const pdbPath = options.pdbPath
		? path.resolve(options.pdbPath)
		: discoverPdbPath(file, codeView?.pdbPath) ?? undefined;
	if (!pdbPath) { throw new Error('No matching sidecar or embedded-path PDB was found.'); }
	const provider: PdbProviderResult = loadPdbProvider({
		pdbPath,
		imageBase: engine.getBaseAddress(),
		...(codeView?.pdbGuid ? { expectedGuid: codeView.pdbGuid } : {}),
		...(codeView?.pdbAge !== undefined ? { expectedAge: codeView.pdbAge } : {}),
		...options.provider,
	});
	if (provider.status === 'error' || !provider.identityValidated || !provider.identity) {
		throw new Error(`PDB identity/provider gate failed: ${provider.diagnostics.map(item => `${item.code}:${item.message}`).join('; ')}`);
	}
	const store = session.getSemanticStore();
	const generation = engine.getAnalysisGeneration();
	const types = ingestDebugTypeInfo(store, provider.debugTypes, {
		provider: 'pdb', unitIdentity: `${provider.identity.guid}:${provider.identity.age}`, generation,
		pointerSizeBits: engine.getArchitecture() === 'x86' ? 32 : 64,
		longSizeBits: 32,
	});
	const debugEvidence = { strength: 'debug' as const, source: 'debug-info' as const, producer: `pdb:${provider.identity.guid}:${provider.identity.age}`, generation };
	const auxiliaryTypes = [];
	for (const enumType of provider.enumTypes) {
		auxiliaryTypes.push(canonicalizeSemanticType({
			kind: 'enum', name: enumType.name,
			nominalIdentity: canonicalSerialize({ targetIdentity: store.targetIdentity, pdb: provider.identity.guid, typeIndex: enumType.typeIndex }),
			sizeBits: 32, alignBits: 32, signed: true,
			enumMembers: enumType.values.map(value => ({ name: value.name, value: value.value, evidence: debugEvidence })),
		}, debugEvidence));
	}
	for (const alias of provider.typeAliases) {
		const target = canonicalizeSemanticType({ kind: 'opaque-c-declaration', opaqueDeclaration: `pdb-type-index ${alias.targetTypeIndex}` }, debugEvidence);
		auxiliaryTypes.push(target, canonicalizeSemanticType({ kind: 'typedef', name: alias.name, targetTypeId: target.typeId }, debugEvidence));
	}
	if (auxiliaryTypes.length > 0) { store.writeBatch({ types: auxiliaryTypes }); }
	const service = new SemanticCommandService(session, { producer: `pdb:${provider.identity.guid}:${provider.identity.age}`, typeNamespace: `pdb:${provider.identity.guid}`, computeStoreHash: false });
	const maxFunctions = options.maxFunctions ?? 100_000;
	if (!Number.isSafeInteger(maxFunctions) || maxFunctions < 1) { throw new Error('PDB maxFunctions must be positive.'); }
	let prototypeCount = 0;
	let reconciledExportPrototypeCount = 0;
	let prototypeFailures = 0;
	const failureDiagnostics: Array<{ functionIdentity: string; message: string }> = [];
	for (const fn of provider.functions.filter(item => item.prototype).slice(0, maxFunctions)) {
		const prototype = fn.prototype!;
		const namedParameters = fn.locals.filter(local => local.parameter);
		try {
			const exported = engine.getExports().find(item => !item.isForwarder && undecoratedExportName(item.name) === fn.name);
			const exportFunction = exported ? engine.getFunctionAt(exported.address) : undefined;
			const thunkTarget = exportFunction?.instructions.find(instruction => instruction.isJump && !instruction.isConditional && instruction.targetAddress !== undefined)?.targetAddress;
			const semanticAddress = thunkTarget ?? exported?.address ?? Number.parseInt(fn.address.slice(2), 16);
			if (exported) { reconciledExportPrototypeCount++; }
			const semanticAddressText = `0x${semanticAddress.toString(16)}`;
			const convention = callingConvention(prototype.callingConvention, engine.getArchitecture());
			const returnRecordName = /^(?:struct|union)\s+(.+)$/.exec(prototype.returnType)?.[1];
			const returnRecordLayout = returnRecordName ? provider.debugTypes.structs[returnRecordName] : undefined;
			const returnRecordType = returnRecordName ? store.listTypes().find(type => type.name === returnRecordName && (type.kind === 'struct' || type.kind === 'union')) : undefined;
			const aggregateDecision = returnRecordLayout
				? classifyAggregateReturn(convention, { sizeBits: returnRecordLayout.size * 8, trivial: true })
				: undefined;
			let nextOrdinal = 0;
			const parameters: SemanticPrototypeParameterInput[] = [];
			let hiddenReturn: { kind: 'sret-parameter'; location: ParameterLocation } | undefined;
			let hiddenStorage: { parameterOrdinal: number; callerAllocated: boolean; calleeReturnsPointer: boolean } | undefined;
			if (aggregateDecision?.kind === 'hidden-pointer' && returnRecordType) {
				const pointer = canonicalizeSemanticType({ kind: 'pointer', targetTypeId: returnRecordType.typeId, sizeBits: engine.getArchitecture() === 'x86' ? 32 : 64, alignBits: engine.getArchitecture() === 'x86' ? 32 : 64 }, debugEvidence);
				store.putType(pointer);
				const abi = getABIModel(convention);
				const sretLocation = aggregateDecision.hiddenPointerRegister
					? { kind: 'implicit' as const, role: 'sret' as const, register: aggregateDecision.hiddenPointerRegister }
					: { kind: 'implicit' as const, role: 'sret' as const, stackOffsetBytes: abi.stack.argumentBaseBytes };
				parameters.push({ ordinal: nextOrdinal, name: '__sret', type: { typeId: pointer.typeId }, location: sretLocation, hiddenSret: true, compilerGenerated: true, direction: 'out', ownership: 'borrow' });
				hiddenReturn = { kind: 'sret-parameter', location: sretLocation };
				hiddenStorage = { parameterOrdinal: nextOrdinal, callerAllocated: true, calleeReturnsPointer: true };
				nextOrdinal++;
			}
			if (prototype.method) {
				parameters.push({ ordinal: nextOrdinal++, name: 'this', type: 'void *', hiddenThis: true, compilerGenerated: true });
			}
			for (const [sourceOrdinal, type] of prototype.parameterTypes.filter(type => type !== '...').entries()) {
				parameters.push({
					ordinal: nextOrdinal++, name: namedParameters[sourceOrdinal]?.name ?? `arg${sourceOrdinal}`, type,
					stableIdentity: `pdb:${provider.identity!.guid}:${semanticAddressText}:parameter:${sourceOrdinal}`,
					...(type.includes('*') || type.startsWith('pdb-type:') ? {
						abiValueClass: 'integer' as const,
						abiSizeBits: engine.getArchitecture() === 'x86' ? 32 : 64,
						abiAlignBits: engine.getArchitecture() === 'x86' ? 32 : 64,
					} : {}),
				});
			}
			service.applyPrototype({
				functionIdentity: `function:${semanticAddressText}`,
				functionAddress: semanticAddressText,
				returnType: returnRecordType ? { typeId: returnRecordType.typeId } : prototype.returnType,
				callingConventionId: convention,
				parameters,
				variadic: prototype.variadic,
				method: prototype.method,
				...(hiddenReturn ? { hiddenReturn } : {}),
				...(hiddenStorage ? { hiddenStorage } : {}),
				evidence: { strength: 'debug', source: 'debug-info', producer: `pdb:${provider.identity.guid}:${provider.identity.age}`, generation },
			});
			prototypeCount++;
		} catch (error) {
			prototypeFailures++;
			failureDiagnostics.push({ functionIdentity: `function:${fn.address}`, message: error instanceof Error ? error.message : String(error) });
		}
	}
	return {
		ok: prototypeFailures === 0,
		command: 'hexcore.pdb.importSemantics',
		semanticStatus: prototypeFailures === 0 && provider.status === 'ok' ? 'ok' as const : 'partial' as const,
		provider,
		types,
		auxiliaryTypeCount: auxiliaryTypes.length,
		prototypeCount,
		reconciledExportPrototypeCount,
		prototypeFailures,
		failureDiagnostics,
		storeHash: store.exportHash(),
	};
}
