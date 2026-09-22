/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Akasha Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as crypto from 'crypto';
import { BasicBlockAnalyzer } from './basicBlockAnalyzer';
import type { DisassemblerEngine, Function, Instruction } from './disassemblerEngine';
import type { StructInfoJson } from './elfBtfLoader';
import type { CanonicalSemanticType } from './semanticModel';
import { SemanticQueryView, openSemanticQueryView, type SemanticQueryIdentity } from './semanticQueryView';

export const HELIX_ANALYSIS_CONTEXT_VERSION = 1 as const;

export interface HelixContextAddressRange {
	start: string;
	end: string;
}

export interface HelixContextBlock extends HelixContextAddressRange {
	id: string;
	owner: string;
	type: 'entry' | 'normal' | 'exit' | 'call';
	instructionAddresses: readonly string[];
}

export interface HelixContextEdge {
	from: string;
	to: string;
	type: 'unconditional' | 'true' | 'false' | 'call' | 'fallthrough';
}

export interface HelixContextImport {
	library: string;
	name: string;
	address: string;
	prototype?: string;
	returnType?: string;
	parameters?: readonly { name: string; type: string }[];
	callingConvention: 'win64' | 'stdcall' | 'platform-default';
}

export interface HelixContextRelocation {
	source: 'elf' | 'elf-text' | 'elf-data';
	address: string;
	type: string;
	symbol?: string;
	section?: string;
	addend?: number;
}

export interface HelixAnalysisContext {
	contextVersion: typeof HELIX_ANALYSIS_CONTEXT_VERSION;
	contextSha256: string;
	queryIdentity?: Readonly<SemanticQueryIdentity>;
	target: {
		id?: string;
		binarySha256?: string;
		filePath?: string;
		format: string;
		architecture: string;
		imageBase: string;
		imageSize: number;
	};
	analysis: {
		generation: number;
		complete: boolean;
		functionStartsAuthoritative: boolean;
	};
	function: HelixContextAddressRange & {
		entry: string;
		name: string;
	};
	functionStarts: readonly number[];
	blocks: readonly HelixContextBlock[];
	edges: readonly HelixContextEdge[];
	imports: readonly HelixContextImport[];
	relocations: readonly HelixContextRelocation[];
	symbols: readonly { address: string; name: string; kind: 'function' | 'export' }[];
	segments: readonly (HelixContextAddressRange & {
		name: string;
		permissions: string;
		isCode: boolean;
		isData: boolean;
	})[];
	abi: {
		platform: 'windows' | 'sysv' | 'unknown';
		defaultCallingConvention: 'win64' | 'sysv64' | 'cdecl' | 'aapcs' | 'unknown';
		stackDeltaStatus: 'pending';
	};
	semantic: {
		storeHash: string;
		types: readonly CanonicalSemanticType[];
		prototypes: readonly any[];
		bindings: readonly any[];
	};
}

export interface HelixDebugTypeEnvelope extends StructInfoJson {
	hexcoreContext: HelixAnalysisContext;
}

function hex(value: number): string {
	return `0x${Math.max(0, Math.trunc(value)).toString(16)}`;
}

function instructionEnd(instructions: readonly Instruction[], fallback: number): number {
	const last = instructions[instructions.length - 1];
	return last ? last.address + Math.max(1, last.size) : fallback;
}

function selectFunction(functions: readonly Function[], address: number): Function | undefined {
	return functions.find(fn => fn.address === address)
		?? functions.find(fn => fn.address <= address && address < fn.endAddress);
}

function freezeRecursively<T>(value: T): T {
	if (value && typeof value === 'object' && !Object.isFrozen(value)) {
		for (const child of Object.values(value as Record<string, unknown>)) {
			freezeRecursively(child);
		}
		Object.freeze(value);
	}
	return value;
}

function platformAbi(format: string, architecture: string): HelixAnalysisContext['abi'] {
	if (/^PE/i.test(format)) {
		return {
			platform: 'windows',
			defaultCallingConvention: architecture === 'x64' ? 'win64' : 'cdecl',
			stackDeltaStatus: 'pending',
		};
	}
	if (/^ELF/i.test(format)) {
		return {
			platform: 'sysv',
			defaultCallingConvention: architecture === 'x64' ? 'sysv64'
				: architecture === 'arm' || architecture === 'arm64' ? 'aapcs' : 'cdecl',
			stackDeltaStatus: 'pending',
		};
	}
	return { platform: 'unknown', defaultCallingConvention: 'unknown', stackDeltaStatus: 'pending' };
}

/**
 * Capture all target-derived evidence once, after function ownership has been
 * reconciled. The returned object is deeply frozen and is the only semantic
 * side channel handed to Helix for this decompile invocation.
 */
export async function createHelixAnalysisContext(
	engine: DisassemblerEngine,
	requestedAddress: number,
): Promise<HelixAnalysisContext> {
	const functions = engine.getFunctions();
	const selected = selectFunction(functions, requestedAddress);
	const entry = selected?.address ?? requestedAddress;
	const instructions = selected ? await engine.getFunctionInstructions(selected.address) : [];
	return buildHelixAnalysisContext(engine, functions, selected, entry, instructions);
}

/** No hydration, cache writes, reconciliation or asynchronous engine reads. */
export function createReadOnlyHelixAnalysisContext(
	engine: DisassemblerEngine,
	requestedAddress: number,
	view: SemanticQueryView,
): HelixAnalysisContext {
	if (!(view instanceof SemanticQueryView)) { throw new Error('read-only-helix: a captured SemanticQueryView is required'); }
	if (!Number.isSafeInteger(requestedAddress) || requestedAddress < 0) { throw new Error('read-only-helix: unsupported address precision'); }
	const session = engine.getSessionStore();
	if (!session || session.getAnalysisTarget()?.id !== view.identity.targetIdentity) { throw new Error('read-only-helix: target mismatch'); }
	if (engine.getAnalysisImageSha256() !== session.getAnalysisTarget()?.binarySha256) { throw new Error('read-only-helix: current image differs from the accepted target'); }
	if (view.identity.engineGeneration === undefined || view.identity.engineGeneration !== engine.getAnalysisGeneration()) { throw new Error('read-only-helix: engine generation mismatch'); }
	const revision = session.getSemanticReadRevision();
	const currentView = openSemanticQueryView(session, { engineGeneration: engine.getAnalysisGeneration() });
	currentView.assertIdentity(view.identity);
	if (currentView.identity.sessionId !== view.identity.sessionId || engine.getArchitecture() !== view.identity.architecture) { throw new Error('read-only-helix: session/architecture mismatch'); }
	const functions = engine.getFunctions();
	const selected = functions.find(fn => fn.address === requestedAddress);
	if (!selected) { throw new Error('read-only-helix: exact function entry required'); }
	const body = engine.peekFunctionBodyCompleteness(requestedAddress);
	if (!body || body.state !== 'complete' || !body.boundaryReached) { throw new Error(`read-only-helix: function body is ${body?.state ?? 'unavailable'}`); }
	if (body.authoritativeStart !== selected.address || body.authoritativeEndExclusive !== selected.endAddress || !Number.isSafeInteger(selected.endAddress) || selected.endAddress <= selected.address) { throw new Error('read-only-helix: inconsistent function boundary'); }
	const byteLength = selected.endAddress - selected.address;
	if (selected.size !== byteLength) { throw new Error('read-only-helix: inconsistent recorded function size'); }
	if (byteLength > 4 * 1024 * 1024 || selected.instructions.length > 250000) { throw new Error('read-only-helix: function capture budget exceeded'); }
	const bytes = engine.getBytes(selected.address, byteLength);
	if (!bytes || bytes.length !== byteLength) { throw new Error('read-only-helix: accepted function bytes unavailable'); }
	let end = selected.address;
	for (const instruction of [...selected.instructions].sort((left, right) => left.address - right.address)) {
		if (!Number.isSafeInteger(instruction.address) || !Number.isSafeInteger(instruction.size) || instruction.size < 1 || instruction.address !== end || instruction.address + instruction.size > selected.endAddress) { throw new Error('read-only-helix: incomplete or overlapping instruction coverage'); }
		if (!Buffer.from(instruction.bytes).equals(bytes.subarray(instruction.address - selected.address, instruction.address - selected.address + instruction.size))) { throw new Error('read-only-helix: accepted instructions differ from current bytes'); }
		end += instruction.size;
	}
	if (end !== selected.endAddress) { throw new Error('read-only-helix: incomplete instruction coverage'); }
	const context = buildHelixAnalysisContext(engine, functions, selected, selected.address, selected.instructions, view);
	if (revision !== session.getSemanticReadRevision() || engine.getAnalysisGeneration() !== view.identity.engineGeneration) { throw new Error('read-only-helix: context changed during capture'); }
	return context;
}

function buildHelixAnalysisContext(
	engine: DisassemblerEngine, functions: readonly Function[], selected: Function | undefined,
	entry: number, instructions: readonly Instruction[], view?: SemanticQueryView,
): HelixAnalysisContext {
	const end = selected?.endAddress ?? instructionEnd(instructions, entry);
	const cfg = new BasicBlockAnalyzer().buildCFG([...instructions], selected?.name ?? `sub_${entry.toString(16)}`, entry);
	const blockStartById = new Map<number, number>();
	const blocks = [...cfg.blocks.values()].map(block => {
		blockStartById.set(block.id, block.startAddress);
		return {
			id: `block:${hex(entry)}:${hex(block.startAddress)}`,
			owner: hex(entry),
			start: hex(block.startAddress),
			end: hex(instructionEnd(block.instructions, block.startAddress)),
			type: block.type,
			instructionAddresses: block.instructions.map(instruction => hex(instruction.address)),
		} satisfies HelixContextBlock;
	}).sort((a, b) => Number.parseInt(a.start, 16) - Number.parseInt(b.start, 16));
	const edges = cfg.edges.flatMap(edge => {
		const from = blockStartById.get(edge.from);
		const to = blockStartById.get(edge.to);
		return from === undefined || to === undefined ? [] : [{
			from: hex(from),
			to: hex(to),
			type: edge.type,
		} satisfies HelixContextEdge];
	});

	const fileInfo = engine.getFileInfo();
	const architecture = engine.getArchitecture();
	const analysisTarget = engine.getSessionStore()?.getAnalysisTarget();
	const typedImports = engine.getTypedImports();
	const imports = typedImports.flatMap(library => library.functions.map(fn => ({
		library: library.name,
		name: fn.name,
		address: hex(fn.address),
		...(fn.signature ? {
			prototype: `${fn.signature.returnType} ${fn.name}(${fn.signature.parameters.map(p => `${p.type} ${p.name}`).join(', ')})`,
			returnType: fn.signature.returnType,
			parameters: fn.signature.parameters.map(parameter => ({ ...parameter })),
		} : {}),
		callingConvention: /^PE/i.test(fileInfo?.format ?? '')
			? architecture === 'x64' ? 'win64' : 'stdcall'
			: 'platform-default',
	} satisfies HelixContextImport))).sort((a, b) => Number.parseInt(a.address, 16) - Number.parseInt(b.address, 16));

	const relocations: HelixContextRelocation[] = [];
	for (const relocation of engine.getELFAnalysis()?.relocations ?? []) {
		if (relocation.offset < entry || relocation.offset >= end) { continue; }
		relocations.push({
			source: 'elf',
			address: hex(relocation.offset),
			type: relocation.typeName,
			symbol: relocation.symbolName || undefined,
			section: relocation.sectionName || undefined,
			addend: relocation.addend,
		});
	}
	for (const [offset, relocation] of engine.getTextRelocations()) {
		if (offset < entry || offset >= end) { continue; }
		relocations.push({
			source: 'elf-text', address: hex(offset), type: String(relocation.type),
			symbol: relocation.name || undefined, addend: relocation.addend,
		});
	}
	for (const [offset, relocation] of engine.getDataRelocations()) {
		if (offset < entry || offset >= end) { continue; }
		relocations.push({
			source: 'elf-data', address: hex(offset), type: String(relocation.type),
			section: relocation.sectionName, addend: relocation.addend,
		});
	}
	relocations.sort((a, b) => Number.parseInt(a.address, 16) - Number.parseInt(b.address, 16));

	const functionStarts = functions.map(fn => fn.address).filter(Number.isSafeInteger).sort((a, b) => a - b);
	const symbols = [
		...functions.filter(fn => !/^sub_[0-9a-f]+$/i.test(fn.name)).map(fn => ({
			address: hex(fn.address), name: fn.name, kind: 'function' as const,
		})),
		...engine.getExports().filter(exp => !exp.isForwarder).map(exp => ({
			address: hex(exp.address), name: exp.name, kind: 'export' as const,
		})),
	].sort((a, b) => Number.parseInt(a.address, 16) - Number.parseInt(b.address, 16));
	const segments = engine.getSections().map(section => ({
		name: section.name,
		start: hex(section.virtualAddress),
		end: hex(section.virtualAddress + Math.max(section.virtualSize, section.rawSize)),
		permissions: section.permissions,
		isCode: section.isCode,
		isData: section.isData,
	})).sort((a, b) => Number.parseInt(a.start, 16) - Number.parseInt(b.start, 16));
	const semanticStore = view ? undefined : engine.getSessionStore()?.getSemanticStore();

	const payload = {
		contextVersion: HELIX_ANALYSIS_CONTEXT_VERSION,
		...(view ? { queryIdentity: view.identity } : {}),
		target: {
			...(analysisTarget ? { id: analysisTarget.id, binarySha256: analysisTarget.binarySha256 } : {}),
			...(engine.getFilePath() ? { filePath: engine.getFilePath() } : {}),
			format: fileInfo?.format ?? 'Raw',
			architecture,
			imageBase: hex(fileInfo?.baseAddress ?? engine.getBaseAddress()),
			imageSize: fileInfo?.imageSize ?? 0,
		},
		analysis: {
			generation: engine.getAnalysisGeneration(),
			complete: engine.isAnalysisComplete(),
			functionStartsAuthoritative: engine.isAnalysisComplete(),
		},
		function: { entry: hex(entry), start: hex(entry), end: hex(end), name: selected?.name ?? `sub_${entry.toString(16)}` },
		functionStarts,
		blocks,
		edges,
		imports,
		relocations,
		symbols,
		segments,
		abi: platformAbi(fileInfo?.format ?? 'Raw', architecture),
		semantic: {
			storeHash: view?.identity.snapshotSha256 ?? semanticStore?.exportHash() ?? '',
			types: view?.listTypes() ?? semanticStore?.listTypes() ?? [],
			prototypes: view?.listPrototypes() ?? semanticStore?.listPrototypes() ?? [],
			bindings: view?.findTypeBindings() ?? semanticStore?.findTypeBindings() ?? [],
		},
	};
	const contextSha256 = crypto.createHash('sha256').update(JSON.stringify(payload)).digest('hex');
	return freezeRecursively({ ...payload, contextSha256 });
}

/** Preserve the existing debug-type schema while attaching the immutable context. */
export function createHelixDebugTypeEnvelope(
	context: HelixAnalysisContext,
	structInfo?: StructInfoJson,
): HelixDebugTypeEnvelope {
	const functions = structInfo ? { ...structInfo.functions } : {};
	const typeById = new Map(context.semantic.types.map(type => [type.typeId, type]));
	const renderType = (typeId: string, depth = 0): string => {
		if (depth > 12) { return 'void'; }
		const type = typeById.get(typeId);
		if (!type) { return typeId; }
		if (type.kind === 'pointer') { return `${renderType(type.targetTypeId!, depth + 1)} *`; }
		if (type.kind === 'array') { return `${renderType(type.targetTypeId!, depth + 1)}[${type.count ?? 0}]`; }
		if (type.kind === 'qualified') {
			const qualifier = [type.const ? 'const' : '', type.volatile ? 'volatile' : '', type.restrict ? 'restrict' : ''].filter(Boolean).join(' ');
			return `${qualifier} ${renderType(type.targetTypeId!, depth + 1)}`.trim();
		}
		if (type.kind === 'struct' || type.kind === 'union' || type.kind === 'enum') { return `${type.kind} ${type.name ?? type.typeId}`; }
		if (type.kind === 'typedef' && type.name) { return type.name; }
		return type.name ?? type.opaqueDeclaration ?? type.typeId;
	};
	const semanticStructs: StructInfoJson['structs'] = {};
	for (const type of context.semantic.types) {
		if (!['struct', 'union'].includes(type.kind) || !type.name || !type.members?.length) { continue; }
		semanticStructs[type.name] = {
			size: Math.ceil((type.sizeBits ?? 0) / 8),
			fields: type.members.map(member => ({
				name: member.name,
				offset: `0x${Math.floor(member.bitOffset / 8).toString(16).toUpperCase()}`,
				size: Math.ceil((member.bitSize ?? typeById.get(member.typeId)?.sizeBits ?? 0) / 8),
				type: renderType(member.typeId),
			})),
		};
	}
	const symbolByAddress = new Map(context.symbols.map(symbol => [symbol.address.toLowerCase(), symbol.name]));
	for (const prototype of context.semantic.prototypes) {
		const address = typeof prototype.functionAddress === 'string' ? prototype.functionAddress.toLowerCase() : undefined;
		const importName = typeof prototype.functionIdentity === 'string' && prototype.functionIdentity.startsWith('import:')
			? prototype.functionIdentity.slice(prototype.functionIdentity.indexOf('!') + 1)
			: undefined;
		const name = (address ? symbolByAddress.get(address) : undefined)
			?? (address === context.function.start.toLowerCase() ? context.function.name : undefined)
			?? importName;
		if (!name) { continue; }
		functions[name] = {
			returnType: renderType(prototype.returnTypeId),
			params: prototype.parameters.map((parameter: any) => ({ index: parameter.ordinal, name: parameter.name, type: renderType(parameter.typeId) })),
			variadic: prototype.variadic === true,
		};
	}
	for (const imported of context.imports) {
		if (!imported.returnType || !imported.parameters || functions[imported.name]) { continue; }
		functions[imported.name] = {
			returnType: imported.returnType,
			params: imported.parameters.map((parameter, index) => ({
				index,
				name: parameter.name,
				type: parameter.type,
			})),
		};
	}
	return freezeRecursively({
		structs: { ...(structInfo ? structInfo.structs : {}), ...semanticStructs },
		functions,
		...(structInfo?.boundaries ? { boundaries: structInfo.boundaries.map(boundary => ({ ...boundary })) } : {}),
		hexcoreContext: context,
	});
}
