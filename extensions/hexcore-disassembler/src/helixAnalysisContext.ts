/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Akasha Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as crypto from 'crypto';
import { BasicBlockAnalyzer } from './basicBlockAnalyzer';
import type { DisassemblerEngine, Function, Instruction } from './disassemblerEngine';
import type { StructInfoJson } from './elfBtfLoader';
import type { CanonicalSemanticType } from './semanticModel';

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
	const end = selected?.endAddress ?? instructionEnd(instructions, entry);
	const cfg = new BasicBlockAnalyzer().buildCFG(instructions, selected?.name ?? `sub_${entry.toString(16)}`, entry);
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
	const semanticStore = engine.getSessionStore()?.getSemanticStore();

	const payload = {
		contextVersion: HELIX_ANALYSIS_CONTEXT_VERSION,
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
			storeHash: semanticStore?.exportHash() ?? '',
			types: semanticStore?.listTypes() ?? [],
			prototypes: semanticStore?.listPrototypes() ?? [],
			bindings: semanticStore?.findTypeBindings() ?? [],
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
