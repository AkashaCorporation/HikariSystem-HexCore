/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Akasha Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as crypto from 'crypto';
import {
	decodeIatOperandVA,
	type DisassemblerEngine,
	type Function,
	type ImportFunction,
	type Instruction,
} from './disassemblerEngine';
import { recoverJumpTableTargets } from './jumpTableLeaders';
import { canonicalSerialize, type SemanticEvidence } from './semanticModel';
import {
	canonicalizeReferenceEdge,
	type CanonicalReferenceEdge,
	type IndirectResolutionSource,
	type ReferenceEdgeSpec,
	type ReferenceRelationKind,
	type ReferenceTarget,
	type TypedReferenceGraph,
} from './typedReferenceGraph';

export const REFERENCE_GRAPH_PRODUCER_ID = 'hexcore-disassembler:typed-reference-producer-r33';

export interface ReferenceGraphProducerBudgets {
	maxFunctions: number;
	maxInstructions: number;
	maxEdges: number;
	maxIndirectCandidates: number;
	maxUnresolvedSets: number;
	maxJumpTableEntries: number;
}

export const DEFAULT_REFERENCE_GRAPH_BUDGETS: Readonly<ReferenceGraphProducerBudgets> = Object.freeze({
	maxFunctions: 50_000,
	maxInstructions: 2_000_000,
	maxEdges: 250_000,
	maxIndirectCandidates: 32_768,
	maxUnresolvedSets: 16_384,
	maxJumpTableEntries: 1_024,
});

export interface IndirectCandidateSetSummary {
	candidateSetId: string;
	callsiteAddress: string;
	ownerFunctionIdentity: string;
	basicBlockIdentity: string;
	operation: 'call' | 'jump';
	status: 'resolved' | 'qualified-candidates';
	source: IndirectResolutionSource;
	targetIdentities: readonly string[];
	reason: string;
}

export interface UnresolvedIndirectSet {
	candidateSetId: string;
	callsiteAddress: string;
	ownerFunctionIdentity: string;
	basicBlockIdentity: string;
	operation: 'call' | 'jump';
	observedOperand: string;
	qualifiedSources: readonly IndirectResolutionSource[];
	reason: string;
}

export interface ReferenceGraphProducerSkipped {
	ambiguousInstructionOwnership: number;
	unownedLegacyXrefs: number;
	legacyXrefsWithoutExactOperand: number;
	dataAccessWithoutDirectionOrWidth: number;
	addressTakenWithoutOwnedSource: number;
	indirectSetsBeyondBudget: number;
}

export interface ReferenceGraphCollection {
	status: 'ok' | 'partial';
	analysisGeneration: number;
	analysisComplete: boolean;
	functionsAvailable: number;
	functionsScanned: number;
	incompleteFunctions: readonly string[];
	instructionsScanned: number;
	edges: readonly CanonicalReferenceEdge[];
	relationCounts: Readonly<Record<string, number>>;
	indirectCandidateSets: readonly IndirectCandidateSetSummary[];
	unresolvedIndirectSets: readonly UnresolvedIndirectSet[];
	skipped: Readonly<ReferenceGraphProducerSkipped>;
	partialReasons: readonly string[];
	collectionHash: string;
}

export interface ReferenceGraphSyncResult extends Omit<ReferenceGraphCollection, 'edges'> {
	edgesCollected: number;
	edgesChanged: number;
	edgesInvalidated: number;
	staleInvalidationDeferred: number;
	futureGenerationInvalidationDeferred: number;
	transactionHash: string;
	graphHash: string;
}

interface ImportRecord {
	identity: string;
	address: number;
	name: string;
	library: string;
}

interface FunctionContext {
	fn: Function;
	identity: string;
	bodyHash: string;
	blockStarts: readonly number[];
}

function sha256(value: string | Buffer): string {
	return crypto.createHash('sha256').update(value).digest('hex');
}

function compareAscii(left: string, right: string): number {
	return left < right ? -1 : left > right ? 1 : 0;
}

function toHex(address: number): string {
	if (!Number.isSafeInteger(address) || address < 0) {
		throw new Error(`Reference producer received an unsafe address: ${String(address)}.`);
	}
	return `0x${address.toString(16)}`;
}

function functionIdentity(address: number): string {
	return `function:${toHex(address)}`;
}

function basicBlockIdentity(owner: string, address: number): string {
	return `basic-block:${owner}:${toHex(address)}`;
}

function normalizeBudget(value: unknown, fallback: number, maximum: number, label: string): number {
	const parsed = value === undefined ? fallback : Number(value);
	if (!Number.isSafeInteger(parsed) || parsed < 1 || parsed > maximum) {
		throw new Error(`${label} must be an integer between 1 and ${maximum}.`);
	}
	return parsed;
}

export function normalizeReferenceGraphBudgets(
	value: Partial<ReferenceGraphProducerBudgets> = {},
): ReferenceGraphProducerBudgets {
	return Object.freeze({
		maxFunctions: normalizeBudget(value.maxFunctions, DEFAULT_REFERENCE_GRAPH_BUDGETS.maxFunctions, 500_000, 'maxFunctions'),
		maxInstructions: normalizeBudget(value.maxInstructions, DEFAULT_REFERENCE_GRAPH_BUDGETS.maxInstructions, 20_000_000, 'maxInstructions'),
		maxEdges: normalizeBudget(value.maxEdges, DEFAULT_REFERENCE_GRAPH_BUDGETS.maxEdges, 2_000_000, 'maxEdges'),
		maxIndirectCandidates: normalizeBudget(value.maxIndirectCandidates, DEFAULT_REFERENCE_GRAPH_BUDGETS.maxIndirectCandidates, 1_000_000, 'maxIndirectCandidates'),
		maxUnresolvedSets: normalizeBudget(value.maxUnresolvedSets, DEFAULT_REFERENCE_GRAPH_BUDGETS.maxUnresolvedSets, 1_000_000, 'maxUnresolvedSets'),
		maxJumpTableEntries: normalizeBudget(value.maxJumpTableEntries, DEFAULT_REFERENCE_GRAPH_BUDGETS.maxJumpTableEntries, 4_096, 'maxJumpTableEntries'),
	});
}

function bodyHash(fn: Function): string {
	return sha256(canonicalSerialize(fn.instructions.map(instruction => ({
		address: toHex(instruction.address),
		bytes: instruction.bytes.toString('hex'),
		mnemonic: instruction.mnemonic,
		opStr: instruction.opStr,
		targetAddress: instruction.targetAddress === undefined ? null : toHex(instruction.targetAddress),
	}))));
}

function computeBlockStarts(fn: Function): readonly number[] {
	const starts = new Set<number>([fn.address]);
	const ordered = [...fn.instructions].sort((left, right) => left.address - right.address);
	for (let index = 0; index < ordered.length; index++) {
		const instruction = ordered[index];
		if (instruction.isJump && instruction.targetAddress !== undefined
			&& instruction.targetAddress >= fn.address && instruction.targetAddress < fn.endAddress) {
			starts.add(instruction.targetAddress);
		}
		if ((instruction.isJump || instruction.isRet) && index + 1 < ordered.length) {
			starts.add(ordered[index + 1].address);
		}
	}
	return Object.freeze([...starts].sort((left, right) => left - right));
}

function blockFor(context: FunctionContext, address: number): string {
	let leader = context.fn.address;
	for (const candidate of context.blockStarts) {
		if (candidate > address) { break; }
		leader = candidate;
	}
	return basicBlockIdentity(context.identity, leader);
}

function splitOperands(opStr: string): string[] {
	const result: string[] = [];
	let start = 0;
	let depth = 0;
	for (let index = 0; index < opStr.length; index++) {
		const ch = opStr[index];
		if (ch === '[' || ch === '(' || ch === '{') { depth++; }
		if (ch === ']' || ch === ')' || ch === '}') { depth = Math.max(0, depth - 1); }
		if (ch === ',' && depth === 0) {
			result.push(opStr.slice(start, index).trim());
			start = index + 1;
		}
	}
	result.push(opStr.slice(start).trim());
	return result.filter(Boolean);
}

function resolveOperandAddress(operand: string, instruction: Instruction): number | undefined {
	const normalized = operand.trim().toLowerCase();
	const immediate = /^#?0x([0-9a-f]+)$/.exec(normalized);
	if (immediate) {
		const value = Number.parseInt(immediate[1], 16);
		return Number.isSafeInteger(value) ? value : undefined;
	}
	const absolute = /\[\s*0x([0-9a-f]+)\s*\]/.exec(normalized);
	if (absolute) {
		const value = Number.parseInt(absolute[1], 16);
		return Number.isSafeInteger(value) ? value : undefined;
	}
	const rip = /\[\s*rip\s*([+-])\s*0x([0-9a-f]+)\s*\]/.exec(normalized);
	if (rip) {
		const displacement = Number.parseInt(rip[2], 16) * (rip[1] === '-' ? -1 : 1);
		const value = instruction.address + instruction.size + displacement;
		return Number.isSafeInteger(value) && value >= 0 ? value : undefined;
	}
	return undefined;
}

const CAPSTONE_ACCESS_READ = 1;
const CAPSTONE_ACCESS_WRITE = 2;
const CAPSTONE_OPERAND_IMMEDIATE = 2;
const CAPSTONE_OPERAND_MEMORY = 3;

interface StructuredOperandAddress {
	index: number;
	address: number;
	access: number;
	widthBits: number | undefined;
	isMemory: boolean;
}

interface LocalIndirectCandidateSet {
	address: number;
	targets: readonly number[];
}

function safeAddress(value: number): number | undefined {
	return Number.isSafeInteger(value) && value >= 0 ? value : undefined;
}

function resolveStructuredOperandAddresses(
	instruction: Instruction,
	registerName: (registerId: number) => string | undefined,
): readonly StructuredOperandAddress[] {
	const operands = instruction.detail?.x86?.operands;
	if (!operands) { return []; }
	const resolved: StructuredOperandAddress[] = [];
	for (let index = 0; index < operands.length; index++) {
		const operand = operands[index];
		const widthBits = Number.isSafeInteger(operand.size) && operand.size > 0
			? operand.size * 8
			: undefined;
		if (operand.type === CAPSTONE_OPERAND_IMMEDIATE && operand.imm !== undefined) {
			const address = safeAddress(operand.imm);
			if (address !== undefined) {
				resolved.push({ index, address, access: operand.access, widthBits, isMemory: false });
			}
			continue;
		}
		if (operand.type !== CAPSTONE_OPERAND_MEMORY || !operand.mem) { continue; }
		const memory = operand.mem;
		if ((memory.segment ?? 0) !== 0 || (memory.index ?? 0) !== 0) { continue; }
		let address: number | undefined;
		if (memory.base === 0) {
			address = safeAddress(memory.disp);
		} else {
			const baseName = registerName(memory.base)?.toLowerCase();
			if (baseName === 'rip' || baseName === 'eip') {
				address = safeAddress(instruction.address + instruction.size + memory.disp);
			}
		}
		if (address !== undefined) {
			resolved.push({ index, address, access: operand.access, widthBits, isMemory: true });
		}
	}
	return resolved;
}

function operandForAddress(
	instruction: Instruction,
	address: number,
	registerName: (registerId: number) => string | undefined,
): StructuredOperandAddress | undefined {
	const structured = resolveStructuredOperandAddresses(instruction, registerName)
		.filter(candidate => candidate.address === address);
	if (structured.length === 1) { return structured[0]; }
	if (structured.length > 1 || instruction.detail?.x86?.operands) { return undefined; }

	const operands = splitOperands(instruction.opStr);
	const matches: number[] = [];
	for (let index = 0; index < operands.length; index++) {
		if (resolveOperandAddress(operands[index], instruction) === address) {
			matches.push(index);
		}
	}
	return matches.length === 1
		? { index: matches[0], address, access: 0, widthBits: undefined, isMemory: /[\[(]/.test(operands[matches[0]]) }
		: undefined;
}

function recoverLocalConstantFunctionPointers(
	instructions: readonly Instruction[],
	isCandidateAddress: (address: number) => boolean,
	registerName: (registerId: number) => string | undefined,
): ReadonlyMap<number, LocalIndirectCandidateSet> {
	const registerTargets = new Map<string, Set<number>>();
	const result = new Map<number, LocalIndirectCandidateSet>();
	for (const instruction of instructions) {
		const operands = instruction.detail?.x86?.operands;
		if (!operands) { continue; }
		const mnemonic = instruction.mnemonic.toLowerCase();
		if ((instruction.isCall || instruction.isJump) && operands[0]?.type === 1 && operands[0].reg) {
			const name = registerName(operands[0].reg)?.toLowerCase();
			const targets = name ? [...(registerTargets.get(name) ?? [])].sort((left, right) => left - right) : [];
			if (targets.length > 0) { result.set(instruction.address, { address: instruction.address, targets }); }
		}
		const destination = operands[0];
		if (!destination || destination.type !== 1 || !destination.reg || (destination.access & CAPSTONE_ACCESS_WRITE) === 0) { continue; }
		const destinationName = registerName(destination.reg)?.toLowerCase();
		if (!destinationName) { continue; }
		let next: Set<number> | undefined;
		if (mnemonic === 'lea' && operands[1]) {
			const resolved = resolveStructuredOperandAddresses(instruction, registerName).find(item => item.index === 1)?.address;
			if (resolved !== undefined && isCandidateAddress(resolved)) { next = new Set([resolved]); }
		} else if (mnemonic === 'mov' && operands[1]) {
			if (operands[1].type === 1 && operands[1].reg) {
				const sourceName = registerName(operands[1].reg)?.toLowerCase();
				if (sourceName && registerTargets.has(sourceName)) { next = new Set(registerTargets.get(sourceName)); }
			} else if (operands[1].type === CAPSTONE_OPERAND_IMMEDIATE && operands[1].imm !== undefined && isCandidateAddress(operands[1].imm)) {
				next = new Set([operands[1].imm]);
			}
		} else if (/^cmov/.test(mnemonic) && operands[1]?.type === 1 && operands[1].reg) {
			next = new Set(registerTargets.get(destinationName) ?? []);
			const sourceName = registerName(operands[1].reg)?.toLowerCase();
			for (const target of sourceName ? registerTargets.get(sourceName) ?? [] : []) { next.add(target); }
		}
		if (next && next.size > 0) { registerTargets.set(destinationName, next); }
		else { registerTargets.delete(destinationName); }
	}
	return result;
}

function binaryHashFromTargetIdentity(identity: string): string | undefined {
	const match = /^target:sha256:([0-9a-f]{64})$/i.exec(identity);
	return match?.[1].toLowerCase();
}

function makeEvidence(generation: number, source: SemanticEvidence['source'] = 'dataflow', strength: SemanticEvidence['strength'] = 'derived'): SemanticEvidence {
	return { source, strength, producer: REFERENCE_GRAPH_PRODUCER_ID, generation };
}

function makeEdge(
	graph: TypedReferenceGraph,
	context: FunctionContext,
	instruction: Instruction,
	relation: ReferenceRelationKind,
	target: ReferenceTarget,
	operandIndex: number,
	generation: number,
	extra: Partial<ReferenceEdgeSpec> = {},
): CanonicalReferenceEdge {
	const binaryHash = binaryHashFromTargetIdentity(graph.analysisTargetIdentity);
	return canonicalizeReferenceEdge({
		analysisTargetIdentity: graph.analysisTargetIdentity,
		relation,
		source: {
			address: toHex(instruction.address),
			ownerFunctionIdentity: context.identity,
			basicBlockIdentity: blockFor(context, instruction.address),
			operandIndex,
		},
		target,
		accessWidthBits: null,
		provenance: {
			sourceEngine: 'hexcore-disassembler',
			...(binaryHash ? { sourceArtifactSha256: binaryHash } : {}),
			evidenceAddress: toHex(instruction.address),
		},
		evidence: makeEvidence(generation),
		invalidationDependencies: [
			{ kind: 'analysis-generation', key: 'disassembler-analysis', generation },
			{ kind: 'function-body', key: context.identity, generation, contentSha256: context.bodyHash },
		],
		...extra,
	});
}

function importIdentity(library: string, fn: ImportFunction): string {
	return `import:${library.toLowerCase()}!${(fn.name || `ordinal-${fn.ordinal ?? 'unknown'}`).toLowerCase()}`;
}

function buildImportRecords(engine: DisassemblerEngine): ImportRecord[] {
	const records: ImportRecord[] = [];
	for (const library of engine.getImports()) {
		for (const fn of library.functions) {
			records.push({
				identity: importIdentity(library.name, fn),
				address: fn.address,
				name: fn.name,
				library: library.name,
			});
		}
	}
	return records.sort((left, right) => left.address - right.address || compareAscii(left.identity, right.identity));
}

function relationCounts(edges: readonly CanonicalReferenceEdge[]): Readonly<Record<string, number>> {
	const counts: Record<string, number> = {};
	for (const edge of edges) {
		counts[edge.relation] = (counts[edge.relation] ?? 0) + 1;
	}
	return Object.freeze(Object.fromEntries(Object.entries(counts).sort(([left], [right]) => compareAscii(left, right))));
}

export function collectTypedReferenceEdges(
	engine: DisassemblerEngine,
	graph: TypedReferenceGraph,
	budgetInput: Partial<ReferenceGraphProducerBudgets> = {},
): ReferenceGraphCollection {
	const budgets = normalizeReferenceGraphBudgets(budgetInput);
	const generation = engine.getAnalysisGeneration();
	const functions = engine.getFunctions().sort((left, right) => left.address - right.address);
	const incompleteFunctions = functions
		.filter(fn => engine.getFunctionBodyStatus(fn.address) === 'partial')
		.map(fn => functionIdentity(fn.address))
		.sort(compareAscii);
	const materializedFunctions = functions.filter(fn => engine.getFunctionBodyStatus(fn.address) === 'materialized');
	const selectedFunctions = materializedFunctions.slice(0, budgets.maxFunctions);
	const knownFunctionAddresses = new Set(functions.map(fn => fn.address));
	const contexts = new Map<number, FunctionContext>();
	const owners = new Map<number, FunctionContext[]>();
	for (const fn of selectedFunctions) {
		const context: FunctionContext = {
			fn,
			identity: functionIdentity(fn.address),
			bodyHash: bodyHash(fn),
			blockStarts: computeBlockStarts(fn),
		};
		contexts.set(fn.address, context);
		for (const instruction of fn.instructions) {
			const entries = owners.get(instruction.address) ?? [];
			entries.push(context);
			owners.set(instruction.address, entries);
		}
	}

	const edges = new Map<string, CanonicalReferenceEdge>();
	const indirectCandidateSets: IndirectCandidateSetSummary[] = [];
	const unresolvedIndirectSets: UnresolvedIndirectSet[] = [];
	const resolvedIndirectSites = new Set<number>();
	const jumpTableSites = new Set<number>();
	const partialReasons = new Set<string>();
	for (const identity of incompleteFunctions) {
		partialReasons.add(`incomplete-function-body:${identity}`);
	}
	const skipped: ReferenceGraphProducerSkipped = {
		ambiguousInstructionOwnership: 0,
		unownedLegacyXrefs: 0,
		legacyXrefsWithoutExactOperand: 0,
		dataAccessWithoutDirectionOrWidth: 0,
		addressTakenWithoutOwnedSource: 0,
		indirectSetsBeyondBudget: 0,
	};
	let instructionsScanned = 0;
	let indirectCandidates = 0;
	let edgeBudgetHit = false;

	const addEdge = (edge: CanonicalReferenceEdge): boolean => {
		if (edges.has(edge.edgeId)) { return true; }
		if (edges.size >= budgets.maxEdges) {
			edgeBudgetHit = true;
			partialReasons.add(`edge-budget:${budgets.maxEdges}`);
			return false;
		}
		edges.set(edge.edgeId, edge);
		return true;
	};
	const importRecords = buildImportRecords(engine);
	const importsByAddress = new Map(importRecords.filter(record => record.address > 0).map(record => [record.address, record]));
	const importsByName = new Map(importRecords.filter(record => record.name).map(record => [record.name, record]));
	const textRelocations = engine.getTextRelocations();
	const fileFormat = engine.getFileInfo()?.format ?? '';
	const registerName = (registerId: number): string | undefined => engine.getRegisterName?.(registerId);
	const executableSections = engine.getSections().filter(section => section.isExecutable);
	const isExecutableCandidate = (address: number): boolean => executableSections.some(section =>
		address >= section.virtualAddress && address < section.virtualAddress + Math.max(section.virtualSize, section.rawSize));

	function emitImportRelation(context: FunctionContext, instruction: Instruction, record: ImportRecord, relation: 'import-iat' | 'import-plt' | 'import-relocation'): void {
		addEdge(makeEdge(graph, context, instruction, relation, {
			kind: 'import', identity: record.identity, ...(record.address > 0 ? { address: toHex(record.address) } : {}),
		}, 0, generation, {
			evidence: makeEvidence(generation, 'import', 'signature'),
			invalidationDependencies: [
				{ kind: 'analysis-generation', key: 'disassembler-analysis', generation },
				{ kind: 'function-body', key: context.identity, generation, contentSha256: context.bodyHash },
				{ kind: relation === 'import-relocation' ? 'relocation-table' : 'import-table', key: record.identity, generation },
			],
		}));
	}

	outer: for (const context of contexts.values()) {
		const ordered = [...context.fn.instructions].sort((left, right) => left.address - right.address);
		const localFunctionPointers = recoverLocalConstantFunctionPointers(ordered, isExecutableCandidate, registerName);
		const jumpHits = recoverJumpTableTargets(
			ordered,
			(address, size) => engine.getBytes(address, size),
			{ maxEntries: budgets.maxJumpTableEntries },
		);
		const hitsBySite = new Map(jumpHits.map(hit => [hit.jmpAddress, hit]));

		for (const instruction of ordered) {
			if (instructionsScanned >= budgets.maxInstructions) {
				partialReasons.add(`instruction-budget:${budgets.maxInstructions}`);
				break outer;
			}
			instructionsScanned++;
			const instructionOwners = owners.get(instruction.address) ?? [];
			if (instructionOwners.length !== 1 || instructionOwners[0] !== context) {
				skipped.ambiguousInstructionOwnership++;
				continue;
			}

			const relocation = textRelocations.get(instruction.address);
			if (relocation?.name && (instruction.isCall || instruction.isJump)) {
				const known = importsByName.get(relocation.name);
				const record: ImportRecord = known ?? {
					identity: `import:external!${relocation.name}`,
					address: 0,
					name: relocation.name,
					library: 'external',
				};
				emitImportRelation(context, instruction, record, 'import-relocation');
				addEdge(makeEdge(graph, context, instruction,
					instruction.isCall ? 'code-call-near' : 'code-tail-call',
					{ kind: 'import', identity: record.identity, ...(record.address > 0 ? { address: toHex(record.address) } : {}) },
					0, generation, {
						evidence: makeEvidence(generation, 'import', 'signature'),
						invalidationDependencies: [
							{ kind: 'function-body', key: context.identity, generation, contentSha256: context.bodyHash },
							{ kind: 'relocation-table', key: record.identity, generation },
						],
					}));
				resolvedIndirectSites.add(instruction.address);
				continue;
			}

			if (instruction.isCall || instruction.isJump) {
				const structuredIat = resolveStructuredOperandAddresses(instruction, registerName)
					.filter(operand => operand.isMemory);
				const iatAddress = structuredIat.length === 1
					? structuredIat[0].address
					: instruction.detail?.x86?.operands
						? undefined
						: decodeIatOperandVA(instruction.opStr, instruction.address, instruction.size);
				const iatImport = iatAddress === undefined ? undefined : importsByAddress.get(iatAddress);
				if (iatImport) {
					emitImportRelation(context, instruction, iatImport, 'import-iat');
					const candidateSetId = `candidate-set:iat:${toHex(instruction.address)}`;
					const target: ReferenceTarget = { kind: 'import', identity: iatImport.identity, address: toHex(iatImport.address) };
					addEdge(makeEdge(graph, context, instruction, 'code-indirect-resolved', target, 0, generation, {
						evidence: makeEvidence(generation, 'import', 'signature'),
						indirectResolution: {
							status: 'resolved', candidateSetId, source: 'import-table',
							reason: 'The decoded memory operand resolves exactly to an indexed IAT slot.',
						},
						invalidationDependencies: [
							{ kind: 'function-body', key: context.identity, generation, contentSha256: context.bodyHash },
							{ kind: 'import-table', key: iatImport.identity, generation },
						],
					}));
					indirectCandidateSets.push(Object.freeze({
						candidateSetId,
						callsiteAddress: toHex(instruction.address),
						ownerFunctionIdentity: context.identity,
						basicBlockIdentity: blockFor(context, instruction.address),
						operation: instruction.isCall ? 'call' : 'jump',
						status: 'resolved',
						source: 'import-table',
						targetIdentities: Object.freeze([iatImport.identity]),
						reason: 'Exact IAT slot identity from the import table and encoded operand.',
					}));
					resolvedIndirectSites.add(instruction.address);
					continue;
				}
			}

			if (instruction.targetAddress !== undefined && (instruction.isCall || instruction.isJump)) {
				const imported = importsByAddress.get(instruction.targetAddress);
				if (imported && fileFormat.startsWith('ELF')) {
					emitImportRelation(context, instruction, imported, 'import-plt');
					addEdge(makeEdge(graph, context, instruction,
						instruction.isCall ? 'code-call-near' : 'code-tail-call',
						{ kind: 'import', identity: imported.identity, address: toHex(imported.address) }, 0, generation,
						{ evidence: makeEvidence(generation, 'import', 'signature') }));
					continue;
				}
				if (instruction.isCall) {
					const target: ReferenceTarget = knownFunctionAddresses.has(instruction.targetAddress)
						? { kind: 'function', identity: functionIdentity(instruction.targetAddress), address: toHex(instruction.targetAddress) }
						: { kind: 'address', identity: `address:${toHex(instruction.targetAddress)}`, address: toHex(instruction.targetAddress) };
					addEdge(makeEdge(graph, context, instruction, 'code-call-near', {
						...target,
					}, 0, generation));
				} else {
					const internal = instruction.targetAddress >= context.fn.address && instruction.targetAddress < context.fn.endAddress;
					const target: ReferenceTarget = internal
						? { kind: 'basic-block', identity: basicBlockIdentity(context.identity, instruction.targetAddress), address: toHex(instruction.targetAddress) }
						: knownFunctionAddresses.has(instruction.targetAddress)
							? { kind: 'function', identity: functionIdentity(instruction.targetAddress), address: toHex(instruction.targetAddress) }
							: { kind: 'address', identity: `address:${toHex(instruction.targetAddress)}`, address: toHex(instruction.targetAddress) };
					addEdge(makeEdge(graph, context, instruction,
						internal ? 'code-jump' : knownFunctionAddresses.has(instruction.targetAddress) ? 'code-tail-call' : 'code-jump',
						target, 0, generation));
				}
			}

			const localPointer = localFunctionPointers.get(instruction.address);
			if (localPointer && (instruction.isCall || instruction.isJump)) {
				const remaining = budgets.maxIndirectCandidates - indirectCandidates;
				const acceptedTargets = localPointer.targets.slice(0, Math.max(0, remaining));
				if (acceptedTargets.length < localPointer.targets.length) {
					partialReasons.add(`indirect-candidate-budget:${budgets.maxIndirectCandidates}`);
					skipped.indirectSetsBeyondBudget += localPointer.targets.length - acceptedTargets.length;
				}
				indirectCandidates += acceptedTargets.length;
				const candidateSetId = `candidate-set:constant-function-pointer:${toHex(instruction.address)}`;
				const identities: string[] = [];
				for (const targetAddress of acceptedTargets) {
					const knownFunction = knownFunctionAddresses.has(targetAddress);
					const identity = knownFunction ? functionIdentity(targetAddress) : `address:${toHex(targetAddress)}`; identities.push(identity);
					addEdge(makeEdge(graph, context, instruction, 'code-indirect-candidate', {
						kind: knownFunction ? 'function' : 'address', identity, address: toHex(targetAddress),
					}, 0, generation, {
						indirectResolution: {
							status: 'candidate', candidateSetId, source: 'constant-function-pointer',
							reason: 'Bounded local LEA/MOV/CMOV register flow retains this exact function address.',
						},
					}));
				}
				indirectCandidateSets.push(Object.freeze({
					candidateSetId, callsiteAddress: toHex(instruction.address), ownerFunctionIdentity: context.identity,
					basicBlockIdentity: blockFor(context, instruction.address), operation: instruction.isCall ? 'call' : 'jump',
					status: 'qualified-candidates', source: 'constant-function-pointer', targetIdentities: Object.freeze(identities.sort(compareAscii)),
					reason: 'Candidate set derived from bounded local constant-function-pointer flow; unknown incoming alternatives remain unresolved.',
				}));
				resolvedIndirectSites.add(instruction.address);
			}

			const jumpHit = hitsBySite.get(instruction.address);
			if (jumpHit) {
				jumpTableSites.add(instruction.address);
				const remaining = budgets.maxIndirectCandidates - indirectCandidates;
				const acceptedTargets = jumpHit.targets.slice(0, Math.max(0, remaining));
				if (acceptedTargets.length < jumpHit.targets.length) {
					partialReasons.add(`indirect-candidate-budget:${budgets.maxIndirectCandidates}`);
					skipped.indirectSetsBeyondBudget += jumpHit.targets.length - acceptedTargets.length;
				}
				indirectCandidates += acceptedTargets.length;
				const targetIdentities: string[] = [];
				const candidateSetId = `candidate-set:jump-table:${toHex(instruction.address)}`;
				for (const targetAddress of acceptedTargets) {
					const internal = targetAddress >= context.fn.address && targetAddress < context.fn.endAddress;
					const target: ReferenceTarget = internal
						? { kind: 'basic-block', identity: basicBlockIdentity(context.identity, targetAddress), address: toHex(targetAddress) }
						: knownFunctionAddresses.has(targetAddress)
							? { kind: 'function', identity: functionIdentity(targetAddress), address: toHex(targetAddress) }
							: { kind: 'address', identity: `address:${toHex(targetAddress)}`, address: toHex(targetAddress) };
					targetIdentities.push(target.identity);
					addEdge(makeEdge(graph, context, instruction, 'code-indirect-candidate', target, 0, generation, {
						indirectResolution: {
							status: 'candidate', candidateSetId, source: 'jump-table',
							reason: `Bounded table ${toHex(jumpHit.tableAddress)} enumerates this exact case target.`,
						},
						invalidationDependencies: [
							{ kind: 'function-body', key: context.identity, generation, contentSha256: context.bodyHash },
							{ kind: 'custom', key: `jump-table:${toHex(jumpHit.tableAddress)}`, generation },
						],
					}));
				}
				indirectCandidateSets.push(Object.freeze({
					candidateSetId,
					callsiteAddress: toHex(instruction.address),
					ownerFunctionIdentity: context.identity,
					basicBlockIdentity: blockFor(context, instruction.address),
					operation: 'jump',
					status: 'qualified-candidates',
					source: 'jump-table',
					targetIdentities: Object.freeze(targetIdentities.sort()),
					reason: `PIC table ${toHex(jumpHit.tableAddress)} yielded ${acceptedTargets.length} bounded targets.`,
				}));
			}

			if ((instruction.isCall || instruction.isJump)
				&& instruction.targetAddress === undefined
				&& !resolvedIndirectSites.has(instruction.address)
				&& !jumpTableSites.has(instruction.address)) {
				if (unresolvedIndirectSets.length < budgets.maxUnresolvedSets) {
					unresolvedIndirectSets.push(Object.freeze({
						candidateSetId: `candidate-set:unresolved:${toHex(instruction.address)}`,
						callsiteAddress: toHex(instruction.address),
						ownerFunctionIdentity: context.identity,
						basicBlockIdentity: blockFor(context, instruction.address),
						operation: instruction.isCall ? 'call' : 'jump',
						observedOperand: instruction.opStr,
						qualifiedSources: Object.freeze([]),
						reason: 'No import, relocation, jump-table, callback, vtable, address-taken or points-to evidence links this site to a target.',
					}));
				} else {
					partialReasons.add(`unresolved-set-budget:${budgets.maxUnresolvedSets}`);
					skipped.indirectSetsBeyondBudget++;
				}
			}
			if (edgeBudgetHit) { break outer; }
		}
	}

	for (const context of contexts.values()) {
		for (const seed of engine.getFunctionDiscoveryEvidence(context.fn.address)) {
			if (seed.kind !== 'address-taken' || seed.sourceAddress === undefined) { continue; }
			const sourceOwners = owners.get(seed.sourceAddress) ?? [];
			if (sourceOwners.length !== 1) {
				skipped.addressTakenWithoutOwnedSource++;
				continue;
			}
			const sourceContext = sourceOwners[0];
			const sourceInstruction = sourceContext.fn.instructions.find(item => item.address === seed.sourceAddress);
			if (!sourceInstruction) {
				skipped.addressTakenWithoutOwnedSource++;
				continue;
			}
			const sourceOperand = operandForAddress(sourceInstruction, context.fn.address, registerName);
			if (!sourceOperand) {
				skipped.addressTakenWithoutOwnedSource++;
				continue;
			}
			addEdge(makeEdge(graph, sourceContext, sourceInstruction, 'data-address-taken', {
				kind: 'function', identity: context.identity, address: toHex(context.fn.address),
			}, sourceOperand.index, generation, {
				invalidationDependencies: [
					{ kind: 'function-body', key: sourceContext.identity, generation, contentSha256: sourceContext.bodyHash },
					{ kind: 'function-body', key: context.identity, generation, contentSha256: context.bodyHash },
				],
			}));
		}
	}

	for (const stringRef of engine.getStrings()) {
		for (const sourceAddress of [...stringRef.references].sort((left, right) => left - right)) {
			const sourceOwners = owners.get(sourceAddress) ?? [];
			if (sourceOwners.length !== 1) {
				skipped.unownedLegacyXrefs++;
				continue;
			}
			const context = sourceOwners[0];
			const instruction = context.fn.instructions.find(item => item.address === sourceAddress);
			const operand = instruction ? operandForAddress(instruction, stringRef.address, registerName) : undefined;
			if (!instruction || !operand) {
				skipped.legacyXrefsWithoutExactOperand++;
				continue;
			}
			addEdge(makeEdge(graph, context, instruction, 'string-reference', {
				kind: 'string', identity: `string:${toHex(stringRef.address)}`, address: toHex(stringRef.address),
			}, operand.index, generation));
		}
	}

	for (const xref of engine.getAllCrossReferences()) {
		if (xref.type !== 'data') { continue; }
		const sourceOwners = owners.get(xref.from) ?? [];
		if (sourceOwners.length !== 1) {
			skipped.unownedLegacyXrefs++;
			continue;
		}
		const context = sourceOwners[0];
		const instruction = context.fn.instructions.find(item => item.address === xref.from);
		const operand = instruction ? operandForAddress(instruction, xref.to, registerName) : undefined;
		if (!instruction || !operand) {
			skipped.legacyXrefsWithoutExactOperand++;
			continue;
		}
		const mnemonic = instruction.mnemonic.toLowerCase();
		let relation: Extract<ReferenceRelationKind, 'data-read' | 'data-write' | 'data-read-write' | 'data-address-taken'>;
		let accessWidthBits: number | null = null;
		if (mnemonic === 'lea') {
			relation = 'data-address-taken';
		} else if (operand.isMemory && operand.widthBits !== undefined && (operand.access & 3) !== 0) {
			accessWidthBits = operand.widthBits;
			relation = (operand.access & CAPSTONE_ACCESS_READ) !== 0 && (operand.access & CAPSTONE_ACCESS_WRITE) !== 0
				? 'data-read-write'
				: (operand.access & CAPSTONE_ACCESS_WRITE) !== 0 ? 'data-write' : 'data-read';
		} else {
			skipped.dataAccessWithoutDirectionOrWidth++;
			continue;
		}
		const target: ReferenceTarget = knownFunctionAddresses.has(xref.to)
			? { kind: 'function', identity: functionIdentity(xref.to), address: toHex(xref.to) }
			: { kind: 'global', identity: `global:${toHex(xref.to)}`, address: toHex(xref.to) };
		addEdge(makeEdge(graph, context, instruction, relation, target, operand.index, generation, { accessWidthBits }));
	}

	if (materializedFunctions.length > selectedFunctions.length) {
		partialReasons.add(`function-budget:${budgets.maxFunctions}`);
	}
	if (!engine.isAnalysisComplete()) {
		partialReasons.add('analysis-not-complete');
	}
	const sortedEdges = Object.freeze([...edges.values()].sort((left, right) => compareAscii(left.edgeId, right.edgeId)));
	const summary = {
		status: partialReasons.size > 0 ? 'partial' as const : 'ok' as const,
		analysisGeneration: generation,
		analysisComplete: engine.isAnalysisComplete(),
		functionsAvailable: functions.length,
		functionsScanned: selectedFunctions.length,
		incompleteFunctions: Object.freeze(incompleteFunctions),
		instructionsScanned,
		relationCounts: relationCounts(sortedEdges),
		indirectCandidateSets: Object.freeze(indirectCandidateSets.sort((left, right) => compareAscii(left.candidateSetId, right.candidateSetId))),
		unresolvedIndirectSets: Object.freeze(unresolvedIndirectSets.sort((left, right) => compareAscii(left.candidateSetId, right.candidateSetId))),
		skipped: Object.freeze({ ...skipped }),
		partialReasons: Object.freeze([...partialReasons].sort()),
	};
	return Object.freeze({
		...summary,
		edges: sortedEdges,
		collectionHash: sha256(canonicalSerialize({ ...summary, edges: sortedEdges })),
	});
}

export function syncTypedReferenceGraph(
	engine: DisassemblerEngine,
	budgetInput: Partial<ReferenceGraphProducerBudgets> = {},
): ReferenceGraphSyncResult {
	const session = engine.getSessionStore();
	if (!session) {
		throw new Error('Typed reference production requires a bound analysis session.');
	}
	const graph = session.getSemanticStore().getReferenceGraph();
	const previousOwned = graph.listStoredEdges(false).filter(stored =>
		stored.edge.evidenceSet.length > 0
		&& stored.edge.evidenceSet.every(item => item.producer === REFERENCE_GRAPH_PRODUCER_ID));
	const collection = collectTypedReferenceEdges(engine, graph, budgetInput);
	const batch = collection.edges.length > 0
		? graph.writeBatch(collection.edges)
		: { transactionHash: sha256(canonicalSerialize({ operation: 'reference-edge-batch', edges: [] })), results: [] as const };
	const newIds = new Set(collection.edges.map(edge => edge.edgeId));
	const incompleteOwners = new Set(collection.incompleteFunctions);
	const invalidationIsCurrent = (stored: typeof previousOwned[number]): boolean =>
		collection.analysisGeneration >= Math.max(stored.validFromGeneration, stored.edge.generation);
	const unsafeStored = previousOwned
		.filter(item => incompleteOwners.has(item.edge.source.ownerFunctionIdentity));
	const unsafeIds = unsafeStored.filter(invalidationIsCurrent).map(item => item.edge.edgeId);
	const unsafeOwnedIdSet = new Set(unsafeStored.map(item => item.edge.edgeId));
	const invalidatedUnsafe = unsafeIds.length > 0
		? graph.invalidateEdges(unsafeIds, collection.analysisGeneration, 'Source function body is incomplete and display-only.')
		: 0;
	const staleStored = previousOwned
		.filter(item => !newIds.has(item.edge.edgeId) && !unsafeOwnedIdSet.has(item.edge.edgeId));
	const canInvalidateStale = collection.status === 'ok';
	const staleIds = staleStored.filter(invalidationIsCurrent).map(item => item.edge.edgeId);
	const invalidated = canInvalidateStale && staleIds.length > 0
		? graph.invalidateEdges(staleIds, collection.analysisGeneration, 'Producer snapshot no longer contains this edge.')
		: 0;
	const futureGenerationInvalidationDeferred = [...unsafeStored, ...staleStored]
		.filter(item => !invalidationIsCurrent(item)).length;
	const { edges: _edges, ...summary } = collection;
	const deferredReason = futureGenerationInvalidationDeferred > 0
		? `${futureGenerationInvalidationDeferred} reference edge invalidation(s) were deferred because the restored analysis generation is older than the active edge generation.`
		: undefined;
	return Object.freeze({
		...summary,
		status: deferredReason ? 'partial' as const : summary.status,
		partialReasons: deferredReason ? [...summary.partialReasons, deferredReason] : summary.partialReasons,
		edgesCollected: collection.edges.length,
		edgesChanged: batch.results.filter(result => result.changed).length,
		edgesInvalidated: invalidatedUnsafe + invalidated,
		staleInvalidationDeferred: canInvalidateStale ? 0 : staleIds.length,
		futureGenerationInvalidationDeferred,
		transactionHash: batch.transactionHash,
		graphHash: graph.exportHash(),
	});
}
