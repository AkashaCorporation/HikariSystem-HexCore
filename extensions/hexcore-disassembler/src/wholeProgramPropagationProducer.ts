/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Akasha Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as crypto from 'crypto';
import type { DisassemblerEngine, Function, Instruction } from './disassemblerEngine';
import { canonicalSerialize, getABIModel, type CanonicalFunctionParameter, type CanonicalFunctionPrototype, type ParameterLocation, type SemanticEvidence } from './semanticModel';
import type { SemanticStore } from './semanticStore';
import { syncTypedReferenceGraph, type ReferenceGraphSyncResult } from './typedReferenceGraphProducer';
import type { CanonicalReferenceEdge } from './typedReferenceGraph';
import {
	WholeProgramPropagationEngine,
	type CallEffect,
	type FunctionSummaryInput,
	type FieldAccessEffect,
	type GlobalEffect,
	type ParameterEffect,
	type PropagationConstraint,
	type PropagationRunResult,
	type PropagationSeedFact,
	type PropagationSolveOptions,
	type PropagationValueRef,
	type SummaryBarrier,
} from './wholeProgramPropagation';
import { runPropagationInWorker, type PropagationWorkerDiagnostics } from './wholeProgramPropagationWorkerClient';

export const PROPAGATION_PRODUCER_ID = 'hexcore-disassembler:whole-program-summary-r34';

export interface PropagationInputCollection {
	status: 'ok' | 'partial';
	analysisGeneration: number;
	analysisComplete: boolean;
	functionsAvailable: number;
	functionsMaterialized: number;
	incompleteFunctions: readonly string[];
	inputs: readonly FunctionSummaryInput[];
	barrierCount: number;
	partialReasons: readonly string[];
	collectionHash: string;
}

export interface PropagationSyncResult {
	references: ReferenceGraphSyncResult;
	collection: PropagationInputCollection;
	run: PropagationRunResult;
	incompleteSummariesInvalidated: number;
	worker?: PropagationWorkerDiagnostics;
	preparation?: {
		referenceSyncMs: number;
		collectionMs: number;
		invalidationMs: number;
	};
}

function compareAscii(left: string, right: string): number {
	return left < right ? -1 : left > right ? 1 : 0;
}

function sha256(value: string): string {
	return crypto.createHash('sha256').update(value).digest('hex');
}

function toHex(address: number): string {
	if (!Number.isSafeInteger(address) || address < 0) { throw new Error(`Unsafe propagation address ${String(address)}.`); }
	return `0x${address.toString(16)}`;
}

function functionIdentity(address: number): string {
	return `function:${toHex(address)}`;
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

function derivedEvidence(generation: number, source: SemanticEvidence['source'] = 'dataflow'): SemanticEvidence {
	return { strength: 'derived', source, producer: PROPAGATION_PRODUCER_ID, generation };
}

function parameterValue(functionId: string, parameter: CanonicalFunctionParameter): PropagationValueRef {
	const location = parameter.location;
	const base = { functionIdentity: functionId, typeId: parameter.typeId, widthBits: parameter.abiSizeBits };
	if (location.kind === 'register') {
		return location.registers.length === 1
			? { kind: 'register', identity: `parameter:${parameter.ordinal}:register:${location.registers[0]}`, ...base }
			: { kind: 'parameter', identity: `parameter:${parameter.ordinal}:registers:${location.registers.join('+')}`, ...base };
	}
	if (location.kind === 'stack') {
		return { kind: 'stack-slot', identity: `parameter:${parameter.ordinal}:stack:${location.offsetBytes}`, ...base };
	}
	return { kind: 'parameter', identity: `parameter:${parameter.ordinal}:${location.kind}`, ...base };
}

function callsiteValue(functionId: string, callsite: string, ordinal: number, location: ParameterLocation, typeId: string, widthBits?: number): PropagationValueRef {
	const base = { functionIdentity: functionId, typeId, widthBits };
	if (location.kind === 'register') {
		return location.registers.length === 1
			? { kind: 'register', identity: `call:${callsite}:arg:${ordinal}:register:${location.registers[0]}`, ...base }
			: { kind: 'ssa', identity: `call:${callsite}:arg:${ordinal}:registers:${location.registers.join('+')}`, ...base };
	}
	if (location.kind === 'stack') {
		return { kind: 'stack-slot', identity: `call:${callsite}:arg:${ordinal}:stack:${location.offsetBytes}`, ...base };
	}
	return { kind: 'ssa', identity: `call:${callsite}:arg:${ordinal}:${location.kind}`, ...base };
}

function returnValue(functionId: string, callsite: string, prototype: CanonicalFunctionPrototype): PropagationValueRef {
	const abi = getABIModel(prototype.callingConventionId);
	return {
		kind: 'register',
		identity: `call:${callsite}:return:${abi.returns.integer[0] ?? 'unknown'}`,
		functionIdentity: functionId,
		typeId: prototype.returnTypeId,
	};
}

type OutgoingReferenceIndex = ReadonlyMap<string, readonly CanonicalReferenceEdge[]>;

function codeEdges(outgoing: OutgoingReferenceIndex, functionId: string): CanonicalReferenceEdge[] {
	return [...(outgoing.get(functionId) ?? [])]
		.filter(edge => edge.family === 'code')
		.filter(edge => ['code-call-near', 'code-call-far', 'code-tail-call', 'code-indirect-resolved', 'code-indirect-candidate'].includes(edge.relation))
		.sort((left, right) => compareAscii(left.edgeId, right.edgeId));
}

function instructionAt(fn: Function, address: string): Instruction | undefined {
	const parsed = Number.parseInt(address.slice(2), 16);
	return fn.instructions.find(instruction => instruction.address === parsed);
}

function callEffects(
	fn: Function,
	functionId: string,
	outgoing: OutgoingReferenceIndex,
	store: SemanticStore,
	generation: number,
): { calls: CallEffect[]; constraints: PropagationConstraint[]; seeds: PropagationSeedFact[]; barriers: FunctionSummaryInput['barriers'] } {
	const byCallsite = new Map<string, CanonicalReferenceEdge[]>();
	for (const edge of codeEdges(outgoing, functionId)) {
		const list = byCallsite.get(edge.source.address) ?? [];
		list.push(edge);
		byCallsite.set(edge.source.address, list);
	}
	const calls: CallEffect[] = [];
	const constraints: PropagationConstraint[] = [];
	const seeds: PropagationSeedFact[] = [];
	const barriers: SummaryBarrier[] = [];
	const coveredSites = new Set<string>();
	for (const [callsite, edges] of [...byCallsite].sort(([left], [right]) => compareAscii(left, right))) {
		const uniqueTargets = [...new Set(edges.map(edge => edge.target.identity))].sort(compareAscii);
		const resolved = edges.find(edge => edge.relation !== 'code-indirect-candidate') ?? edges[0];
		const calleeIdentity = uniqueTargets.length === 1 ? uniqueTargets[0] : `unknown-callee:${callsite}`;
		const prototype = store.getPrototype(calleeIdentity)
			?? (resolved.target.address ? store.getPrototypeAtAddress(resolved.target.address) : undefined);
		const arguments_ = prototype?.parameters.map(parameter => ({
			ordinal: parameter.ordinal,
			argument: callsiteValue(functionId, callsite, parameter.ordinal, parameter.location, parameter.typeId, parameter.abiSizeBits),
		})) ?? [];
		for (const argument of arguments_) {
			const parameter = prototype!.parameters.find(item => item.ordinal === argument.ordinal)!;
			seeds.push({ value: argument.argument, typeId: parameter.typeId, evidence: prototype!.evidence });
		}
		const effect: CallEffect = {
			callsiteIdentity: `callsite:${callsite}`,
			calleeIdentity,
			arguments: arguments_,
			...(prototype ? { result: returnValue(functionId, callsite, prototype) } : {}),
			...(uniqueTargets.length > 1 ? { indirectCandidates: uniqueTargets } : {}),
		};
		calls.push(effect);
		constraints.push({ id: `call:${callsite}`, kind: 'call', call: effect, evidence: resolved.evidence });
		coveredSites.add(callsite);
	}
	for (const instruction of fn.instructions) {
		if (!(instruction.isCall || (instruction.isJump && instruction.targetAddress === undefined))) { continue; }
		const address = toHex(instruction.address);
		if (coveredSites.has(address)) { continue; }
		barriers.push({
			identity: `unresolved-indirect:${address}`,
			reason: `No qualified R33 reference edge for ${instruction.mnemonic} ${instruction.opStr}`.trim(),
			lossy: true,
		});
		constraints.push({ id: `barrier:${address}`, kind: 'barrier', reason: 'unresolved-indirect-target', values: [], lossy: true, evidence: derivedEvidence(generation) });
	}
	return { calls, constraints, seeds, barriers };
}

function globalEffects(fn: Function, functionId: string, outgoing: OutgoingReferenceIndex, generation: number): {
	effects: GlobalEffect[];
	constraints: PropagationConstraint[];
} {
	const effects: GlobalEffect[] = [];
	const constraints: PropagationConstraint[] = [];
	const edges = [...(outgoing.get(functionId) ?? [])]
		.filter(edge => edge.family === 'data')
		.filter(edge => edge.target.kind === 'global' && ['data-read', 'data-write', 'data-read-write'].includes(edge.relation));
	for (const edge of edges.sort((left, right) => compareAscii(left.edgeId, right.edgeId))) {
		const instruction = instructionAt(fn, edge.source.address);
		if (!instruction) { continue; }
		const access = edge.relation === 'data-read' ? 'read' : edge.relation === 'data-write' ? 'write' : 'read-write';
		const value: PropagationValueRef = {
			kind: 'memory-region', identity: `access:${edge.source.address}:operand:${edge.source.operandIndex}`,
			functionIdentity: functionId, widthBits: edge.accessWidthBits ?? undefined,
		};
		effects.push({ globalIdentity: edge.target.identity, access, value });
		if (access === 'read' || access === 'read-write') {
			constraints.push({ id: `global-read:${edge.edgeId}`, kind: 'global-read', globalIdentity: edge.target.identity, to: value, evidence: edge.evidence });
		}
		if (access === 'write' || access === 'read-write') {
			constraints.push({ id: `global-write:${edge.edgeId}`, kind: 'global-write', globalIdentity: edge.target.identity, from: value, evidence: edge.evidence });
		}
	}
	return { effects, constraints };
}

function fieldEffects(
	engine: DisassemblerEngine,
	fn: Function,
	functionId: string,
	prototype: CanonicalFunctionPrototype | undefined,
	generation: number,
): { effects: FieldAccessEffect[]; constraints: PropagationConstraint[] } {
	if (!prototype) { return { effects: [], constraints: [] }; }
	const registerParameters = new Map<string, CanonicalFunctionParameter>();
	for (const parameter of prototype.parameters) {
		if (parameter.location.kind !== 'register') { continue; }
		for (const register of parameter.location.registers) { registerParameters.set(register.toLowerCase(), parameter); }
	}
	const effects: FieldAccessEffect[] = [];
	const constraints: PropagationConstraint[] = [];
	for (const instruction of fn.instructions) {
		const operands = instruction.detail?.x86?.operands;
		if (!operands) { continue; }
		for (let operandIndex = 0; operandIndex < operands.length; operandIndex++) {
			const operand = operands[operandIndex];
			if (operand.type !== 3 || !operand.mem || operand.mem.base === 0 || (operand.mem.index ?? 0) !== 0 || (operand.mem.segment ?? 0) !== 0) { continue; }
			const baseRegister = engine.getRegisterName(operand.mem.base)?.toLowerCase();
			const parameter = baseRegister ? registerParameters.get(baseRegister) : undefined;
			if (!parameter || !Number.isSafeInteger(operand.mem.disp)) { continue; }
			const base = parameterValue(functionId, parameter);
			const widthBits = Number.isSafeInteger(operand.size) && operand.size > 0 ? operand.size * 8 : undefined;
			const addressOnly = instruction.mnemonic.toLowerCase() === 'lea';
			const access = addressOnly ? 'address'
				: (operand.access & 1) !== 0 && (operand.access & 2) !== 0 ? 'read-write'
					: (operand.access & 2) !== 0 ? 'write'
						: (operand.access & 1) !== 0 ? 'read' : undefined;
			if (!access || (!addressOnly && widthBits === undefined)) { continue; }
			const fieldIdentity = `${functionId}:parameter:${parameter.ordinal}:offset:${operand.mem.disp}`;
			const value: PropagationValueRef = {
				kind: addressOnly ? 'field' : 'memory-region',
				identity: `field-access:${toHex(instruction.address)}:operand:${operandIndex}`,
				functionIdentity: functionId,
				...(widthBits ? { widthBits } : {}),
			};
			const field: FieldAccessEffect = {
				fieldIdentity, base, offsetBytes: operand.mem.disp, access,
				value,
			};
			effects.push(field);
			const evidence = derivedEvidence(generation);
			if (addressOnly) {
				constraints.push({ id: `field-address:${toHex(instruction.address)}:${operandIndex}`, kind: 'base-offset', base, to: value, offsetBytes: operand.mem.disp, fieldIdentity, evidence });
			} else {
				if (access === 'read' || access === 'read-write') {
					constraints.push({ id: `field-read:${toHex(instruction.address)}:${operandIndex}`, kind: 'field-read', field, to: value, evidence });
				}
				if (access === 'write' || access === 'read-write') {
					constraints.push({ id: `field-write:${toHex(instruction.address)}:${operandIndex}`, kind: 'field-write', field, from: value, evidence });
				}
			}
		}
	}
	return { effects, constraints };
}

export function collectWholeProgramPropagationInputs(engine: DisassemblerEngine, store: SemanticStore): PropagationInputCollection {
	const generation = engine.getAnalysisGeneration();
	const graph = store.getReferenceGraph();
	const outgoing = new Map<string, CanonicalReferenceEdge[]>();
	for (const edge of graph.query({ includeInvalidated: false })) {
		const indexed = outgoing.get(edge.source.ownerFunctionIdentity) ?? [];
		indexed.push(edge);
		outgoing.set(edge.source.ownerFunctionIdentity, indexed);
	}
	const functions = engine.getFunctions().sort((left, right) => left.address - right.address);
	const incompleteFunctions = functions
		.filter(fn => engine.getFunctionBodyStatus(fn.address) === 'partial')
		.map(fn => functionIdentity(fn.address))
		.sort(compareAscii);
	const materialized = functions.filter(fn => engine.getFunctionBodyStatus(fn.address) === 'materialized');
	const inputs: FunctionSummaryInput[] = [];
	let barrierCount = 0;
	for (const fn of materialized) {
		const identity = functionIdentity(fn.address);
		const prototype = store.getPrototype(identity) ?? store.getPrototypeAtAddress(toHex(fn.address));
		const parameters: ParameterEffect[] = [];
		const seeds: PropagationSeedFact[] = [];
		if (prototype) {
			for (const parameter of prototype.parameters) {
				const value = parameterValue(identity, parameter);
				parameters.push({
					ordinal: parameter.ordinal, value,
					reads: parameter.direction === 'in' || parameter.direction === 'inout',
					writes: parameter.direction === 'out' || parameter.direction === 'inout',
					escapes: parameter.ownership === 'transfer',
				});
				seeds.push({ value, typeId: parameter.typeId, evidence: prototype.evidence });
			}
			seeds.push({
				value: { kind: 'return', identity: 'return', functionIdentity: identity, typeId: prototype.returnTypeId },
				typeId: prototype.returnTypeId,
				evidence: prototype.evidence,
			});
		}
		const call = callEffects(fn, identity, outgoing, store, generation);
		const globals = globalEffects(fn, identity, outgoing, generation);
		const fields = fieldEffects(engine, fn, identity, prototype, generation);
		barrierCount += call.barriers?.length ?? 0;
		inputs.push({
			analysisTargetIdentity: store.targetIdentity,
			functionIdentity: identity,
			functionBodySha256: bodyHash(fn),
			generation,
			materialized: true,
			parameters,
			calls: call.calls,
			globalEffects: globals.effects,
			fieldAccesses: fields.effects,
			barriers: call.barriers,
			seedFacts: [...seeds, ...call.seeds],
			constraints: [...call.constraints, ...globals.constraints, ...fields.constraints],
		});
	}
	const partialReasons = [
		...(engine.isAnalysisComplete() ? [] : ['analysis-not-complete']),
		...incompleteFunctions.map(identity => `incomplete-function-body:${identity}`),
	];
	const logical = {
		status: partialReasons.length === 0 ? 'ok' as const : 'partial' as const,
		analysisGeneration: generation,
		analysisComplete: engine.isAnalysisComplete(),
		functionsAvailable: functions.length,
		functionsMaterialized: materialized.length,
		incompleteFunctions,
		inputs: inputs.sort((left, right) => compareAscii(left.functionIdentity, right.functionIdentity)),
		barrierCount,
		partialReasons,
	};
	return Object.freeze({ ...logical, collectionHash: sha256(canonicalSerialize(logical)) });
}

export function syncWholeProgramPropagation(
	engine: DisassemblerEngine,
	options: Omit<PropagationSolveOptions, 'generation'> = {},
): PropagationSyncResult {
	const session = engine.getSessionStore();
	if (!session) { throw new Error('Whole-program propagation requires a bound HXDB analysis session.'); }
	const references = syncTypedReferenceGraph(engine);
	const store = session.getSemanticStore();
	const collection = collectWholeProgramPropagationInputs(engine, store);
	const propagationStore = store.getWholeProgramPropagationStore();
	const incompleteSet = new Set(collection.incompleteFunctions);
	const incompleteSummariesInvalidated = propagationStore.invalidateCurrentSummaries(
		propagationStore.listSummaries().map(item => item.functionIdentity).filter(identity => incompleteSet.has(identity)),
		collection.analysisGeneration,
		'Function body became incomplete and display-only.',
	);
	const solver = new WholeProgramPropagationEngine(store);
	const run = solver.solve(collection.inputs, { ...options, generation: collection.analysisGeneration });
	return Object.freeze({ references, collection, run, incompleteSummariesInvalidated });
}

export async function syncWholeProgramPropagationIsolated(
	engine: DisassemblerEngine,
	options: Omit<PropagationSolveOptions, 'generation'> = {},
): Promise<PropagationSyncResult> {
	const session = engine.getSessionStore();
	if (!session) { throw new Error('Whole-program propagation requires a bound HXDB analysis session.'); }
	const referenceStartedAt = Date.now();
	const references = syncTypedReferenceGraph(engine);
	const referenceSyncMs = Date.now() - referenceStartedAt;
	const store = session.getSemanticStore();
	const collectionStartedAt = Date.now();
	const collection = collectWholeProgramPropagationInputs(engine, store);
	const collectionMs = Date.now() - collectionStartedAt;
	const propagationStore = store.getWholeProgramPropagationStore();
	const incompleteSet = new Set(collection.incompleteFunctions);
	const invalidationStartedAt = Date.now();
	const incompleteSummariesInvalidated = propagationStore.invalidateCurrentSummaries(
		propagationStore.listSummaries().map(item => item.functionIdentity).filter(identity => incompleteSet.has(identity)),
		collection.analysisGeneration,
		'Function body became incomplete and display-only.',
	);
	const invalidationMs = Date.now() - invalidationStartedAt;
	const outcome = await runPropagationInWorker(store, collection.inputs, {
		...options,
		generation: collection.analysisGeneration,
	});
	return Object.freeze({
		references,
		collection,
		run: outcome.run,
		incompleteSummariesInvalidated,
		worker: outcome.diagnostics,
		preparation: { referenceSyncMs, collectionMs, invalidationMs },
	});
}
