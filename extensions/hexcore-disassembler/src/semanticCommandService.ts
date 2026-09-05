/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Akasha Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as crypto from 'crypto';
import {
	SemanticTypeCatalog,
	canonicalSerialize,
	canonicalizeFunctionPrototype,
	canonicalizeSemanticType,
	getABIModel,
	type ABIModel,
	type CallingConventionId,
	type CanonicalFunctionParameter,
	type CanonicalFunctionPrototype,
	type CanonicalSemanticType,
	type CanonicalTypeBinding,
	type FunctionParameterSpec,
	type FunctionPrototypeSpec,
	type LegacyCTypeOptions,
	type ParameterLocation,
	type SemanticEvidence,
} from './semanticModel';
import type { SessionStore } from './sessionStore';
import type {
	SemanticSnapshot,
	SemanticStoredConflict,
	SemanticStoredGeneration,
	SemanticStore,
} from './semanticStore';

export const SEMANTIC_COMMAND_EXPORT_SCHEMA_VERSION = 1 as const;

export type SemanticTypeReference =
	| string
	| { typeId: string }
	| { cType: string };

export interface SemanticPrototypeParameterInput extends Omit<FunctionParameterSpec, 'typeId' | 'location'> {
	type: SemanticTypeReference;
	location?: ParameterLocation;
}

export interface SemanticParameterPatch extends Partial<Omit<FunctionParameterSpec, 'ordinal' | 'typeId' | 'location'>> {
	type?: SemanticTypeReference;
	location?: ParameterLocation;
}

export interface ApplyPrototypeRequest {
	functionIdentity: string;
	functionAddress?: string;
	returnType: SemanticTypeReference;
	callingConventionId: CallingConventionId;
	parameters: readonly SemanticPrototypeParameterInput[];
	variadic?: boolean;
	noreturn?: boolean;
	method?: boolean;
	staticMethod?: boolean;
	hiddenReturn?: FunctionPrototypeSpec['hiddenReturn'];
	hiddenStorage?: FunctionPrototypeSpec['hiddenStorage'];
	evidence?: SemanticEvidence;
}

export interface SetCallingConventionRequest {
	functionIdentity: string;
	callingConventionId: CallingConventionId;
	locationPolicy?: 'preserve' | 'infer';
	evidence?: SemanticEvidence;
}

export interface SetParameterRequest {
	functionIdentity: string;
	ordinal: number;
	parameter: SemanticParameterPatch;
	reassignLocations?: boolean;
	evidence?: SemanticEvidence;
}

export interface ClearOverrideRequest {
	functionIdentity: string;
}

export interface ExplainPrototypeRequest {
	functionIdentity: string;
}

export interface SemanticLocationInference {
	ordinal: number;
	location: ParameterLocation;
	valueClass: 'integer' | 'floating' | 'vector';
	reason: string;
}

export interface SemanticCommandChangeEvent {
	command: 'applyPrototype' | 'setCallingConvention' | 'setParameter' | 'clearOverride' | 'import';
	targetIdentity: string;
	functionIdentity: string;
	previousPrototypeHash?: string;
	prototypeHash?: string;
	evidenceGeneration: number;
	transactionHash: string;
}

export interface SemanticCommandCallbacks {
	onGeneration?: (event: SemanticCommandChangeEvent) => void;
	onInvalidate?: (event: SemanticCommandChangeEvent) => void;
	onPropagateConsumers?: (event: SemanticCommandChangeEvent) => void;
}

export interface SemanticCommandServiceOptions {
	producer?: string;
	typeNamespace?: string;
	legacyCTypeOptions?: LegacyCTypeOptions;
	callbacks?: SemanticCommandCallbacks;
	/** Bulk providers may defer the expensive full-store hash until their final envelope. */
	computeStoreHash?: boolean;
}

export interface SemanticCallbackFailure {
	callback: keyof SemanticCommandCallbacks;
	message: string;
}

export interface SemanticMutationResult {
	ok: true;
	command: SemanticCommandChangeEvent['command'];
	changed: boolean;
	prototype: CanonicalFunctionPrototype;
	status: string;
	transactionHash: string;
	storeHash: string;
	inferredLocations: readonly SemanticLocationInference[];
	conflicts: readonly SemanticStoredConflict[];
	callbackFailures: readonly SemanticCallbackFailure[];
	propagationComplete: boolean;
}

export interface ClearOverrideChangedResult {
	ok: true;
	command: 'clearOverride';
	status: 'restored' | 'removed';
	changed: true;
	previousPrototype: CanonicalFunctionPrototype;
	prototype?: CanonicalFunctionPrototype;
	transactionHash: string;
	storeHash: string;
	conflicts: readonly SemanticStoredConflict[];
	generations: readonly SemanticStoredGeneration[];
	callbackFailures: readonly SemanticCallbackFailure[];
	propagationComplete: boolean;
}

export interface ClearOverrideNoopResult {
	ok: true;
	command: 'clearOverride';
	status: 'no-override';
	changed: false;
	reason: string;
}

export type ClearOverrideResult = ClearOverrideChangedResult | ClearOverrideNoopResult;

export interface ExplainedParameter {
	parameter: CanonicalFunctionParameter;
	type?: CanonicalSemanticType;
	locationSource: 'stored-explicit-or-inferred';
}

export interface PrototypeExplanation {
	ok: true;
	command: 'explainPrototype';
	targetIdentity: string;
	prototype: CanonicalFunctionPrototype;
	returnType?: CanonicalSemanticType;
	parameters: readonly ExplainedParameter[];
	abi: ABIModel;
	conflicts: readonly SemanticStoredConflict[];
	generations: readonly SemanticStoredGeneration[];
	dependencies: ReturnType<SemanticStore['listDependencies']>;
	storeHash: string;
}

export interface SemanticCommandExportPayload {
	schemaVersion: typeof SEMANTIC_COMMAND_EXPORT_SCHEMA_VERSION;
	targetIdentity: string;
	types: readonly CanonicalSemanticType[];
	prototypes: readonly CanonicalFunctionPrototype[];
	typeBindings: readonly CanonicalTypeBinding[];
}

export interface SemanticCommandExportEnvelope {
	format: 'hexcore-semantic-command-export';
	contentHash: string;
	payload: SemanticCommandExportPayload;
}

export interface SemanticImportResult {
	ok: true;
	command: 'import';
	contentHash: string;
	storeHash: string;
	transactionHash: string;
	typeCount: number;
	prototypeCount: number;
	bindingCount: number;
	changedPrototypeCount: number;
	callbackFailures: readonly SemanticCallbackFailure[];
	propagationComplete: boolean;
}

type SemanticSessionAccess = Pick<SessionStore, 'getSemanticStore'>;

interface ResolvedTypeReference {
	type: CanonicalSemanticType;
	types: readonly CanonicalSemanticType[];
}

interface ParameterDraft extends Omit<FunctionParameterSpec, 'typeId' | 'location'> {
	typeId: string;
	location?: ParameterLocation;
}

interface AllocatedParameters {
	parameters: FunctionParameterSpec[];
	inferences: SemanticLocationInference[];
}

function sha256(value: string): string {
	return crypto.createHash('sha256').update(value).digest('hex');
}

function compareAscii(left: string, right: string): number {
	return left < right ? -1 : left > right ? 1 : 0;
}

function requireIdentity(value: string, label: string): string {
	const normalized = value.trim().toLowerCase();
	if (!normalized) {
		throw new Error(`${label} must not be empty.`);
	}
	return normalized;
}

function requireOrdinal(value: number): number {
	if (!Number.isSafeInteger(value) || value < 0) {
		throw new Error('Parameter ordinal must be a non-negative safe integer.');
	}
	return value;
}

function alignUp(value: number, alignment: number): number {
	return Math.ceil(value / alignment) * alignment;
}

function isTypeId(value: string): boolean {
	return /^type:[a-z0-9][a-z0-9:._-]*$/i.test(value.trim());
}

function typeReferenceText(reference: SemanticTypeReference): { kind: 'type-id' | 'c-type'; value: string } {
	if (typeof reference === 'string') {
		const value = reference.trim();
		if (!value) { throw new Error('Type reference must not be empty.'); }
		return { kind: isTypeId(value) ? 'type-id' : 'c-type', value };
	}
	if ('typeId' in reference) {
		const value = reference.typeId.trim();
		if (!isTypeId(value)) { throw new Error(`Invalid semantic type ID: ${value || '<empty>'}`); }
		return { kind: 'type-id', value };
	}
	const value = reference.cType.trim();
	if (!value) { throw new Error('C type declaration must not be empty.'); }
	return { kind: 'c-type', value };
}

function prototypeProjection(prototype: CanonicalFunctionPrototype): unknown {
	return {
		targetIdentity: prototype.targetIdentity,
		functionIdentity: prototype.functionIdentity,
		functionAddress: prototype.functionAddress,
		returnTypeId: prototype.returnTypeId,
		callingConventionId: prototype.callingConventionId,
		parameters: prototype.parameters.map(parameter => ({
			ordinal: parameter.ordinal,
			parameterId: parameter.parameterId,
			stableIdentity: parameter.stableIdentity,
			stableIdentityAliases: parameter.stableIdentityAliases,
			abiValueClass: parameter.abiValueClass,
			abiSizeBits: parameter.abiSizeBits,
			abiAlignBits: parameter.abiAlignBits,
			name: parameter.name,
			typeId: parameter.typeId,
			location: parameter.location,
			direction: parameter.direction,
			optional: parameter.optional,
			nullable: parameter.nullable,
			buffer: parameter.buffer,
			ownership: parameter.ownership,
			lifetime: parameter.lifetime,
			hiddenThis: parameter.hiddenThis,
			hiddenSret: parameter.hiddenSret,
			compilerGenerated: parameter.compilerGenerated,
		})),
		variadic: prototype.variadic,
		noreturn: prototype.noreturn,
		method: prototype.method,
		staticMethod: prototype.staticMethod,
		hiddenReturn: prototype.hiddenReturn,
		hiddenStorage: prototype.hiddenStorage,
	};
}

function prototypeSemanticallyEqual(
	left: CanonicalFunctionPrototype | undefined,
	right: CanonicalFunctionPrototype,
): boolean {
	return left !== undefined
		&& canonicalSerialize(prototypeProjection(left)) === canonicalSerialize(prototypeProjection(right));
}

function storedFactConflicts(store: SemanticStore, functionIdentity: string): SemanticStoredConflict[] {
	return store.listConflicts()
		.filter(conflict => conflict.factKind === 'prototype' && conflict.factKey === functionIdentity)
		.sort((left, right) => compareAscii(left.conflictHash, right.conflictHash));
}

function storedFactGenerations(store: SemanticStore, functionIdentity: string): SemanticStoredGeneration[] {
	return store.listGenerations()
		.filter(generation => generation.factKind === 'prototype' && generation.factKey === functionIdentity)
		.sort((left, right) => compareAscii(left.generationHash, right.generationHash));
}

/**
 * Deterministic command surface for the persistent R32 prototype model.
 *
 * It intentionally delegates arbitration and provenance retention to SemanticStore. Consumer
 * recomputation is surfaced through callbacks because the store does not own the caller graph.
 */
export class SemanticCommandService {
	private readonly store: SemanticStore;
	private readonly producer: string;
	private readonly typeNamespace: string;
	private readonly legacyCTypeOptions: LegacyCTypeOptions;
	private readonly callbacks: SemanticCommandCallbacks;
	private readonly computeStoreHash: boolean;

	constructor(sessionStore: SemanticSessionAccess, options: SemanticCommandServiceOptions = {}) {
		this.store = sessionStore.getSemanticStore();
		this.producer = options.producer?.trim() || 'semantic-command-service:r32';
		this.typeNamespace = options.typeNamespace?.trim() || 'analyst-prototypes';
		this.legacyCTypeOptions = { ...options.legacyCTypeOptions };
		this.callbacks = { ...options.callbacks };
		this.computeStoreHash = options.computeStoreHash !== false;
	}

	applyPrototype(request: ApplyPrototypeRequest): SemanticMutationResult {
		const functionIdentity = requireIdentity(request.functionIdentity, 'Function identity');
		const current = this.store.getPrototype(functionIdentity);
		const provisionalEvidence = this.resolveEvidence(request.evidence, current, false);
		const catalog = new SemanticTypeCatalog(this.store.targetIdentity, this.typeNamespace);
		const effectiveConvention = this.effectiveConvention(request.callingConventionId, request.variadic === true);
		const returnType = this.resolveType(request.returnType, provisionalEvidence, catalog, effectiveConvention);
		const resolvedTypes = new Map<string, CanonicalSemanticType>();
		for (const type of returnType.types) { resolvedTypes.set(type.typeId, type); }
		const drafts = request.parameters.map(parameter => {
			const resolved = this.resolveType(parameter.type, provisionalEvidence, catalog, effectiveConvention);
			for (const type of resolved.types) { resolvedTypes.set(type.typeId, type); }
			const { type: _type, ...rest } = parameter;
			return { ...rest, typeId: resolved.type.typeId } as ParameterDraft;
		});
		const allocated = this.allocateParameterLocations(
			drafts,
			effectiveConvention,
			request.variadic === true,
			resolvedTypes,
		);
		let prototype = canonicalizeFunctionPrototype({
			targetIdentity: this.store.targetIdentity,
			functionIdentity,
			functionAddress: requireIdentity(request.functionAddress ?? functionIdentity, 'Function address'),
			returnTypeId: returnType.type.typeId,
			callingConventionId: request.callingConventionId,
			parameters: allocated.parameters,
			variadic: request.variadic ?? false,
			noreturn: request.noreturn ?? false,
			method: request.method ?? false,
			staticMethod: request.staticMethod ?? false,
			...(request.hiddenReturn ? { hiddenReturn: request.hiddenReturn } : {}),
			...(request.hiddenStorage ? { hiddenStorage: request.hiddenStorage } : {}),
			evidence: provisionalEvidence,
			corroboratingEvidence: current?.evidenceSet ?? [],
		});
		const changed = !prototypeSemanticallyEqual(current, prototype);
		if (changed && request.evidence === undefined) {
			const finalEvidence = this.resolveEvidence(undefined, current, true);
			prototype = canonicalizeFunctionPrototype({
				...prototype,
				evidence: finalEvidence,
				corroboratingEvidence: current?.evidenceSet ?? [],
			});
			for (const [typeId, type] of resolvedTypes) {
				resolvedTypes.set(typeId, canonicalizeSemanticType(type, finalEvidence));
			}
		}
		return this.persistPrototype('applyPrototype', current, prototype, [...resolvedTypes.values()], allocated.inferences);
	}

	setCallingConvention(request: SetCallingConventionRequest): SemanticMutationResult {
		const functionIdentity = requireIdentity(request.functionIdentity, 'Function identity');
		const current = this.requirePrototype(functionIdentity);
		const requestedABI = getABIModel(request.callingConventionId);
		const locationPolicy = request.locationPolicy ?? (requestedABI.userDefined ? 'preserve' : 'infer');
		const provisionalEvidence = this.resolveEvidence(request.evidence, current, false);
		const effectiveConvention = this.effectiveConvention(request.callingConventionId, current.variadic);
		const drafts: ParameterDraft[] = current.parameters.map(parameter => ({
			...parameter,
			...(locationPolicy === 'infer' ? { location: undefined } : {}),
		}));
		const allocated = this.allocateParameterLocations(
			drafts,
			effectiveConvention,
			current.variadic,
			new Map(),
		);
		let prototype = canonicalizeFunctionPrototype({
			...current,
			callingConventionId: request.callingConventionId,
			parameters: allocated.parameters,
			evidence: provisionalEvidence,
			corroboratingEvidence: current.evidenceSet,
		});
		const changed = !prototypeSemanticallyEqual(current, prototype);
		if (changed && request.evidence === undefined) {
			prototype = canonicalizeFunctionPrototype({
				...prototype,
				evidence: this.resolveEvidence(undefined, current, true),
				corroboratingEvidence: current.evidenceSet,
			});
		}
		return this.persistPrototype('setCallingConvention', current, prototype, [], allocated.inferences);
	}

	setParameter(request: SetParameterRequest): SemanticMutationResult {
		const functionIdentity = requireIdentity(request.functionIdentity, 'Function identity');
		const ordinal = requireOrdinal(request.ordinal);
		const current = this.requirePrototype(functionIdentity);
		const existing = current.parameters.find(parameter => parameter.ordinal === ordinal);
		if (!existing && (!request.parameter.name || !request.parameter.type)) {
			throw new Error(`New parameter ${ordinal} requires both name and type.`);
		}
		const provisionalEvidence = this.resolveEvidence(request.evidence, current, false);
		const catalog = new SemanticTypeCatalog(this.store.targetIdentity, this.typeNamespace);
		let newTypes: CanonicalSemanticType[] = [];
		let typeId = existing?.typeId;
		if (request.parameter.type !== undefined) {
			const resolved = this.resolveType(
				request.parameter.type,
				provisionalEvidence,
				catalog,
				current.callingConventionId,
			);
			typeId = resolved.type.typeId;
			newTypes.push(...resolved.types);
		}
		if (!typeId) { throw new Error(`Parameter ${ordinal} has no semantic type.`); }
		const { type: _type, ...patch } = request.parameter;
		const base: ParameterDraft = existing
			? { ...existing }
			: { ordinal, name: request.parameter.name!, typeId };
		const replacement: ParameterDraft = {
			...base,
			...patch,
			ordinal,
			typeId,
			...(request.reassignLocations ? { location: undefined } : {}),
		};
		const drafts: ParameterDraft[] = [
			...current.parameters.filter(parameter => parameter.ordinal !== ordinal).map(parameter => ({
				...parameter,
				...(request.reassignLocations ? { location: undefined } : {}),
			})),
			replacement,
		].sort((left, right) => left.ordinal - right.ordinal);
		const allocated = this.allocateParameterLocations(
			drafts,
			current.callingConventionId,
			current.variadic,
			new Map(newTypes.map(type => [type.typeId, type])),
		);
		let prototype = canonicalizeFunctionPrototype({
			...current,
			parameters: allocated.parameters,
			evidence: provisionalEvidence,
			corroboratingEvidence: current.evidenceSet,
		});
		const changed = !prototypeSemanticallyEqual(current, prototype);
		if (changed && request.evidence === undefined) {
			const finalEvidence = this.resolveEvidence(undefined, current, true);
			prototype = canonicalizeFunctionPrototype({
				...prototype,
				evidence: finalEvidence,
				corroboratingEvidence: current.evidenceSet,
			});
			newTypes = newTypes.map(type => canonicalizeSemanticType(type, finalEvidence));
		}
		return this.persistPrototype('setParameter', current, prototype, newTypes, allocated.inferences);
	}

	clearOverride(request: ClearOverrideRequest): ClearOverrideResult {
		const functionIdentity = requireIdentity(request.functionIdentity, 'Function identity');
		const current = this.store.getPrototype(functionIdentity);
		if (!current || current.evidence.userDefined !== true) {
			return {
				ok: true,
				command: 'clearOverride',
				status: 'no-override',
				changed: false,
				reason: current ? 'The accepted prototype is not an analyst override.' : 'No accepted prototype exists.',
			};
		}
		const cleared = this.store.clearUserPrototypeOverride(functionIdentity);
		if (cleared.status === 'no-override' || !cleared.changed || !cleared.transactionHash || !cleared.previousPrototype) {
			throw new Error(`HXDB failed to clear the accepted override for ${functionIdentity}.`);
		}
		const evidenceGeneration = Math.max(
			current.evidence.generation,
			cleared.restoredPrototype?.evidence.generation ?? 0,
		) + 1;
		const callbackFailures = this.notifyCallbacks({
			command: 'clearOverride',
			targetIdentity: this.store.targetIdentity,
			functionIdentity,
			previousPrototypeHash: current.prototypeHash,
			...(cleared.restoredPrototype ? { prototypeHash: cleared.restoredPrototype.prototypeHash } : {}),
			evidenceGeneration,
			transactionHash: cleared.transactionHash,
		});
		return {
			ok: true,
			command: 'clearOverride',
			status: cleared.status,
			changed: true,
			previousPrototype: current,
			...(cleared.restoredPrototype ? { prototype: cleared.restoredPrototype } : {}),
			transactionHash: cleared.transactionHash,
			storeHash: this.computeStoreHash ? this.store.exportHash() : '',
			conflicts: storedFactConflicts(this.store, functionIdentity),
			generations: storedFactGenerations(this.store, functionIdentity),
			callbackFailures,
			propagationComplete: this.hasPropagationCallbacks() && callbackFailures.length === 0,
		};
	}

	explainPrototype(request: ExplainPrototypeRequest): PrototypeExplanation {
		const functionIdentity = requireIdentity(request.functionIdentity, 'Function identity');
		const prototype = this.requirePrototype(functionIdentity);
		return {
			ok: true,
			command: 'explainPrototype',
			targetIdentity: this.store.targetIdentity,
			prototype,
			returnType: this.store.getType(prototype.returnTypeId),
			parameters: prototype.parameters.map(parameter => ({
				parameter,
				type: this.store.getType(parameter.typeId),
				locationSource: 'stored-explicit-or-inferred',
			})),
			abi: getABIModel(prototype.callingConventionId),
			conflicts: storedFactConflicts(this.store, functionIdentity),
			generations: storedFactGenerations(this.store, functionIdentity),
			dependencies: this.store.listDependencies('prototype', functionIdentity),
			storeHash: this.store.exportHash(),
		};
	}

	export(): SemanticCommandExportEnvelope {
		const snapshot = this.store.exportSnapshot();
		const payload: SemanticCommandExportPayload = {
			schemaVersion: SEMANTIC_COMMAND_EXPORT_SCHEMA_VERSION,
			targetIdentity: snapshot.targetIdentity,
			types: snapshot.types,
			prototypes: snapshot.prototypes,
			typeBindings: snapshot.typeBindings,
		};
		return {
			format: 'hexcore-semantic-command-export',
			contentHash: sha256(canonicalSerialize(payload)),
			payload,
		};
	}

	exportCanonical(): string {
		return canonicalSerialize(this.export());
	}

	import(input: string | SemanticCommandExportEnvelope): SemanticImportResult {
		const envelope = typeof input === 'string'
			? JSON.parse(input) as SemanticCommandExportEnvelope
			: input;
		this.validateImportEnvelope(envelope);
		const before = new Map(this.store.listPrototypes().map(prototype => [prototype.functionIdentity, prototype]));
		const result = this.store.writeBatch({
			types: envelope.payload.types,
			prototypes: envelope.payload.prototypes,
			typeBindings: envelope.payload.typeBindings,
		});
		const callbackFailures: SemanticCallbackFailure[] = [];
		let changedPrototypeCount = 0;
		for (const prototype of this.store.listPrototypes()) {
			const previous = before.get(prototype.functionIdentity);
			if (prototypeSemanticallyEqual(previous, prototype)) { continue; }
			changedPrototypeCount++;
			callbackFailures.push(...this.notifyCallbacks({
				command: 'import',
				targetIdentity: this.store.targetIdentity,
				functionIdentity: prototype.functionIdentity,
				...(previous ? { previousPrototypeHash: previous.prototypeHash } : {}),
				prototypeHash: prototype.prototypeHash,
				evidenceGeneration: prototype.evidence.generation,
				transactionHash: result.transactionHash,
			}));
		}
		return {
			ok: true,
			command: 'import',
			contentHash: envelope.contentHash,
			storeHash: this.store.exportHash(),
			transactionHash: result.transactionHash,
			typeCount: result.typeResults.length,
			prototypeCount: result.prototypeResults.length,
			bindingCount: result.bindingResults.length,
			changedPrototypeCount,
			callbackFailures,
			propagationComplete: changedPrototypeCount === 0
				|| (this.hasPropagationCallbacks() && callbackFailures.length === 0),
		};
	}

	private requirePrototype(functionIdentity: string): CanonicalFunctionPrototype {
		const prototype = this.store.getPrototype(functionIdentity);
		if (!prototype) {
			throw new Error(`No semantic prototype exists for ${functionIdentity}.`);
		}
		return prototype;
	}

	private resolveEvidence(
		requested: SemanticEvidence | undefined,
		current: CanonicalFunctionPrototype | undefined,
		changed: boolean,
	): SemanticEvidence {
		if (requested) { return requested; }
		const currentGeneration = Math.max(0, ...(current?.evidenceSet ?? []).map(evidence => evidence.generation));
		const reuse = !changed && current?.evidence.userDefined === true && current.evidence.producer === this.producer;
		return reuse
			? current.evidence
			: {
				strength: 'definitive',
				source: 'analyst',
				producer: this.producer,
				generation: currentGeneration + (changed ? 1 : current ? 0 : 1),
				userDefined: true,
			};
	}

	private resolveType(
		reference: SemanticTypeReference,
		evidence: SemanticEvidence,
		catalog: SemanticTypeCatalog,
		callingConventionId: CallingConventionId,
	): ResolvedTypeReference {
		const parsed = typeReferenceText(reference);
		if (parsed.kind === 'type-id') {
			const type = this.store.getType(parsed.value);
			if (!type) { throw new Error(`Unknown semantic type ID: ${parsed.value}`); }
			return { type, types: [] };
		}
		const abi = getABIModel(callingConventionId);
		const pointerSizeBits: 32 | 64 = ['x86', 'arm'].includes(abi.architecture) ? 32 : 64;
		const result = catalog.parseLegacyCType(parsed.value, evidence, {
			...this.legacyCTypeOptions,
			pointerSizeBits,
			targetIdentity: this.store.targetIdentity,
			nominalScope: this.typeNamespace,
		});
		return { type: result.type, types: result.types };
	}

	private effectiveConvention(callingConventionId: CallingConventionId, variadic: boolean): CallingConventionId {
		const abi = getABIModel(callingConventionId);
		if (variadic && !abi.variadic.supported) {
			if (!abi.variadic.fallbackConventionId) {
				throw new Error(`${callingConventionId} does not support variadic prototypes.`);
			}
			return abi.variadic.fallbackConventionId;
		}
		return callingConventionId;
	}

	private resolveStoredType(typeId: string, pendingTypes: ReadonlyMap<string, CanonicalSemanticType>): CanonicalSemanticType {
		const type = pendingTypes.get(typeId) ?? this.store.getType(typeId);
		if (!type) { throw new Error(`Parameter references unknown semantic type ID: ${typeId}`); }
		return type;
	}

	private unwrapType(
		type: CanonicalSemanticType,
		pendingTypes: ReadonlyMap<string, CanonicalSemanticType>,
		seen = new Set<string>(),
	): CanonicalSemanticType {
		if (seen.has(type.typeId)) { return type; }
		seen.add(type.typeId);
		if (['qualified', 'typedef'].includes(type.kind) && type.targetTypeId) {
			const target = pendingTypes.get(type.targetTypeId) ?? this.store.getType(type.targetTypeId);
			if (target) { return this.unwrapType(target, pendingTypes, seen); }
		}
		return type;
	}

	private classifyParameter(
		parameter: ParameterDraft,
		pendingTypes: ReadonlyMap<string, CanonicalSemanticType>,
		variadic: boolean,
		abi: ABIModel,
	): { valueClass: 'integer' | 'floating' | 'vector'; sizeBits: number; alignBits: number } {
		const stored = this.resolveStoredType(parameter.typeId, pendingTypes);
		const type = this.unwrapType(stored, pendingTypes);
		let valueClass = parameter.abiValueClass;
		if (valueClass === 'aggregate') {
			throw new Error(`ABI location for aggregate parameter ${parameter.ordinal} requires an explicit location or scalar ABI class.`);
		}
		if (!valueClass) {
			if (['integer', 'bool', 'enum', 'pointer', 'function'].includes(type.kind)) {
				valueClass = 'integer';
			} else if (type.kind === 'float') {
				valueClass = 'floating';
			} else if (type.kind === 'vector') {
				valueClass = 'vector';
			} else {
				throw new Error(`ABI location for ${type.kind} parameter ${parameter.ordinal} is indeterminate; provide an explicit location or abiValueClass.`);
			}
		}
		if (variadic && abi.variadic.floatingArgumentsUseIntegerBank && valueClass !== 'integer') {
			valueClass = 'integer';
		}
		const sizeBits = parameter.abiSizeBits ?? type.sizeBits ?? 0;
		const alignBits = parameter.abiAlignBits ?? type.alignBits ?? sizeBits;
		if (!Number.isSafeInteger(sizeBits) || sizeBits <= 0) {
			throw new Error(`ABI size for parameter ${parameter.ordinal} is unknown; provide abiSizeBits or an explicit location.`);
		}
		return { valueClass, sizeBits, alignBits: alignBits > 0 ? alignBits : sizeBits };
	}

	private allocateParameterLocations(
		drafts: readonly ParameterDraft[],
		callingConventionId: CallingConventionId,
		variadic: boolean,
		pendingTypes: ReadonlyMap<string, CanonicalSemanticType>,
	): AllocatedParameters {
		const abi = getABIModel(callingConventionId);
		const sorted = [...drafts].sort((left, right) => left.ordinal - right.ordinal);
		const seenOrdinals = new Set<number>();
		for (const parameter of sorted) {
			const ordinal = requireOrdinal(parameter.ordinal);
			if (seenOrdinals.has(ordinal)) { throw new Error(`Duplicate parameter ordinal ${ordinal}.`); }
			seenOrdinals.add(ordinal);
		}
		if (abi.userDefined && sorted.some(parameter => !parameter.location)) {
			throw new Error('usercall parameter locations are explicit; no ABI inference is available.');
		}

		const bankCursor = new Map<string, number>();
		const usedPhysicalUnits = new Set<string>();
		let stackCursor = abi.stack.argumentBaseBytes;
		const inferences: SemanticLocationInference[] = [];
		const parameters: FunctionParameterSpec[] = [];
		for (const draft of sorted) {
			if (draft.location) {
				this.observeExplicitLocation(draft.location, abi, bankCursor, usedPhysicalUnits);
				if (draft.location.kind === 'stack') {
					stackCursor = Math.max(stackCursor, draft.location.offsetBytes + (draft.location.sizeBytes ?? abi.stack.slotSizeBytes));
				}
				parameters.push({ ...draft, location: draft.location });
				continue;
			}

			const hiddenRole = draft.hiddenThis ? 'this' : draft.hiddenSret ? 'sret' : undefined;
			if (hiddenRole) {
				const register = hiddenRole === 'this'
					? abi.hiddenParameters.find(parameter => parameter.role === 'this')?.register
					: abi.aggregateReturn.hiddenPointerRegister;
				let location: ParameterLocation;
				if (register) {
					location = { kind: 'implicit', role: hiddenRole, register };
					this.observeExplicitLocation(location, abi, bankCursor, usedPhysicalUnits);
				} else {
					location = { kind: 'implicit', role: hiddenRole, stackOffsetBytes: stackCursor };
					stackCursor += abi.stack.slotSizeBytes;
				}
				parameters.push({ ...draft, location });
				inferences.push({ ordinal: draft.ordinal, location, valueClass: 'integer', reason: `${callingConventionId} hidden ${hiddenRole} contract` });
				continue;
			}

			const classification = this.classifyParameter(draft, pendingTypes, variadic, abi);
			let location: ParameterLocation | undefined;
			if (abi.argumentAllocation === 'shared-ordinal-slots') {
				const bankKind = classification.valueClass;
				const selectedKind = variadic && abi.variadic.floatingArgumentsUseIntegerBank ? 'integer' : bankKind;
				const bank = abi.argumentBanks.find(candidate => candidate.kind === selectedKind);
				const register = bank?.registers[draft.ordinal];
				if (register) { location = { kind: 'register', registers: [register] }; }
			} else if (abi.argumentAllocation === 'independent-register-banks') {
				const bank = abi.argumentBanks.find(candidate => candidate.kind === classification.valueClass);
				if (bank) {
					const bankKey = canonicalSerialize(bank.registers);
					const cursor = bankCursor.get(bankKey) ?? 0;
					const slotBits = abi.stack.slotSizeBytes * 8;
					const requiresCoreRegisterPairAlignment = abi.architecture === 'arm'
						&& classification.valueClass === 'integer'
						&& classification.alignBits > slotBits;
					const alignedCursor = requiresCoreRegisterPairAlignment
						? alignUp(cursor, Math.ceil(classification.alignBits / slotBits))
						: cursor;
					let registerIndex = alignedCursor;
					while (registerIndex < bank.registers.length
						&& this.registerPhysicalUnits(bank.registers[registerIndex]).some(unit => usedPhysicalUnits.has(unit))) {
						registerIndex++;
					}
					const register = bank.registers[registerIndex];
					if (register) {
						const capacityBits = this.registerCapacityBits(register, abi);
						if (capacityBits === undefined || classification.sizeBits <= capacityBits) {
							location = { kind: 'register', registers: [register] };
							bankCursor.set(bankKey, registerIndex + 1);
							for (const unit of this.registerPhysicalUnits(register)) { usedPhysicalUnits.add(unit); }
						} else if (abi.architecture === 'arm' && classification.valueClass === 'integer') {
							const registerCount = Math.ceil(classification.sizeBits / capacityBits);
							const splitRegisters = bank.registers.slice(registerIndex, registerIndex + registerCount);
							if (splitRegisters.length === registerCount
								&& splitRegisters.every(candidate => this.registerCapacityBits(candidate, abi) === capacityBits)
								&& splitRegisters.every(candidate => this.registerPhysicalUnits(candidate)
									.every(unit => !usedPhysicalUnits.has(unit)))) {
								location = {
									kind: 'split',
									parts: splitRegisters.map(candidate => ({ kind: 'register', registers: [candidate] })),
								};
								bankCursor.set(bankKey, registerIndex + registerCount);
								for (const candidate of splitRegisters) {
									for (const unit of this.registerPhysicalUnits(candidate)) { usedPhysicalUnits.add(unit); }
								}
							}
						}
					}
				}
			}

			if (!location) {
				const sizeBytes = Math.max(abi.stack.slotSizeBytes, Math.ceil(classification.sizeBits / 8));
				const alignmentBytes = Math.max(
					abi.stack.slotSizeBytes,
					Math.min(abi.stack.alignmentBytes, Math.ceil(classification.alignBits / 8)),
				);
				if (abi.argumentAllocation === 'shared-ordinal-slots') {
					const sharedSlots = Math.max(0, ...abi.argumentBanks.map(bank => bank.registers.length));
					stackCursor = Math.max(stackCursor, abi.stack.argumentBaseBytes + Math.max(0, draft.ordinal - sharedSlots) * abi.stack.slotSizeBytes);
				}
				stackCursor = alignUp(stackCursor, alignmentBytes);
				location = { kind: 'stack', base: 'entry-sp', offsetBytes: stackCursor, sizeBytes };
				stackCursor += alignUp(sizeBytes, abi.stack.slotSizeBytes);
			}
			parameters.push({
				...draft,
				abiValueClass: draft.abiValueClass ?? classification.valueClass,
				abiSizeBits: draft.abiSizeBits ?? classification.sizeBits,
				abiAlignBits: draft.abiAlignBits ?? classification.alignBits,
				location,
			});
			inferences.push({
				ordinal: draft.ordinal,
				location,
				valueClass: classification.valueClass,
				reason: `${callingConventionId} ${abi.argumentAllocation} allocation from canonical type ${draft.typeId}`,
			});
		}
		return { parameters, inferences };
	}

	private observeExplicitLocation(
		location: ParameterLocation,
		abi: ABIModel,
		bankCursor: Map<string, number>,
		usedPhysicalUnits: Set<string>,
	): void {
		const registers = location.kind === 'register'
			? location.registers
			: location.kind === 'split'
				? location.parts.flatMap(part => part.kind === 'register' ? part.registers : [])
				: location.kind === 'implicit' && location.register ? [location.register] : [];
		for (const register of registers) {
			const normalized = register.toLowerCase();
			for (const unit of this.registerPhysicalUnits(normalized)) { usedPhysicalUnits.add(unit); }
			for (const bank of abi.argumentBanks.filter(candidate => candidate.registers.includes(normalized))) {
				const bankKey = canonicalSerialize(bank.registers);
				bankCursor.set(bankKey, Math.max(bankCursor.get(bankKey) ?? 0, bank.registers.indexOf(normalized) + 1));
			}
		}
	}

	private registerPhysicalUnits(register: string): string[] {
		const normalized = register.toLowerCase();
		let match = /^(?:xmm|ymm|zmm)([0-9]+)$/.exec(normalized);
		if (match) { return [`x86-simd:${match[1]}`]; }
		match = /^s([0-9]+)$/.exec(normalized);
		if (match) { return [`arm-vfp-s:${Number(match[1])}`]; }
		match = /^d([0-9]+)$/.exec(normalized);
		if (match) {
			const start = Number(match[1]) * 2;
			return [`arm-vfp-s:${start}`, `arm-vfp-s:${start + 1}`];
		}
		match = /^q([0-9]+)$/.exec(normalized);
		if (match) {
			const start = Number(match[1]) * 4;
			return [0, 1, 2, 3].map(offset => `arm-vfp-s:${start + offset}`);
		}
		match = /^(?:v|q|d|s|h|b)([0-9]+)$/.exec(normalized);
		if (match) { return [`aarch64-v:${match[1]}`]; }
		return [`register:${normalized}`];
	}

	private registerCapacityBits(register: string, abi: ABIModel): number | undefined {
		const normalized = register.toLowerCase();
		if (/^(?:e(?:ax|bx|cx|dx|si|di|bp|sp)|r[0-9]+d)$/.test(normalized)) { return 32; }
		if (/^r[0-9]+$/.test(normalized)) { return abi.architecture === 'arm' ? 32 : 64; }
		if (/^(?:r(?:ax|bx|cx|dx|si|di|bp|sp)|x[0-9]+)$/.test(normalized)) { return 64; }
		if (/^s[0-9]+$/.test(normalized)) { return 32; }
		if (/^d[0-9]+$/.test(normalized)) { return 64; }
		if (/^(?:xmm[0-9]+|q[0-9]+|v[0-9]+)$/.test(normalized)) { return 128; }
		if (/^ymm[0-9]+$/.test(normalized)) { return 256; }
		if (/^zmm[0-9]+$/.test(normalized)) { return 512; }
		return undefined;
	}

	private persistPrototype(
		command: SemanticCommandChangeEvent['command'],
		previous: CanonicalFunctionPrototype | undefined,
		prototype: CanonicalFunctionPrototype,
		newTypes: readonly CanonicalSemanticType[],
		inferredLocations: readonly SemanticLocationInference[],
	): SemanticMutationResult {
		const deduplicatedTypes = [...new Map(newTypes.map(type => [type.typeId, type])).values()]
			.sort((left, right) => compareAscii(left.typeId, right.typeId));
		const result = this.store.writeBatch({ types: deduplicatedTypes, prototypes: [prototype] });
		const arbitration = result.prototypeResults[0];
		if (!arbitration) { throw new Error('SemanticStore returned no prototype arbitration result.'); }
		const accepted = arbitration.accepted;
		const changed = !prototypeSemanticallyEqual(previous, accepted);
		const callbackFailures = changed ? this.notifyCallbacks({
			command,
			targetIdentity: this.store.targetIdentity,
			functionIdentity: accepted.functionIdentity,
			...(previous ? { previousPrototypeHash: previous.prototypeHash } : {}),
			prototypeHash: accepted.prototypeHash,
			evidenceGeneration: accepted.evidence.generation,
			transactionHash: result.transactionHash,
		}) : [];
		return {
			ok: true,
			command,
			changed,
			prototype: accepted,
			status: arbitration.status,
			transactionHash: result.transactionHash,
			storeHash: this.computeStoreHash ? this.store.exportHash() : '',
			inferredLocations,
			conflicts: storedFactConflicts(this.store, accepted.functionIdentity),
			callbackFailures,
			propagationComplete: !changed || (this.hasPropagationCallbacks() && callbackFailures.length === 0),
		};
	}

	private hasPropagationCallbacks(): boolean {
		return Boolean(this.callbacks.onGeneration && this.callbacks.onInvalidate && this.callbacks.onPropagateConsumers);
	}

	private notifyCallbacks(event: SemanticCommandChangeEvent): SemanticCallbackFailure[] {
		const failures: SemanticCallbackFailure[] = [];
		const ordered: readonly (keyof SemanticCommandCallbacks)[] = ['onGeneration', 'onInvalidate', 'onPropagateConsumers'];
		for (const callbackName of ordered) {
			const callback = this.callbacks[callbackName];
			if (!callback) { continue; }
			try {
				callback(event);
			} catch (error) {
				failures.push({
					callback: callbackName,
					message: error instanceof Error ? error.message : String(error),
				});
			}
		}
		return failures;
	}

	private validateImportEnvelope(envelope: SemanticCommandExportEnvelope): void {
		if (!envelope || envelope.format !== 'hexcore-semantic-command-export') {
			throw new Error('Unsupported semantic import format.');
		}
		if (envelope.payload?.schemaVersion !== SEMANTIC_COMMAND_EXPORT_SCHEMA_VERSION) {
			throw new Error(`Unsupported semantic command export schema: ${String(envelope.payload?.schemaVersion)}`);
		}
		if (envelope.payload.targetIdentity !== this.store.targetIdentity) {
			throw new Error(`Semantic import target mismatch: expected ${this.store.targetIdentity}, received ${envelope.payload.targetIdentity}.`);
		}
		if (!Array.isArray(envelope.payload.types)
			|| !Array.isArray(envelope.payload.prototypes)
			|| !Array.isArray(envelope.payload.typeBindings)) {
			throw new Error('Semantic import payload arrays are missing.');
		}
		const actualHash = sha256(canonicalSerialize(envelope.payload));
		if (!/^[a-f0-9]{64}$/.test(envelope.contentHash) || actualHash !== envelope.contentHash) {
			throw new Error(`Semantic import content hash mismatch: expected ${envelope.contentHash}, computed ${actualHash}.`);
		}
		for (const prototype of envelope.payload.prototypes) {
			canonicalizeFunctionPrototype(prototype);
		}
	}
}
