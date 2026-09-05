/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Akasha Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as crypto from 'crypto';

export const SEMANTIC_SCHEMA_VERSION = 2 as const;

export type EvidenceStrength = 'guessed' | 'derived' | 'signature' | 'debug' | 'definitive';

export type EvidenceSource =
	| 'analyst'
	| 'debug-info'
	| 'import'
	| 'signature'
	| 'abi-recovery'
	| 'dataflow'
	| 'migration'
	| 'architecture-default'
	| 'compiler-metadata'
	| 'unknown';

export interface EvidenceCalibration {
	corpus: string;
	corpusSha256?: string;
	positiveSamples: number;
	negativeSamples: number;
}

export interface SemanticEvidence {
	strength: EvidenceStrength;
	source: EvidenceSource;
	producer: string;
	generation: number;
	confidence?: number;
	calibration?: EvidenceCalibration;
	userDefined?: boolean;
}

export type SemanticTypeKind =
	| 'unknown'
	| 'void'
	| 'bool'
	| 'integer'
	| 'float'
	| 'pointer'
	| 'array'
	| 'vector'
	| 'function'
	| 'struct'
	| 'union'
	| 'enum'
	| 'typedef'
	| 'qualified'
	| 'opaque-c-declaration';

export interface TypeQualifiers {
	const?: boolean;
	volatile?: boolean;
	restrict?: boolean;
}

export interface SemanticTypeMemberSpec {
	name: string;
	typeId: string;
	bitOffset: number;
	bitSize?: number;
	arrayStrideBits?: number;
	anonymous?: boolean;
	nested?: boolean;
	bitfield?: boolean;
	evidence?: SemanticEvidence;
	evidenceSet?: readonly SemanticEvidence[];
}

export interface SemanticEnumMemberSpec {
	name: string;
	value: string | number | bigint;
	evidence?: SemanticEvidence;
	evidenceSet?: readonly SemanticEvidence[];
}

export interface SemanticTypeAliasSpec {
	name: string;
	targetTypeId: string;
	evidence?: SemanticEvidence;
	evidenceSet?: readonly SemanticEvidence[];
}

export interface SemanticFunctionTypeSpec {
	returnTypeId: string;
	parameterTypeIds: readonly string[];
	variadic?: boolean;
	callingConventionId?: CallingConventionId;
}

export interface SemanticTypeSpec extends TypeQualifiers {
	kind: SemanticTypeKind;
	name?: string;
	nominalIdentity?: string;
	incomplete?: boolean;
	sizeBits?: number;
	alignBits?: number;
	signed?: boolean;
	count?: number;
	targetTypeId?: string;
	members?: readonly SemanticTypeMemberSpec[];
	enumMembers?: readonly SemanticEnumMemberSpec[];
	aliases?: readonly SemanticTypeAliasSpec[];
	dependencies?: readonly string[];
	functionType?: SemanticFunctionTypeSpec;
	opaqueDeclaration?: string;
}

export interface CanonicalSemanticType extends SemanticTypeSpec {
	typeId: string;
	canonicalHash: string;
	canonicalSerialization: string;
	dependencies: readonly string[];
	evidence: SemanticEvidence;
	evidenceSet: readonly SemanticEvidence[];
}

export type ParameterDirection = 'in' | 'out' | 'inout';
export type ParameterOwnership = 'none' | 'borrow' | 'acquire' | 'release' | 'transfer' | 'retain';
export type ParameterLifetime = 'call' | 'caller' | 'callee' | 'heap' | 'static' | 'unknown';

export interface RegisterParameterLocation {
	kind: 'register';
	registers: readonly string[];
}

export interface StackParameterLocation {
	kind: 'stack';
	base: 'entry-sp' | 'frame-base';
	offsetBytes: number;
	sizeBytes?: number;
}

export interface SplitParameterLocation {
	kind: 'split';
	parts: readonly (RegisterParameterLocation | StackParameterLocation)[];
}

export interface ImplicitParameterLocation {
	kind: 'implicit';
	role: 'this' | 'sret' | 'varargs-metadata' | 'compiler-generated' | 'user-defined';
	register?: string;
	stackOffsetBytes?: number;
}

export type ParameterLocation =
	| RegisterParameterLocation
	| StackParameterLocation
	| SplitParameterLocation
	| ImplicitParameterLocation;

export interface BufferRelationship {
	kind: 'bytes' | 'elements' | 'nul-terminated';
	countParameterOrdinal?: number;
	fixedCount?: number;
}

export interface FunctionParameterSpec {
	ordinal: number;
	parameterId?: string;
	stableIdentity?: string;
	stableIdentityAliases?: readonly string[];
	abiValueClass?: 'integer' | 'floating' | 'vector' | 'aggregate';
	abiSizeBits?: number;
	abiAlignBits?: number;
	name: string;
	typeId: string;
	location: ParameterLocation;
	direction?: ParameterDirection;
	optional?: boolean;
	nullable?: boolean;
	buffer?: BufferRelationship;
	ownership?: ParameterOwnership;
	lifetime?: ParameterLifetime;
	hiddenThis?: boolean;
	hiddenSret?: boolean;
	compilerGenerated?: boolean;
}

export interface CanonicalFunctionParameter extends FunctionParameterSpec {
	parameterId: string;
	direction: ParameterDirection;
	optional: boolean;
	nullable: boolean;
	ownership: ParameterOwnership;
	lifetime: ParameterLifetime;
	hiddenThis: boolean;
	hiddenSret: boolean;
	compilerGenerated: boolean;
}

export interface HiddenReturnSemantics {
	kind: 'register' | 'sret-parameter' | 'split-registers' | 'memory';
	location?: ParameterLocation;
}

export interface HiddenStorageSemantics {
	parameterOrdinal: number;
	callerAllocated: boolean;
	calleeReturnsPointer: boolean;
}

export interface FunctionPrototypeSpec {
	targetIdentity: string;
	functionIdentity: string;
	functionAddress?: string;
	returnTypeId: string;
	callingConventionId: CallingConventionId;
	parameters: readonly FunctionParameterSpec[];
	variadic?: boolean;
	noreturn?: boolean;
	method?: boolean;
	staticMethod?: boolean;
	hiddenReturn?: HiddenReturnSemantics;
	hiddenStorage?: HiddenStorageSemantics;
	evidence: SemanticEvidence;
	corroboratingEvidence?: readonly SemanticEvidence[];
}

export interface CanonicalFunctionPrototype extends Omit<FunctionPrototypeSpec, 'parameters' | 'evidence'> {
	prototypeId: string;
	prototypeHash: string;
	canonicalHash: string;
	canonicalSerialization: string;
	parameters: readonly CanonicalFunctionParameter[];
	variadic: boolean;
	noreturn: boolean;
	method: boolean;
	staticMethod: boolean;
	evidence: SemanticEvidence;
	evidenceSet: readonly SemanticEvidence[];
}

export type TypeBindingScope =
	| 'function-parameter'
	| 'local'
	| 'stack-slot'
	| 'register-value'
	| 'ssa-value'
	| 'global'
	| 'memory-region'
	| 'struct-field'
	| 'return-value';

export interface TypeBindingSpec {
	targetIdentity: string;
	scope: TypeBindingScope;
	valueIdentity: string;
	functionIdentity?: string;
	typeId: string;
	invalidationDependencies?: readonly string[];
	evidence: SemanticEvidence;
	corroboratingEvidence?: readonly SemanticEvidence[];
}

export interface CanonicalTypeBinding extends TypeBindingSpec {
	bindingId: string;
	canonicalHash: string;
	canonicalSerialization: string;
	invalidationDependencies: readonly string[];
	evidence: SemanticEvidence;
	evidenceSet: readonly SemanticEvidence[];
}

export type PrototypeRecoveryObservationKind =
	| 'register-read-before-definition'
	| 'entry-stack-read'
	| 'ret-immediate'
	| 'caller-stack-adjustment'
	| 'callsite-argument-write'
	| 'caller-return-register-use'
	| 'this-pattern'
	| 'debug-prototype'
	| 'import-prototype'
	| 'signature-prototype'
	| 'caller-consensus';

export interface PrototypeRecoveryObservationSpec {
	targetIdentity: string;
	functionIdentity: string;
	kind: PrototypeRecoveryObservationKind;
	atAddress?: string;
	callsiteAddress?: string;
	callerIdentity?: string;
	register?: string;
	stackOffsetBytes?: number;
	byteCount?: number;
	parameterOrdinal?: number;
	callerIdentities?: readonly string[];
	corroboratingObservationIds?: readonly string[];
	evidence: SemanticEvidence;
	corroboratingEvidence?: readonly SemanticEvidence[];
}

export interface CanonicalPrototypeRecoveryObservation extends PrototypeRecoveryObservationSpec {
	observationId: string;
	canonicalHash: string;
	canonicalSerialization: string;
	evidenceSet: readonly SemanticEvidence[];
}

export interface PrototypeRecoveryAssessment {
	targetIdentity: string;
	functionIdentity: string;
	prototype: CanonicalFunctionPrototype;
	observations: readonly CanonicalPrototypeRecoveryObservation[];
	callerConsensusCount: number;
	canonicalHash: string;
	canonicalSerialization: string;
}

export type CallingConventionId =
	| 'cdecl'
	| 'stdcall'
	| 'fastcall'
	| 'thiscall'
	| 'vectorcall'
	| 'usercall'
	| 'win64'
	| 'sysv64'
	| 'aapcs32'
	| 'aapcs64';

export type ABIArchitecture = 'x86' | 'x86_64' | 'arm' | 'aarch64' | 'user-defined';

export interface ABIArgumentBank {
	kind: 'integer' | 'floating' | 'vector';
	registers: readonly string[];
	allocation: 'left-to-right' | 'right-to-left';
}

export interface ABIStackContract {
	direction: 'down';
	argumentOrder: 'left-to-right' | 'right-to-left';
	argumentBaseBytes: number;
	slotSizeBytes: number;
	alignmentBytes: number;
	cleanup: 'caller' | 'callee' | 'convention-specific';
	shadowSpaceBytes: number;
	redZoneBytes: number;
}

export interface ABIReturnContract {
	integer: readonly string[];
	floating: readonly string[];
	vector: readonly string[];
	splitInteger?: readonly string[];
}

export interface ABIAggregateReturnContract {
	strategy: 'register-classification' | 'register-up-to-bits' | 'hidden-pointer' | 'user-defined';
	classifier?: 'x86-msvc' | 'win64' | 'sysv-eightbyte' | 'x86-vectorcall-hva' | 'aapcs32' | 'aapcs64';
	registerLimitBits?: number;
	registerSizesBits?: readonly number[];
	requiresTrivialAggregate?: boolean;
	hiddenPointerRegister?: string;
	hiddenPointerConsumesArgumentSlot: boolean;
	returnsHiddenPointer?: string;
}

export interface ABIVariadicContract {
	supported: boolean;
	fallbackConventionId?: CallingConventionId;
	floatingArgumentsUseIntegerBank?: boolean;
	floatingRegisterCountRegister?: string;
	requiresRegisterSaveArea?: boolean;
}

export interface ABIHiddenParameter {
	role: 'this' | 'sret' | 'varargs-metadata';
	register?: string;
	position: 'before-explicit' | 'convention-specific';
	shiftsExplicitArguments: boolean;
}

export interface ABIPartialRegisterPreservation {
	registers: readonly string[];
	preservedLowBits: number;
}

export interface ABIModel {
	id: CallingConventionId;
	displayName: string;
	architecture: ABIArchitecture;
	argumentAllocation: 'stack-only' | 'independent-register-banks' | 'shared-ordinal-slots' | 'explicit-usercall';
	argumentBanks: readonly ABIArgumentBank[];
	stack: ABIStackContract;
	returns: ABIReturnContract;
	aggregateReturn: ABIAggregateReturnContract;
	variadic: ABIVariadicContract;
	callerSaved: readonly string[];
	calleeSaved: readonly string[];
	partialCalleeSaved?: readonly ABIPartialRegisterPreservation[];
	platformSpecificRegisters?: readonly string[];
	hiddenParameters: readonly ABIHiddenParameter[];
	userDefined: boolean;
	canonicalHash: string;
}

export interface ResolvedABI {
	model: ABIModel;
	inferred: boolean;
	evidence: SemanticEvidence;
}

export interface SemanticConflict<T> {
	winner: T;
	loser: T;
	reason: 'stronger-evidence' | 'user-defined-override' | 'newer-peer' | 'calibrated-peer' | 'deterministic-peer';
}

export type ArbitrationStatus =
	| 'accepted-new'
	| 'equivalent-retained'
	| 'equivalent-updated'
	| 'replaced-stronger'
	| 'replaced-peer'
	| 'rejected-weaker'
	| 'rejected-peer';

export interface ArbitrationResult<T> {
	status: ArbitrationStatus;
	accepted: T;
	conflict?: SemanticConflict<T>;
}

const STRENGTH_RANK: Readonly<Record<EvidenceStrength, number>> = {
	guessed: 0,
	derived: 1,
	signature: 2,
	debug: 3,
	definitive: 4,
};

const EVIDENCE_SOURCES = new Set<EvidenceSource>([
	'analyst', 'debug-info', 'import', 'signature', 'abi-recovery', 'dataflow', 'migration',
	'architecture-default', 'compiler-metadata', 'unknown',
]);

const SEMANTIC_TYPE_KINDS = new Set<SemanticTypeKind>([
	'unknown', 'void', 'bool', 'integer', 'float', 'pointer', 'array', 'vector', 'function',
	'struct', 'union', 'enum', 'typedef', 'qualified', 'opaque-c-declaration',
]);

const TYPE_BINDING_SCOPES = new Set<TypeBindingScope>([
	'function-parameter', 'local', 'stack-slot', 'register-value', 'ssa-value', 'global',
	'memory-region', 'struct-field', 'return-value',
]);

function sha256(value: string): string {
	return crypto.createHash('sha256').update(value, 'utf8').digest('hex');
}

function canonicalJsonValue(value: unknown): unknown {
	if (value === undefined) {
		return undefined;
	}
	if (typeof value === 'bigint') {
		return value.toString(10);
	}
	if (typeof value === 'number') {
		if (!Number.isFinite(value)) {
			throw new Error('Canonical semantic values must be finite numbers.');
		}
		return Object.is(value, -0) ? 0 : value;
	}
	if (Array.isArray(value)) {
		return value.map(item => {
			const normalized = canonicalJsonValue(item);
			return normalized === undefined ? null : normalized;
		});
	}
	if (value !== null && typeof value === 'object') {
		const object = value as Record<string, unknown>;
		const normalized: Record<string, unknown> = {};
		for (const key of Object.keys(object).sort()) {
			const child = canonicalJsonValue(object[key]);
			if (child !== undefined) {
				normalized[key] = child;
			}
		}
		return normalized;
	}
	return value;
}

export function canonicalSerialize(value: unknown): string {
	return JSON.stringify(canonicalJsonValue(value));
}

function canonicalHash(value: unknown): string {
	return sha256(canonicalSerialize(value));
}

function stableStringCompare(left: string, right: string): number {
	return left < right ? -1 : left > right ? 1 : 0;
}

function requireNonEmpty(value: string, label: string): string {
	const normalized = value.trim();
	if (!normalized) {
		throw new Error(`${label} must not be empty.`);
	}
	return normalized;
}

function requireNonNegativeInteger(value: number, label: string): number {
	if (!Number.isSafeInteger(value) || value < 0) {
		throw new Error(`${label} must be a non-negative safe integer.`);
	}
	return value;
}

function requirePositiveInteger(value: number, label: string): number {
	if (!Number.isSafeInteger(value) || value <= 0) {
		throw new Error(`${label} must be a positive safe integer.`);
	}
	return value;
}

function assertOptionalBoolean(value: unknown, label: string): void {
	if (value !== undefined && typeof value !== 'boolean') {
		throw new Error(`${label} must be boolean when present.`);
	}
}

function normalizeConfidence(value: number | undefined, calibration: EvidenceCalibration | undefined): number | undefined {
	if (value === undefined) {
		return undefined;
	}
	if (!Number.isFinite(value) || value < 0 || value > 1) {
		throw new Error('Evidence confidence must be between 0 and 1.');
	}
	if (!calibration) {
		throw new Error('Evidence confidence requires explicit calibration metadata.');
	}
	return value;
}

export function normalizeSemanticEvidence(evidence: SemanticEvidence): SemanticEvidence {
	if (!(evidence.strength in STRENGTH_RANK)) {
		throw new Error(`Unknown evidence strength: ${String(evidence.strength)}`);
	}
	if (!EVIDENCE_SOURCES.has(evidence.source)) {
		throw new Error(`Unknown evidence source: ${String(evidence.source)}`);
	}
	assertOptionalBoolean(evidence.userDefined, 'Evidence userDefined');
	if (evidence.userDefined === true && (evidence.source !== 'analyst' || evidence.strength !== 'definitive')) {
		throw new Error('User-defined evidence must be definitive analyst evidence.');
	}
	const producer = requireNonEmpty(evidence.producer, 'Evidence producer');
	const generation = requireNonNegativeInteger(evidence.generation, 'Evidence generation');
	let calibration: EvidenceCalibration | undefined;
	if (evidence.calibration) {
		calibration = {
			corpus: requireNonEmpty(evidence.calibration.corpus, 'Calibration corpus'),
			...(evidence.calibration.corpusSha256
				? { corpusSha256: requireSha256(evidence.calibration.corpusSha256, 'Calibration corpus SHA-256') }
				: {}),
			positiveSamples: requireNonNegativeInteger(evidence.calibration.positiveSamples, 'Positive sample count'),
			negativeSamples: requireNonNegativeInteger(evidence.calibration.negativeSamples, 'Negative sample count'),
		};
		if (calibration.positiveSamples === 0 || calibration.negativeSamples === 0) {
			throw new Error('Evidence calibration requires at least one positive and one negative sample.');
		}
	}
	const confidence = normalizeConfidence(evidence.confidence, calibration);
	return deepFreeze({
		strength: evidence.strength,
		source: evidence.source,
		producer,
		generation,
		...(confidence !== undefined ? { confidence } : {}),
		...(calibration ? { calibration } : {}),
		...(evidence.userDefined === true ? { userDefined: true } : {}),
	});
}

function normalizeEvidenceSet(
	primary: SemanticEvidence,
	corroborating: readonly SemanticEvidence[] = [],
): readonly SemanticEvidence[] {
	const unique = new Map<string, SemanticEvidence>();
	for (const item of [primary, ...corroborating]) {
		const normalized = normalizeSemanticEvidence(item);
		unique.set(canonicalSerialize(normalized), normalized);
	}
	return deepFreeze([...unique.values()].sort((left, right) => {
		const preference = compareEvidence(right, left);
		return preference !== 0
			? preference
			: stableStringCompare(canonicalSerialize(left), canonicalSerialize(right));
	}));
}

function requireSha256(value: string, label: string): string {
	const normalized = value.trim().toLowerCase();
	if (!/^[a-f0-9]{64}$/.test(normalized)) {
		throw new Error(`${label} must contain exactly 64 hexadecimal characters.`);
	}
	return normalized;
}

function normalizeTypeId(typeId: string, label = 'Type ID'): string {
	return requireNonEmpty(typeId, label);
}

function normalizeQualifiers(spec: TypeQualifiers): Required<TypeQualifiers> {
	assertOptionalBoolean(spec.const, 'const qualifier');
	assertOptionalBoolean(spec.volatile, 'volatile qualifier');
	assertOptionalBoolean(spec.restrict, 'restrict qualifier');
	return deepFreeze({
		const: spec.const === true,
		volatile: spec.volatile === true,
		restrict: spec.restrict === true,
	});
}

function normalizeIntegerText(value: string | number | bigint, label: string): string {
	if (typeof value === 'bigint') {
		return value.toString(10);
	}
	if (typeof value === 'number') {
		if (!Number.isSafeInteger(value)) {
			throw new Error(`${label} must be a safe integer or an exact decimal string.`);
		}
		return value.toString(10);
	}
	const normalized = value.trim();
	if (!/^[+-]?(?:0|[1-9][0-9]*)$/.test(normalized)) {
		throw new Error(`${label} must be an exact decimal integer.`);
	}
	return BigInt(normalized).toString(10);
}

function normalizeTypeMember(member: SemanticTypeMemberSpec, fallbackEvidence: SemanticEvidence): SemanticTypeMemberSpec {
	const name = member.name.trim();
	if (!name && member.anonymous !== true) {
		throw new Error('Named type members must not have an empty name.');
	}
	assertOptionalBoolean(member.anonymous, 'Member anonymous flag');
	assertOptionalBoolean(member.nested, 'Member nested flag');
	assertOptionalBoolean(member.bitfield, 'Member bitfield flag');
	const evidenceSet = normalizeEvidenceSet(member.evidence ?? fallbackEvidence, member.evidenceSet);
	return {
		name,
		typeId: normalizeTypeId(member.typeId, 'Member type ID'),
		bitOffset: requireNonNegativeInteger(member.bitOffset, 'Member bit offset'),
		...(member.bitSize !== undefined ? { bitSize: requirePositiveInteger(member.bitSize, 'Member bit size') } : {}),
		...(member.arrayStrideBits !== undefined
			? { arrayStrideBits: requirePositiveInteger(member.arrayStrideBits, 'Member array stride') }
			: {}),
		...(member.anonymous === true ? { anonymous: true } : {}),
		...(member.nested === true ? { nested: true } : {}),
		...(member.bitfield === true ? { bitfield: true } : {}),
		evidence: evidenceSet[0],
		evidenceSet,
	};
}

function normalizeEnumMember(member: SemanticEnumMemberSpec, fallbackEvidence: SemanticEvidence): SemanticEnumMemberSpec {
	const evidenceSet = normalizeEvidenceSet(member.evidence ?? fallbackEvidence, member.evidenceSet);
	return {
		name: requireNonEmpty(member.name, 'Enum member name'),
		value: normalizeIntegerText(member.value, 'Enum member value'),
		evidence: evidenceSet[0],
		evidenceSet,
	};
}

function normalizeTypeAlias(member: SemanticTypeAliasSpec, fallbackEvidence: SemanticEvidence): SemanticTypeAliasSpec {
	const evidenceSet = normalizeEvidenceSet(member.evidence ?? fallbackEvidence, member.evidenceSet);
	return {
		name: requireNonEmpty(member.name, 'Type alias name'),
		targetTypeId: normalizeTypeId(member.targetTypeId),
		evidence: evidenceSet[0],
		evidenceSet,
	};
}

function validateTypeShape(spec: SemanticTypeSpec): void {
	if (!SEMANTIC_TYPE_KINDS.has(spec.kind)) {
		throw new Error(`Unknown semantic type kind: ${String(spec.kind)}`);
	}
	if (spec.sizeBits !== undefined) {
		requireNonNegativeInteger(spec.sizeBits, 'Type size');
	}
	assertOptionalBoolean(spec.signed, 'Type signed flag');
	assertOptionalBoolean(spec.incomplete, 'Type incomplete flag');
	if (spec.alignBits !== undefined) {
		requirePositiveInteger(spec.alignBits, 'Type alignment');
	}
	if (['pointer', 'array', 'vector', 'typedef', 'qualified'].includes(spec.kind) && !spec.targetTypeId) {
		throw new Error(`${spec.kind} types require targetTypeId.`);
	}
	if (['array', 'vector'].includes(spec.kind)) {
		requirePositiveInteger(spec.count ?? 0, `${spec.kind} element count`);
	}
	if (spec.kind === 'function' && !spec.functionType) {
		throw new Error('function types require functionType metadata.');
	}
	if (spec.kind === 'opaque-c-declaration' && !spec.opaqueDeclaration?.trim()) {
		throw new Error('opaque-c-declaration types require the original declaration.');
	}
	if (spec.kind !== 'opaque-c-declaration' && spec.opaqueDeclaration !== undefined) {
		throw new Error('opaqueDeclaration is only valid for opaque-c-declaration types.');
	}
	if (spec.targetTypeId !== undefined && !['pointer', 'array', 'vector', 'typedef', 'qualified'].includes(spec.kind)) {
		throw new Error(`targetTypeId is not valid for ${spec.kind} types.`);
	}
	if (spec.count !== undefined && !['array', 'vector'].includes(spec.kind)) {
		throw new Error(`count is not valid for ${spec.kind} types.`);
	}
	if (spec.members !== undefined && !['struct', 'union'].includes(spec.kind)) {
		throw new Error(`members are not valid for ${spec.kind} types.`);
	}
	if (spec.enumMembers !== undefined && spec.kind !== 'enum') {
		throw new Error(`enumMembers are not valid for ${spec.kind} types.`);
	}
	if (spec.functionType !== undefined && spec.kind !== 'function') {
		throw new Error(`functionType is not valid for ${spec.kind} types.`);
	}
	if (spec.signed !== undefined && !['integer', 'enum'].includes(spec.kind)) {
		throw new Error(`signed is not valid for ${spec.kind} types.`);
	}
	if (spec.nominalIdentity !== undefined && !['struct', 'union', 'enum'].includes(spec.kind)) {
		throw new Error(`nominalIdentity is not valid for ${spec.kind} types.`);
	}
	if (spec.nominalIdentity !== undefined && !spec.nominalIdentity.trim()) {
		throw new Error('Nominal types require a stable identity.');
	}
	if (spec.incomplete !== undefined && !['struct', 'union', 'enum'].includes(spec.kind)) {
		throw new Error(`incomplete is not valid for ${spec.kind} types.`);
	}
}

export function canonicalizeSemanticType(
	spec: SemanticTypeSpec,
	evidence: SemanticEvidence,
): CanonicalSemanticType {
	validateTypeShape(spec);
	const normalizedEvidence = normalizeSemanticEvidence(evidence);
	const evidenceSet = normalizeEvidenceSet(normalizedEvidence);
	const qualifiers = normalizeQualifiers(spec);
	const members = (spec.members ?? [])
		.map(member => normalizeTypeMember(member, normalizedEvidence))
		.sort((left, right) => left.bitOffset - right.bitOffset || stableStringCompare(left.name, right.name));
	const enumMembers = (spec.enumMembers ?? [])
		.map(member => normalizeEnumMember(member, normalizedEvidence))
		.sort((left, right) => stableStringCompare(left.name, right.name)
			|| stableStringCompare(String(left.value), String(right.value)));
	const aliases = (spec.aliases ?? [])
		.map(alias => normalizeTypeAlias(alias, normalizedEvidence))
		.sort((left, right) => stableStringCompare(left.name, right.name) || stableStringCompare(left.targetTypeId, right.targetTypeId));
	if (spec.functionType) {
		assertOptionalBoolean(spec.functionType.variadic, 'Function type variadic flag');
	}
	const functionType = spec.functionType ? {
		returnTypeId: normalizeTypeId(spec.functionType.returnTypeId, 'Function return type ID'),
		parameterTypeIds: spec.functionType.parameterTypeIds.map((typeId, index) => normalizeTypeId(typeId, `Parameter ${index} type ID`)),
		variadic: spec.functionType.variadic === true,
		...(spec.functionType.callingConventionId ? { callingConventionId: normalizeCallingConventionId(spec.functionType.callingConventionId) } : {}),
	} : undefined;
	const dependencies = new Set<string>((spec.dependencies ?? []).map(item => normalizeTypeId(item, 'Type dependency')));
	if (spec.targetTypeId) { dependencies.add(normalizeTypeId(spec.targetTypeId)); }
	for (const member of members) { dependencies.add(member.typeId); }
	for (const alias of aliases) { dependencies.add(alias.targetTypeId); }
	if (functionType) {
		dependencies.add(functionType.returnTypeId);
		for (const parameterTypeId of functionType.parameterTypeIds) { dependencies.add(parameterTypeId); }
	}

	const payload = {
		schemaVersion: SEMANTIC_SCHEMA_VERSION,
		kind: spec.kind,
		...(spec.name?.trim() ? { name: spec.name.trim() } : {}),
		...(spec.nominalIdentity ? { nominalIdentity: requireNonEmpty(spec.nominalIdentity, 'Nominal type identity') } : {}),
		...(spec.incomplete === true ? { incomplete: true } : {}),
		...(spec.sizeBits !== undefined ? { sizeBits: spec.sizeBits } : {}),
		...(spec.alignBits !== undefined ? { alignBits: spec.alignBits } : {}),
		...(spec.signed !== undefined ? { signed: spec.signed } : {}),
		...(spec.count !== undefined ? { count: spec.count } : {}),
		...(spec.targetTypeId ? { targetTypeId: normalizeTypeId(spec.targetTypeId) } : {}),
		qualifiers,
		...(members.length > 0 ? { members: members.map(({ evidence: _evidence, evidenceSet: _set, ...member }) => member) } : {}),
		...(enumMembers.length > 0 ? { enumMembers: enumMembers.map(({ evidence: _evidence, evidenceSet: _set, ...member }) => member) } : {}),
		...(aliases.length > 0 ? { aliases: aliases.map(({ evidence: _evidence, evidenceSet: _set, ...alias }) => alias) } : {}),
		...(dependencies.size > 0 ? { dependencies: [...dependencies].sort() } : {}),
		...(functionType ? { functionType } : {}),
		...(spec.opaqueDeclaration ? { opaqueDeclaration: normalizeOpaqueDeclaration(spec.opaqueDeclaration) } : {}),
	};
	const serialization = canonicalSerialize(payload);
	const hash = sha256(serialization);
	const typeId = spec.nominalIdentity
		? `type:nominal:sha256:${canonicalHash({
			schemaVersion: SEMANTIC_SCHEMA_VERSION,
			kind: spec.kind,
			nominalIdentity: requireNonEmpty(spec.nominalIdentity, 'Nominal type identity'),
		})}`
		: `type:sha256:${hash}`;
	return deepFreeze({
		kind: spec.kind,
		...(spec.name?.trim() ? { name: spec.name.trim() } : {}),
		...(spec.nominalIdentity ? { nominalIdentity: requireNonEmpty(spec.nominalIdentity, 'Nominal type identity') } : {}),
		...(spec.incomplete === true ? { incomplete: true } : {}),
		...(spec.sizeBits !== undefined ? { sizeBits: spec.sizeBits } : {}),
		...(spec.alignBits !== undefined ? { alignBits: spec.alignBits } : {}),
		...(spec.signed !== undefined ? { signed: spec.signed } : {}),
		...(spec.count !== undefined ? { count: spec.count } : {}),
		...(spec.targetTypeId ? { targetTypeId: normalizeTypeId(spec.targetTypeId) } : {}),
		...qualifiers,
		...(members.length > 0 ? { members } : {}),
		...(enumMembers.length > 0 ? { enumMembers } : {}),
		...(aliases.length > 0 ? { aliases } : {}),
		dependencies: [...dependencies].sort(),
		...(functionType ? { functionType } : {}),
		...(spec.opaqueDeclaration ? { opaqueDeclaration: normalizeOpaqueDeclaration(spec.opaqueDeclaration) } : {}),
		typeId,
		canonicalHash: hash,
		canonicalSerialization: serialization,
		evidence: normalizedEvidence,
		evidenceSet,
	});
}

function normalizeOpaqueDeclaration(declaration: string): string {
	return requireNonEmpty(declaration, 'Opaque C declaration')
		.replace(/\s+/g, ' ')
		.replace(/\s*\*\s*/g, ' * ')
		.replace(/\s*\[\s*/g, '[')
		.replace(/\s*\]\s*/g, ']')
		.trim();
}

export function createOpaqueCDeclaration(
	declaration: string,
	evidence: SemanticEvidence,
): CanonicalSemanticType {
	return canonicalizeSemanticType({
		kind: 'opaque-c-declaration',
		opaqueDeclaration: normalizeOpaqueDeclaration(declaration),
	}, evidence);
}

export interface LegacyCTypeOptions {
	pointerSizeBits?: 32 | 64;
	longSizeBits?: 32 | 64;
	wcharSizeBits?: 16 | 32;
	longDoubleSizeBits?: 64 | 80 | 128;
	targetIdentity?: string;
	nominalScope?: string;
}

export interface LegacyCTypeResult {
	status: 'parsed' | 'opaque';
	rootTypeId: string;
	type: CanonicalSemanticType;
	types: readonly CanonicalSemanticType[];
	reason?: string;
}

interface PrimitiveShape {
	kind: 'void' | 'bool' | 'integer' | 'float';
	sizeBits?: number;
	alignBits?: number;
	signed?: boolean;
	name?: string;
}

const QUALIFIER_TOKENS = new Set(['const', 'volatile', 'restrict', '__restrict', '__restrict__']);

function qualifierShape(tokens: readonly string[]): Required<TypeQualifiers> | undefined {
	const normalized = tokens.map(token => token.toLowerCase());
	if (normalized.some(token => !QUALIFIER_TOKENS.has(token))) {
		return undefined;
	}
	return {
		const: normalized.includes('const'),
		volatile: normalized.includes('volatile'),
		restrict: normalized.includes('restrict') || normalized.includes('__restrict') || normalized.includes('__restrict__'),
	};
}

type LegacyCDataModel = Required<Pick<
	LegacyCTypeOptions,
	'pointerSizeBits' | 'longSizeBits' | 'wcharSizeBits' | 'longDoubleSizeBits'
>>;

function primitiveShape(base: string, options: LegacyCDataModel): PrimitiveShape | undefined {
	const normalized = base.toLowerCase().replace(/\s+/g, ' ').trim();
	const integer = (sizeBits: number, signed: boolean, name?: string): PrimitiveShape => ({
		kind: 'integer', sizeBits, alignBits: Math.min(sizeBits, options.pointerSizeBits), signed, ...(name ? { name } : {}),
	});
	const shapes: Record<string, PrimitiveShape> = {
		'void': { kind: 'void', sizeBits: 0 },
		'_bool': { kind: 'bool', sizeBits: 8, alignBits: 8 },
		'bool': { kind: 'bool', sizeBits: 8, alignBits: 8 },
		'char': { kind: 'integer', sizeBits: 8, alignBits: 8, name: 'char' },
		'signed char': integer(8, true),
		'unsigned char': integer(8, false),
		'short': integer(16, true),
		'short int': integer(16, true),
		'signed short': integer(16, true),
		'signed short int': integer(16, true),
		'unsigned short': integer(16, false),
		'unsigned short int': integer(16, false),
		'int': integer(32, true),
		'signed': integer(32, true),
		'signed int': integer(32, true),
		'unsigned': integer(32, false),
		'unsigned int': integer(32, false),
		'long': integer(options.longSizeBits, true),
		'long int': integer(options.longSizeBits, true),
		'signed long': integer(options.longSizeBits, true),
		'signed long int': integer(options.longSizeBits, true),
		'unsigned long': integer(options.longSizeBits, false),
		'unsigned long int': integer(options.longSizeBits, false),
		'long long': integer(64, true),
		'long long int': integer(64, true),
		'signed long long': integer(64, true),
		'signed long long int': integer(64, true),
		'unsigned long long': integer(64, false),
		'unsigned long long int': integer(64, false),
		'__int8': integer(8, true),
		'unsigned __int8': integer(8, false),
		'__int16': integer(16, true),
		'unsigned __int16': integer(16, false),
		'__int32': integer(32, true),
		'unsigned __int32': integer(32, false),
		'__int64': integer(64, true),
		'unsigned __int64': integer(64, false),
		'int8_t': integer(8, true),
		'uint8_t': integer(8, false),
		'int16_t': integer(16, true),
		'uint16_t': integer(16, false),
		'int32_t': integer(32, true),
		'uint32_t': integer(32, false),
		'int64_t': integer(64, true),
		'uint64_t': integer(64, false),
		'intptr_t': integer(options.pointerSizeBits, true),
		'uintptr_t': integer(options.pointerSizeBits, false),
		'size_t': integer(options.pointerSizeBits, false),
		'ssize_t': integer(options.pointerSizeBits, true),
		'wchar_t': integer(options.wcharSizeBits, false, 'wchar_t'),
		'float': { kind: 'float', sizeBits: 32, alignBits: 32 },
		'double': { kind: 'float', sizeBits: 64, alignBits: 64 },
		'long double': {
			kind: 'float',
			sizeBits: options.longDoubleSizeBits,
			alignBits: options.longDoubleSizeBits === 80 ? 128 : options.longDoubleSizeBits,
		},
	};
	return shapes[normalized];
}

interface LegacyAliasShape {
	name: string;
	target: PrimitiveShape | 'void-pointer' | 'const-void-pointer';
}

function legacyAliasShape(base: string, options: LegacyCDataModel): LegacyAliasShape | undefined {
	const name = base.trim();
	const key = name.toUpperCase();
	const integer = (sizeBits: number, signed: boolean): PrimitiveShape => ({ kind: 'integer', sizeBits, alignBits: Math.min(sizeBits, options.pointerSizeBits), signed });
	const aliases: Record<string, PrimitiveShape | 'void-pointer' | 'const-void-pointer'> = {
		BYTE: integer(8, false), BOOLEAN: integer(8, false), WORD: integer(16, false),
		DWORD: integer(32, false), QWORD: integer(64, false), BOOL: integer(32, true),
		CHAR: { kind: 'integer', sizeBits: 8, alignBits: 8, name: 'char' },
		WCHAR: integer(options.wcharSizeBits, false), SHORT: integer(16, true), USHORT: integer(16, false),
		LONG: integer(32, true), ULONG: integer(32, false), INT: integer(32, true), UINT: integer(32, false),
		INT64: integer(64, true), UINT64: integer(64, false), ULONG_PTR: integer(options.pointerSizeBits, false),
		LONG_PTR: integer(options.pointerSizeBits, true), DWORD_PTR: integer(options.pointerSizeBits, false),
		HANDLE: 'void-pointer', HMODULE: 'void-pointer', HWND: 'void-pointer', PVOID: 'void-pointer',
		LPVOID: 'void-pointer', LPCVOID: 'const-void-pointer',
	};
	const target = aliases[key];
	return target ? { name, target } : undefined;
}

export class SemanticTypeCatalog {
	private readonly types = new Map<string, CanonicalSemanticType>();
	private readonly conflictLog = new Map<string, SemanticConflict<CanonicalSemanticType>[]>();
	private readonly targetIdentity?: string;
	private readonly nominalScope?: string;

	constructor(targetIdentity?: string, nominalScope?: string) {
		this.targetIdentity = targetIdentity ? requireNonEmpty(targetIdentity, 'Type catalog target identity') : undefined;
		this.nominalScope = nominalScope ? requireNonEmpty(nominalScope, 'Type catalog nominal scope') : undefined;
	}

	intern(spec: SemanticTypeSpec, evidence: SemanticEvidence): CanonicalSemanticType {
		let candidate = canonicalizeSemanticType(spec, evidence);
		const inheritedEvidence = 'evidenceSet' in spec && Array.isArray(spec.evidenceSet)
			? spec.evidenceSet as readonly SemanticEvidence[]
			: [];
		if (inheritedEvidence.length > 0) {
			const evidenceSet = normalizeEvidenceSet(candidate.evidence, inheritedEvidence);
			candidate = deepFreeze({ ...candidate, evidence: evidenceSet[0], evidenceSet });
		}
		const current = this.types.get(candidate.typeId);
		if (!current) {
			this.types.set(candidate.typeId, candidate);
			return candidate;
		}
		let preferred: CanonicalSemanticType;
		if (current.incomplete === true && candidate.incomplete !== true) {
			preferred = mergeEvidenceBackedValue(candidate, current);
		} else if (current.incomplete !== true && candidate.incomplete === true) {
			preferred = mergeEvidenceBackedValue(current, candidate);
		} else if (current.canonicalHash === candidate.canonicalHash) {
			preferred = mergeCanonicalTypeEvidence(current, candidate);
		} else {
			const arbitration = arbitrateSemanticValue(current, candidate);
			preferred = arbitration.accepted;
			if (arbitration.conflict) {
				recordSemanticConflict(this.conflictLog, candidate.typeId, arbitration.conflict);
			}
		}
		this.types.set(candidate.typeId, preferred);
		return preferred;
	}

	forwardDeclare(
		kind: 'struct' | 'union' | 'enum',
		name: string,
		evidence: SemanticEvidence,
		originIdentity?: string,
	): CanonicalSemanticType {
		return this.intern({
			kind,
			name: requireNonEmpty(name, 'Forward type name'),
			nominalIdentity: this.nominalIdentity(kind, name, originIdentity),
			incomplete: true,
		}, evidence);
	}

	defineNominal(
		spec: Omit<SemanticTypeSpec, 'nominalIdentity' | 'incomplete'> & { kind: 'struct' | 'union' | 'enum' },
		evidence: SemanticEvidence,
		originIdentity?: string,
	): CanonicalSemanticType {
		if (!spec.name?.trim() && !originIdentity?.trim()) {
			throw new Error('Anonymous nominal definitions require an origin identity.');
		}
		return this.intern({
			...spec,
			...(spec.name?.trim() ? { name: spec.name.trim() } : {}),
			nominalIdentity: this.nominalIdentity(spec.kind, spec.name, originIdentity),
			incomplete: false,
		}, evidence);
	}

	forwardDeclareAnonymous(
		kind: 'struct' | 'union' | 'enum',
		originIdentity: string,
		evidence: SemanticEvidence,
	): CanonicalSemanticType {
		return this.intern({
			kind,
			nominalIdentity: this.nominalIdentity(kind, undefined, originIdentity),
			incomplete: true,
		}, evidence);
	}

	private nominalIdentity(kind: 'struct' | 'union' | 'enum', name?: string, originIdentity?: string): string {
		if (!this.targetIdentity || !this.nominalScope) {
			throw new Error('Nominal types require a target identity and a CU/PDB/analyst scope.');
		}
		return canonicalSerialize({
			targetIdentity: this.targetIdentity,
			nominalScope: this.nominalScope,
			kind,
			...(name?.trim() ? { name: name.trim() } : {}),
			...(originIdentity?.trim() ? { originIdentity: originIdentity.trim() } : {}),
		});
	}

	get(typeId: string): CanonicalSemanticType | undefined {
		return this.types.get(typeId);
	}

	conflicts(typeId: string): readonly SemanticConflict<CanonicalSemanticType>[] {
		return [...(this.conflictLog.get(typeId) ?? [])];
	}

	list(): CanonicalSemanticType[] {
		return [...this.types.values()].sort((left, right) => stableStringCompare(left.typeId, right.typeId));
	}

	parseLegacyCType(
		declaration: string,
		evidence: SemanticEvidence,
		options: LegacyCTypeOptions = {},
	): LegacyCTypeResult {
		const normalizedEvidence = normalizeSemanticEvidence(evidence);
		const normalizedOptions: LegacyCDataModel = {
			pointerSizeBits: options.pointerSizeBits ?? 64,
			longSizeBits: options.longSizeBits ?? 32,
			wcharSizeBits: options.wcharSizeBits ?? 16,
			longDoubleSizeBits: options.longDoubleSizeBits ?? 64,
		};
		const original = declaration.trim();
		const opaque = (reason: string): LegacyCTypeResult => {
			const type = this.intern({ kind: 'opaque-c-declaration', opaqueDeclaration: original || '<empty>' }, normalizedEvidence);
			return { status: 'opaque', rootTypeId: type.typeId, type, types: this.list(), reason };
		};
		if (options.targetIdentity !== undefined && options.targetIdentity.trim() !== this.targetIdentity) {
			throw new Error('Legacy type target identity does not match the catalog.');
		}
		if (options.nominalScope !== undefined && options.nominalScope.trim() !== this.nominalScope) {
			throw new Error('Legacy type nominal scope does not match the catalog.');
		}
		if (!original) {
			return opaque('empty declaration');
		}
		const explicitOpaque = /^opaque-c-declaration\s*:\s*(.+)$/i.exec(original);
		if (explicitOpaque) {
			return opaque('explicit opaque-c-declaration');
		}
		if (/[();{},]/.test(original)) {
			return opaque('unsupported C declarator syntax');
		}

		let core = original;
		const arrayCounts: number[] = [];
		while (true) {
			const array = /\[\s*([0-9]+)\s*\]\s*$/.exec(core);
			if (!array) { break; }
			const count = Number(array[1]);
			if (!Number.isSafeInteger(count) || count <= 0) {
				return opaque('invalid array bound');
			}
			arrayCounts.push(count);
			core = core.slice(0, array.index).trim();
		}
		if (core.includes('[') || core.includes(']')) {
			return opaque('unsupported or incomplete array declarator');
		}

		const pointerSegments = core.split('*');
		const baseTokens = pointerSegments.shift()?.trim().split(/\s+/).filter(Boolean) ?? [];
		const baseQualifierTokens = baseTokens.filter(token => QUALIFIER_TOKENS.has(token.toLowerCase()));
		const baseNameTokens = baseTokens.filter(token => !QUALIFIER_TOKENS.has(token.toLowerCase()));
		const baseQualifiers = qualifierShape(baseQualifierTokens);
		if (!baseQualifiers || baseNameTokens.length === 0) {
			return opaque('invalid base type');
		}

		const baseName = baseNameTokens.join(' ');
		let current: CanonicalSemanticType;
		const tagged = /^(struct|union|enum)\s+([A-Za-z_$][A-Za-z0-9_$]*)$/.exec(baseName);
		const primitive = primitiveShape(baseName, normalizedOptions);
		const alias = legacyAliasShape(baseName, normalizedOptions);
		if (tagged) {
			const kind = tagged[1] as 'struct' | 'union' | 'enum';
			try {
				current = this.forwardDeclare(kind, tagged[2], normalizedEvidence);
			} catch (error) {
				return opaque(error instanceof Error ? error.message : 'nominal identity unavailable');
			}
			if (baseQualifiers.const || baseQualifiers.volatile || baseQualifiers.restrict) {
				current = this.intern({ kind: 'qualified', targetTypeId: current.typeId, ...baseQualifiers }, normalizedEvidence);
			}
		} else if (primitive) {
			current = this.intern({ ...primitive, ...baseQualifiers }, normalizedEvidence);
		} else if (alias) {
			let target: CanonicalSemanticType;
			if (alias.target === 'void-pointer' || alias.target === 'const-void-pointer') {
				const voidType = this.intern({ kind: 'void', ...(alias.target === 'const-void-pointer' ? { const: true } : {}) }, normalizedEvidence);
				target = this.intern({ kind: 'pointer', targetTypeId: voidType.typeId, sizeBits: normalizedOptions.pointerSizeBits, alignBits: normalizedOptions.pointerSizeBits }, normalizedEvidence);
			} else {
				target = this.intern(alias.target, normalizedEvidence);
			}
			current = this.intern({ kind: 'typedef', name: alias.name, targetTypeId: target.typeId, ...baseQualifiers }, normalizedEvidence);
		} else {
			return opaque(`unrecognized base type: ${baseName}`);
		}

		for (const segment of pointerSegments) {
			const tokens = segment.trim() ? segment.trim().split(/\s+/) : [];
			const qualifiers = qualifierShape(tokens);
			if (!qualifiers) {
				return opaque('named or unsupported pointer declarator');
			}
			current = this.intern({
				kind: 'pointer',
				targetTypeId: current.typeId,
				sizeBits: normalizedOptions.pointerSizeBits,
				alignBits: normalizedOptions.pointerSizeBits,
				...qualifiers,
			}, normalizedEvidence);
		}
		for (const count of arrayCounts) {
			current = this.intern({
				kind: 'array',
				targetTypeId: current.typeId,
				count,
				sizeBits: current.sizeBits !== undefined ? current.sizeBits * count : undefined,
				alignBits: current.alignBits,
			}, normalizedEvidence);
		}

		return { status: 'parsed', rootTypeId: current.typeId, type: current, types: this.list() };
	}
}

export function parseLegacyCType(
	declaration: string,
	evidence: SemanticEvidence,
	options: LegacyCTypeOptions = {},
): LegacyCTypeResult {
	return new SemanticTypeCatalog(options.targetIdentity, options.nominalScope)
		.parseLegacyCType(declaration, evidence, options);
}

function normalizeRegister(register: string): string {
	return requireNonEmpty(register, 'Register name').toLowerCase();
}

function normalizeLocation(location: ParameterLocation): ParameterLocation {
	switch (location.kind) {
		case 'register': {
			const registers = [...new Set(location.registers.map(normalizeRegister))];
			if (registers.length === 0) { throw new Error('Register locations require at least one register.'); }
			return { kind: 'register', registers };
		}
		case 'stack':
			if (!['entry-sp', 'frame-base'].includes(location.base)) {
				throw new Error(`Unknown stack location base: ${String(location.base)}`);
			}
			if (!Number.isSafeInteger(location.offsetBytes)) { throw new Error('Stack offset must be a safe integer.'); }
			if (location.base === 'entry-sp' && location.offsetBytes < 0) {
				throw new Error('Entry-SP parameter offsets must not be negative.');
			}
			return {
				kind: 'stack', base: location.base, offsetBytes: location.offsetBytes,
				...(location.sizeBytes !== undefined ? { sizeBytes: requirePositiveInteger(location.sizeBytes, 'Stack location size') } : {}),
			};
		case 'split':
			if (location.parts.length < 2) { throw new Error('Split locations require at least two parts.'); }
			if (location.parts.some(part => !['register', 'stack'].includes((part as { kind?: string }).kind ?? ''))) {
				throw new Error('Split locations may contain only register or stack parts.');
			}
			return { kind: 'split', parts: location.parts.map(part => normalizeLocation(part) as RegisterParameterLocation | StackParameterLocation) };
		case 'implicit':
			if (!['this', 'sret', 'varargs-metadata', 'compiler-generated', 'user-defined'].includes(location.role)) {
				throw new Error(`Unknown implicit parameter role: ${String(location.role)}`);
			}
			if (location.stackOffsetBytes !== undefined && !Number.isSafeInteger(location.stackOffsetBytes)) {
				throw new Error('Implicit stack offset must be a safe integer.');
			}
			if (location.register !== undefined && location.stackOffsetBytes !== undefined) {
				throw new Error('Implicit locations cannot specify both register and stack storage.');
			}
			return {
				kind: 'implicit', role: location.role,
				...(location.register ? { register: normalizeRegister(location.register) } : {}),
				...(location.stackOffsetBytes !== undefined ? { stackOffsetBytes: location.stackOffsetBytes } : {}),
			};
		default:
			throw new Error(`Unknown parameter location kind: ${String((location as { kind?: unknown }).kind)}`);
	}
}

function hiddenParameterRole(parameter: FunctionParameterSpec): string {
	if (parameter.hiddenThis) { return 'this'; }
	if (parameter.hiddenSret) { return 'sret'; }
	if (parameter.compilerGenerated) { return 'compiler-generated'; }
	return 'explicit';
}

function canonicalParameterIdentity(
	targetIdentity: string,
	functionIdentity: string,
	anchor: string,
): string {
	return canonicalHash({ targetIdentity, functionIdentity, anchor });
}

function parameterLocationRegisters(location: ParameterLocation): string[] {
	switch (location.kind) {
		case 'register': return [...location.registers];
		case 'split': return location.parts.flatMap(parameterLocationRegisters);
		case 'implicit': return location.register ? [location.register] : [];
		case 'stack': return [];
	}
}

function isStackParameterLocation(location: ParameterLocation): boolean {
	return location.kind === 'stack'
		|| (location.kind === 'implicit' && location.stackOffsetBytes !== undefined && location.register === undefined);
}

function physicalRegisterUnits(register: string): string[] {
	let match = /^(?:xmm|ymm|zmm)([0-9]+)$/.exec(register);
	if (match) { return [`x86-simd:${match[1]}`]; }
	match = /^s([0-9]+)$/.exec(register);
	if (match) { return [`arm-vfp-s:${Number(match[1])}`]; }
	match = /^d([0-9]+)$/.exec(register);
	if (match) {
		const index = Number(match[1]) * 2;
		return [`arm-vfp-s:${index}`, `arm-vfp-s:${index + 1}`];
	}
	match = /^q([0-9]+)$/.exec(register);
	if (match) {
		const index = Number(match[1]) * 4;
		return [0, 1, 2, 3].map(offset => `arm-vfp-s:${index + offset}`);
	}
	match = /^(?:v|q|d|s|h|b)([0-9]+)$/.exec(register);
	if (match) { return [`aarch64-v:${match[1]}`]; }
	return [`register:${register}`];
}

function validateABIParameterLocations(
	callingConventionId: CallingConventionId,
	parameters: readonly CanonicalFunctionParameter[],
): void {
	const abi = getABIModel(callingConventionId);
	if (abi.userDefined) { return; }
	const usedRegisters = new Set<string>();
	const usedPhysicalUnits = new Set<string>();
	const bankPositions = new Map<string, number>();
	for (const parameter of parameters) {
		const registers = parameterLocationRegisters(parameter.location);
		if (registers.length === 0) { continue; }
		for (const register of registers) {
			if (usedRegisters.has(register)) {
				throw new Error(`${callingConventionId} register ${register} is assigned to multiple parameters.`);
			}
			usedRegisters.add(register);
			for (const unit of physicalRegisterUnits(register)) {
				if (usedPhysicalUnits.has(unit)) {
					throw new Error(`${callingConventionId} register ${register} aliases another parameter location.`);
				}
				usedPhysicalUnits.add(unit);
			}
		}
		if (abi.argumentAllocation === 'stack-only') {
			throw new Error(`${callingConventionId} parameter ${parameter.ordinal} cannot use a register location.`);
		}
		if (abi.argumentAllocation === 'shared-ordinal-slots') {
			const allowed = new Set(abi.argumentBanks
				.map(bank => bank.registers[parameter.ordinal])
				.filter((register): register is string => register !== undefined));
			if (registers.length !== 1 || !allowed.has(registers[0])) {
				throw new Error(
					`${callingConventionId} parameter ${parameter.ordinal} register location violates shared ordinal slots.`,
				);
			}
		} else {
			const hiddenExpected = parameter.hiddenThis
				? abi.hiddenParameters.find(hidden => hidden.role === 'this')?.register
				: parameter.hiddenSret ? abi.aggregateReturn.hiddenPointerRegister : undefined;
			for (const register of registers) {
				const bank = abi.argumentBanks.find(candidate => candidate.registers.includes(register));
				if (!bank) {
					if (register === hiddenExpected) { continue; }
					throw new Error(`${callingConventionId} parameter ${parameter.ordinal} uses a non-argument register.`);
				}
				const bankKey = canonicalSerialize(bank.registers);
				const index = bank.registers.indexOf(register);
				const previous = bankPositions.get(bankKey);
				const registerWidthBits = abi.stack.slotSizeBytes * 8;
				const alignedGap = previous !== undefined
					&& parameter.abiAlignBits !== undefined
					&& parameter.abiAlignBits > registerWidthBits
					&& index > previous + 1
					&& index % Math.ceil(parameter.abiAlignBits / registerWidthBits) === 0;
				if ((previous === undefined && index !== 0)
					|| (previous !== undefined && index !== previous + 1 && !alignedGap)) {
					throw new Error(`${callingConventionId} parameter ${parameter.ordinal} violates ${bank.kind} register allocation order.`);
				}
				if (abi.architecture === 'x86' && bank.kind === 'integer'
					&& parameter.abiSizeBits !== undefined && parameter.abiSizeBits > 32) {
					throw new Error(`${callingConventionId} parameter ${parameter.ordinal} exceeds the x86 integer register width.`);
				}
				bankPositions.set(bankKey, index);
			}
		}
		if (parameter.hiddenThis) {
			const expected = abi.hiddenParameters.find(hidden => hidden.role === 'this')?.register;
			if (expected && (registers.length !== 1 || registers[0] !== expected)) {
				throw new Error(`${callingConventionId} hidden this location must use ${expected}.`);
			}
		}
		if (parameter.hiddenSret) {
			const expected = abi.aggregateReturn.hiddenPointerRegister;
			if (expected && (registers.length !== 1 || registers[0] !== expected)) {
				throw new Error(`${callingConventionId} hidden sret location must use ${expected}.`);
			}
		}
	}
}

function normalizeCallingConventionId(id: CallingConventionId): CallingConventionId {
	if (!ABI_MODEL_BUILDERS[id]) {
		throw new Error(`Unknown calling convention: ${String(id)}`);
	}
	return id;
}

function normalizePrototypeParameter(
	targetIdentity: string,
	functionIdentity: string,
	parameter: FunctionParameterSpec,
): CanonicalFunctionParameter {
	const ordinal = requireNonNegativeInteger(parameter.ordinal, 'Parameter ordinal');
	assertOptionalBoolean(parameter.optional, `Parameter ${ordinal} optional flag`);
	assertOptionalBoolean(parameter.nullable, `Parameter ${ordinal} nullable flag`);
	assertOptionalBoolean(parameter.hiddenThis, `Parameter ${ordinal} hiddenThis flag`);
	assertOptionalBoolean(parameter.hiddenSret, `Parameter ${ordinal} hiddenSret flag`);
	assertOptionalBoolean(parameter.compilerGenerated, `Parameter ${ordinal} compilerGenerated flag`);
	if (parameter.hiddenThis === true && parameter.hiddenSret === true) {
		throw new Error(`Parameter ${ordinal} cannot be both hidden this and hidden sret.`);
	}
	if ((parameter.hiddenThis === true || parameter.hiddenSret === true) && parameter.location.kind !== 'implicit') {
		throw new Error(`Hidden parameter ${ordinal} must use an implicit location.`);
	}
	if (parameter.hiddenThis === true && parameter.location.kind === 'implicit' && parameter.location.role !== 'this') {
		throw new Error(`Hidden this parameter ${ordinal} must use the implicit this role.`);
	}
	if (parameter.hiddenSret === true && parameter.location.kind === 'implicit' && parameter.location.role !== 'sret') {
		throw new Error(`Hidden sret parameter ${ordinal} must use the implicit sret role.`);
	}
	const direction = parameter.direction ?? 'in';
	if (!['in', 'out', 'inout'].includes(direction)) {
		throw new Error(`Unknown direction for parameter ${ordinal}: ${String(direction)}`);
	}
	const ownership = parameter.ownership ?? 'none';
	if (!['none', 'borrow', 'acquire', 'release', 'transfer', 'retain'].includes(ownership)) {
		throw new Error(`Unknown ownership effect for parameter ${ordinal}: ${String(ownership)}`);
	}
	const lifetime = parameter.lifetime ?? 'unknown';
	if (!['call', 'caller', 'callee', 'heap', 'static', 'unknown'].includes(lifetime)) {
		throw new Error(`Unknown lifetime for parameter ${ordinal}: ${String(lifetime)}`);
	}
	if (parameter.buffer && !['bytes', 'elements', 'nul-terminated'].includes(parameter.buffer.kind)) {
		throw new Error(`Unknown buffer relationship for parameter ${ordinal}: ${String(parameter.buffer.kind)}`);
	}
	if (parameter.buffer?.countParameterOrdinal !== undefined && parameter.buffer.fixedCount !== undefined) {
		throw new Error(`Parameter ${ordinal} buffer cannot use both a count parameter and a fixed count.`);
	}
	if (parameter.buffer?.countParameterOrdinal === ordinal) {
		throw new Error(`Parameter ${ordinal} cannot be its own buffer count parameter.`);
	}
	if (parameter.buffer && parameter.buffer.kind !== 'nul-terminated'
		&& parameter.buffer.countParameterOrdinal === undefined
		&& parameter.buffer.fixedCount === undefined) {
		throw new Error(`Parameter ${ordinal} ${parameter.buffer.kind} buffer requires a count relationship or fixed count.`);
	}
	let stableIdentity = parameter.stableIdentity?.trim()
		? requireNonEmpty(parameter.stableIdentity, `Parameter ${ordinal} stable identity`)
		: undefined;
	const suppliedAliases = [...new Set((parameter.stableIdentityAliases ?? [])
		.map(item => requireNonEmpty(item, `Parameter ${ordinal} stable identity alias`)))].sort();
	if (!stableIdentity && suppliedAliases.length > 0) {
		stableIdentity = suppliedAliases.shift();
	}
	const identityAliases = suppliedAliases.filter(alias => alias !== stableIdentity);
	if (parameter.abiValueClass !== undefined
		&& !['integer', 'floating', 'vector', 'aggregate'].includes(parameter.abiValueClass)) {
		throw new Error(`Unknown ABI value class for parameter ${ordinal}: ${String(parameter.abiValueClass)}`);
	}
	const abiSizeBits = parameter.abiSizeBits !== undefined
		? requirePositiveInteger(parameter.abiSizeBits, `Parameter ${ordinal} ABI size`)
		: undefined;
	const abiAlignBits = parameter.abiAlignBits !== undefined
		? requirePositiveInteger(parameter.abiAlignBits, `Parameter ${ordinal} ABI alignment`)
		: undefined;
	let parameterId: string;
	if (parameter.parameterId !== undefined) {
		parameterId = requireNonEmpty(parameter.parameterId, `Parameter ${ordinal} ID`);
		if (!/^parameter:sha256:[a-f0-9]{64}$/.test(parameterId)) {
			throw new Error(`Parameter ${ordinal} ID must be a canonical parameter SHA-256 ID.`);
		}
	} else {
		parameterId = `parameter:sha256:${canonicalParameterIdentity(
			targetIdentity,
			functionIdentity,
			stableIdentity ?? `ordinal:${ordinal}:role:${hiddenParameterRole(parameter)}`,
		)}`;
	}
	return {
		parameterId,
		ordinal,
		...(stableIdentity ? { stableIdentity } : {}),
		...(identityAliases.length > 0 ? { stableIdentityAliases: identityAliases } : {}),
		...(parameter.abiValueClass ? { abiValueClass: parameter.abiValueClass } : {}),
		...(abiSizeBits !== undefined ? { abiSizeBits } : {}),
		...(abiAlignBits !== undefined ? { abiAlignBits } : {}),
		name: requireNonEmpty(parameter.name, `Parameter ${ordinal} name`),
		typeId: normalizeTypeId(parameter.typeId, `Parameter ${ordinal} type ID`),
		location: normalizeLocation(parameter.location),
		direction,
		optional: parameter.optional === true,
		nullable: parameter.nullable === true,
		...(parameter.buffer ? {
			buffer: {
				kind: parameter.buffer.kind,
				...(parameter.buffer.countParameterOrdinal !== undefined
					? { countParameterOrdinal: requireNonNegativeInteger(parameter.buffer.countParameterOrdinal, 'Buffer count parameter ordinal') }
					: {}),
				...(parameter.buffer.fixedCount !== undefined ? { fixedCount: requireNonNegativeInteger(parameter.buffer.fixedCount, 'Fixed buffer count') } : {}),
			},
		} : {}),
		ownership,
		lifetime,
		hiddenThis: parameter.hiddenThis === true,
		hiddenSret: parameter.hiddenSret === true,
		compilerGenerated: parameter.compilerGenerated === true,
	};
}

export function canonicalizeFunctionPrototype(spec: FunctionPrototypeSpec): CanonicalFunctionPrototype {
	const targetIdentity = requireNonEmpty(spec.targetIdentity, 'Prototype target identity');
	const functionIdentity = requireNonEmpty(spec.functionIdentity, 'Function identity');
	assertOptionalBoolean(spec.variadic, 'Prototype variadic flag');
	assertOptionalBoolean(spec.noreturn, 'Prototype noreturn flag');
	assertOptionalBoolean(spec.method, 'Prototype method flag');
	assertOptionalBoolean(spec.staticMethod, 'Prototype staticMethod flag');
	const inheritedEvidence = 'evidenceSet' in spec && Array.isArray(spec.evidenceSet)
		? spec.evidenceSet as readonly SemanticEvidence[]
		: [];
	const evidenceSet = normalizeEvidenceSet(spec.evidence, [
		...(spec.corroboratingEvidence ?? []),
		...inheritedEvidence,
	]);
	const evidence = evidenceSet[0];
	const requestedCallingConventionId = normalizeCallingConventionId(spec.callingConventionId);
	const requestedABI = getABIModel(requestedCallingConventionId);
	const callingConventionId = spec.variadic === true && !requestedABI.variadic.supported
		? requestedABI.variadic.fallbackConventionId
			?? (() => { throw new Error(`${requestedCallingConventionId} does not support variadic prototypes.`); })()
		: requestedCallingConventionId;
	const parameters = spec.parameters
		.map(parameter => normalizePrototypeParameter(targetIdentity, functionIdentity, parameter))
		.sort((left, right) => left.ordinal - right.ordinal);
	if (callingConventionId !== requestedCallingConventionId
		&& parameters.some(parameter => !isStackParameterLocation(parameter.location))) {
		throw new Error(
			`Variadic ${requestedCallingConventionId} falls back to ${callingConventionId}; explicit parameters must use stack locations.`,
		);
	}
	if (spec.method === true && spec.staticMethod === true) {
		throw new Error('A function prototype cannot be both a non-static method and a static method.');
	}
	if (parameters.some(parameter => parameter.hiddenThis) && spec.method !== true) {
		throw new Error('A hidden this parameter requires method=true.');
	}
	const ordinals = new Set<number>();
	const parameterIds = new Set<string>();
	for (const parameter of parameters) {
		if (ordinals.has(parameter.ordinal)) {
			throw new Error(`Duplicate parameter ordinal ${parameter.ordinal}.`);
		}
		ordinals.add(parameter.ordinal);
		if (parameterIds.has(parameter.parameterId)) {
			throw new Error(`Duplicate stable parameter identity for parameter ${parameter.ordinal}.`);
		}
		parameterIds.add(parameter.parameterId);
	}
	if (parameters.filter(parameter => parameter.hiddenThis).length > 1) {
		throw new Error('A prototype may contain at most one hidden this parameter.');
	}
	if (parameters.filter(parameter => parameter.hiddenSret).length > 1) {
		throw new Error('A prototype may contain at most one hidden sret parameter.');
	}
	for (const parameter of parameters) {
		if (parameter.buffer?.countParameterOrdinal !== undefined && !parameters.some(item => item.ordinal === parameter.buffer?.countParameterOrdinal)) {
			throw new Error(`Parameter ${parameter.ordinal} references missing count parameter ${parameter.buffer.countParameterOrdinal}.`);
		}
	}
	validateABIParameterLocations(callingConventionId, parameters);
	if (spec.hiddenStorage && !parameters.some(parameter => parameter.ordinal === spec.hiddenStorage?.parameterOrdinal && parameter.hiddenSret)) {
		throw new Error('Hidden storage semantics must reference a hidden sret parameter.');
	}
	if (spec.hiddenStorage
		&& (typeof spec.hiddenStorage.callerAllocated !== 'boolean' || typeof spec.hiddenStorage.calleeReturnsPointer !== 'boolean')) {
		throw new Error('Hidden storage flags must be boolean.');
	}
	const normalizedHiddenReturn = spec.hiddenReturn ? normalizeHiddenReturn(spec.hiddenReturn) : undefined;
	const hiddenSretParameter = parameters.find(parameter => parameter.hiddenSret);
	if (normalizedHiddenReturn?.kind === 'sret-parameter' && !hiddenSretParameter) {
		throw new Error('sret hidden return semantics require a hidden sret parameter.');
	}
	if (hiddenSretParameter && normalizedHiddenReturn
		&& ['sret-parameter', 'memory'].includes(normalizedHiddenReturn.kind)
		&& canonicalSerialize(hiddenSretParameter.location) !== canonicalSerialize(normalizedHiddenReturn.location)) {
		throw new Error('Hidden return location must match the hidden sret parameter location.');
	}
	if (spec.hiddenStorage && normalizedHiddenReturn
		&& !['sret-parameter', 'memory'].includes(normalizedHiddenReturn.kind)) {
		throw new Error('Hidden storage is incompatible with register return semantics.');
	}
	const payload = {
		schemaVersion: SEMANTIC_SCHEMA_VERSION,
		returnTypeId: normalizeTypeId(spec.returnTypeId, 'Return type ID'),
		callingConventionId,
		variadic: spec.variadic === true,
		noreturn: spec.noreturn === true,
		method: spec.method === true,
		staticMethod: spec.staticMethod === true,
		parameters: parameters.map(({
			parameterId: _id,
			stableIdentity: _stableIdentity,
			stableIdentityAliases: _stableIdentityAliases,
			...parameter
		}) => parameter),
		...(normalizedHiddenReturn ? { hiddenReturn: normalizedHiddenReturn } : {}),
		...(spec.hiddenStorage ? { hiddenStorage: {
			parameterOrdinal: requireNonNegativeInteger(spec.hiddenStorage.parameterOrdinal, 'Hidden storage parameter ordinal'),
			callerAllocated: spec.hiddenStorage.callerAllocated,
			calleeReturnsPointer: spec.hiddenStorage.calleeReturnsPointer,
		} } : {}),
	};
	const serialization = canonicalSerialize(payload);
	const hash = sha256(serialization);
	return deepFreeze({
		targetIdentity,
		functionIdentity,
		...(spec.functionAddress ? { functionAddress: normalizeAddress(spec.functionAddress) } : {}),
		returnTypeId: payload.returnTypeId,
		callingConventionId,
		parameters,
		variadic: payload.variadic,
		noreturn: payload.noreturn,
		method: payload.method,
		staticMethod: payload.staticMethod,
		...(payload.hiddenReturn ? { hiddenReturn: payload.hiddenReturn } : {}),
		...(payload.hiddenStorage ? { hiddenStorage: payload.hiddenStorage } : {}),
		prototypeId: `prototype:sha256:${hash}`,
		prototypeHash: hash,
		canonicalHash: hash,
		canonicalSerialization: serialization,
		evidence,
		evidenceSet,
	});
}

function normalizeAddress(address: string): string {
	const normalized = requireNonEmpty(address, 'Function address').toLowerCase();
	if (!/^0x[0-9a-f]+$/.test(normalized)) {
		throw new Error('Function address must be hexadecimal with a 0x prefix.');
	}
	return `0x${BigInt(normalized).toString(16)}`;
}

function normalizeHiddenReturn(value: HiddenReturnSemantics): HiddenReturnSemantics {
	if (!['register', 'sret-parameter', 'split-registers', 'memory'].includes(value.kind)) {
		throw new Error(`Unknown hidden return kind: ${String(value.kind)}`);
	}
	if (!value.location) {
		throw new Error(`${value.kind} hidden return semantics require a concrete location.`);
	}
	const location = normalizeLocation(value.location);
	if (value.kind === 'register' && (location.kind !== 'register' || location.registers.length !== 1)) {
		throw new Error('Register hidden return semantics require a register location.');
	}
	if (value.kind === 'sret-parameter'
		&& (location.kind !== 'implicit' || location.role !== 'sret')) {
		throw new Error('sret hidden return semantics require an implicit sret location.');
	}
	if (value.kind === 'split-registers'
		&& (location.kind !== 'split' || location.parts.some(part => part.kind !== 'register'))) {
		throw new Error('Split-register hidden return semantics require a split location.');
	}
	if (value.kind === 'memory'
		&& location.kind !== 'stack'
		&& !(location.kind === 'implicit' && location.role === 'sret')) {
		throw new Error('Memory hidden return semantics require a stack or implicit sret location.');
	}
	return {
		kind: value.kind,
		location,
	};
}

export function canonicalizeTypeBinding(spec: TypeBindingSpec): CanonicalTypeBinding {
	const inheritedEvidence = 'evidenceSet' in spec && Array.isArray(spec.evidenceSet)
		? spec.evidenceSet as readonly SemanticEvidence[]
		: [];
	const evidenceSet = normalizeEvidenceSet(spec.evidence, [
		...(spec.corroboratingEvidence ?? []),
		...inheritedEvidence,
	]);
	const evidence = evidenceSet[0];
	if (!TYPE_BINDING_SCOPES.has(spec.scope)) {
		throw new Error(`Unknown type binding scope: ${String(spec.scope)}`);
	}
	const functionLocalScopes = new Set<TypeBindingScope>([
		'function-parameter', 'local', 'stack-slot', 'register-value', 'ssa-value', 'return-value',
	]);
	if (functionLocalScopes.has(spec.scope) && !spec.functionIdentity?.trim()) {
		throw new Error(`${spec.scope} bindings require functionIdentity.`);
	}
	const identityPayload = {
		targetIdentity: requireNonEmpty(spec.targetIdentity, 'Binding target identity'),
		scope: spec.scope,
		valueIdentity: requireNonEmpty(spec.valueIdentity, 'Bound value identity'),
		...(spec.functionIdentity ? { functionIdentity: requireNonEmpty(spec.functionIdentity, 'Binding function identity') } : {}),
	};
	const bindingId = `binding:sha256:${canonicalHash(identityPayload)}`;
	const dependencies = [...new Set((spec.invalidationDependencies ?? []).map(item => requireNonEmpty(item, 'Invalidation dependency')))].sort();
	const payload = {
		...identityPayload,
		typeId: normalizeTypeId(spec.typeId),
		invalidationDependencies: dependencies,
	};
	const serialization = canonicalSerialize(payload);
	return deepFreeze({
		...identityPayload,
		typeId: payload.typeId,
		bindingId,
		canonicalHash: sha256(serialization),
		canonicalSerialization: serialization,
		invalidationDependencies: dependencies,
		evidence,
		evidenceSet,
	});
}

const PROTOTYPE_RECOVERY_KINDS = new Set<PrototypeRecoveryObservationKind>([
	'register-read-before-definition', 'entry-stack-read', 'ret-immediate', 'caller-stack-adjustment',
	'callsite-argument-write', 'caller-return-register-use', 'this-pattern', 'debug-prototype',
	'import-prototype', 'signature-prototype', 'caller-consensus',
]);

export function canonicalizePrototypeRecoveryObservation(
	spec: PrototypeRecoveryObservationSpec,
): CanonicalPrototypeRecoveryObservation {
	if (!PROTOTYPE_RECOVERY_KINDS.has(spec.kind)) {
		throw new Error(`Unknown prototype recovery observation kind: ${String(spec.kind)}`);
	}
	const targetIdentity = requireNonEmpty(spec.targetIdentity, 'Recovery observation target identity');
	const functionIdentity = requireNonEmpty(spec.functionIdentity, 'Recovery observation function identity');
	const atAddress = spec.atAddress ? normalizeAddress(spec.atAddress) : undefined;
	const callsiteAddress = spec.callsiteAddress ? normalizeAddress(spec.callsiteAddress) : undefined;
	const callerIdentity = spec.callerIdentity ? requireNonEmpty(spec.callerIdentity, 'Caller identity') : undefined;
	const register = spec.register ? normalizeRegister(spec.register) : undefined;
	if (spec.stackOffsetBytes !== undefined && !Number.isSafeInteger(spec.stackOffsetBytes)) {
		throw new Error('Recovery stack offset must be a safe integer.');
	}
	const byteCount = spec.byteCount !== undefined
		? requireNonNegativeInteger(spec.byteCount, 'Recovery byte count')
		: undefined;
	const parameterOrdinal = spec.parameterOrdinal !== undefined
		? requireNonNegativeInteger(spec.parameterOrdinal, 'Recovery parameter ordinal')
		: undefined;
	const callerIdentities = [...new Set((spec.callerIdentities ?? []).map(item => requireNonEmpty(item, 'Consensus caller identity')))].sort();
	const corroboratingObservationIds = [...new Set((spec.corroboratingObservationIds ?? []).map(item => requireNonEmpty(item, 'Corroborating observation ID')))].sort();
	const suppliedFields: Readonly<Record<string, boolean>> = {
		atAddress: spec.atAddress !== undefined,
		callsiteAddress: spec.callsiteAddress !== undefined,
		callerIdentity: spec.callerIdentity !== undefined,
		register: spec.register !== undefined,
		stackOffsetBytes: spec.stackOffsetBytes !== undefined,
		byteCount: spec.byteCount !== undefined,
		parameterOrdinal: spec.parameterOrdinal !== undefined,
		callerIdentities: spec.callerIdentities !== undefined,
		corroboratingObservationIds: spec.corroboratingObservationIds !== undefined,
	};
	const allowedFields: Readonly<Record<PrototypeRecoveryObservationKind, readonly string[]>> = {
		'register-read-before-definition': ['atAddress', 'register'],
		'entry-stack-read': ['atAddress', 'stackOffsetBytes'],
		'ret-immediate': ['atAddress', 'byteCount'],
		'caller-stack-adjustment': ['callerIdentity', 'callsiteAddress', 'byteCount'],
		'callsite-argument-write': ['callerIdentity', 'callsiteAddress', 'register', 'stackOffsetBytes', 'parameterOrdinal'],
		'caller-return-register-use': ['callerIdentity', 'callsiteAddress', 'register'],
		'this-pattern': ['atAddress', 'register'],
		'debug-prototype': ['atAddress'],
		'import-prototype': ['atAddress'],
		'signature-prototype': ['atAddress'],
		'caller-consensus': ['callerIdentities', 'corroboratingObservationIds'],
	};
	for (const [field, supplied] of Object.entries(suppliedFields)) {
		if (supplied && !allowedFields[spec.kind].includes(field)) {
			throw new Error(`${spec.kind} does not allow ${field}.`);
		}
	}

	switch (spec.kind) {
		case 'register-read-before-definition':
		case 'this-pattern':
			if (!atAddress || !register) { throw new Error(`${spec.kind} requires an address and register.`); }
			break;
		case 'entry-stack-read':
			if (!atAddress || spec.stackOffsetBytes === undefined) { throw new Error('entry-stack-read requires an address and stackOffsetBytes.'); }
			break;
		case 'ret-immediate':
			if (!atAddress || byteCount === undefined) { throw new Error('ret-immediate requires an address and byteCount.'); }
			break;
		case 'caller-stack-adjustment':
			if (!callerIdentity || !callsiteAddress || byteCount === undefined) {
				throw new Error('caller-stack-adjustment requires caller, callsite, and byteCount.');
			}
			break;
		case 'callsite-argument-write':
			if (!callerIdentity || !callsiteAddress || (!register && spec.stackOffsetBytes === undefined)) {
				throw new Error('callsite-argument-write requires caller, callsite, and register or stack location.');
			}
			break;
		case 'caller-return-register-use':
			if (!callsiteAddress || !callerIdentity || !register) {
				throw new Error('caller-return-register-use requires caller, callsite, and register.');
			}
			break;
		case 'caller-consensus':
			if (callerIdentities.length < 2 || corroboratingObservationIds.length < 2) {
				throw new Error('caller-consensus requires at least two callers and two corroborating observations.');
			}
			break;
	}

	const inheritedEvidence = 'evidenceSet' in spec && Array.isArray(spec.evidenceSet)
		? spec.evidenceSet as readonly SemanticEvidence[]
		: [];
	const evidenceSet = normalizeEvidenceSet(spec.evidence, [
		...(spec.corroboratingEvidence ?? []),
		...inheritedEvidence,
	]);
	const payload = {
		schemaVersion: SEMANTIC_SCHEMA_VERSION,
		targetIdentity,
		functionIdentity,
		kind: spec.kind,
		...(atAddress ? { atAddress } : {}),
		...(callsiteAddress ? { callsiteAddress } : {}),
		...(callerIdentity ? { callerIdentity } : {}),
		...(register ? { register } : {}),
		...(spec.stackOffsetBytes !== undefined ? { stackOffsetBytes: spec.stackOffsetBytes } : {}),
		...(byteCount !== undefined ? { byteCount } : {}),
		...(parameterOrdinal !== undefined ? { parameterOrdinal } : {}),
		...(callerIdentities.length > 0 ? { callerIdentities } : {}),
		...(corroboratingObservationIds.length > 0 ? { corroboratingObservationIds } : {}),
	};
	const serialization = canonicalSerialize(payload);
	const hash = sha256(serialization);
	return deepFreeze({
		...payload,
		observationId: `prototype-observation:sha256:${hash}`,
		canonicalHash: hash,
		canonicalSerialization: serialization,
		evidence: evidenceSet[0],
		evidenceSet,
	});
}

export function assessPrototypeRecovery(
	prototype: FunctionPrototypeSpec | CanonicalFunctionPrototype,
	observations: readonly (PrototypeRecoveryObservationSpec | CanonicalPrototypeRecoveryObservation)[],
): PrototypeRecoveryAssessment {
	const canonicalPrototype = canonicalizeFunctionPrototype(prototype);
	const canonicalObservations = observations.map(item => canonicalizePrototypeRecoveryObservation(item));
	for (const observation of canonicalObservations) {
		if (observation.targetIdentity !== canonicalPrototype.targetIdentity
			|| observation.functionIdentity !== canonicalPrototype.functionIdentity) {
			throw new Error('Prototype recovery observation belongs to a different target or function.');
		}
		if (observation.parameterOrdinal !== undefined
			&& !canonicalPrototype.parameters.some(parameter => parameter.ordinal === observation.parameterOrdinal)) {
			throw new Error(`Recovery observation references missing parameter ${observation.parameterOrdinal}.`);
		}
	}
	const unique = new Map<string, CanonicalPrototypeRecoveryObservation>();
	for (const observation of canonicalObservations) {
		const current = unique.get(observation.observationId);
		unique.set(
			observation.observationId,
			current ? arbitrateSemanticValue(current, observation).accepted : observation,
		);
	}
	for (const observation of unique.values()) {
		if (observation.kind !== 'caller-consensus') { continue; }
		const supportingCallers = new Set<string>();
		const supportingClaims = new Set<string>();
		for (const observationId of observation.corroboratingObservationIds ?? []) {
			const supporting = unique.get(observationId);
			if (!supporting) {
				throw new Error(`Caller consensus references missing observation ${observationId}.`);
			}
			if (!['caller-stack-adjustment', 'callsite-argument-write', 'caller-return-register-use'].includes(supporting.kind)
				|| !supporting.callerIdentity) {
				throw new Error('Caller consensus may reference only caller-derived recovery observations.');
			}
			supportingCallers.add(supporting.callerIdentity);
			const claim = supporting.kind === 'caller-stack-adjustment'
				? { kind: supporting.kind, byteCount: supporting.byteCount }
				: supporting.kind === 'callsite-argument-write'
					? {
						kind: supporting.kind,
						parameterOrdinal: supporting.parameterOrdinal,
						register: supporting.register,
						stackOffsetBytes: supporting.stackOffsetBytes,
					}
					: { kind: supporting.kind, register: supporting.register };
			supportingClaims.add(canonicalSerialize(claim));
		}
		if (supportingCallers.size < 2) {
			throw new Error('Caller consensus must be backed by observations from at least two distinct callers.');
		}
		if (supportingClaims.size !== 1) {
			throw new Error('Caller consensus observations must support the same semantic claim.');
		}
		if (canonicalSerialize([...supportingCallers].sort()) !== canonicalSerialize(observation.callerIdentities ?? [])) {
			throw new Error('Caller consensus declarations must exactly match its supporting callers.');
		}
	}
	const ordered = [...unique.values()].sort((left, right) => stableStringCompare(left.observationId, right.observationId));
	const callers = new Set<string>();
	for (const observation of ordered) {
		if (observation.kind !== 'caller-consensus') { continue; }
		for (const caller of observation.callerIdentities ?? []) { callers.add(caller); }
	}
	const payload = {
		schemaVersion: SEMANTIC_SCHEMA_VERSION,
		targetIdentity: canonicalPrototype.targetIdentity,
		functionIdentity: canonicalPrototype.functionIdentity,
		prototypeHash: canonicalPrototype.prototypeHash,
		observationIds: ordered.map(item => item.observationId),
		callerConsensusCount: callers.size,
	};
	const serialization = canonicalSerialize(payload);
	return deepFreeze({
		targetIdentity: canonicalPrototype.targetIdentity,
		functionIdentity: canonicalPrototype.functionIdentity,
		prototype: canonicalPrototype,
		observations: ordered,
		callerConsensusCount: callers.size,
		canonicalHash: sha256(serialization),
		canonicalSerialization: serialization,
	});
}

function compareEvidence(left: SemanticEvidence, right: SemanticEvidence): number {
	if (left.userDefined === true !== (right.userDefined === true)) {
		return left.userDefined === true ? 1 : -1;
	}
	const strength = STRENGTH_RANK[left.strength] - STRENGTH_RANK[right.strength];
	if (strength !== 0) { return strength; }
	const generation = left.generation - right.generation;
	if (generation !== 0) { return generation; }
	const confidence = (left.confidence ?? -1) - (right.confidence ?? -1);
	if (confidence !== 0) { return confidence; }
	const source = stableStringCompare(left.source, right.source);
	if (source !== 0) { return source; }
	return stableStringCompare(left.producer, right.producer);
}

function mergeEvidenceBackedValue<T extends {
	canonicalHash: string;
	evidence: SemanticEvidence;
	evidenceSet?: readonly SemanticEvidence[];
}>(preferred: T, other: T): T {
	const evidenceSet = normalizeEvidenceSet(preferred.evidence, [
		...(preferred.evidenceSet ?? []),
		other.evidence,
		...(other.evidenceSet ?? []),
	]);
	return deepFreeze({ ...preferred, evidence: evidenceSet[0], evidenceSet }) as T;
}

function mergeCanonicalTypeEvidence(
	left: CanonicalSemanticType,
	right: CanonicalSemanticType,
): CanonicalSemanticType {
	const preferred = compareEvidence(right.evidence, left.evidence) > 0 ? right : left;
	const other = preferred === left ? right : left;
	const merged = mergeEvidenceBackedValue(preferred, other);
	const childKey = (value: Record<string, unknown>): string => canonicalSerialize(
		Object.fromEntries(Object.entries(value).filter(([key]) => key !== 'evidence' && key !== 'evidenceSet')),
	);
	const mergeChildren = <T extends { evidence?: SemanticEvidence; evidenceSet?: readonly SemanticEvidence[] }>(
		primary: readonly T[] | undefined,
		secondary: readonly T[] | undefined,
	): readonly T[] | undefined => {
		if (!primary) { return undefined; }
		const secondaryByKey = new Map((secondary ?? []).map(item => [childKey(item as Record<string, unknown>), item]));
		return primary.map(item => {
			const sibling = secondaryByKey.get(childKey(item as Record<string, unknown>));
			if (!sibling || !item.evidence || !sibling.evidence) { return item; }
			const evidenceSet = normalizeEvidenceSet(item.evidence, [
				...(item.evidenceSet ?? []), sibling.evidence, ...(sibling.evidenceSet ?? []),
			]);
			return deepFreeze({ ...item, evidence: evidenceSet[0], evidenceSet }) as T;
		});
	};
	return deepFreeze({
		...merged,
		...(merged.members ? { members: mergeChildren(merged.members, other.members) } : {}),
		...(merged.enumMembers ? { enumMembers: mergeChildren(merged.enumMembers, other.enumMembers) } : {}),
		...(merged.aliases ? { aliases: mergeChildren(merged.aliases, other.aliases) } : {}),
	});
}

function mergeCanonicalPrototypeMetadata(
	preferred: CanonicalFunctionPrototype,
	other: CanonicalFunctionPrototype,
): CanonicalFunctionPrototype {
	const mergedEvidence = mergeEvidenceBackedValue(preferred, other);
	const otherByOrdinal = new Map(other.parameters.map(parameter => [parameter.ordinal, parameter]));
	const parameters = preferred.parameters.map(parameter => {
		const sibling = otherByOrdinal.get(parameter.ordinal);
		const stableIdentity = parameter.stableIdentity ?? sibling?.stableIdentity;
		const aliases = [...new Set([
			...(parameter.stableIdentityAliases ?? []),
			...(sibling?.stableIdentityAliases ?? []),
			...(sibling?.stableIdentity && sibling.stableIdentity !== stableIdentity ? [sibling.stableIdentity] : []),
		])].filter(alias => alias !== stableIdentity).sort();
		if (!stableIdentity && aliases.length === 0) { return parameter; }
		return deepFreeze({
			...parameter,
			...(stableIdentity ? { stableIdentity } : {}),
			...(aliases.length > 0 ? { stableIdentityAliases: aliases } : { stableIdentityAliases: [] }),
		});
	});
	return deepFreeze({ ...mergedEvidence, parameters });
}

function makeSemanticConflict<T>(
	winner: T,
	loser: T,
	reason: SemanticConflict<T>['reason'],
): SemanticConflict<T> {
	return deepFreeze({ winner, loser, reason });
}

function recordSemanticConflict<T extends {
	canonicalHash: string;
	evidence: SemanticEvidence;
	evidenceSet?: readonly SemanticEvidence[];
}>(
	log: Map<string, SemanticConflict<T>[]>,
	key: string,
	conflict: SemanticConflict<T>,
): void {
	const conflicts = log.get(key) ?? [];
	const identity = canonicalSerialize({
		winnerHash: conflict.winner.canonicalHash,
		loserHash: conflict.loser.canonicalHash,
		reason: conflict.reason,
	});
	const existingIndex = conflicts.findIndex(existing => canonicalSerialize({
		winnerHash: existing.winner.canonicalHash,
		loserHash: existing.loser.canonicalHash,
		reason: existing.reason,
	}) === identity);
	if (existingIndex < 0) {
		conflicts.push(conflict);
	} else {
		const existing = conflicts[existingIndex];
		conflicts[existingIndex] = makeSemanticConflict(
			mergeEvidenceBackedValue(existing.winner, conflict.winner),
			mergeEvidenceBackedValue(existing.loser, conflict.loser),
			existing.reason,
		);
	}
	log.set(key, conflicts);
}

export function arbitrateSemanticValue<T extends {
	canonicalHash: string;
	evidence: SemanticEvidence;
	evidenceSet?: readonly SemanticEvidence[];
}>(
	current: T | undefined,
	incoming: T,
): ArbitrationResult<T> {
	if (!current) {
		return { status: 'accepted-new', accepted: incoming };
	}
	const comparison = compareEvidence(incoming.evidence, current.evidence);
	if (incoming.canonicalHash === current.canonicalHash) {
		const incomingPreferred = comparison > 0;
		return incomingPreferred
			? { status: 'equivalent-updated', accepted: mergeEvidenceBackedValue(incoming, current) }
			: { status: 'equivalent-retained', accepted: mergeEvidenceBackedValue(current, incoming) };
	}
	const incomingStrength = STRENGTH_RANK[incoming.evidence.strength];
	const currentStrength = STRENGTH_RANK[current.evidence.strength];
	if (incomingStrength < currentStrength) {
		return {
			status: 'rejected-weaker', accepted: current,
			conflict: makeSemanticConflict(current, incoming, 'stronger-evidence'),
		};
	}
	if (incomingStrength > currentStrength) {
		return {
			status: 'replaced-stronger', accepted: incoming,
			conflict: makeSemanticConflict(incoming, current, 'stronger-evidence'),
		};
	}
	const reason: SemanticConflict<T>['reason'] = incoming.evidence.userDefined !== current.evidence.userDefined
		? 'user-defined-override'
		: incoming.evidence.generation !== current.evidence.generation
			? 'newer-peer'
			: incoming.evidence.confidence !== current.evidence.confidence
			? 'calibrated-peer'
			: 'deterministic-peer';
	const deterministicComparison = comparison !== 0
		? comparison
		: stableStringCompare(incoming.canonicalHash, current.canonicalHash);
	if (deterministicComparison > 0) {
		return { status: 'replaced-peer', accepted: incoming, conflict: makeSemanticConflict(incoming, current, reason) };
	}
	return { status: 'rejected-peer', accepted: current, conflict: makeSemanticConflict(current, incoming, reason) };
}

export class PrototypeRegistry {
	private readonly accepted = new Map<string, CanonicalFunctionPrototype>();
	private readonly conflictLog = new Map<string, SemanticConflict<CanonicalFunctionPrototype>[]>();

	apply(spec: FunctionPrototypeSpec | CanonicalFunctionPrototype): ArbitrationResult<CanonicalFunctionPrototype> {
		const incoming = canonicalizeFunctionPrototype(spec);
		const key = this.key(incoming.targetIdentity, incoming.functionIdentity);
		const current = this.accepted.get(key);
		let result = arbitrateSemanticValue(current, incoming);
		if (current && current.canonicalHash === incoming.canonicalHash) {
			const withCurrent = mergeCanonicalPrototypeMetadata(result.accepted, current);
			result = {
				...result,
				accepted: mergeCanonicalPrototypeMetadata(withCurrent, incoming),
			};
		}
		this.accepted.set(key, result.accepted);
		if (result.conflict) {
			recordSemanticConflict(this.conflictLog, key, result.conflict);
		}
		return result;
	}

	get(targetIdentity: string, functionIdentity: string): CanonicalFunctionPrototype | undefined {
		return this.accepted.get(this.key(targetIdentity, functionIdentity));
	}

	conflicts(targetIdentity: string, functionIdentity: string): readonly SemanticConflict<CanonicalFunctionPrototype>[] {
		return [...(this.conflictLog.get(this.key(targetIdentity, functionIdentity)) ?? [])];
	}

	private key(targetIdentity: string, functionIdentity: string): string {
		return canonicalSerialize({
			targetIdentity: requireNonEmpty(targetIdentity, 'Prototype target identity'),
			functionIdentity: requireNonEmpty(functionIdentity, 'Function identity'),
		});
	}
}

export class TypeBindingRegistry {
	private readonly accepted = new Map<string, CanonicalTypeBinding>();
	private readonly conflictLog = new Map<string, SemanticConflict<CanonicalTypeBinding>[]>();

	apply(spec: TypeBindingSpec | CanonicalTypeBinding): ArbitrationResult<CanonicalTypeBinding> {
		const incoming = canonicalizeTypeBinding(spec);
		const result = arbitrateSemanticValue(this.accepted.get(incoming.bindingId), incoming);
		this.accepted.set(incoming.bindingId, result.accepted);
		if (result.conflict) {
			recordSemanticConflict(this.conflictLog, incoming.bindingId, result.conflict);
		}
		return result;
	}

	get(bindingId: string): CanonicalTypeBinding | undefined {
		return this.accepted.get(bindingId);
	}

	conflicts(bindingId: string): readonly SemanticConflict<CanonicalTypeBinding>[] {
		return [...(this.conflictLog.get(bindingId) ?? [])];
	}
}

type ABIModelWithoutHash = Omit<ABIModel, 'canonicalHash'>;

function deepFreeze<T>(value: T): T {
	if (value !== null && typeof value === 'object' && !Object.isFrozen(value)) {
		for (const child of Object.values(value as Record<string, unknown>)) {
			deepFreeze(child);
		}
		Object.freeze(value);
	}
	return value;
}

function buildABI(model: ABIModelWithoutHash): ABIModel {
	const normalized: ABIModelWithoutHash = {
		...model,
		argumentBanks: model.argumentBanks.map(bank => ({ ...bank, registers: bank.registers.map(normalizeRegister) })),
		returns: {
			integer: model.returns.integer.map(normalizeRegister),
			floating: model.returns.floating.map(normalizeRegister),
			vector: model.returns.vector.map(normalizeRegister),
			...(model.returns.splitInteger ? { splitInteger: model.returns.splitInteger.map(normalizeRegister) } : {}),
		},
		aggregateReturn: {
			...model.aggregateReturn,
			...(model.aggregateReturn.hiddenPointerRegister ? { hiddenPointerRegister: normalizeRegister(model.aggregateReturn.hiddenPointerRegister) } : {}),
			...(model.aggregateReturn.returnsHiddenPointer ? { returnsHiddenPointer: normalizeRegister(model.aggregateReturn.returnsHiddenPointer) } : {}),
		},
		callerSaved: model.callerSaved.map(normalizeRegister),
		calleeSaved: model.calleeSaved.map(normalizeRegister),
		...(model.partialCalleeSaved ? {
			partialCalleeSaved: model.partialCalleeSaved.map(group => ({
				registers: group.registers.map(normalizeRegister),
				preservedLowBits: requirePositiveInteger(group.preservedLowBits, 'Partially preserved register width'),
			})),
		} : {}),
		...(model.platformSpecificRegisters ? { platformSpecificRegisters: model.platformSpecificRegisters.map(normalizeRegister) } : {}),
		hiddenParameters: model.hiddenParameters.map(parameter => ({
			...parameter,
			...(parameter.register ? { register: normalizeRegister(parameter.register) } : {}),
		})),
	};
	return deepFreeze({ ...normalized, canonicalHash: canonicalHash(normalized) });
}

const x86Stack = (cleanup: ABIStackContract['cleanup']): ABIStackContract => ({
	direction: 'down', argumentOrder: 'right-to-left', argumentBaseBytes: 4,
	slotSizeBytes: 4, alignmentBytes: 4, cleanup, shadowSpaceBytes: 0, redZoneBytes: 0,
});

const ABI_MODEL_BUILDERS: Readonly<Record<CallingConventionId, () => ABIModel>> = {
	cdecl: () => buildABI({
		id: 'cdecl', displayName: 'x86 cdecl', architecture: 'x86', argumentAllocation: 'stack-only', argumentBanks: [], stack: x86Stack('caller'),
		returns: { integer: ['eax'], floating: ['st0'], vector: ['xmm0'], splitInteger: ['edx', 'eax'] },
		aggregateReturn: { strategy: 'register-up-to-bits', classifier: 'x86-msvc', registerLimitBits: 64, registerSizesBits: [8, 16, 32, 64], requiresTrivialAggregate: true, hiddenPointerConsumesArgumentSlot: true, returnsHiddenPointer: 'eax' },
		variadic: { supported: true }, callerSaved: ['eax', 'ecx', 'edx'], calleeSaved: ['ebx', 'esi', 'edi', 'ebp', 'esp'],
		hiddenParameters: [{ role: 'sret', position: 'before-explicit', shiftsExplicitArguments: true }], userDefined: false,
	}),
	stdcall: () => buildABI({
		id: 'stdcall', displayName: 'x86 stdcall', architecture: 'x86', argumentAllocation: 'stack-only', argumentBanks: [], stack: x86Stack('callee'),
		returns: { integer: ['eax'], floating: ['st0'], vector: ['xmm0'], splitInteger: ['edx', 'eax'] },
		aggregateReturn: { strategy: 'register-up-to-bits', classifier: 'x86-msvc', registerLimitBits: 64, registerSizesBits: [8, 16, 32, 64], requiresTrivialAggregate: true, hiddenPointerConsumesArgumentSlot: true, returnsHiddenPointer: 'eax' },
		variadic: { supported: false, fallbackConventionId: 'cdecl' }, callerSaved: ['eax', 'ecx', 'edx'],
		calleeSaved: ['ebx', 'esi', 'edi', 'ebp', 'esp'], hiddenParameters: [{ role: 'sret', position: 'before-explicit', shiftsExplicitArguments: true }],
		userDefined: false,
	}),
	fastcall: () => buildABI({
		id: 'fastcall', displayName: 'x86 fastcall', architecture: 'x86', argumentAllocation: 'independent-register-banks',
		argumentBanks: [{ kind: 'integer', registers: ['ecx', 'edx'], allocation: 'left-to-right' }], stack: x86Stack('callee'),
		returns: { integer: ['eax'], floating: ['st0'], vector: ['xmm0'], splitInteger: ['edx', 'eax'] },
		aggregateReturn: { strategy: 'register-up-to-bits', classifier: 'x86-msvc', registerLimitBits: 64, registerSizesBits: [8, 16, 32, 64], requiresTrivialAggregate: true, hiddenPointerConsumesArgumentSlot: true, returnsHiddenPointer: 'eax' },
		variadic: { supported: false, fallbackConventionId: 'cdecl' }, callerSaved: ['eax', 'ecx', 'edx'],
		calleeSaved: ['ebx', 'esi', 'edi', 'ebp', 'esp'], hiddenParameters: [{ role: 'sret', position: 'before-explicit', shiftsExplicitArguments: true }],
		userDefined: false,
	}),
	thiscall: () => buildABI({
		id: 'thiscall', displayName: 'x86 thiscall', architecture: 'x86', argumentAllocation: 'independent-register-banks',
		argumentBanks: [{ kind: 'integer', registers: ['ecx'], allocation: 'left-to-right' }], stack: x86Stack('callee'),
		returns: { integer: ['eax'], floating: ['st0'], vector: ['xmm0'], splitInteger: ['edx', 'eax'] },
		aggregateReturn: { strategy: 'register-up-to-bits', classifier: 'x86-msvc', registerLimitBits: 64, registerSizesBits: [8, 16, 32, 64], requiresTrivialAggregate: true, hiddenPointerConsumesArgumentSlot: true, returnsHiddenPointer: 'eax' },
		variadic: { supported: false, fallbackConventionId: 'cdecl' }, callerSaved: ['eax', 'ecx', 'edx'],
		calleeSaved: ['ebx', 'esi', 'edi', 'ebp', 'esp'],
		hiddenParameters: [
			{ role: 'this', register: 'ecx', position: 'before-explicit', shiftsExplicitArguments: false },
			{ role: 'sret', position: 'convention-specific', shiftsExplicitArguments: true },
		], userDefined: false,
	}),
	vectorcall: () => buildABI({
		id: 'vectorcall', displayName: 'x86 vectorcall', architecture: 'x86', argumentAllocation: 'independent-register-banks', argumentBanks: [
			{ kind: 'integer', registers: ['ecx', 'edx'], allocation: 'left-to-right' },
			{ kind: 'floating', registers: ['xmm0', 'xmm1', 'xmm2', 'xmm3', 'xmm4', 'xmm5'], allocation: 'left-to-right' },
			{ kind: 'vector', registers: ['xmm0', 'xmm1', 'xmm2', 'xmm3', 'xmm4', 'xmm5'], allocation: 'left-to-right' },
		], stack: { ...x86Stack('callee'), alignmentBytes: 16 },
		returns: { integer: ['eax'], floating: ['xmm0'], vector: ['xmm0'], splitInteger: ['edx', 'eax'] },
		aggregateReturn: { strategy: 'register-classification', classifier: 'x86-vectorcall-hva', hiddenPointerConsumesArgumentSlot: true, returnsHiddenPointer: 'eax' },
		variadic: { supported: false, fallbackConventionId: 'cdecl' }, callerSaved: ['eax', 'ecx', 'edx', 'xmm0', 'xmm1', 'xmm2', 'xmm3', 'xmm4', 'xmm5'],
		calleeSaved: ['ebx', 'esi', 'edi', 'ebp', 'esp', 'xmm6', 'xmm7'], hiddenParameters: [{ role: 'sret', position: 'convention-specific', shiftsExplicitArguments: true }],
		userDefined: false,
	}),
	usercall: () => buildABI({
		id: 'usercall', displayName: 'Explicit usercall', architecture: 'user-defined', argumentAllocation: 'explicit-usercall', argumentBanks: [],
		stack: { ...x86Stack('convention-specific'), alignmentBytes: 1 }, returns: { integer: [], floating: [], vector: [] },
		aggregateReturn: { strategy: 'user-defined', hiddenPointerConsumesArgumentSlot: false }, variadic: { supported: true },
		callerSaved: [], calleeSaved: [], hiddenParameters: [], userDefined: true,
	}),
	win64: () => buildABI({
		id: 'win64', displayName: 'Windows x64', architecture: 'x86_64', argumentAllocation: 'shared-ordinal-slots', argumentBanks: [
			{ kind: 'integer', registers: ['rcx', 'rdx', 'r8', 'r9'], allocation: 'left-to-right' },
			{ kind: 'floating', registers: ['xmm0', 'xmm1', 'xmm2', 'xmm3'], allocation: 'left-to-right' },
			{ kind: 'vector', registers: ['xmm0', 'xmm1', 'xmm2', 'xmm3'], allocation: 'left-to-right' },
		], stack: { direction: 'down', argumentOrder: 'right-to-left', argumentBaseBytes: 40, slotSizeBytes: 8, alignmentBytes: 16, cleanup: 'caller', shadowSpaceBytes: 32, redZoneBytes: 0 },
		returns: { integer: ['rax'], floating: ['xmm0'], vector: ['xmm0'] },
		aggregateReturn: { strategy: 'register-up-to-bits', classifier: 'win64', registerLimitBits: 64, registerSizesBits: [8, 16, 32, 64], requiresTrivialAggregate: true, hiddenPointerRegister: 'rcx', hiddenPointerConsumesArgumentSlot: true, returnsHiddenPointer: 'rax' },
		variadic: { supported: true, floatingArgumentsUseIntegerBank: true },
		callerSaved: ['rax', 'rcx', 'rdx', 'r8', 'r9', 'r10', 'r11', 'xmm0', 'xmm1', 'xmm2', 'xmm3', 'xmm4', 'xmm5'],
		calleeSaved: ['rbx', 'rbp', 'rdi', 'rsi', 'rsp', 'r12', 'r13', 'r14', 'r15', 'xmm6', 'xmm7', 'xmm8', 'xmm9', 'xmm10', 'xmm11', 'xmm12', 'xmm13', 'xmm14', 'xmm15'],
		hiddenParameters: [{ role: 'sret', register: 'rcx', position: 'before-explicit', shiftsExplicitArguments: true }], userDefined: false,
	}),
	sysv64: () => buildABI({
		id: 'sysv64', displayName: 'System V AMD64', architecture: 'x86_64', argumentAllocation: 'independent-register-banks', argumentBanks: [
			{ kind: 'integer', registers: ['rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9'], allocation: 'left-to-right' },
			{ kind: 'floating', registers: ['xmm0', 'xmm1', 'xmm2', 'xmm3', 'xmm4', 'xmm5', 'xmm6', 'xmm7'], allocation: 'left-to-right' },
			{ kind: 'vector', registers: ['xmm0', 'xmm1', 'xmm2', 'xmm3', 'xmm4', 'xmm5', 'xmm6', 'xmm7'], allocation: 'left-to-right' },
		], stack: { direction: 'down', argumentOrder: 'right-to-left', argumentBaseBytes: 8, slotSizeBytes: 8, alignmentBytes: 16, cleanup: 'caller', shadowSpaceBytes: 0, redZoneBytes: 128 },
		returns: { integer: ['rax'], floating: ['xmm0', 'st0'], vector: ['xmm0'], splitInteger: ['rax', 'rdx'] },
		aggregateReturn: { strategy: 'register-classification', classifier: 'sysv-eightbyte', hiddenPointerRegister: 'rdi', hiddenPointerConsumesArgumentSlot: true, returnsHiddenPointer: 'rax' },
		variadic: { supported: true, floatingRegisterCountRegister: 'al', requiresRegisterSaveArea: true },
		callerSaved: ['rax', 'rcx', 'rdx', 'rdi', 'rsi', 'r8', 'r9', 'r10', 'r11', 'xmm0', 'xmm1', 'xmm2', 'xmm3', 'xmm4', 'xmm5', 'xmm6', 'xmm7', 'xmm8', 'xmm9', 'xmm10', 'xmm11', 'xmm12', 'xmm13', 'xmm14', 'xmm15'],
		calleeSaved: ['rbx', 'rbp', 'rsp', 'r12', 'r13', 'r14', 'r15'], hiddenParameters: [
			{ role: 'sret', register: 'rdi', position: 'before-explicit', shiftsExplicitArguments: true },
			{ role: 'varargs-metadata', register: 'al', position: 'convention-specific', shiftsExplicitArguments: false },
		], userDefined: false,
	}),
	aapcs32: () => buildABI({
		id: 'aapcs32', displayName: 'ARM AAPCS32', architecture: 'arm', argumentAllocation: 'independent-register-banks', argumentBanks: [
			{ kind: 'integer', registers: ['r0', 'r1', 'r2', 'r3'], allocation: 'left-to-right' },
			{ kind: 'floating', registers: ['s0', 's1', 's2', 's3', 's4', 's5', 's6', 's7', 's8', 's9', 's10', 's11', 's12', 's13', 's14', 's15'], allocation: 'left-to-right' },
			{ kind: 'vector', registers: ['d0', 'd1', 'd2', 'd3', 'd4', 'd5', 'd6', 'd7'], allocation: 'left-to-right' },
		], stack: { direction: 'down', argumentOrder: 'left-to-right', argumentBaseBytes: 0, slotSizeBytes: 4, alignmentBytes: 8, cleanup: 'caller', shadowSpaceBytes: 0, redZoneBytes: 0 },
		returns: { integer: ['r0'], floating: ['s0', 'd0'], vector: ['d0'], splitInteger: ['r0', 'r1'] },
		aggregateReturn: { strategy: 'register-up-to-bits', classifier: 'aapcs32', registerLimitBits: 32, hiddenPointerRegister: 'r0', hiddenPointerConsumesArgumentSlot: true, returnsHiddenPointer: 'r0' },
		variadic: { supported: true, floatingArgumentsUseIntegerBank: true }, callerSaved: ['r0', 'r1', 'r2', 'r3', 'r12', 'lr', 's0', 's1', 's2', 's3', 's4', 's5', 's6', 's7', 's8', 's9', 's10', 's11', 's12', 's13', 's14', 's15'],
		calleeSaved: ['r4', 'r5', 'r6', 'r7', 'r8', 'r9', 'r10', 'r11', 'sp', 'd8', 'd9', 'd10', 'd11', 'd12', 'd13', 'd14', 'd15'],
		hiddenParameters: [{ role: 'sret', register: 'r0', position: 'before-explicit', shiftsExplicitArguments: true }], userDefined: false,
	}),
	aapcs64: () => buildABI({
		id: 'aapcs64', displayName: 'AArch64 AAPCS64', architecture: 'aarch64', argumentAllocation: 'independent-register-banks', argumentBanks: [
			{ kind: 'integer', registers: ['x0', 'x1', 'x2', 'x3', 'x4', 'x5', 'x6', 'x7'], allocation: 'left-to-right' },
			{ kind: 'floating', registers: ['v0', 'v1', 'v2', 'v3', 'v4', 'v5', 'v6', 'v7'], allocation: 'left-to-right' },
			{ kind: 'vector', registers: ['v0', 'v1', 'v2', 'v3', 'v4', 'v5', 'v6', 'v7'], allocation: 'left-to-right' },
		], stack: { direction: 'down', argumentOrder: 'left-to-right', argumentBaseBytes: 0, slotSizeBytes: 8, alignmentBytes: 16, cleanup: 'caller', shadowSpaceBytes: 0, redZoneBytes: 0 },
		returns: { integer: ['x0'], floating: ['v0'], vector: ['v0'], splitInteger: ['x0', 'x1'] },
		aggregateReturn: { strategy: 'register-classification', classifier: 'aapcs64', hiddenPointerRegister: 'x8', hiddenPointerConsumesArgumentSlot: false },
		variadic: { supported: true, requiresRegisterSaveArea: true }, callerSaved: ['x0', 'x1', 'x2', 'x3', 'x4', 'x5', 'x6', 'x7', 'x8', 'x9', 'x10', 'x11', 'x12', 'x13', 'x14', 'x15', 'x16', 'x17', 'x30', 'v0', 'v1', 'v2', 'v3', 'v4', 'v5', 'v6', 'v7', 'v16', 'v17', 'v18', 'v19', 'v20', 'v21', 'v22', 'v23', 'v24', 'v25', 'v26', 'v27', 'v28', 'v29', 'v30', 'v31'],
		calleeSaved: ['x19', 'x20', 'x21', 'x22', 'x23', 'x24', 'x25', 'x26', 'x27', 'x28', 'x29', 'sp'],
		partialCalleeSaved: [{ registers: ['v8', 'v9', 'v10', 'v11', 'v12', 'v13', 'v14', 'v15'], preservedLowBits: 64 }],
		platformSpecificRegisters: ['x18'],
		hiddenParameters: [{ role: 'sret', register: 'x8', position: 'before-explicit', shiftsExplicitArguments: false }], userDefined: false,
	}),
};

const ABI_MODELS: Readonly<Record<CallingConventionId, ABIModel>> = Object.freeze({
	cdecl: ABI_MODEL_BUILDERS.cdecl(), stdcall: ABI_MODEL_BUILDERS.stdcall(), fastcall: ABI_MODEL_BUILDERS.fastcall(),
	thiscall: ABI_MODEL_BUILDERS.thiscall(), vectorcall: ABI_MODEL_BUILDERS.vectorcall(), usercall: ABI_MODEL_BUILDERS.usercall(),
	win64: ABI_MODEL_BUILDERS.win64(), sysv64: ABI_MODEL_BUILDERS.sysv64(),
	aapcs32: ABI_MODEL_BUILDERS.aapcs32(), aapcs64: ABI_MODEL_BUILDERS.aapcs64(),
});

export function listABIModels(): ABIModel[] {
	return (Object.keys(ABI_MODELS) as CallingConventionId[]).sort().map(id => ABI_MODELS[id]);
}

export function getABIModel(id: CallingConventionId): ABIModel {
	return ABI_MODELS[normalizeCallingConventionId(id)];
}

export type ABIAggregateValueClass =
	| 'integer'
	| 'sse'
	| 'sseup'
	| 'x87'
	| 'x87up'
	| 'complex-x87'
	| 'no-class'
	| 'floating'
	| 'vector'
	| 'memory';

export interface ABIAggregateReturnInput {
	sizeBits: number;
	trivial?: boolean;
	eightByteClasses?: readonly ABIAggregateValueClass[];
	homogeneousMemberClass?: 'floating' | 'vector';
	homogeneousMemberCount?: number;
}

export interface ABIAggregateReturnDecision {
	kind: 'registers' | 'hidden-pointer' | 'indeterminate';
	registers: readonly string[];
	hiddenPointerRegister?: string;
	reason: string;
}

export function classifyAggregateReturn(
	modelOrId: ABIModel | CallingConventionId,
	input: ABIAggregateReturnInput,
): ABIAggregateReturnDecision {
	const model = typeof modelOrId === 'string' ? getABIModel(modelOrId) : modelOrId;
	const sizeBits = requirePositiveInteger(input.sizeBits, 'Aggregate size');
	const homogeneousMemberCount = input.homogeneousMemberCount !== undefined
		? requirePositiveInteger(input.homogeneousMemberCount, 'Homogeneous aggregate member count')
		: undefined;
	if (input.homogeneousMemberClass !== undefined
		&& !['floating', 'vector'].includes(input.homogeneousMemberClass)) {
		throw new Error(`Unknown homogeneous aggregate class: ${String(input.homogeneousMemberClass)}`);
	}
	if ((input.homogeneousMemberClass === undefined) !== (homogeneousMemberCount === undefined)) {
		throw new Error('Homogeneous aggregate class and member count must be provided together.');
	}
	const contract = model.aggregateReturn;
	const hidden = (reason: string): ABIAggregateReturnDecision => deepFreeze({
		kind: 'hidden-pointer',
		registers: [],
		...(contract.hiddenPointerRegister ? { hiddenPointerRegister: contract.hiddenPointerRegister } : {}),
		reason,
	});
	const registers = (locations: readonly string[], reason: string): ABIAggregateReturnDecision => deepFreeze({
		kind: 'registers', registers: locations.map(normalizeRegister), reason,
	});
	const indeterminate = (reason: string): ABIAggregateReturnDecision => deepFreeze({
		kind: 'indeterminate', registers: [], reason,
	});

	if (contract.strategy === 'hidden-pointer') {
		return hidden(`${model.id} specifies aggregate return through hidden storage`);
	}
	if (contract.strategy === 'user-defined') {
		return indeterminate('usercall requires an explicit aggregate return location');
	}
	if (contract.strategy === 'register-up-to-bits') {
		if (contract.requiresTrivialAggregate && input.trivial !== true) {
			return hidden(`${model.id} requires a proven trivial aggregate for register return`);
		}
		if (contract.registerSizesBits && !contract.registerSizesBits.includes(sizeBits)) {
			return hidden(`${sizeBits}-bit aggregate is not an allowed ${model.id} register-return size`);
		}
		if (contract.registerLimitBits !== undefined && sizeBits > contract.registerLimitBits) {
			return hidden(`${sizeBits}-bit aggregate exceeds the ${contract.registerLimitBits}-bit register-return limit`);
		}
		if (contract.classifier === 'x86-msvc' && sizeBits === 64) {
			return registers(model.returns.splitInteger ?? ['edx', 'eax'], 'x86 MSVC 8-byte aggregate return');
		}
		return registers(model.returns.integer.slice(0, 1), `${model.id} aggregate satisfies its register-return contract`);
	}

	switch (contract.classifier) {
		case 'sysv-eightbyte': {
			const classes = input.eightByteClasses;
			if (!classes || classes.length === 0) {
				return indeterminate('SysV aggregate return requires explicit eightbyte classification');
			}
			if (classes.length === 1 && classes[0] === 'complex-x87') {
				return sizeBits === 256
					? registers(['st0', 'st1'], 'SysV complex long double return')
					: indeterminate('SysV COMPLEX_X87 class requires a 256-bit complex long double');
			}
			if (sizeBits > 128 || classes.length > 2 || classes.includes('memory')) {
				return hidden('SysV aggregate is MEMORY class or exceeds two eightbytes');
			}
			if (classes.length !== Math.ceil(sizeBits / 64)
				|| classes.some(valueClass => ![
					'integer', 'sse', 'sseup', 'x87', 'x87up', 'complex-x87', 'no-class', 'floating', 'vector',
				].includes(valueClass))) {
				return indeterminate('SysV eightbyte classes do not match aggregate size or contain an unknown class');
			}
			let integerIndex = 0;
			let vectorIndex = 0;
			let lastVectorRegister: string | undefined;
			let sawX87 = false;
			const locations: string[] = [];
			for (const valueClass of classes) {
				if (valueClass === 'integer') {
					const register = ['rax', 'rdx'][integerIndex++];
					if (!register) { return hidden('SysV integer return register capacity exceeded'); }
					locations.push(register);
				} else if (['sse', 'floating', 'vector'].includes(valueClass)) {
					const register = ['xmm0', 'xmm1'][vectorIndex++];
					if (!register) { return hidden('SysV SSE return register capacity exceeded'); }
					locations.push(register);
					lastVectorRegister = register;
				} else if (valueClass === 'sseup') {
					if (!lastVectorRegister) { return indeterminate('SysV SSEUP class lacks a preceding SSE class'); }
					if (!locations.includes(lastVectorRegister)) { locations.push(lastVectorRegister); }
				} else if (valueClass === 'x87') {
					locations.push('st0');
					sawX87 = true;
				} else if (valueClass === 'x87up') {
					if (!sawX87) { return indeterminate('SysV X87UP class lacks a preceding X87 class'); }
				} else if (valueClass === 'complex-x87') {
					locations.push('st0', 'st1');
				} else if (valueClass === 'no-class') {
					continue;
				}
			}
			return registers(locations, 'SysV eightbyte classes fit return registers');
		}
		case 'aapcs64': {
			const memberCount = homogeneousMemberCount ?? 0;
			if (input.homogeneousMemberClass && memberCount >= 1 && memberCount <= 4) {
				const memberSizeBits = sizeBits / memberCount;
				const allowedSizes = input.homogeneousMemberClass === 'floating'
					? [16, 32, 64, 128]
					: [64, 128];
				if (!Number.isInteger(memberSizeBits) || !allowedSizes.includes(memberSizeBits)) {
					return indeterminate('AAPCS64 homogeneous aggregate size is inconsistent with its member class/count');
				}
				return registers(['v0', 'v1', 'v2', 'v3'].slice(0, memberCount), 'AAPCS64 HFA/HVA return');
			}
			if (sizeBits <= 128) {
				return registers(['x0', 'x1'].slice(0, Math.ceil(sizeBits / 64)), 'AAPCS64 aggregate fits general return registers');
			}
			return hidden('AAPCS64 aggregate does not fit result registers');
		}
		case 'x86-vectorcall-hva': {
			const memberCount = homogeneousMemberCount ?? 0;
			if (input.homogeneousMemberClass && memberCount >= 1 && memberCount <= 4) {
				const memberSizeBits = sizeBits / memberCount;
				const allowedSizes = input.homogeneousMemberClass === 'floating' ? [32, 64] : [128, 256];
				if (!Number.isInteger(memberSizeBits) || !allowedSizes.includes(memberSizeBits)) {
					return indeterminate('x86 vectorcall homogeneous aggregate size is inconsistent with its member class/count');
				}
				const registerPrefix = input.homogeneousMemberClass === 'vector' && memberSizeBits === 256 ? 'ymm' : 'xmm';
				return registers(
					[0, 1, 2, 3].slice(0, memberCount).map(index => `${registerPrefix}${index}`),
					'x86 vectorcall homogeneous aggregate return',
				);
			}
			if (input.trivial === true && [8, 16, 32, 64].includes(sizeBits)) {
				return registers(sizeBits === 64 ? ['edx', 'eax'] : ['eax'], 'x86 vectorcall integer-class aggregate return');
			}
			return hidden('x86 vectorcall aggregate is not a proven HVA/HFA');
		}
		default:
			return indeterminate(`${model.id} has no executable aggregate classifier`);
	}
}

export function createUsercallABI(overrides: Partial<Omit<ABIModelWithoutHash, 'id' | 'userDefined'>>): ABIModel {
	const { canonicalHash: _canonicalHash, ...base } = ABI_MODEL_BUILDERS.usercall();
	return buildABI({
		...base,
		...overrides,
		id: 'usercall',
		userDefined: true,
	});
}

export function resolveArchitectureDefaultABI(
	architecture: 'x86' | 'x86_64' | 'arm' | 'aarch64',
	platform: 'windows' | 'linux' | 'macos' | 'unknown',
	generation = 0,
): ResolvedABI {
	if (architecture === 'x86_64' && platform === 'unknown') {
		throw new Error('x86_64 architecture defaults require a platform to distinguish Win64 from SysV64.');
	}
	const id: CallingConventionId = architecture === 'x86'
		? 'cdecl'
		: architecture === 'x86_64'
			? (platform === 'windows' ? 'win64' : 'sysv64')
			: architecture === 'arm' ? 'aapcs32' : 'aapcs64';
	return {
		model: getABIModel(id),
		inferred: true,
		evidence: normalizeSemanticEvidence({
			strength: 'guessed',
			source: 'architecture-default',
			producer: `abi-default:${platform}:${architecture}`,
			generation,
		}),
	};
}
