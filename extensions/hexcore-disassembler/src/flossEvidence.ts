import * as crypto from 'crypto';

export type FlossFactKind = 'static-string' | 'language-string' | 'language-string-missed' | 'stack-string' | 'tight-string' | 'decoded-string';
export type FlossResolution = 'exact' | 'ambiguous' | 'unresolved';

export interface FlossEvidenceContext {
	binarySha256: string;
	toolVersion: string;
	toolSha256: string;
	configurationSha256: string;
	normalizationPolicyId: string;
	normalizationPolicySha256: string;
}

export interface FlossStringFact {
	id: string;
	kind: FlossFactKind;
	value: string;
	encoding: string;
	evidenceLevel: 'signal';
	promotionAllowed: false;
	resolution: FlossResolution;
	fileOffset?: string;
	functionAddress?: string;
	programCounter?: string;
	stackPointer?: string;
	originalStackPointer?: string;
	stackOffset?: string;
	frameOffset?: string;
	address?: string;
	addressType?: 'STACK' | 'GLOBAL' | 'HEAP';
	decodedAt?: string;
	decodingRoutine?: string;
}

export interface FlossEvidenceReport {
	schemaVersion: 1;
	producer: 'mandiant.flare-floss';
	targetSha256: string;
	toolVersion: string;
	toolSha256: string;
	configurationSha256: string;
	normalizationPolicyId: string;
	normalizationPolicySha256: string;
	sourceJsonSha256: string;
	imageBase: string;
	minimumLength: number;
	facts: FlossStringFact[];
	normalizedSha256: string;
}

const SHA256 = /^[a-f0-9]{64}$/;
const ENCODINGS = new Set(['ASCII', 'UTF-8', 'UTF-16LE']);

export function importFlossEvidence(jsonText: string, context: FlossEvidenceContext): FlossEvidenceReport {
	for (const [name, hash] of Object.entries({
		binarySha256: context.binarySha256,
		toolSha256: context.toolSha256,
		configurationSha256: context.configurationSha256,
		normalizationPolicySha256: context.normalizationPolicySha256,
	})) {
		if (!SHA256.test(hash)) throw new Error(`FLOSS ${name} must be a lowercase SHA-256`);
	}
	if (!/^[a-z0-9][a-z0-9._-]+$/.test(context.normalizationPolicyId)) throw new Error('FLOSS normalizationPolicyId is invalid');
	let document: any;
	try { document = JSON.parse(jsonText.replace(/^\uFEFF/, '')); }
	catch (error) { throw new Error(`Malformed FLOSS JSON: ${error instanceof Error ? error.message : String(error)}`); }
	if (!document || typeof document !== 'object' || Array.isArray(document)) throw new Error('FLOSS result must be an object');
	if (document.metadata?.version !== context.toolVersion) throw new Error(`Unsupported FLOSS result version ${String(document.metadata?.version)}`);
	if (!/^3\.1\./.test(context.toolVersion)) throw new Error(`Unsupported FLOSS importer version ${context.toolVersion}`);
	if (!document.strings || typeof document.strings !== 'object') throw new Error('FLOSS result is missing strings');
	const imageBase = exactHex(document.metadata?.imagebase, 'metadata.imagebase');
	const minimumLength = safeInteger(document.metadata?.min_length, 'metadata.min_length', 0);
	const facts = new Map<string, FlossStringFact>();

	const add = (payload: Omit<FlossStringFact, 'id' | 'evidenceLevel' | 'promotionAllowed'>): void => {
		const canonical = canonicalJson(payload);
		const id = `floss:sha256:${sha256(canonical)}`;
		facts.set(id, { id, evidenceLevel: 'signal', promotionAllowed: false, ...payload });
	};
	const staticKinds: Array<[string, FlossFactKind]> = [
		['static_strings', 'static-string'], ['language_strings', 'language-string'], ['language_strings_missed', 'language-string-missed'],
	];
	for (const [field, kind] of staticKinds) {
		for (const [index, raw] of array(document.strings[field], `strings.${field}`).entries()) {
			const item = record(raw, `strings.${field}[${index}]`);
			add({ kind, value: stringField(item.string, `${field}.string`), encoding: encoding(item.encoding), resolution: 'exact', fileOffset: exactHex(item.offset, `${field}.offset`) });
		}
	}
	for (const [field, kind] of [['stack_strings', 'stack-string'], ['tight_strings', 'tight-string']] as const) {
		for (const [index, raw] of array(document.strings[field], `strings.${field}`).entries()) {
			const item = record(raw, `strings.${field}[${index}]`);
			add({
				kind, value: stringField(item.string, `${field}.string`), encoding: encoding(item.encoding), resolution: 'exact',
				functionAddress: exactHex(item.function, `${field}.function`), programCounter: exactHex(item.program_counter, `${field}.program_counter`),
				stackPointer: exactHex(item.stack_pointer, `${field}.stack_pointer`), originalStackPointer: exactHex(item.original_stack_pointer, `${field}.original_stack_pointer`),
				stackOffset: exactSigned(item.offset, `${field}.offset`), frameOffset: exactSigned(item.frame_offset, `${field}.frame_offset`),
			});
		}
	}
	for (const [index, raw] of array(document.strings.decoded_strings, 'strings.decoded_strings').entries()) {
		const item = record(raw, `strings.decoded_strings[${index}]`);
		if (!['STACK', 'GLOBAL', 'HEAP'].includes(item.address_type)) throw new Error(`decoded string ${index} has invalid address_type`);
		add({
			kind: 'decoded-string', value: stringField(item.string, 'decoded.string'), encoding: encoding(item.encoding), resolution: 'exact',
			address: exactHex(item.address, 'decoded.address'), addressType: item.address_type,
			decodedAt: exactHex(item.decoded_at, 'decoded.decoded_at'), decodingRoutine: exactHex(item.decoding_routine, 'decoded.decoding_routine'),
		});
	}
	const sortedFacts = [...facts.values()].sort((left, right) => left.id < right.id ? -1 : left.id > right.id ? 1 : 0);
	const stableIdentity = {
		schemaVersion: 1 as const, producer: 'mandiant.flare-floss' as const, targetSha256: context.binarySha256,
		toolVersion: context.toolVersion, toolSha256: context.toolSha256, configurationSha256: context.configurationSha256,
		normalizationPolicyId: context.normalizationPolicyId, normalizationPolicySha256: context.normalizationPolicySha256,
		imageBase, minimumLength, facts: sortedFacts,
	};
	return { ...stableIdentity, sourceJsonSha256: sha256(jsonText), normalizedSha256: sha256(canonicalJson(stableIdentity)) };
}

function canonicalJson(value: unknown): string {
	if (value === null || typeof value !== 'object') return JSON.stringify(value);
	if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
	const object = value as Record<string, unknown>;
	return `{${Object.keys(object).filter(key => object[key] !== undefined).sort().map(key => `${JSON.stringify(key)}:${canonicalJson(object[key])}`).join(',')}}`;
}
function sha256(value: string): string { return crypto.createHash('sha256').update(value, 'utf8').digest('hex'); }
function array(value: unknown, label: string): unknown[] { if (!Array.isArray(value)) throw new Error(`FLOSS ${label} must be an array`); return value; }
function record(value: unknown, label: string): Record<string, any> { if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error(`FLOSS ${label} must be an object`); return value as Record<string, any>; }
function stringField(value: unknown, label: string): string { if (typeof value !== 'string') throw new Error(`FLOSS ${label} must be a string`); return value; }
function encoding(value: unknown): string { if (typeof value !== 'string' || !ENCODINGS.has(value)) throw new Error(`FLOSS encoding ${String(value)} is unsupported`); return value; }
function safeInteger(value: unknown, label: string, minimum?: number): number { if (!Number.isSafeInteger(value) || (minimum !== undefined && Number(value) < minimum)) throw new Error(`FLOSS ${label} must be a safe integer`); return Number(value); }
function exactHex(value: unknown, label: string): string { return `0x${BigInt(safeInteger(value, label, 0)).toString(16)}`; }
function exactSigned(value: unknown, label: string): string { return BigInt(safeInteger(value, label)).toString(10); }
