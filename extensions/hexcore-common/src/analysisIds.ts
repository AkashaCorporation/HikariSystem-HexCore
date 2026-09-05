/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Akasha Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import {
	AnalysisAddressSpace,
	AnalysisTarget,
	normalizeAddressValue,
	normalizeSha256,
} from './analysisContract';

/**
 * Stable object identities for the Analysis Contract (3.8.4 work item C1).
 *
 * An object ID is a canonical, deterministic string derived exclusively from
 * the target content identity plus kind-specific location/name data. The same
 * binary content analyzed twice must produce the same IDs; IDs never contain
 * run counters, timestamps, randomness, or source paths.
 *
 * Serialized grammar (all components are lowercase; `:` is the separator and
 * never appears inside a component):
 *
 * ```text
 * fn:sha256:<digest>:<space>:<hex>
 * blk:sha256:<digest>:<space>:<fnHex>:<blkHex>
 * insn:sha256:<digest>:<space>:<hex>
 * data:sha256:<digest>:<space>:<hex>
 * str:sha256:<digest>:file-offset:<hex>
 * type:sha256:<digest>:<slug>
 * var:sha256:<digest>:<space>:<fnHex>:<slug>
 * var:sha256:<digest>:global:<slug>
 * xref:sha256:<digest>:<fromSpace>:<fromHex>:<toSpace>:<toHex>:<kindSlug>
 * finding:sha256:<digest>:<categorySlug>:<space>:<hex>
 * finding:sha256:<digest>:<categorySlug>:token:<tokenSlug>
 * artifact:sha256:<digest>   (content-bound; not target-bound)
 * ```
 */

export type AnalysisObjectKind =
	| 'function'
	| 'basic-block'
	| 'instruction'
	| 'data-object'
	| 'string'
	| 'type'
	| 'variable'
	| 'xref'
	| 'finding'
	| 'artifact';

const OBJECT_ID_PREFIXES: Readonly<Record<string, AnalysisObjectKind>> = {
	fn: 'function',
	blk: 'basic-block',
	insn: 'instruction',
	data: 'data-object',
	str: 'string',
	type: 'type',
	var: 'variable',
	xref: 'xref',
	finding: 'finding',
	artifact: 'artifact',
};

export interface AnalysisAddressedObjectIdInput {
	target: AnalysisTarget;
	space: AnalysisAddressSpace;
	address: string | bigint | number;
}

export interface AnalysisBasicBlockIdInput {
	target: AnalysisTarget;
	space: AnalysisAddressSpace;
	/** Entry address of the owning function, in the same address space. */
	functionEntry: string | bigint | number;
	/** Start address of the basic block, in the same address space. */
	blockStart: string | bigint | number;
}

export interface AnalysisStringIdInput {
	target: AnalysisTarget;
	/** File offset of the first byte of the string. */
	fileOffset: string | bigint | number;
}

export interface AnalysisTypeIdInput {
	target: AnalysisTarget;
	/** Type name; normalized to a slug (e.g. `struct _PEB` -> `struct-peb`). */
	name: string;
}

export interface AnalysisVariableIdInput {
	target: AnalysisTarget;
	/** Variable name; normalized to a slug. */
	name: string;
	/** Owning function; omit (or pass 'global') for global variables. */
	owner?: {
		space: AnalysisAddressSpace;
		functionEntry: string | bigint | number;
	} | 'global';
}

export interface AnalysisXrefIdInput {
	target: AnalysisTarget;
	from: { space: AnalysisAddressSpace; address: string | bigint | number };
	to: { space: AnalysisAddressSpace; address: string | bigint | number };
	/** Xref kind such as `call`, `jump`, `data-read`; normalized to a slug. */
	kind: string;
}

export interface AnalysisFindingIdInput {
	target: AnalysisTarget;
	/** Finding category such as `anti-debug`, `network-url`; normalized to a slug. */
	category: string;
	/** What the finding describes: an address, or an opaque subject token. */
	subject:
		| { space: AnalysisAddressSpace; address: string | bigint | number }
		| { token: string };
}

export interface ParsedAnalysisObjectId {
	kind: AnalysisObjectKind;
	/** Owning target id (`target:sha256:<digest>`); undefined for content-bound artifact IDs. */
	targetId?: string;
	/** Raw 64-hex digest embedded in the ID (target digest, or content digest for artifacts). */
	digest: string;
	/** Discriminator components after the digest (spaces, addresses, slugs). */
	parts: string[];
}

/** Stable ID for a function, derived from its entry address. */
export function createFunctionId(input: AnalysisAddressedObjectIdInput): string {
	return addressedId('fn', input.target, input.space, input.address);
}

/** Stable ID for a basic block, derived from its owning function and start address. */
export function createBasicBlockId(input: AnalysisBasicBlockIdInput): string {
	const digest = targetDigest(input.target);
	return `blk:sha256:${digest}:${input.space}:${normalizeAddressValue(input.functionEntry)}:${normalizeAddressValue(input.blockStart)}`;
}

/** Stable ID for an instruction, derived from its address. */
export function createInstructionId(input: AnalysisAddressedObjectIdInput): string {
	return addressedId('insn', input.target, input.space, input.address);
}

/** Stable ID for a data object, derived from its address. */
export function createDataObjectId(input: AnalysisAddressedObjectIdInput): string {
	return addressedId('data', input.target, input.space, input.address);
}

/** Stable ID for an extracted string, derived from its file offset. */
export function createStringId(input: AnalysisStringIdInput): string {
	return `str:sha256:${targetDigest(input.target)}:file-offset:${normalizeAddressValue(input.fileOffset)}`;
}

/** Stable ID for a named type (struct, union, enum, signature). */
export function createTypeId(input: AnalysisTypeIdInput): string {
	return `type:sha256:${targetDigest(input.target)}:${normalizeIdSlug(input.name, 'type name')}`;
}

/** Stable ID for a variable, owned by a function or global. */
export function createVariableId(input: AnalysisVariableIdInput): string {
	const digest = targetDigest(input.target);
	const slug = normalizeIdSlug(input.name, 'variable name');
	if (!input.owner || input.owner === 'global') {
		return `var:sha256:${digest}:global:${slug}`;
	}
	return `var:sha256:${digest}:${input.owner.space}:${normalizeAddressValue(input.owner.functionEntry)}:${slug}`;
}

/** Stable ID for a cross-reference, derived from both endpoints and its kind. */
export function createXrefId(input: AnalysisXrefIdInput): string {
	const digest = targetDigest(input.target);
	return `xref:sha256:${digest}:${input.from.space}:${normalizeAddressValue(input.from.address)}` +
		`:${input.to.space}:${normalizeAddressValue(input.to.address)}:${normalizeIdSlug(input.kind, 'xref kind')}`;
}

/** Stable ID for a finding, derived from its category and subject. */
export function createFindingId(input: AnalysisFindingIdInput): string {
	const digest = targetDigest(input.target);
	const category = normalizeIdSlug(input.category, 'finding category');
	if ('token' in input.subject) {
		return `finding:sha256:${digest}:${category}:token:${normalizeIdSlug(input.subject.token, 'finding subject token')}`;
	}
	return `finding:sha256:${digest}:${category}:${input.subject.space}:${normalizeAddressValue(input.subject.address)}`;
}

/** Content-bound artifact ID (the existing `artifact:sha256:` form). */
export function createArtifactId(contentSha256: string): string {
	return `artifact:sha256:${normalizeSha256(contentSha256)}`;
}

/**
 * Parse and validate a stable object ID. Throws on malformed input; use
 * `isAnalysisObjectId` for a non-throwing check.
 */
export function parseAnalysisObjectId(id: string): ParsedAnalysisObjectId {
	const components = id.trim().split(':');
	if (components.length < 3) {
		throw new Error(`Malformed analysis object ID: ${id}`);
	}
	const kind = OBJECT_ID_PREFIXES[components[0]];
	if (!kind) {
		throw new Error(`Unknown analysis object ID prefix: ${components[0]}`);
	}
	if (components[1] !== 'sha256') {
		throw new Error(`Analysis object IDs must use sha256 identity: ${id}`);
	}
	const digest = normalizeSha256(components[2]);
	const parts = components.slice(3);
	if (kind !== 'artifact' && parts.length === 0) {
		throw new Error(`Analysis object ID is missing its discriminator: ${id}`);
	}
	for (const part of parts) {
		if (part.length === 0) {
			throw new Error(`Analysis object ID contains an empty component: ${id}`);
		}
	}
	return {
		kind,
		...(kind === 'artifact' ? {} : { targetId: `target:sha256:${digest}` }),
		digest,
		parts,
	};
}

/** Non-throwing stable-ID check for integration boundaries. */
export function isAnalysisObjectId(value: unknown): value is string {
	if (typeof value !== 'string') {
		return false;
	}
	try {
		parseAnalysisObjectId(value);
		return true;
	} catch {
		return false;
	}
}

/**
 * Owning target id for provenance/wrong-target checks. Returns undefined for
 * content-bound artifact IDs, which are not tied to a single target.
 */
export function analysisObjectIdTargetId(id: string): string | undefined {
	return parseAnalysisObjectId(id).targetId;
}

function addressedId(
	prefix: string,
	target: AnalysisTarget,
	space: AnalysisAddressSpace,
	address: string | bigint | number,
): string {
	return `${prefix}:sha256:${targetDigest(target)}:${space}:${normalizeAddressValue(address)}`;
}

function targetDigest(target: AnalysisTarget): string {
	return normalizeSha256(target.binarySha256);
}

/**
 * Normalize a free-form token (names, categories, kinds) into an ID-safe
 * slug: lowercase ASCII alphanumeric runs joined by single dashes. Throws
 * when nothing usable remains.
 */
function normalizeIdSlug(value: string, label: string): string {
	const slug = value.trim().toLowerCase()
		.replace(/[^a-z0-9]+/g, '-')
		.replace(/^-+|-+$/g, '');
	if (!slug) {
		throw new Error(`${label} cannot be empty or contain no ASCII alphanumeric characters`);
	}
	if (slug.length > 128) {
		throw new Error(`${label} cannot exceed 128 characters`);
	}
	return slug;
}
