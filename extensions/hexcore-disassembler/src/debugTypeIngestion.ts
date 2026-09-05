/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Akasha Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as crypto from 'crypto';
import type { StructInfoJson } from './elfBtfLoader';
import {
	canonicalSerialize,
	SemanticTypeCatalog,
	type CanonicalSemanticType,
	type SemanticEvidence,
	type SemanticTypeMemberSpec,
} from './semanticModel';
import type { SemanticStore } from './semanticStore';

export interface ExtendedDebugField {
	name: string;
	offset: string;
	size: number;
	type: string;
	bitOffset?: number;
	bitSize?: number;
	arrayStrideBits?: number;
	anonymous?: boolean;
	nested?: boolean;
	bitfield?: boolean;
}

export interface ExtendedDebugRecord {
	kind?: 'struct' | 'union';
	size: number;
	align?: number;
	packed?: boolean;
	fields: ExtendedDebugField[];
}

export type ExtendedStructInfoJson = Omit<StructInfoJson, 'structs'> & {
	structs: Record<string, ExtendedDebugRecord>;
};

export interface DebugTypeIngestionOptions {
	provider: 'btf' | 'dwarf' | 'pdb' | 'manual-debug-adapter';
	unitIdentity: string;
	generation: number;
	pointerSizeBits?: 32 | 64;
	longSizeBits?: 32 | 64;
}

export interface DebugTypeIngestionResult {
	status: 'ok' | 'partial';
	provider: DebugTypeIngestionOptions['provider'];
	unitIdentity: string;
	recordCount: number;
	typeCount: number;
	opaqueFieldCount: number;
	functionSignaturesDeferred: number;
	typeIds: readonly string[];
	transactionHash: string;
	contentHash: string;
}

function compareAscii(left: string, right: string): number { return left < right ? -1 : left > right ? 1 : 0; }
function sha256(value: string): string { return crypto.createHash('sha256').update(value).digest('hex'); }

function parseOffset(value: string): number {
	const normalized = value.trim();
	const parsed = /^0x[0-9a-f]+$/i.test(normalized) ? Number.parseInt(normalized.slice(2), 16) : Number(normalized);
	if (!Number.isSafeInteger(parsed) || parsed < 0) { throw new Error(`Invalid debug field offset ${value}.`); }
	return parsed;
}

export function ingestDebugTypeInfo(
	store: SemanticStore,
	input: ExtendedStructInfoJson,
	options: DebugTypeIngestionOptions,
): DebugTypeIngestionResult {
	const unitIdentity = options.unitIdentity.trim();
	if (!unitIdentity) { throw new Error('Debug type unit identity must not be empty.'); }
	if (!Number.isSafeInteger(options.generation) || options.generation < 0) { throw new Error('Debug generation must be non-negative.'); }
	const evidence: SemanticEvidence = {
		strength: 'debug', source: 'debug-info', producer: `${options.provider}:${unitIdentity}`, generation: options.generation,
	};
	const catalog = new SemanticTypeCatalog(store.targetIdentity, `${options.provider}:${unitIdentity}`);
	const names = Object.keys(input.structs).sort(compareAscii);
	for (const name of names) {
		const record = input.structs[name];
		catalog.forwardDeclare(record.kind ?? 'struct', name, evidence);
	}
	let opaqueFieldCount = 0;
	for (const name of names) {
		const record = input.structs[name];
		if (!Number.isSafeInteger(record.size) || record.size < 0) { throw new Error(`Invalid debug record size for ${name}.`); }
		const members: SemanticTypeMemberSpec[] = [];
		for (const [index, field] of record.fields.entries()) {
			const parsed = catalog.parseLegacyCType(field.type, evidence, {
				pointerSizeBits: options.pointerSizeBits ?? 64,
				longSizeBits: options.longSizeBits ?? 32,
				targetIdentity: store.targetIdentity,
				nominalScope: `${options.provider}:${unitIdentity}`,
			});
			if (parsed.status === 'opaque') { opaqueFieldCount++; }
			const byteOffset = parseOffset(field.offset);
			const bitOffset = field.bitOffset ?? byteOffset * 8;
			if (!Number.isSafeInteger(bitOffset) || bitOffset < 0) { throw new Error(`Invalid bit offset for ${name}.${field.name}.`); }
			members.push({
				name: field.name.trim() || `anonymous_${index}`,
				typeId: parsed.rootTypeId,
				bitOffset,
				...(field.bitSize !== undefined ? { bitSize: field.bitSize } : field.size > 0 ? { bitSize: field.size * 8 } : {}),
				...(field.arrayStrideBits !== undefined ? { arrayStrideBits: field.arrayStrideBits } : {}),
				anonymous: field.anonymous ?? !field.name.trim(),
				nested: field.nested ?? /\b(?:struct|union)\b/.test(field.type),
				bitfield: field.bitfield ?? field.bitSize !== undefined,
				evidence,
			});
		}
		catalog.defineNominal({
			kind: record.kind ?? 'struct',
			name,
			sizeBits: record.size * 8,
			...(record.align ? { alignBits: record.align * 8 } : {}),
			members,
			dependencies: members.map(member => member.typeId),
		}, evidence);
	}
	const types: CanonicalSemanticType[] = catalog.list();
	const write = store.writeBatch({ types });
	const logical = {
		status: opaqueFieldCount > 0 || Object.keys(input.functions).length > 0 ? 'partial' as const : 'ok' as const,
		provider: options.provider,
		unitIdentity,
		recordCount: names.length,
		typeCount: write.typeResults.length,
		opaqueFieldCount,
		functionSignaturesDeferred: Object.keys(input.functions).length,
		typeIds: write.typeResults.map(item => item.accepted.typeId).sort(compareAscii),
		transactionHash: write.transactionHash,
	};
	return { ...logical, contentHash: sha256(canonicalSerialize(logical)) };
}
