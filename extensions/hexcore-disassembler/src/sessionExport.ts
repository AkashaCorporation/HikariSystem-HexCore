/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import * as crypto from 'crypto';
import type { DisassemblerEngine, Function } from './disassemblerEngine';
import { canonicalSerialize } from './semanticModel';

export const SESSION_EXPORT_COLLECTIONS = [
	'functions', 'xrefs', 'callers', 'imports', 'strings', 'sections', 'unwind',
] as const;
export type SessionExportCollection = typeof SESSION_EXPORT_COLLECTIONS[number];

export interface SessionExportOptions {
	format?: 'json';
	include?: SessionExportCollection[];
	limit?: number;
}

interface CollectionEnvelope<T> {
	total: number;
	returned: number;
	truncated: boolean;
	items: T[];
}

function hex(address: number): string {
	return `0x${address.toString(16).toUpperCase()}`;
}

function boundedLimit(value: unknown): number {
	const limit = value === undefined ? 100_000 : Number(value);
	if (!Number.isSafeInteger(limit) || limit < 1 || limit > 1_000_000) {
		throw new Error('session.export limit must be an integer in the range 1..1000000.');
	}
	return limit;
}

function collection<T>(items: T[], limit: number): CollectionEnvelope<T> {
	const selected = items.slice(0, limit);
	return { total: items.length, returned: selected.length, truncated: selected.length < items.length, items: selected };
}

function containingOwner(functions: readonly Function[], address: number): Function | undefined {
	let lo = 0;
	let hi = functions.length - 1;
	let candidate: Function | undefined;
	while (lo <= hi) {
		const mid = lo + ((hi - lo) >> 1);
		const fn = functions[mid];
		if (fn.address <= address) { candidate = fn; lo = mid + 1; } else { hi = mid - 1; }
	}
	return candidate && address < candidate.endAddress ? candidate : undefined;
}

export function runSessionExport(engine: DisassemblerEngine, options: SessionExportOptions = {}) {
	if (options.format !== undefined && options.format !== 'json') {
		throw new Error('session.export currently supports format:"json" only.');
	}
	const limit = boundedLimit(options.limit);
	const include = options.include ?? [...SESSION_EXPORT_COLLECTIONS];
	if (!Array.isArray(include) || include.length === 0) {
		throw new Error('session.export include must be a non-empty array.');
	}
	const unknown = include.filter(name => !SESSION_EXPORT_COLLECTIONS.includes(name));
	if (unknown.length > 0) { throw new Error(`session.export unknown collection(s): ${unknown.join(', ')}`); }
	const selected = new Set(include);
	const functions = engine.getFunctions();
	const session = engine.getSessionStore()?.getAnalysisSession();
	const universe = engine.getSessionStore()?.getAnalysisUniverseManifest();
	const collections: Record<string, CollectionEnvelope<unknown>> = {};

	if (selected.has('functions')) {
		collections.functions = collection(functions.map(fn => ({
			address: hex(fn.address),
			endExclusive: hex(fn.endAddress),
			name: fn.name,
			size: fn.size,
			bodyStatus: engine.getFunctionBodyStatus(fn.address),
			bodyCompleteness: engine.peekFunctionBodyCompleteness(fn.address),
			discoveryEvidence: engine.getFunctionDiscoveryEvidence(fn.address),
			callerSites: fn.callers.map(hex),
			callees: fn.callees.map(hex),
		})), limit);
	}
	if (selected.has('xrefs')) {
		collections.xrefs = collection(engine.getAllCrossReferences().map(xref => {
			const owner = containingOwner(functions, xref.from);
			return {
				from: hex(xref.from), to: hex(xref.to), type: xref.type,
				ownerFunction: owner ? hex(owner.address) : undefined,
			};
		}), limit);
	}
	if (selected.has('callers')) {
		collections.callers = collection(functions.map(fn => ({
			function: hex(fn.address),
			callerSites: fn.callers.map(hex),
			callees: fn.callees.map(hex),
		})), limit);
	}
	if (selected.has('imports')) {
		const imports = engine.getImports()
			.flatMap(library => library.functions.map(fn => ({
				library: library.name,
				name: fn.name,
				address: hex(fn.address),
				...(fn.ordinal !== undefined ? { ordinal: fn.ordinal } : {}),
				...(fn.hint !== undefined ? { hint: fn.hint } : {}),
			})))
			.sort((left, right) => left.library.localeCompare(right.library) || left.address.localeCompare(right.address) || left.name.localeCompare(right.name));
		collections.imports = collection(imports, limit);
	}
	if (selected.has('strings')) {
		collections.strings = collection(engine.getStrings().map(entry => ({
			address: hex(entry.address), string: entry.string, encoding: entry.encoding,
			references: entry.references.map(hex),
			...(entry.fileOffset !== undefined ? { fileOffset: entry.fileOffset } : {}),
			...(entry.evidenceClass ? { evidenceClass: entry.evidenceClass } : {}),
			...(entry.literalConfidence !== undefined ? { literalConfidence: entry.literalConfidence } : {}),
		})), limit);
	}
	if (selected.has('sections')) {
		collections.sections = collection(engine.getSections().map(section => ({
			name: section.name,
			virtualAddress: hex(section.virtualAddress),
			virtualSize: section.virtualSize,
			rawAddress: section.rawAddress,
			rawSize: section.rawSize,
			permissions: section.permissions,
			isCode: section.isCode,
			isData: section.isData,
			isExecutable: section.isExecutable,
		})), limit);
	}
	if (selected.has('unwind')) {
		const baseAddress = engine.getBaseAddress();
		collections.unwind = collection(engine.getPdataEntries().map(entry => ({
			beginRva: hex(entry.beginAddress),
			endRvaExclusive: hex(entry.endAddress),
			beginAddress: hex(baseAddress + entry.beginAddress),
			endAddressExclusive: hex(baseAddress + entry.endAddress),
			unwindInfoRva: hex(entry.unwindInfoAddress),
		})), limit);
	}

	const truncatedCollections = Object.entries(collections)
		.filter(([, value]) => value.truncated)
		.map(([name]) => name);
	const payload = {
		schemaVersion: 1 as const,
		status: truncatedCollections.length > 0 ? 'partial' as const : 'ok' as const,
		semanticStatus: truncatedCollections.length > 0 ? 'partial' as const : 'ok' as const,
		target: engine.getFilePath(),
		fileInfo: engine.getFileInfo(),
		architecture: engine.getArchitecture(),
		baseAddress: hex(engine.getBaseAddress()),
		analysisComplete: engine.isAnalysisComplete(),
		analysisGeneration: engine.getAnalysisGeneration(),
		closureRestoration: engine.getAnalysisClosureRestoration(),
		...(session ? { session: { id: session.id, generation: session.generation } } : {}),
		...(universe ? {
			universe: {
				sha256: universe.universeSha256,
				materializedFunctions: universe.materializedFunctions.length,
			},
		} : {}),
		include: [...selected],
		limit,
		truncatedCollections,
		collections,
	};
	return Object.freeze({
		...payload,
		outputHash: crypto.createHash('sha256').update(canonicalSerialize(payload), 'utf8').digest('hex'),
	});
}
