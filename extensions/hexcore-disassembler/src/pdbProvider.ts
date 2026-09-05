/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Akasha Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import { spawnSync } from 'child_process';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import { findPdbutil, parseSectionHeaders } from './pdbLoader';
import type { ExtendedStructInfoJson } from './debugTypeIngestion';

export const PDB_PROVIDER_SCHEMA_VERSION = 1 as const;
export const PDB_PROVIDER_VERSION = 'hexcore-pdb-provider-r36-v1';

export interface PdbIdentity { guid: string; age: number; signature?: number; }
export interface PdbDiagnostic { severity: 'info' | 'warning' | 'error'; code: string; message: string; recordKind?: string; }
export interface PdbLocalSymbol {
	name: string; typeIndex: string; typeName?: string; parameter: boolean;
	locations: readonly { kind: 'register' | 'register-relative' | 'frame-relative' | 'unknown'; register?: string; offset?: number; rangeStart?: string; rangeLength?: number }[];
}
export interface PdbFunctionPrototype {
	typeIndex: string; returnType: string; parameterTypes: readonly string[]; callingConvention: string; variadic: boolean; method: boolean;
}
export interface PdbFunctionSymbol {
	name: string; address: string; endExclusive: string; size: number; section: number; offset: number;
	addressModel: 'pdb-module-record';
	visibility: 'public' | 'private'; prototype?: PdbFunctionPrototype; locals: readonly PdbLocalSymbol[];
}
export interface PdbLineRecord { sourceFile: string; sourceHash?: string; line: number; address: string; }
export interface PdbInlineFrame { inlineeTypeIndex: string; inlineeName?: string; parentRecordOffset: number; endRecordOffset: number; annotations: readonly string[]; }
export interface PdbEnumType { name: string; typeIndex: string; values: readonly { name: string; value: string }[]; }
export interface PdbTypeAlias { name: string; targetTypeIndex: string; }
export interface PdbProviderResult {
	schemaVersion: typeof PDB_PROVIDER_SCHEMA_VERSION;
	providerVersion: typeof PDB_PROVIDER_VERSION;
	status: 'ok' | 'partial' | 'error';
	pdbPath: string; pdbSha256: string; identity?: PdbIdentity; identityValidated: boolean;
	toolPath?: string; toolSha256?: string;
	functions: readonly PdbFunctionSymbol[];
	debugTypes: ExtendedStructInfoJson;
	lines: readonly PdbLineRecord[];
	inlineFrames: readonly PdbInlineFrame[];
	enumTypes: readonly PdbEnumType[];
	typeAliases: readonly PdbTypeAlias[];
	compilands: readonly string[];
	diagnostics: readonly PdbDiagnostic[];
	contentHash: string;
}

interface TypeRecord {
	index: string; kind: string; name?: string; size?: number; fieldList?: string;
	returnType?: string; argList?: string; callingConvention?: string; method?: boolean;
	arguments?: string[]; members?: Array<{ name: string; type: string; typeIndex?: string; offset: number }>;
	enumValues?: Array<{ name: string; value: string }>;
	bitfield?: { type: string; bitOffset: number; bitSize: number };
	referent?: string;
}

export interface PdbProviderOptions {
	pdbPath: string;
	imageBase: number;
	expectedGuid?: string;
	expectedAge?: number;
	timeoutMs?: number;
	maxBufferBytes?: number;
}

export interface PdbResolveOptions {
	pdbName: string; guid: string; age: number; cacheDirectory: string; symbolServers?: readonly string[];
}

function compareAscii(left: string, right: string): number { return left < right ? -1 : left > right ? 1 : 0; }
function sha256Buffer(value: Buffer | string): string { return crypto.createHash('sha256').update(value).digest('hex'); }
function sha256File(file: string): string { return sha256Buffer(fs.readFileSync(file)); }
function normalizeGuid(value: string): string { return value.replace(/[{}-]/g, '').toUpperCase(); }
function hex(address: number): string { return `0x${address.toString(16)}`; }

function runPdbutil(tool: string, args: string[], options: PdbProviderOptions, diagnostics: PdbDiagnostic[]): string | undefined {
	const result = spawnSync(tool, args, {
		encoding: 'utf8', timeout: options.timeoutMs ?? 120_000, maxBuffer: options.maxBufferBytes ?? 512 * 1024 * 1024,
	});
	if (result.status !== 0) {
		diagnostics.push({ severity: 'error', code: 'PDBUTIL_FAILED', message: `${args.join(' ')} failed: ${(result.stderr || '').slice(0, 500)}` });
		return undefined;
	}
	return result.stdout;
}

export function parsePdbSummary(output: string): PdbIdentity | undefined {
	const guid = /^\s*GUID:\s*\{([^}]+)\}/mi.exec(output)?.[1] ?? /^\s*Guid:\s*\{([^}]+)\}/mi.exec(output)?.[1];
	const ageText = /^\s*Age:\s*(\d+)/mi.exec(output)?.[1];
	const signatureText = /^\s*Signature:\s*(\d+)/mi.exec(output)?.[1];
	if (!guid || ageText === undefined) { return undefined; }
	return { guid: normalizeGuid(guid), age: Number(ageText), ...(signatureText ? { signature: Number(signatureText) } : {}) };
}

function typeText(value: string): string {
	const text = /\((.+)\)/.exec(value)?.[1]?.trim();
	return text || `pdb-type:${/^0x[0-9a-f]+/i.exec(value)?.[0]?.toUpperCase() ?? 'unknown'}`;
}

function parseTypeRecords(output: string, diagnostics: PdbDiagnostic[]): Map<string, TypeRecord> {
	const lines = output.split(/\r?\n/);
	const records = new Map<string, TypeRecord>();
	for (let index = 0; index < lines.length; index++) {
		const header = /^\s*(0x[0-9A-Fa-f]+)\s*\|\s*(LF_[A-Z0-9_]+).*?(?:`([^`]+)`)?\s*$/.exec(lines[index]);
		if (!header) { continue; }
		const block: string[] = [];
		for (let cursor = index + 1; cursor < lines.length && !/^\s*0x[0-9A-Fa-f]+\s*\|\s*LF_/.test(lines[cursor]); cursor++) { block.push(lines[cursor]); }
		const indexKey = header[1].toUpperCase();
		const kind = header[2];
		const record: TypeRecord = { index: indexKey, kind, ...(header[3] ? { name: header[3] } : {}) };
		const text = block.join('\n');
		if (['LF_STRUCTURE', 'LF_CLASS', 'LF_UNION'].includes(kind)) {
			record.size = Number(/sizeof\s+(\d+)/i.exec(text)?.[1] ?? 0);
			record.fieldList = /field list:\s*(0x[0-9A-Fa-f]+)/i.exec(text)?.[1]?.toUpperCase();
		}
		if (kind === 'LF_FIELDLIST') {
			record.members = block.flatMap(line => {
				const member = /LF_MEMBER\s*\[name\s*=\s*`([^`]+)`,\s*Type\s*=\s*([^,]+),\s*offset\s*=\s*(-?\d+)/i.exec(line);
				const memberTypeIndex = member ? /0x[0-9A-Fa-f]+/.exec(member[2])?.[0]?.toUpperCase() : undefined;
				return member ? [{ name: member[1], type: typeText(member[2]), ...(memberTypeIndex ? { typeIndex: memberTypeIndex } : {}), offset: Number(member[3]) }] : [];
			});
			record.enumValues = block.flatMap(line => {
				const value = /LF_ENUMERATE\s*\[([^=\]]+)\s*=\s*([^\]]+)\]/i.exec(line);
				return value ? [{ name: value[1].trim(), value: value[2].trim() }] : [];
			});
		}
		if (kind === 'LF_ENUM') {
			record.fieldList = /field list:\s*(0x[0-9A-Fa-f]+)/i.exec(text)?.[1]?.toUpperCase();
		}
		if (kind === 'LF_BITFIELD') {
			const bits = /type\s*=\s*([^,\n]+),\s*bit offset\s*=\s*(\d+),\s*# bits\s*=\s*(\d+)/i.exec(text);
			if (bits) record.bitfield = { type: typeText(bits[1]), bitOffset: Number(bits[2]), bitSize: Number(bits[3]) };
		}
		if (kind === 'LF_POINTER' || kind === 'LF_MODIFIER') {
			record.referent = /(?:referent|type)\s*=\s*(0x[0-9A-Fa-f]+)/i.exec(text)?.[1]?.toUpperCase();
		}
		if (kind === 'LF_ARGLIST') {
			record.arguments = block.flatMap(line => {
				if (/^\s*<no type>:\s*``/.test(line)) return ['...'];
				return /^\s*0x[0-9A-Fa-f]+(?:\s*\([^)]*\))?:\s*`([^`]+)`/.exec(line)?.[1] ?? [];
			}).filter(Boolean);
		}
		if (kind === 'LF_PROCEDURE' || kind === 'LF_MFUNCTION') {
			record.returnType = typeText(/return type\s*=\s*([^,\n]+)/i.exec(text)?.[1] ?? '');
			record.argList = /param list\s*=\s*(0x[0-9A-Fa-f]+)/i.exec(text)?.[1]?.toUpperCase();
			record.callingConvention = /calling conv\s*=\s*([^,\n]+)/i.exec(text)?.[1]?.trim() ?? 'unknown';
			record.method = kind === 'LF_MFUNCTION';
		}
		records.set(indexKey, record);
	}
	const unsupported = new Map<string, number>();
	for (const record of records.values()) {
		if (!['LF_STRUCTURE', 'LF_CLASS', 'LF_UNION', 'LF_FIELDLIST', 'LF_ARGLIST', 'LF_PROCEDURE', 'LF_MFUNCTION',
			'LF_POINTER', 'LF_MODIFIER', 'LF_ARRAY', 'LF_ENUM', 'LF_BITFIELD', 'LF_VTSHAPE', 'LF_METHODLIST'].includes(record.kind)) {
			unsupported.set(record.kind, (unsupported.get(record.kind) ?? 0) + 1);
		}
	}
	for (const [recordKind, count] of [...unsupported].sort(([left], [right]) => compareAscii(left, right))) {
		diagnostics.push({ severity: 'warning', code: 'UNSUPPORTED_TYPE_RECORD', recordKind, message: `${count} ${recordKind} records were retained only as diagnostics.` });
	}
	return records;
}

function parsePrototype(typeIndex: string, records: ReadonlyMap<string, TypeRecord>): PdbFunctionPrototype | undefined {
	const record = records.get(typeIndex.toUpperCase());
	if (!record || !['LF_PROCEDURE', 'LF_MFUNCTION'].includes(record.kind)) { return undefined; }
	const args = record.argList ? records.get(record.argList)?.arguments ?? [] : [];
	const resolve = (value: string, depth = 0): string => {
		if (depth > 12) return value;
		const index = /^pdb-type:(0x[0-9a-f]+)$/i.exec(value)?.[1]?.toUpperCase();
		const type = index ? records.get(index) : undefined;
		if (!type) return value;
		if (['LF_STRUCTURE', 'LF_CLASS'].includes(type.kind) && type.name) return `struct ${type.name}`;
		if (type.kind === 'LF_UNION' && type.name) return `union ${type.name}`;
		if (type.kind === 'LF_ENUM' && type.name) return `enum ${type.name}`;
		if (type.kind === 'LF_POINTER' && type.referent) return `${resolve(`pdb-type:${type.referent}`, depth + 1)} *`;
		if (type.kind === 'LF_MODIFIER' && type.referent) return resolve(`pdb-type:${type.referent}`, depth + 1);
		return type.name ?? value;
	};
	return {
		typeIndex: record.index, returnType: resolve(record.returnType ?? 'unknown'), parameterTypes: args.map(value => resolve(value)),
		callingConvention: record.callingConvention ?? 'unknown', variadic: args.at(-1) === '...', method: record.method === true,
	};
}

function parseFunctions(output: string, sectionVAs: Map<number, number>, imageBase: number, records: ReadonlyMap<string, TypeRecord>): PdbFunctionSymbol[] {
	const lines = output.split(/\r?\n/);
	const functions: PdbFunctionSymbol[] = [];
	for (let index = 0; index < lines.length; index++) {
		const header = /^\s*(\d+)\s*\|\s*S_(GPROC32|LPROC32).*`([^`]+)`/.exec(lines[index]);
		if (!header) { continue; }
		const recordEnd = Number(/end\s*=\s*(\d+)/.exec(lines[index + 1] ?? '')?.[1] ?? Number.MAX_SAFE_INTEGER);
		const address = /addr\s*=\s*(\d+)\s*:\s*([0-9A-Fa-f]+)\s*,\s*code size\s*=\s*(\d+)/.exec(lines[index + 1] ?? '');
		const typeIndex = /type\s*=\s*`?(0x[0-9A-Fa-f]+)/.exec(lines[index + 2] ?? '')?.[1]?.toUpperCase();
		if (!address) { continue; }
		const section = Number(address[1]); const offset = Number.parseInt(address[2], 16); const size = Number(address[3]);
		const sectionVA = sectionVAs.get(section);
		if (sectionVA === undefined || size <= 0) { continue; }
		const locals: Array<{ symbol: PdbLocalSymbol; recordOffset: number; lineIndex: number; topLevel: boolean }> = [];
		let enteredNestedBlock = false;
		for (let cursor = index + 3; cursor < lines.length; cursor++) {
			const offsetMatch = /^\s*(\d+)\s*\|/.exec(lines[cursor]);
			if (offsetMatch && Number(offsetMatch[1]) >= recordEnd) { break; }
			if (/\|\s*S_BLOCK32\b/.test(lines[cursor])) { enteredNestedBlock = true; }
			const local = /^\s*(\d+)\s*\|\s*S_(LOCAL|REGREL32|REGISTER|BPREL32).*`([^`]+)`/.exec(lines[cursor]);
			if (!local) { continue; }
			const detail = lines[cursor + 1] ?? '';
			const localType = /type\s*=\s*(0x[0-9A-Fa-f]+)(?:\s*\(([^)]*)\))?/i.exec(detail);
			const parameter = /flags\s*=.*\bparam\b/i.test(detail);
			const registerRelative = local[2] === 'REGREL32' ? /register\s*=\s*([A-Za-z0-9]+),\s*offset\s*=\s*(-?\d+)/i.exec(detail) : undefined;
			const directRegister = local[2] === 'REGISTER' ? /register\s*=\s*([A-Za-z0-9]+)/i.exec(detail) : undefined;
			const locations: PdbLocalSymbol['locations'] = registerRelative
				? [{ kind: 'register-relative', register: registerRelative[1], offset: Number(registerRelative[2]) }]
				: directRegister ? [{ kind: 'register', register: directRegister[1] }] : [];
			locals.push({ symbol: { name: local[3], typeIndex: localType?.[1]?.toUpperCase() ?? '0x0000', ...(localType?.[2] ? { typeName: localType[2] } : {}), parameter, locations }, recordOffset: Number(local[1]), lineIndex: cursor, topLevel: !enteredNestedBlock });
		}
		for (let localIndex = 0; localIndex < locals.length; localIndex++) {
			const start = locals[localIndex].lineIndex;
			const end = localIndex + 1 < locals.length ? locals[localIndex + 1].lineIndex : Math.min(lines.length, start + 24);
			const block = lines.slice(start + 2, end > start ? end : start + 16);
			const locations: PdbLocalSymbol['locations'][number][] = [];
			for (const line of block) {
				const register = /register\s*=\s*([A-Za-z0-9]+)/.exec(line)?.[1];
				const range = /range start\s*=\s*(\d+):([0-9A-Fa-f]+),\s*length\s*=\s*(\d+)/.exec(line);
				if (register) locations.push({ kind: 'register', register, ...(range ? { rangeStart: `${range[1]}:${range[2]}`, rangeLength: Number(range[3]) } : {}) });
			}
			locals[localIndex].symbol = { ...locals[localIndex].symbol, locations: [...locals[localIndex].symbol.locations, ...locations] };
		}
		const va = imageBase + sectionVA + offset;
		const prototype = typeIndex ? parsePrototype(typeIndex, records) : undefined;
		if (prototype) {
			let remaining = prototype.parameterTypes.filter(type => type !== '...').length;
			for (const local of locals) {
				if (remaining <= 0) { break; }
				if (!local.topLevel || local.symbol.parameter) { if (local.symbol.parameter) { remaining--; } continue; }
				local.symbol = { ...local.symbol, parameter: true };
				remaining--;
			}
		}
		functions.push({
			name: header[3], address: hex(va), endExclusive: hex(va + size), size, section, offset,
			addressModel: 'pdb-module-record',
			visibility: header[2] === 'GPROC32' ? 'public' : 'private',
			...(prototype ? { prototype } : {}),
			locals: locals.map(item => item.symbol),
		});
	}
	return [...new Map(functions.map(fn => [`${fn.address}:${fn.name}`, fn])).values()]
		.sort((left, right) => Number.parseInt(left.address.slice(2), 16) - Number.parseInt(right.address.slice(2), 16) || compareAscii(left.name, right.name));
}

function parseCompilands(output: string): string[] {
	return output.split(/\r?\n/).flatMap(line => /^\s*Mod\s+\d+\s*\|\s*`([^`]+)`/.exec(line)?.[1] ?? [])
		.filter(Boolean).sort(compareAscii);
}

function parseInlineFrames(output: string): PdbInlineFrame[] {
	const lines = output.split(/\r?\n/);
	const result: PdbInlineFrame[] = [];
	for (let index = 0; index < lines.length; index++) {
		if (!/\|\s*S_INLINESITE\b/.test(lines[index])) { continue; }
		const detail = /inlinee\s*=\s*(0x[0-9A-Fa-f]+)(?:\s*\(([^)]*)\))?,\s*parent\s*=\s*(\d+),\s*end\s*=\s*(\d+)/.exec(lines[index + 1] ?? '');
		if (!detail) { continue; }
		const annotations: string[] = [];
		for (let cursor = index + 2; cursor < lines.length && !/\|\s*S_INLINESITE_END\b/.test(lines[cursor]); cursor++) {
			const value = lines[cursor].trim(); if (value) { annotations.push(value); }
		}
		result.push({
			inlineeTypeIndex: detail[1].toUpperCase(), ...(detail[2] ? { inlineeName: detail[2] } : {}),
			parentRecordOffset: Number(detail[3]), endRecordOffset: Number(detail[4]), annotations,
		});
	}
	return result.sort((left, right) => left.parentRecordOffset - right.parentRecordOffset || compareAscii(left.inlineeTypeIndex, right.inlineeTypeIndex));
}

function parseLines(output: string, sectionVAs: Map<number, number>, imageBase: number): PdbLineRecord[] {
	const result: PdbLineRecord[] = [];
	let sourceFile: string | undefined; let sourceHash: string | undefined; let section: number | undefined;
	for (const line of output.split(/\r?\n/)) {
		const source = /^\s*(.+?)\s+\((?:SHA-[0-9]+|MD5):\s*([0-9A-Fa-f]+)\)\s*$/.exec(line);
		if (source) { sourceFile = source[1].trim(); sourceHash = source[2].toLowerCase(); continue; }
		const range = /^\s*(\d+):[0-9A-Fa-f]+-[0-9A-Fa-f]+,\s*line\/addr entries/.exec(line);
		if (range) { section = Number(range[1]); continue; }
		if (!sourceFile || section === undefined) { continue; }
		for (const match of line.matchAll(/(\d+)\s+([0-9A-Fa-f]{4,16})/g)) {
			const sectionVA = sectionVAs.get(section); if (sectionVA === undefined) { continue; }
			result.push({ sourceFile, ...(sourceHash ? { sourceHash } : {}), line: Number(match[1]), address: hex(imageBase + sectionVA + Number.parseInt(match[2], 16)) });
		}
	}
	return result.sort((left, right) => Number.parseInt(left.address.slice(2), 16) - Number.parseInt(right.address.slice(2), 16) || left.line - right.line);
}

function debugRecords(records: ReadonlyMap<string, TypeRecord>): ExtendedStructInfoJson {
	const structs: ExtendedStructInfoJson['structs'] = {};
	for (const record of records.values()) {
		if (!['LF_STRUCTURE', 'LF_CLASS', 'LF_UNION'].includes(record.kind) || !record.name || !record.size || !record.fieldList) { continue; }
		const fields = records.get(record.fieldList)?.members ?? [];
		structs[record.name] = {
			kind: record.kind === 'LF_UNION' ? 'union' : 'struct', size: record.size,
			fields: fields.map(field => {
				const bitfield = field.typeIndex ? records.get(field.typeIndex)?.bitfield : undefined;
				return {
					name: field.name, offset: hex(field.offset), size: 0, type: bitfield?.type ?? field.type,
					...(bitfield ? { bitOffset: field.offset * 8 + bitfield.bitOffset, bitSize: bitfield.bitSize, bitfield: true } : {}),
				};
			}),
		};
	}
	return { structs, functions: {} };
}

function enumTypes(records: ReadonlyMap<string, TypeRecord>): PdbEnumType[] {
	return [...records.values()].filter(record => record.kind === 'LF_ENUM' && record.name && record.fieldList).map(record => ({
		name: record.name!, typeIndex: record.index, values: records.get(record.fieldList!)?.enumValues ?? [],
	})).sort((left, right) => compareAscii(left.name, right.name));
}

function typeAliases(output: string): PdbTypeAlias[] {
	return [...new Map(output.split(/\r?\n/).flatMap((line, index, lines) => {
		const alias = /\|\s*S_UDT.*`([^`]+)`/.exec(line);
		const target = alias ? /original type\s*=\s*(0x[0-9A-Fa-f]+)/i.exec(lines[index + 1] ?? '')?.[1]?.toUpperCase() : undefined;
		return alias && target ? [[alias[1], { name: alias[1], targetTypeIndex: target }] as const] : [];
	})).values()].sort((left, right) => compareAscii(left.name, right.name));
}

export async function resolvePdbFromSymbolServers(options: PdbResolveOptions): Promise<string | undefined> {
	const key = `${normalizeGuid(options.guid)}${options.age.toString(16).toUpperCase()}`;
	const identityDirectory = path.join(options.cacheDirectory, options.pdbName, key);
	const cached = path.join(identityDirectory, options.pdbName);
	if (fs.existsSync(cached)) { return cached; }
	fs.mkdirSync(identityDirectory, { recursive: true });
	for (const server of options.symbolServers ?? ['https://msdl.microsoft.com/download/symbols']) {
		const url = `${server.replace(/\/$/, '')}/${encodeURIComponent(options.pdbName)}/${key}/${encodeURIComponent(options.pdbName)}`;
		try {
			const response = await fetch(url);
			if (!response.ok) { continue; }
			const data = Buffer.from(await response.arrayBuffer());
			const contentDirectory = path.join(options.cacheDirectory, 'sha256', sha256Buffer(data));
			fs.mkdirSync(contentDirectory, { recursive: true });
			const contentPath = path.join(contentDirectory, options.pdbName);
			if (!fs.existsSync(contentPath)) { fs.writeFileSync(contentPath, data); }
			fs.copyFileSync(contentPath, cached);
			return cached;
		} catch { /* try the next configured server */ }
	}
	return undefined;
}

export function loadPdbProvider(options: PdbProviderOptions): PdbProviderResult {
	const diagnostics: PdbDiagnostic[] = [];
	const pdbPath = path.resolve(options.pdbPath);
	if (!fs.existsSync(pdbPath)) {
		const logical: Omit<PdbProviderResult, 'contentHash'> = { schemaVersion: PDB_PROVIDER_SCHEMA_VERSION, providerVersion: PDB_PROVIDER_VERSION, status: 'error', pdbPath, pdbSha256: '', identityValidated: false, functions: [], debugTypes: { structs: {}, functions: {} }, lines: [], inlineFrames: [], enumTypes: [], typeAliases: [], compilands: [], diagnostics: [{ severity: 'error', code: 'PDB_NOT_FOUND', message: `PDB not found: ${pdbPath}` }] };
		return { ...logical, contentHash: sha256Buffer(JSON.stringify(logical)) };
	}
	const pdbSha256 = sha256File(pdbPath);
	const tool = findPdbutil();
	if (!tool) {
		const logical: Omit<PdbProviderResult, 'contentHash'> = { schemaVersion: PDB_PROVIDER_SCHEMA_VERSION, providerVersion: PDB_PROVIDER_VERSION, status: 'error', pdbPath, pdbSha256, identityValidated: false, functions: [], debugTypes: { structs: {}, functions: {} }, lines: [], inlineFrames: [], enumTypes: [], typeAliases: [], compilands: [], diagnostics: [{ severity: 'error', code: 'PDBUTIL_NOT_FOUND', message: 'llvm-pdbutil is unavailable.' }] };
		return { ...logical, contentHash: sha256Buffer(JSON.stringify(logical)) };
	}
	const summary = runPdbutil(tool, ['dump', '--summary', pdbPath], options, diagnostics);
	const sections = runPdbutil(tool, ['dump', '--section-headers', pdbPath], options, diagnostics);
	const typesText = runPdbutil(tool, ['dump', '--types', pdbPath], options, diagnostics);
	const symbols = runPdbutil(tool, ['dump', '--symbols', pdbPath], options, diagnostics);
	const linesText = runPdbutil(tool, ['dump', '-l', '--modules', pdbPath], options, diagnostics);
	const identity = summary ? parsePdbSummary(summary) : undefined;
	let identityValidated = identity !== undefined;
	if (identity && options.expectedGuid && normalizeGuid(options.expectedGuid) !== identity.guid) {
		diagnostics.push({ severity: 'error', code: 'PDB_GUID_MISMATCH', message: `PE expects ${normalizeGuid(options.expectedGuid)}, PDB contains ${identity.guid}.` }); identityValidated = false;
	}
	if (identity && options.expectedAge !== undefined && options.expectedAge !== identity.age) {
		diagnostics.push({ severity: 'error', code: 'PDB_AGE_MISMATCH', message: `PE expects age ${options.expectedAge}, PDB contains ${identity.age}.` }); identityValidated = false;
	}
	const sectionVAs = sections ? parseSectionHeaders(sections) : new Map<number, number>();
	const records = typesText ? parseTypeRecords(typesText, diagnostics) : new Map<string, TypeRecord>();
	const functions = symbols ? parseFunctions(symbols, sectionVAs, options.imageBase, records) : [];
	if (functions.length > 0) diagnostics.push({ severity: 'warning', code: 'PE_ADDRESS_RECONCILIATION_REQUIRED', message: 'Procedure addresses come from PDB module records; PE consumers must reconcile exports/thunks before publishing exact runtime VAs.' });
	const lineRecords = linesText ? parseLines(linesText, sectionVAs, options.imageBase) : [];
	const inlineFrames = symbols ? parseInlineFrames(symbols) : [];
	const compilands = linesText ? parseCompilands(linesText) : [];
	if (functions.some(fn => !fn.prototype)) diagnostics.push({ severity: 'warning', code: 'PARTIAL_PROTOTYPES', message: `${functions.filter(fn => !fn.prototype).length} functions have no decoded procedure type.` });
	if (functions.some(fn => fn.locals.some(local => local.locations.length === 0))) diagnostics.push({ severity: 'warning', code: 'PARTIAL_LOCAL_LOCATIONS', message: 'Some locals have no supported location range.' });
	const fatal = diagnostics.some(item => item.severity === 'error');
	const status = fatal ? 'error' as const : diagnostics.some(item => item.severity === 'warning') ? 'partial' as const : 'ok' as const;
	const logical: Omit<PdbProviderResult, 'contentHash'> = {
		schemaVersion: PDB_PROVIDER_SCHEMA_VERSION, providerVersion: PDB_PROVIDER_VERSION, status,
		pdbPath, pdbSha256, ...(identity ? { identity } : {}), identityValidated,
		toolPath: tool, toolSha256: fs.existsSync(tool) ? sha256File(tool) : undefined,
		functions, debugTypes: debugRecords(records), lines: lineRecords, inlineFrames, enumTypes: enumTypes(records), typeAliases: symbols ? typeAliases(symbols) : [], compilands, diagnostics,
	};
	return { ...logical, contentHash: sha256Buffer(JSON.stringify(logical)) };
}
