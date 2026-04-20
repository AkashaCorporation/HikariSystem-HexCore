/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as fs from 'fs';
import * as path from 'path';

// BTF Kind Constants
const BTF_KIND_VOID = 0;
const BTF_KIND_INT = 1;
const BTF_KIND_PTR = 2;
const BTF_KIND_ARRAY = 3;
const BTF_KIND_STRUCT = 4;
const BTF_KIND_UNION = 5;
const BTF_KIND_ENUM = 6;
const BTF_KIND_FWD = 7;
const BTF_KIND_TYPEDEF = 8;
const BTF_KIND_VOLATILE = 9;
const BTF_KIND_CONST = 10;
const BTF_KIND_RESTRICT = 11;
const BTF_KIND_FUNC = 12;
const BTF_KIND_FUNC_PROTO = 13;
const BTF_KIND_VAR = 14;
const BTF_KIND_DATASEC = 15;
const BTF_KIND_FLOAT = 16;
const BTF_KIND_DECL_TAG = 17;
const BTF_KIND_TYPE_TAG = 18;
const BTF_KIND_ENUM64 = 19;

// BTF Header magic number
const BTF_MAGIC = 0xEB9F;

// Kind names for display
const KIND_NAMES: Record<number, string> = {
	[BTF_KIND_VOID]: 'void',
	[BTF_KIND_INT]: 'int',
	[BTF_KIND_PTR]: 'ptr',
	[BTF_KIND_ARRAY]: 'array',
	[BTF_KIND_STRUCT]: 'struct',
	[BTF_KIND_UNION]: 'union',
	[BTF_KIND_ENUM]: 'enum',
	[BTF_KIND_FWD]: 'fwd',
	[BTF_KIND_TYPEDEF]: 'typedef',
	[BTF_KIND_VOLATILE]: 'volatile',
	[BTF_KIND_CONST]: 'const',
	[BTF_KIND_RESTRICT]: 'restrict',
	[BTF_KIND_FUNC]: 'func',
	[BTF_KIND_FUNC_PROTO]: 'func_proto',
	[BTF_KIND_VAR]: 'var',
	[BTF_KIND_DATASEC]: 'datasec',
	[BTF_KIND_FLOAT]: 'float',
	[BTF_KIND_DECL_TAG]: 'decl_tag',
	[BTF_KIND_TYPE_TAG]: 'type_tag',
	[BTF_KIND_ENUM64]: 'enum64',
};

/** BTF header structure */
interface BTFHeader {
	magic: number;
	version: number;
	flags: number;
	hdrLen: number;
	typeOff: number;
	typeLen: number;
	strOff: number;
	strLen: number;
}

/** Parsed BTF type entry */
export interface BTFType {
	/** Type ID (1-based index) */
	id: number;
	/** BTF kind (BTF_KIND_*) */
	kind: number;
	/** Kind name for display */
	kindName: string;
	/** Type name from string table (empty for anonymous types) */
	name: string;
	/** Size in bytes (for INT, STRUCT, UNION, ENUM) or referenced type ID (for PTR, TYPEDEF, etc.) */
	sizeOrType: number;
	/** Additional data depending on kind */
	members?: BTFMember[];       // for STRUCT/UNION
	params?: BTFParam[];         // for FUNC_PROTO
	enumValues?: BTFEnumValue[]; // for ENUM
	encoding?: number;           // for INT
	bits?: number;               // for INT
	nelems?: number;             // for ARRAY
	elemType?: number;           // for ARRAY
	indexType?: number;          // for ARRAY
}

/** Struct/Union member */
export interface BTFMember {
	name: string;
	typeId: number;
	/** Bit offset from struct start (if kflag=0: raw offset, if kflag=1: bits [0:23]=bit_offset, [24:31]=bitfield_size) */
	offset: number;
}

/** Function parameter */
export interface BTFParam {
	name: string;
	typeId: number;
}

/** Enum value */
export interface BTFEnumValue {
	name: string;
	value: number;
}

/** Result of loading BTF from a vmlinux or .ko file */
export interface BTFData {
	/** All parsed types indexed by type ID */
	types: Map<number, BTFType>;
	/** Named types for quick lookup */
	namedTypes: Map<string, BTFType>;
	/** Total number of types parsed */
	typeCount: number;
	/** BTF version */
	version: number;
	/** String table */
	strings: string[];
}

/** Kernel struct type hint for decompilation */
export interface KernelTypeHint {
	/** Parameter index (0-based) */
	paramIndex: number;
	/** C type string (e.g., 'struct kbase_context *') */
	cType: string;
	/** BTF type ID for resolution */
	btfTypeId: number;
}

/**
 * Parse the BTF header from the section data.
 * @param data The BTF section data
 * @returns Parsed BTF header
 */
function parseBtfHeader(data: Buffer): BTFHeader {
	return {
		magic: data.readUInt16LE(0),
		version: data.readUInt8(2),
		flags: data.readUInt8(3),
		hdrLen: data.readUInt32LE(4),
		typeOff: data.readUInt32LE(8),
		typeLen: data.readUInt32LE(12),
		strOff: data.readUInt32LE(16),
		strLen: data.readUInt32LE(20),
	};
}

/**
 * Parse the string table from BTF section data.
 * @param data The BTF section data
 * @param strOff Offset to string section from end of header
 * @param strLen Length of string section
 * @param hdrLen Length of BTF header
 * @returns Array of strings from the string table
 */
function parseStringTable(data: Buffer, strOff: number, strLen: number, hdrLen: number): string[] {
	const strings: string[] = [];
	const strStart = hdrLen + strOff;
	const strEnd = strStart + strLen;

	let currentStr = '';
	for (let i = strStart; i < strEnd; i++) {
		const byte = data.readUInt8(i);
		if (byte === 0) {
			strings.push(currentStr);
			currentStr = '';
		} else {
			currentStr += String.fromCharCode(byte);
		}
	}

	return strings;
}

/**
 * Get a string from the string table by offset.
 * @param strings The string table array
 * @param offset The offset into the string table
 * @returns The string at the given offset, or empty string if invalid
 */
function getStringAtOffset(strings: string[], offset: number): string {
	// The string table is stored as concatenated null-terminated strings
	// We need to reconstruct the offset-based lookup
	let currentOffset = 0;
	for (const str of strings) {
		if (currentOffset === offset) {
			return str;
		}
		currentOffset += str.length + 1; // +1 for null terminator
	}
	return '';
}

/**
 * Parse BTF type information from the section data.
 * @param data The BTF section data
 * @param typeOff Offset to type section from end of header
 * @param typeLen Length of type section
 * @param hdrLen Length of BTF header
 * @param strings String table
 * @returns Map of type ID to BTFType
 */
function parseTypes(
	data: Buffer,
	typeOff: number,
	typeLen: number,
	hdrLen: number,
	strings: string[]
): Map<number, BTFType> {
	const types = new Map<number, BTFType>();
	const typeStart = hdrLen + typeOff;
	const typeEnd = typeStart + typeLen;

	let offset = typeStart;
	let typeId = 1; // BTF type IDs are 1-based

	// Reconstruct string table for offset-based lookup
	const stringTable: string[] = [];
	let currentOffset = 0;
	for (const str of strings) {
		stringTable[currentOffset] = str;
		currentOffset += str.length + 1;
	}

	while (offset < typeEnd) {
		// Each btf_type entry is 12 bytes minimum
		if (offset + 12 > typeEnd) {
			break;
		}

		const nameOff = data.readUInt32LE(offset);
		const info = data.readUInt32LE(offset + 4);
		const sizeOrType = data.readUInt32LE(offset + 8);

		// Extract info fields
		const vlen = info & 0xFFFF;
		const kind = (info >> 24) & 0x1F;
		const kflag = (info >> 31) & 0x1;

		const name = stringTable[nameOff] || '';
		const kindName = KIND_NAMES[kind] || 'unknown';

		const btfType: BTFType = {
			id: typeId,
			kind,
			kindName,
			name,
			sizeOrType,
		};

		let entrySize = 12; // Base size of btf_type

		switch (kind) {
			case BTF_KIND_INT: {
				// INT has 4 bytes of extra encoding info
				if (offset + 16 <= typeEnd) {
					const encoding = data.readUInt32LE(offset + 12);
					btfType.encoding = encoding & 0xFF;
					// bits [8:15] = offset, [16:31] = nr_bits
					btfType.bits = (encoding >> 16) & 0xFFFF;
					entrySize = 16;
				}
				break;
			}

			case BTF_KIND_ARRAY: {
				// ARRAY has 12 bytes of extra info: elem_type (4), index_type (4), nelems (4)
				if (offset + 24 <= typeEnd) {
					btfType.elemType = data.readUInt32LE(offset + 12);
					btfType.indexType = data.readUInt32LE(offset + 16);
					btfType.nelems = data.readUInt32LE(offset + 20);
					entrySize = 24;
				}
				break;
			}

			case BTF_KIND_STRUCT:
			case BTF_KIND_UNION: {
				// STRUCT/UNION have vlen member entries following btf_type
				// Each member entry: name_off (4), type (4), offset (4)
				const members: BTFMember[] = [];
				let memberOffset = offset + 12;

				for (let i = 0; i < vlen && memberOffset + 12 <= typeEnd; i++) {
					const memberNameOff = data.readUInt32LE(memberOffset);
					const memberType = data.readUInt32LE(memberOffset + 4);
					const memberOffsetVal = data.readUInt32LE(memberOffset + 8);

					members.push({
						name: stringTable[memberNameOff] || '',
						typeId: memberType,
						offset: memberOffsetVal,
					});

					memberOffset += 12;
				}

				btfType.members = members;
				entrySize = memberOffset - offset;
				break;
			}

			case BTF_KIND_ENUM: {
				// ENUM has vlen enum value entries following btf_type
				// Each enum entry: name_off (4), val (4)
				const enumValues: BTFEnumValue[] = [];
				let enumOffset = offset + 12;

				for (let i = 0; i < vlen && enumOffset + 8 <= typeEnd; i++) {
					const enumNameOff = data.readUInt32LE(enumOffset);
					const enumVal = data.readInt32LE(enumOffset + 4);

					enumValues.push({
						name: stringTable[enumNameOff] || '',
						value: enumVal,
					});

					enumOffset += 8;
				}

				btfType.enumValues = enumValues;
				entrySize = enumOffset - offset;
				break;
			}

			case BTF_KIND_ENUM64: {
				// ENUM64 has vlen enum value entries following btf_type
				// Each enum64 entry: name_off (4), val_lo (4), val_hi (4)
				const enumValues: BTFEnumValue[] = [];
				let enumOffset = offset + 12;

				for (let i = 0; i < vlen && enumOffset + 12 <= typeEnd; i++) {
					const enumNameOff = data.readUInt32LE(enumOffset);
					const valLo = data.readUInt32LE(enumOffset + 4);
					const valHi = data.readUInt32LE(enumOffset + 8);

					// Combine high and low 32-bit values
					const enumVal = valLo | (valHi << 32);

					enumValues.push({
						name: stringTable[enumNameOff] || '',
						value: enumVal,
					});

					enumOffset += 12;
				}

				btfType.enumValues = enumValues;
				entrySize = enumOffset - offset;
				break;
			}

			case BTF_KIND_FUNC_PROTO: {
				// FUNC_PROTO has vlen parameter entries following btf_type
				// Each param entry: name_off (4), type (4)
				const params: BTFParam[] = [];
				let paramOffset = offset + 12;

				for (let i = 0; i < vlen && paramOffset + 8 <= typeEnd; i++) {
					const paramNameOff = data.readUInt32LE(paramOffset);
					const paramType = data.readUInt32LE(paramOffset + 4);

					params.push({
						name: stringTable[paramNameOff] || '',
						typeId: paramType,
					});

					paramOffset += 8;
				}

				btfType.params = params;
				entrySize = paramOffset - offset;
				break;
			}

			// PTR, TYPEDEF, CONST, VOLATILE, RESTRICT, FWD, FUNC, VAR, DATASEC, FLOAT, DECL_TAG, TYPE_TAG
			// These only have the base btf_type structure (12 bytes)
			default:
				break;
		}

		types.set(typeId, btfType);
		typeId++;
		offset += entrySize;
	}

	return types;
}

/**
 * Parse a BTF section and extract type information.
 * @param sectionData The raw BTF section data
 * @returns Parsed BTF data including types and string table
 */
export function parseBtfSection(sectionData: Buffer): BTFData {
	// Parse header
	const header = parseBtfHeader(sectionData);

	// Validate magic and version
	if (header.magic !== BTF_MAGIC) {
		throw new Error(`Invalid BTF magic: expected 0x${BTF_MAGIC.toString(16)}, got 0x${header.magic.toString(16)}`);
	}

	if (header.version !== 1) {
		throw new Error(`Unsupported BTF version: ${header.version}`);
	}

	// Parse string table
	const strings = parseStringTable(sectionData, header.strOff, header.strLen, header.hdrLen);

	// Parse types
	const types = parseTypes(sectionData, header.typeOff, header.typeLen, header.hdrLen, strings);

	// Build named types map
	const namedTypes = new Map<string, BTFType>();
	for (const type of types.values()) {
		if (type.name) {
			namedTypes.set(type.name, type);
		}
	}

	return {
		types,
		namedTypes,
		typeCount: types.size,
		version: header.version,
		strings,
	};
}

/**
 * Read an ELF file and extract the .BTF section data.
 * @param filePath Path to the ELF file
 * @returns Buffer containing the .BTF section data, or null if not found
 */
async function extractBtfSectionFromElf(filePath: string): Promise<Buffer | null> {
	return new Promise((resolve, reject) => {
		// Read file header first to determine ELF class
		const headerBuffer = Buffer.alloc(64);
		const fd = fs.openSync(filePath, 'r');

		try {
			fs.readSync(fd, headerBuffer, 0, 64, 0);

			// Check ELF magic
			if (headerBuffer.readUInt8(0) !== 0x7F ||
				headerBuffer.readUInt8(1) !== 0x45 ||
				headerBuffer.readUInt8(2) !== 0x4C ||
				headerBuffer.readUInt8(3) !== 0x46) {
				fs.closeSync(fd);
				resolve(null);
				return;
			}

			const elfClass = headerBuffer.readUInt8(4); // 1 = 32-bit, 2 = 64-bit
			const littleEndian = headerBuffer.readUInt8(5) === 1;

			const is64Bit = elfClass === 2;

			// Parse ELF header fields
			let e_shoff: number;
			let e_shentsize: number;
			let e_shnum: number;
			let e_shstrndx: number;

			if (is64Bit) {
				e_shoff = Number(littleEndian ? headerBuffer.readBigUInt64LE(40) : headerBuffer.readBigUInt64BE(40));
				e_shentsize = littleEndian ? headerBuffer.readUInt16LE(58) : headerBuffer.readUInt16BE(58);
				e_shnum = littleEndian ? headerBuffer.readUInt16LE(60) : headerBuffer.readUInt16BE(60);
				e_shstrndx = littleEndian ? headerBuffer.readUInt16LE(62) : headerBuffer.readUInt16BE(62);
			} else {
				e_shoff = littleEndian ? headerBuffer.readUInt32LE(32) : headerBuffer.readUInt32BE(32);
				e_shentsize = littleEndian ? headerBuffer.readUInt16LE(46) : headerBuffer.readUInt16BE(46);
				e_shnum = littleEndian ? headerBuffer.readUInt16LE(48) : headerBuffer.readUInt16BE(48);
				e_shstrndx = littleEndian ? headerBuffer.readUInt16LE(50) : headerBuffer.readUInt16BE(50);
			}

			// Read section header string table
			const shstrOffset = Number(e_shoff) + e_shstrndx * e_shentsize;
			const shstrEntry = Buffer.alloc(is64Bit ? 64 : 40);
			fs.readSync(fd, shstrEntry, 0, shstrEntry.length, Number(shstrOffset));

			const shstrAddr = littleEndian
				? (is64Bit ? Number(shstrEntry.readBigUInt64LE(24)) : shstrEntry.readUInt32LE(16))
				: (is64Bit ? Number(shstrEntry.readBigUInt64BE(24)) : shstrEntry.readUInt32BE(16));
			const shstrSize = littleEndian
				? (is64Bit ? Number(shstrEntry.readBigUInt64LE(32)) : shstrEntry.readUInt32LE(20))
				: (is64Bit ? Number(shstrEntry.readBigUInt64BE(32)) : shstrEntry.readUInt32BE(20));

			// Read string table
			const stringTable = Buffer.alloc(Number(shstrSize));
			fs.readSync(fd, stringTable, 0, Number(shstrSize), Number(shstrAddr));

			// Iterate sections to find .BTF
			for (let i = 0; i < e_shnum; i++) {
				const shOffset = Number(e_shoff) + i * e_shentsize;
				const shEntry = Buffer.alloc(is64Bit ? 64 : 40);
				fs.readSync(fd, shEntry, 0, shEntry.length, shOffset);

				const shNameOffset = littleEndian ? shEntry.readUInt32LE(0) : shEntry.readUInt32BE(0);

				// Read section name from string table
				let sectionName = '';
				for (let j = shNameOffset; j < stringTable.length; j++) {
					const byte = stringTable.readUInt8(j);
					if (byte === 0) break;
					sectionName += String.fromCharCode(byte);
				}

				if (sectionName === '.BTF') {
					// Found .BTF section, read its data
					const shAddr = littleEndian
						? (is64Bit ? Number(shEntry.readBigUInt64LE(24)) : shEntry.readUInt32LE(16))
						: (is64Bit ? Number(shEntry.readBigUInt64BE(24)) : shEntry.readUInt32BE(16));
					const shSize = littleEndian
						? (is64Bit ? Number(shEntry.readBigUInt64LE(32)) : shEntry.readUInt32LE(20))
						: (is64Bit ? Number(shEntry.readBigUInt64BE(32)) : shEntry.readUInt32BE(20));

					const btfData = Buffer.alloc(Number(shSize));
					fs.readSync(fd, btfData, 0, Number(shSize), Number(shAddr));

					fs.closeSync(fd);
					resolve(btfData);
					return;
				}
			}

			fs.closeSync(fd);
			resolve(null);
		} catch (error) {
			fs.closeSync(fd);
			reject(error);
		}
	});
}

/**
 * Load BTF type information from an ELF file (vmlinux or .ko module).
 * @param filePath Path to the ELF file
 * @returns Parsed BTF data, or null if no .BTF section found
 */
export async function loadBtfFromFile(filePath: string): Promise<BTFData | null> {
	try {
		const btfSectionData = await extractBtfSectionFromElf(filePath);
		if (!btfSectionData) {
			return null;
		}

		return parseBtfSection(btfSectionData);
	} catch (error) {
		console.error(`Error loading BTF from ${filePath}:`, error);
		return null;
	}
}

/**
 * Resolve a BTF type ID to a C type string.
 * @param typeId The BTF type ID to resolve
 * @param btfData The BTF data containing types
 * @param depth Current recursion depth (to prevent infinite recursion)
 * @returns C type string representation
 */
export function resolveTypeString(typeId: number, btfData: BTFData, depth: number = 0): string {
	// Prevent infinite recursion
	if (depth > 20) {
		return 'void';
	}

	const type = btfData.types.get(typeId);
	if (!type) {
		return 'void';
	}

	switch (type.kind) {
		case BTF_KIND_VOID:
			return 'void';

		case BTF_KIND_INT:
		case BTF_KIND_FLOAT:
			return type.name || 'int';

		case BTF_KIND_PTR: {
			const pointeeType = resolveTypeString(type.sizeOrType, btfData, depth + 1);
			return `${pointeeType} *`;
		}

		case BTF_KIND_CONST: {
			const baseType = resolveTypeString(type.sizeOrType, btfData, depth + 1);
			return `const ${baseType}`;
		}

		case BTF_KIND_VOLATILE: {
			const baseType = resolveTypeString(type.sizeOrType, btfData, depth + 1);
			return `volatile ${baseType}`;
		}

		case BTF_KIND_RESTRICT: {
			const baseType = resolveTypeString(type.sizeOrType, btfData, depth + 1);
			return `restrict ${baseType}`;
		}

		case BTF_KIND_TYPEDEF:
			return type.name || resolveTypeString(type.sizeOrType, btfData, depth + 1);

		case BTF_KIND_STRUCT:
			return type.name ? `struct ${type.name}` : 'struct <anonymous>';

		case BTF_KIND_UNION:
			return type.name ? `union ${type.name}` : 'union <anonymous>';

		case BTF_KIND_ENUM:
		case BTF_KIND_ENUM64:
			return type.name ? `enum ${type.name}` : 'enum <anonymous>';

		case BTF_KIND_ARRAY: {
			if (type.elemType !== undefined && type.nelems !== undefined) {
				const elemTypeStr = resolveTypeString(type.elemType, btfData, depth + 1);
				return `${elemTypeStr}[${type.nelems}]`;
			}
			return 'array';
		}

		case BTF_KIND_FUNC:
			return type.name || 'func';

		case BTF_KIND_FUNC_PROTO:
			return 'func_proto';

		case BTF_KIND_FWD:
			return type.name || 'forward';

		case BTF_KIND_VAR:
			return type.name || 'var';

		case BTF_KIND_DATASEC:
			return type.name || 'datasec';

		case BTF_KIND_DECL_TAG:
			return 'decl_tag';

		case BTF_KIND_TYPE_TAG:
			return type.name || 'type_tag';

		default:
			return 'unknown';
	}
}

/**
 * Get the layout of a struct from BTF data.
 * @param structName Name of the struct to look up
 * @param btfData The BTF data
 * @returns Struct layout information, or null if not found
 */
export function getStructLayout(
	structName: string,
	btfData: BTFData
): { size: number; members: Array<{ name: string; offset: number; type: string }> } | null {
	// Look up the struct by name
	const type = btfData.namedTypes.get(structName);
	if (!type || (type.kind !== BTF_KIND_STRUCT && type.kind !== BTF_KIND_UNION)) {
		return null;
	}

	const members: Array<{ name: string; offset: number; type: string }> = [];

	if (type.members) {
		for (const member of type.members) {
			const memberTypeStr = resolveTypeString(member.typeId, btfData);
			// Extract bit offset (lower 24 bits if kflag is set)
			const offset = member.offset & 0xFFFFFF;

			members.push({
				name: member.name,
				offset,
				type: memberTypeStr,
			});
		}
	}

	return {
		size: type.sizeOrType,
		members,
	};
}

/**
 * Resolve the byte size of a BTF type by following type chains.
 * For pointers, returns the pointer size (8 for 64-bit).
 * For INT/STRUCT/UNION/ENUM, returns sizeOrType directly.
 * For TYPEDEF/CONST/VOLATILE/RESTRICT, follows the chain.
 */
export function resolveTypeSize(typeId: number, btfData: BTFData, pointerSize: number = 8, depth: number = 0): number {
	if (depth > 20) { return 0; }

	const type = btfData.types.get(typeId);
	if (!type) { return 0; }

	switch (type.kind) {
		case BTF_KIND_INT:
		case BTF_KIND_STRUCT:
		case BTF_KIND_UNION:
		case BTF_KIND_ENUM:
		case BTF_KIND_ENUM64:
		case BTF_KIND_FLOAT:
			return type.sizeOrType;

		case BTF_KIND_PTR:
			return pointerSize;

		case BTF_KIND_TYPEDEF:
		case BTF_KIND_CONST:
		case BTF_KIND_VOLATILE:
		case BTF_KIND_RESTRICT:
		case BTF_KIND_TYPE_TAG:
			return resolveTypeSize(type.sizeOrType, btfData, pointerSize, depth + 1);

		case BTF_KIND_ARRAY: {
			if (type.elemType !== undefined && type.nelems !== undefined) {
				const elemSize = resolveTypeSize(type.elemType, btfData, pointerSize, depth + 1);
				return elemSize * type.nelems;
			}
			return 0;
		}

		default:
			return 0;
	}
}

// ---------------------------------------------------------------------------
// Struct info JSON export (v3.8.0 — struct field naming for Helix)
// ---------------------------------------------------------------------------

/** Single field in the exported struct info JSON */
export interface StructFieldInfo {
	name: string;
	offset: string;   // hex string e.g. "0xC6F0"
	size: number;
	type: string;
}

/** Single struct in the exported JSON */
export interface StructInfo {
	size: number;
	fields: StructFieldInfo[];
}

/** Function parameter info in the exported JSON */
export interface FunctionParamInfo {
	index: number;
	name: string;
	type: string;
	/** If param is a struct pointer, the struct name (stripped of 'struct ' prefix) */
	structName?: string;
}

/** Exported function signature */
export interface FunctionSignatureInfo {
	returnType: string;
	params: FunctionParamInfo[];
}

/** Function boundary from debug info (DWARF DW_TAG_subprogram low_pc/high_pc). */
export interface FunctionBoundaryInfo {
	name: string;
	/** Absolute virtual address of first instruction */
	lowPc: number;
	/** Absolute virtual address of first byte AFTER function body */
	highPc: number;
}

/** Top-level struct info JSON format for Helix integration */
export interface StructInfoJson {
	structs: Record<string, StructInfo>;
	functions: Record<string, FunctionSignatureInfo>;
	/** Optional: function entry/end boundaries sourced from debug info.
	 * Present when DWARF parses successfully; absent for BTF-only data
	 * (BTF carries no address ranges). Consumed by Pathfinder to
	 * supplement .symtab-derived function boundaries on stripped .ko. */
	boundaries?: FunctionBoundaryInfo[];
}

/**
 * Export all struct layouts from BTF data as the Helix struct-info JSON format.
 *
 * Only exports named structs with at least one named member.
 * Offsets are in bytes (BTF stores bit offsets for non-bitfield members as byte*8).
 */
export function exportStructInfoJson(btfData: BTFData, pointerSize: number = 8): StructInfoJson {
	const structs: Record<string, StructInfo> = {};
	const functions: Record<string, FunctionSignatureInfo> = {};

	// Export all named structs
	for (const type of btfData.types.values()) {
		if ((type.kind !== BTF_KIND_STRUCT && type.kind !== BTF_KIND_UNION) || !type.name) {
			continue;
		}
		if (!type.members || type.members.length === 0) {
			continue;
		}

		const fields: StructFieldInfo[] = [];
		for (const member of type.members) {
			if (!member.name) { continue; }

			// BTF stores bit offsets; for non-bitfield members offset is byte-aligned
			const bitOffset = member.offset & 0xFFFFFF;
			const byteOffset = Math.floor(bitOffset / 8);
			const memberSize = resolveTypeSize(member.typeId, btfData, pointerSize);
			const memberType = resolveTypeString(member.typeId, btfData);

			fields.push({
				name: member.name,
				offset: `0x${byteOffset.toString(16).toUpperCase()}`,
				size: memberSize,
				type: memberType,
			});
		}

		if (fields.length > 0) {
			structs[type.name] = {
				size: type.sizeOrType,
				fields,
			};
		}
	}

	// Export all function signatures (FUNC → FUNC_PROTO)
	for (const type of btfData.types.values()) {
		if (type.kind !== BTF_KIND_FUNC || !type.name) { continue; }

		const protoType = btfData.types.get(type.sizeOrType);
		if (!protoType || protoType.kind !== BTF_KIND_FUNC_PROTO) { continue; }

		const returnType = resolveTypeString(protoType.sizeOrType, btfData);
		const params: FunctionParamInfo[] = [];

		if (protoType.params) {
			for (let i = 0; i < protoType.params.length; i++) {
				const param = protoType.params[i];
				const paramType = resolveTypeString(param.typeId, btfData);

				const info: FunctionParamInfo = {
					index: i,
					name: param.name || `param_${i}`,
					type: paramType,
				};

				// Resolve struct pointer: "struct kbase_context *" → structName = "kbase_context"
				const ptrMatch = paramType.match(/^(?:const\s+)?struct\s+(\w+)\s*\*$/);
				if (ptrMatch) {
					info.structName = ptrMatch[1];
				}

				params.push(info);
			}
		}

		functions[type.name] = { returnType, params };
	}

	return { structs, functions };
}

/**
 * Get struct info for a specific function and the structs it references.
 * Returns only the structs that are referenced by the function's parameters.
 */
export function getStructInfoForFunction(
	functionName: string,
	btfData: BTFData,
	pointerSize: number = 8,
): StructInfoJson | null {
	const fullJson = exportStructInfoJson(btfData, pointerSize);

	const funcSig = fullJson.functions[functionName];
	if (!funcSig) { return null; }

	// Collect only structs referenced by this function's params
	const relevantStructs: Record<string, StructInfo> = {};
	for (const param of funcSig.params) {
		if (param.structName && fullJson.structs[param.structName]) {
			relevantStructs[param.structName] = fullJson.structs[param.structName];

			// Also collect nested struct types (one level deep)
			for (const field of fullJson.structs[param.structName].fields) {
				const nestedMatch = field.type.match(/^struct\s+(\w+)$/);
				if (nestedMatch && fullJson.structs[nestedMatch[1]]) {
					relevantStructs[nestedMatch[1]] = fullJson.structs[nestedMatch[1]];
				}
			}
		}
	}

	return {
		structs: relevantStructs,
		functions: { [functionName]: funcSig },
	};
}

/**
 * Resolve kernel function parameter types from BTF data.
 * @param symbols Array of symbols with names and optional parameter info
 * @param btfData The BTF data
 * @returns Map of function name to parameter type hints
 */
export function resolveKernelStructs(
	symbols: Array<{ name: string; params?: string[] }>,
	btfData: BTFData
): Map<string, KernelTypeHint[]> {
	const result = new Map<string, KernelTypeHint[]>();

	// Find all FUNC types in BTF
	const funcTypes: BTFType[] = [];
	for (const type of btfData.types.values()) {
		if (type.kind === BTF_KIND_FUNC) {
			funcTypes.push(type);
		}
	}

	// Build a map of function name to FUNC type
	const funcByName = new Map<string, BTFType>();
	for (const func of funcTypes) {
		if (func.name) {
			funcByName.set(func.name, func);
		}
	}

	// For each symbol, try to resolve its parameter types
	for (const symbol of symbols) {
		const func = funcByName.get(symbol.name);
		if (!func) {
			continue;
		}

		// Get the FUNC_PROTO type
		const protoType = btfData.types.get(func.sizeOrType);
		if (!protoType || protoType.kind !== BTF_KIND_FUNC_PROTO) {
			continue;
		}

		const hints: KernelTypeHint[] = [];

		if (protoType.params) {
			for (let i = 0; i < protoType.params.length; i++) {
				const param = protoType.params[i];
				const typeStr = resolveTypeString(param.typeId, btfData);

				hints.push({
					paramIndex: i,
					cType: typeStr,
					btfTypeId: param.typeId,
				});
			}
		}

		if (hints.length > 0) {
			result.set(symbol.name, hints);
		}
	}

	return result;
}
