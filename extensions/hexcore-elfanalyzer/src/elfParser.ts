/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as fs from 'fs';
import * as path from 'path';

// ============================================================================
// TYPE DEFINITIONS
// ============================================================================

/**
 * Complete analysis result for an ELF binary file.
 */
export interface ELFAnalysis {
	fileName: string;
	filePath: string;
	fileSize: number;
	isELF: boolean;
	error?: string;
	elfClass: 'ELF32' | 'ELF64';
	endianness: 'little' | 'big';
	osABI: string;
	type: string;
	machine: string;
	entryPoint: string;
	sections: ELFSection[];
	segments: ELFSegment[];
	symbols: ELFSymbol[];
	dynamicEntries: ELFDynamic[];
	imports: ELFImport[];
	security: ELFSecurity;
}

/**
 * Represents a single ELF section header entry.
 */
export interface ELFSection {
	name: string;
	type: string;
	address: string;
	offset: number;
	size: number;
	flags: string[];
	entropy: number;
}

/**
 * Represents a single ELF program header (segment) entry.
 */
export interface ELFSegment {
	type: string;
	offset: number;
	virtualAddress: string;
	physicalAddress: string;
	fileSize: number;
	memorySize: number;
	flags: string[];
	alignment: number;
}

/**
 * Represents a symbol from the ELF symbol table.
 */
export interface ELFSymbol {
	name: string;
	value: string;
	size: number;
	type: string;
	binding: string;
	section: string;
}

/**
 * Represents a dynamic section entry.
 */
export interface ELFDynamic {
	tag: string;
	value: string;
}

/**
 * Represents an imported function/symbol.
 */
export interface ELFImport {
	name: string;
	library: string;
}

/**
 * Security mitigations detected in the ELF binary.
 */
export interface ELFSecurity {
	relro: 'full' | 'partial' | 'none';
	stackCanary: boolean;
	nx: boolean;
	pie: boolean;
}

// ============================================================================
// ELF CONSTANTS
// ============================================================================

const ELF_MAGIC = Buffer.from([0x7f, 0x45, 0x4c, 0x46]); // \x7fELF

// ELF Class
const ELFCLASS32 = 1;
const ELFCLASS64 = 2;

// ELF Data encoding
const ELFDATA2LSB = 1; // Little-endian
const ELFDATA2MSB = 2; // Big-endian

// ELF Type
const ET_NONE = 0;
const ET_REL = 1;
const ET_EXEC = 2;
const ET_DYN = 3;
const ET_CORE = 4;

// Section header types
const SHT_NULL = 0;
const SHT_PROGBITS = 1;
const SHT_SYMTAB = 2;
const SHT_STRTAB = 3;
const SHT_RELA = 4;
const SHT_HASH = 5;
const SHT_DYNAMIC = 6;
const SHT_NOTE = 7;
const SHT_NOBITS = 8;
const SHT_REL = 9;
const SHT_DYNSYM = 11;

// Section flags
const SHF_WRITE = 0x1;
const SHF_ALLOC = 0x2;
const SHF_EXECINSTR = 0x4;

// Program header types
const PT_NULL = 0;
const PT_LOAD = 1;
const PT_DYNAMIC = 2;
const PT_INTERP = 3;
const PT_NOTE = 4;
const PT_GNU_EH_FRAME = 0x6474e550;
const PT_GNU_STACK = 0x6474e551;
const PT_GNU_RELRO = 0x6474e552;

// Program header flags
const PF_X = 0x1; // Execute
const PF_W = 0x2; // Write
const PF_R = 0x4; // Read

// Symbol binding
const STB_LOCAL = 0;
const STB_GLOBAL = 1;
const STB_WEAK = 2;

// Symbol type
const STT_NOTYPE = 0;
const STT_OBJECT = 1;
const STT_FUNC = 2;
const STT_SECTION = 3;
const STT_FILE = 4;

// Dynamic tags
const DT_NULL = 0;
const DT_NEEDED = 1;
const DT_STRTAB = 5;
const DT_SYMTAB = 6;
const DT_STRSZ = 10;
const DT_BIND_NOW = 24;
const DT_FLAGS = 30;
const DT_FLAGS_1 = 0x6ffffffb;

// DT_FLAGS bits
const DF_BIND_NOW = 0x8;

// DT_FLAGS_1 bits
const DF_1_NOW = 0x1;
const DF_1_PIE = 0x8000000;

// Minimum ELF header sizes
const ELF32_HEADER_SIZE = 52;
const ELF64_HEADER_SIZE = 64;

// ============================================================================
// LOOKUP TABLES
// ============================================================================

/** Maps ELF e_type values to human-readable strings. */
const ELF_TYPE_MAP: Record<number, string> = {
	[ET_NONE]: 'NONE',
	[ET_REL]: 'REL',
	[ET_EXEC]: 'EXEC',
	[ET_DYN]: 'DYN',
	[ET_CORE]: 'CORE',
};

/** Maps ELF e_machine values to architecture names. */
const ELF_MACHINE_MAP: Record<number, string> = {
	0x00: 'None',
	0x02: 'SPARC',
	0x03: 'x86',
	0x08: 'MIPS',
	0x14: 'PowerPC',
	0x15: 'PowerPC64',
	0x16: 'S390',
	0x28: 'ARM',
	0x2A: 'SuperH',
	0x32: 'IA-64',
	0x3E: 'x86_64',
	0xB7: 'AArch64',
	0xF3: 'RISC-V',
};

/** Maps ELF OS/ABI values to names. */
const ELF_OSABI_MAP: Record<number, string> = {
	0: 'UNIX System V',
	1: 'HP-UX',
	2: 'NetBSD',
	3: 'Linux',
	4: 'GNU Hurd',
	6: 'Solaris',
	7: 'AIX',
	8: 'IRIX',
	9: 'FreeBSD',
	10: 'Tru64',
	11: 'Novell Modesto',
	12: 'OpenBSD',
	13: 'OpenVMS',
	14: 'NonStop Kernel',
	15: 'AROS',
	16: 'FenixOS',
	97: 'ARM EABI',
	255: 'Standalone',
};

/** Maps program header type values to names. */
const PT_TYPE_MAP: Record<number, string> = {
	[PT_NULL]: 'NULL',
	[PT_LOAD]: 'LOAD',
	[PT_DYNAMIC]: 'DYNAMIC',
	[PT_INTERP]: 'INTERP',
	[PT_NOTE]: 'NOTE',
	5: 'SHLIB',
	6: 'PHDR',
	7: 'TLS',
	[PT_GNU_EH_FRAME]: 'GNU_EH_FRAME',
	[PT_GNU_STACK]: 'GNU_STACK',
	[PT_GNU_RELRO]: 'GNU_RELRO',
};

/** Maps symbol binding values to names. */
const STB_MAP: Record<number, string> = {
	[STB_LOCAL]: 'LOCAL',
	[STB_GLOBAL]: 'GLOBAL',
	[STB_WEAK]: 'WEAK',
};

/** Maps symbol type values to names. */
const STT_MAP: Record<number, string> = {
	[STT_NOTYPE]: 'NOTYPE',
	[STT_OBJECT]: 'OBJECT',
	[STT_FUNC]: 'FUNC',
	[STT_SECTION]: 'SECTION',
	[STT_FILE]: 'FILE',
};

/** Maps dynamic tag values to names. */
const DT_TAG_MAP: Record<number, string> = {
	[DT_NULL]: 'DT_NULL',
	[DT_NEEDED]: 'DT_NEEDED',
	2: 'DT_PLTRELSZ',
	3: 'DT_PLTGOT',
	4: 'DT_HASH',
	[DT_STRTAB]: 'DT_STRTAB',
	[DT_SYMTAB]: 'DT_SYMTAB',
	7: 'DT_RELA',
	8: 'DT_RELASZ',
	9: 'DT_RELAENT',
	[DT_STRSZ]: 'DT_STRSZ',
	11: 'DT_SYMENT',
	12: 'DT_INIT',
	13: 'DT_FINI',
	14: 'DT_SONAME',
	15: 'DT_RPATH',
	17: 'DT_REL',
	18: 'DT_RELSZ',
	19: 'DT_RELENT',
	20: 'DT_PLTREL',
	21: 'DT_DEBUG',
	23: 'DT_JMPREL',
	[DT_BIND_NOW]: 'DT_BIND_NOW',
	25: 'DT_INIT_ARRAY',
	26: 'DT_FINI_ARRAY',
	27: 'DT_INIT_ARRAYSZ',
	28: 'DT_FINI_ARRAYSZ',
	29: 'DT_RUNPATH',
	[DT_FLAGS]: 'DT_FLAGS',
	[DT_FLAGS_1]: 'DT_FLAGS_1',
};

/** Maps section header type values to names. */
const SHT_TYPE_MAP: Record<number, string> = {
	[SHT_NULL]: 'NULL',
	[SHT_PROGBITS]: 'PROGBITS',
	[SHT_SYMTAB]: 'SYMTAB',
	[SHT_STRTAB]: 'STRTAB',
	[SHT_RELA]: 'RELA',
	[SHT_HASH]: 'HASH',
	[SHT_DYNAMIC]: 'DYNAMIC',
	[SHT_NOTE]: 'NOTE',
	[SHT_NOBITS]: 'NOBITS',
	[SHT_REL]: 'REL',
	10: 'SHLIB',
	[SHT_DYNSYM]: 'DYNSYM',
	14: 'INIT_ARRAY',
	15: 'FINI_ARRAY',
	16: 'PREINIT_ARRAY',
	17: 'GROUP',
	18: 'SYMTAB_SHNDX',
};

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

/**
 * Creates a set of endian-aware buffer read functions.
 */
function getReaders(buf: Buffer, isLittle: boolean) {
	return {
		u16: (offset: number) => isLittle ? buf.readUInt16LE(offset) : buf.readUInt16BE(offset),
		u32: (offset: number) => isLittle ? buf.readUInt32LE(offset) : buf.readUInt32BE(offset),
		u64: (offset: number) => {
			if (isLittle) {
				const lo = buf.readUInt32LE(offset);
				const hi = buf.readUInt32LE(offset + 4);
				return BigInt(lo) | (BigInt(hi) << 32n);
			} else {
				const hi = buf.readUInt32BE(offset);
				const lo = buf.readUInt32BE(offset + 4);
				return (BigInt(hi) << 32n) | BigInt(lo);
			}
		},
	};
}

/**
 * Reads a null-terminated string from a buffer at the given offset.
 */
function readStringFromTable(buffer: Buffer, offset: number): string {
	if (offset < 0 || offset >= buffer.length) {
		return '';
	}
	let end = offset;
	while (end < buffer.length && buffer[end] !== 0) {
		end++;
	}
	return buffer.subarray(offset, end).toString('utf-8');
}

/**
 * Calculates Shannon entropy for a buffer of bytes.
 * Returns a value between 0.0 (uniform) and 8.0 (maximum randomness).
 */
function calculateEntropy(buffer: Buffer): number {
	if (buffer.length === 0) {
		return 0;
	}

	const freq = new Array(256).fill(0);
	for (let i = 0; i < buffer.length; i++) {
		freq[buffer[i]]++;
	}

	let entropy = 0;
	for (let i = 0; i < 256; i++) {
		if (freq[i] > 0) {
			const p = freq[i] / buffer.length;
			entropy -= p * Math.log2(p);
		}
	}

	return Math.round(entropy * 100) / 100;
}

/**
 * Formats a BigInt or number as a hex string with '0x' prefix.
 */
function toHex(value: bigint | number): string {
	return '0x' + value.toString(16);
}

/**
 * Parses section flags bitmask into an array of flag names.
 */
function parseSectionFlags(flags: number): string[] {
	const result: string[] = [];
	if (flags & SHF_WRITE) {
		result.push('WRITE');
	}
	if (flags & SHF_ALLOC) {
		result.push('ALLOC');
	}
	if (flags & SHF_EXECINSTR) {
		result.push('EXECINSTR');
	}
	return result;
}

/**
 * Creates a default (empty) ELFAnalysis result for error cases.
 */
function createErrorResult(filePath: string, fileSize: number, error: string): ELFAnalysis {
	return {
		fileName: path.basename(filePath),
		filePath,
		fileSize,
		isELF: false,
		error,
		elfClass: 'ELF64',
		endianness: 'little',
		osABI: '',
		type: '',
		machine: '',
		entryPoint: '0x0',
		sections: [],
		segments: [],
		symbols: [],
		dynamicEntries: [],
		imports: [],
		security: { relro: 'none', stackCanary: false, nx: false, pie: false },
	};
}

// ============================================================================
// SECURITY DETECTION
// ============================================================================

/**
 * Detects security mitigations present in an ELF binary.
 *
 * Checks for RELRO (none/partial/full), stack canary symbols, NX bit on the
 * GNU_STACK segment, and PIE via ELF type + DT_FLAGS_1 or DT_DEBUG heuristic.
 *
 * @param segments - Parsed program headers (segments).
 * @param dynamicEntries - Parsed dynamic section entries.
 * @param symbols - Parsed symbol table entries.
 * @param elfType - The ELF type string (e.g. 'DYN', 'EXEC').
 * @returns Security mitigations status.
 */
function detectSecurity(
	segments: ELFSegment[],
	dynamicEntries: ELFDynamic[],
	symbols: ELFSymbol[],
	elfType: string,
): ELFSecurity {
	// --- RELRO detection ---
	const hasGnuRelro = segments.some(s => s.type === 'GNU_RELRO');
	let relro: ELFSecurity['relro'] = 'none';

	if (hasGnuRelro) {
		// Check for full RELRO: DT_BIND_NOW present, or DF_BIND_NOW in DT_FLAGS,
		// or DF_1_NOW in DT_FLAGS_1
		const hasBindNow = dynamicEntries.some(e => e.tag === 'DT_BIND_NOW');

		const dtFlags = dynamicEntries.find(e => e.tag === 'DT_FLAGS');
		const hasDfBindNow = dtFlags !== undefined &&
			(parseInt(dtFlags.value, 16) & DF_BIND_NOW) !== 0;

		const dtFlags1 = dynamicEntries.find(e => e.tag === 'DT_FLAGS_1');
		const hasDf1Now = dtFlags1 !== undefined &&
			(parseInt(dtFlags1.value, 16) & DF_1_NOW) !== 0;

		relro = (hasBindNow || hasDfBindNow || hasDf1Now) ? 'full' : 'partial';
	}

	// --- Stack Canary detection ---
	const stackCanary = symbols.some(
		s => s.name === '__stack_chk_fail' || s.name === '__stack_chk_guard'
	);

	// --- NX detection ---
	const gnuStack = segments.find(s => s.type === 'GNU_STACK');
	const nx = gnuStack !== undefined && !gnuStack.flags.includes('EXECUTE');

	// --- PIE detection ---
	let pie = false;
	if (elfType === 'DYN') {
		const dtFlags1 = dynamicEntries.find(e => e.tag === 'DT_FLAGS_1');
		const hasDf1Pie = dtFlags1 !== undefined &&
			(parseInt(dtFlags1.value, 16) & DF_1_PIE) !== 0;

		const hasDtDebug = dynamicEntries.some(e => e.tag === 'DT_DEBUG');

		// DF_1_PIE is the definitive check; absence of DT_DEBUG is a heuristic
		// (shared libraries lack DT_DEBUG, but PIE executables typically have it)
		pie = hasDf1Pie || !hasDtDebug;
	}

	return { relro, stackCanary, nx, pie };
}

// ============================================================================
// MAIN PARSER
// ============================================================================

/**
 * Analyzes an ELF binary file and returns a complete structural analysis.
 *
 * Parses the ELF header, section headers (with names from the string table),
 * program headers (segments), symbol tables (.symtab and .dynsym), dynamic
 * section, and imports. Calculates Shannon entropy per section. Supports
 * both ELF32 and ELF64.
 *
 * @param filePath - Absolute or relative path to the ELF file.
 * @returns Complete ELF analysis result.
 */
export function analyzeELFFile(filePath: string): ELFAnalysis {
	// Read the entire file into a buffer
	const buffer = fs.readFileSync(filePath);
	const fileSize = buffer.length;

	// --- Validate magic bytes ---
	if (fileSize < 4 || !buffer.subarray(0, 4).equals(ELF_MAGIC)) {
		return createErrorResult(filePath, fileSize, 'Not an ELF file: invalid magic bytes');
	}

	// --- Validate minimum header size ---
	if (fileSize < 16) {
		return createErrorResult(filePath, fileSize, 'Truncated ELF header');
	}

	// --- Parse ELF identification (e_ident) ---
	const eiClass = buffer[4];
	const eiData = buffer[5];
	const eiOsAbi = buffer[7];

	const is64 = eiClass === ELFCLASS64;
	const isLittle = eiData === ELFDATA2LSB;

	if (eiClass !== ELFCLASS32 && eiClass !== ELFCLASS64) {
		return createErrorResult(filePath, fileSize, 'Unknown ELF class: ' + eiClass);
	}

	if (eiData !== ELFDATA2LSB && eiData !== ELFDATA2MSB) {
		return createErrorResult(filePath, fileSize, 'Unknown ELF data encoding: ' + eiData);
	}

	const minHeaderSize = is64 ? ELF64_HEADER_SIZE : ELF32_HEADER_SIZE;
	if (fileSize < minHeaderSize) {
		return createErrorResult(filePath, fileSize, 'Truncated ELF header');
	}

	const r = getReaders(buffer, isLittle);

	// --- Parse ELF header fields ---
	const eType = r.u16(16);
	const eMachine = r.u16(18);

	let entryPoint: bigint;
	let shOff: number;    // section header table offset
	let shEntSize: number; // section header entry size
	let shNum: number;     // number of section headers
	let shStrNdx: number;  // section name string table index

	if (is64) {
		entryPoint = r.u64(24);
		shOff = Number(r.u64(40));
		shEntSize = r.u16(58);
		shNum = r.u16(60);
		shStrNdx = r.u16(62);
	} else {
		entryPoint = BigInt(r.u32(24));
		shOff = r.u32(32);
		shEntSize = r.u16(46);
		shNum = r.u16(48);
		shStrNdx = r.u16(50);
	}

	// --- Parse section headers ---
	const sections = parseSectionHeaders(
		buffer, is64, isLittle, shOff, shEntSize, shNum, shStrNdx
	);

	// --- Parse program headers (segments) ---
	const segments = parseProgramHeaders(buffer, is64, isLittle);

	// --- Parse symbol table, dynamic section, and imports ---
	const rawSections = readRawSectionHeaders(buffer, is64, isLittle);
	const symbols = parseSymbolTable(buffer, is64, isLittle, rawSections);
	const dynamicEntries = parseDynamicSection(buffer, is64, isLittle, rawSections);
	const imports = parseImports(buffer, is64, isLittle, rawSections, symbols, dynamicEntries);

	return {
		fileName: path.basename(filePath),
		filePath,
		fileSize,
		isELF: true,
		elfClass: is64 ? 'ELF64' : 'ELF32',
		endianness: isLittle ? 'little' : 'big',
		osABI: ELF_OSABI_MAP[eiOsAbi] ?? ('Unknown (' + eiOsAbi + ')'),
		type: ELF_TYPE_MAP[eType] ?? ('Unknown (' + eType + ')'),
		machine: ELF_MACHINE_MAP[eMachine] ?? ('Unknown (0x' + eMachine.toString(16) + ')'),
		entryPoint: toHex(entryPoint),
		sections,
		segments,
		symbols,
		dynamicEntries,
		imports,
		// Detect security mitigations
		security: detectSecurity(segments, dynamicEntries, symbols,
			ELF_TYPE_MAP[eType] ?? ''),
	};
}

// ============================================================================
// PROGRAM HEADER PARSING
// ============================================================================

/**
 * Parses segment flags bitmask into an array of flag names.
 */
function parseSegmentFlags(flags: number): string[] {
	const result: string[] = [];
	if (flags & PF_R) {
		result.push('READ');
	}
	if (flags & PF_W) {
		result.push('WRITE');
	}
	if (flags & PF_X) {
		result.push('EXECUTE');
	}
	return result;
}

/**
 * Parses all program headers (segments) from the ELF file buffer.
 *
 * Reads the program header table using offsets from the ELF header and
 * returns an array of ELFSegment entries with type, flags, addresses,
 * and alignment information.
 *
 * @param buffer - The full file buffer.
 * @param is64 - Whether this is a 64-bit ELF.
 * @param isLittle - Whether the byte order is little-endian.
 * @returns Array of parsed ELF segments.
 */
function parseProgramHeaders(
	buffer: Buffer,
	is64: boolean,
	isLittle: boolean,
): ELFSegment[] {
	const r = getReaders(buffer, isLittle);

	let phOff: number;
	let phEntSize: number;
	let phNum: number;

	if (is64) {
		phOff = Number(r.u64(32));
		phEntSize = r.u16(54);
		phNum = r.u16(56);
	} else {
		phOff = r.u32(28);
		phEntSize = r.u16(42);
		phNum = r.u16(44);
	}

	if (phOff === 0 || phNum === 0) {
		return [];
	}

	// Validate that the program header table fits within the file
	const phTableEnd = phOff + phNum * phEntSize;
	if (phTableEnd > buffer.length) {
		return [];
	}

	const segments: ELFSegment[] = [];

	for (let i = 0; i < phNum; i++) {
		const off = phOff + i * phEntSize;

		if (off + phEntSize > buffer.length) {
			break;
		}

		const pType = r.u32(off);

		let pFlags: number;
		let pOffset: number;
		let pVaddr: bigint;
		let pPaddr: bigint;
		let pFilesz: number;
		let pMemsz: number;
		let pAlign: number;

		if (is64) {
			// ELF64 program header layout:
			// p_type(4) p_flags(4) p_offset(8) p_vaddr(8) p_paddr(8) p_filesz(8) p_memsz(8) p_align(8)
			pFlags = r.u32(off + 4);
			pOffset = Number(r.u64(off + 8));
			pVaddr = r.u64(off + 16);
			pPaddr = r.u64(off + 24);
			pFilesz = Number(r.u64(off + 32));
			pMemsz = Number(r.u64(off + 40));
			pAlign = Number(r.u64(off + 48));
		} else {
			// ELF32 program header layout:
			// p_type(4) p_offset(4) p_vaddr(4) p_paddr(4) p_filesz(4) p_memsz(4) p_flags(4) p_align(4)
			pOffset = r.u32(off + 4);
			pVaddr = BigInt(r.u32(off + 8));
			pPaddr = BigInt(r.u32(off + 12));
			pFilesz = r.u32(off + 16);
			pMemsz = r.u32(off + 20);
			pFlags = r.u32(off + 24);
			pAlign = r.u32(off + 28);
		}

		segments.push({
			type: PT_TYPE_MAP[pType] ?? ('Unknown (0x' + pType.toString(16) + ')'),
			offset: pOffset,
			virtualAddress: toHex(pVaddr),
			physicalAddress: toHex(pPaddr),
			fileSize: pFilesz,
			memorySize: pMemsz,
			flags: parseSegmentFlags(pFlags),
			alignment: pAlign,
		});
	}

	return segments;
}

// ============================================================================
// SYMBOL TABLE PARSING
// ============================================================================

/**
 * Internal representation of a raw section header for symbol/dynamic parsing.
 */
interface RawSectionHeader {
	nameIdx: number;
	type: number;
	offset: number;
	size: number;
	link: number;
	entSize: number;
}

/**
 * Reads raw section headers needed for symbol and dynamic parsing.
 *
 * @param buffer - The full file buffer.
 * @param is64 - Whether this is a 64-bit ELF.
 * @param isLittle - Whether the byte order is little-endian.
 * @returns Array of raw section headers.
 */
function readRawSectionHeaders(
	buffer: Buffer,
	is64: boolean,
	isLittle: boolean,
): RawSectionHeader[] {
	const r = getReaders(buffer, isLittle);

	let shOff: number;
	let shEntSize: number;
	let shNum: number;

	if (is64) {
		shOff = Number(r.u64(40));
		shEntSize = r.u16(58);
		shNum = r.u16(60);
	} else {
		shOff = r.u32(32);
		shEntSize = r.u16(46);
		shNum = r.u16(48);
	}

	if (shOff === 0 || shNum === 0) {
		return [];
	}

	if (shOff + shNum * shEntSize > buffer.length) {
		return [];
	}

	const headers: RawSectionHeader[] = [];

	for (let i = 0; i < shNum; i++) {
		const off = shOff + i * shEntSize;

		if (off + shEntSize > buffer.length) {
			break;
		}

		const nameIdx = r.u32(off);
		const type = r.u32(off + 4);

		let offset: number;
		let size: number;
		let link: number;
		let entSize: number;

		if (is64) {
			offset = Number(r.u64(off + 24));
			size = Number(r.u64(off + 32));
			link = r.u32(off + 40);
			entSize = Number(r.u64(off + 56));
		} else {
			offset = r.u32(off + 16);
			size = r.u32(off + 20);
			link = r.u32(off + 24);
			entSize = r.u32(off + 36);
		}

		headers.push({ nameIdx, type, offset, size, link, entSize });
	}

	return headers;
}

/**
 * Parses symbols from SHT_SYMTAB and SHT_DYNSYM sections.
 *
 * For each symbol table section found, reads the associated string table
 * (via sh_link) and parses each symbol entry to extract name, value, size,
 * type, binding, and section index.
 *
 * @param buffer - The full file buffer.
 * @param is64 - Whether this is a 64-bit ELF.
 * @param isLittle - Whether the byte order is little-endian.
 * @param rawSections - Pre-parsed raw section headers.
 * @returns Array of parsed ELF symbols.
 */
function parseSymbolTable(
	buffer: Buffer,
	is64: boolean,
	isLittle: boolean,
	rawSections: RawSectionHeader[],
): ELFSymbol[] {
	const r = getReaders(buffer, isLittle);
	const symbols: ELFSymbol[] = [];
	const symEntrySize = is64 ? 24 : 16;

	for (const section of rawSections) {
		if (section.type !== SHT_SYMTAB && section.type !== SHT_DYNSYM) {
			continue;
		}

		// Validate section data fits in buffer
		if (section.offset + section.size > buffer.length) {
			continue;
		}

		// Get the associated string table via sh_link
		let strTab: Buffer | null = null;
		if (section.link > 0 && section.link < rawSections.length) {
			const strSection = rawSections[section.link];
			if (strSection.offset + strSection.size <= buffer.length) {
				strTab = buffer.subarray(strSection.offset, strSection.offset + strSection.size);
			}
		}

		const entSize = section.entSize > 0 ? section.entSize : symEntrySize;
		const numSymbols = Math.floor(section.size / entSize);

		for (let i = 0; i < numSymbols; i++) {
			const off = section.offset + i * entSize;

			if (off + entSize > buffer.length) {
				break;
			}

			let stName: number;
			let stInfo: number;
			let stShndx: number;
			let stValue: bigint;
			let stSize: number;

			if (is64) {
				// ELF64 symbol: st_name(4) st_info(1) st_other(1) st_shndx(2) st_value(8) st_size(8)
				stName = r.u32(off);
				stInfo = buffer[off + 4];
				stShndx = r.u16(off + 6);
				stValue = r.u64(off + 8);
				stSize = Number(r.u64(off + 16));
			} else {
				// ELF32 symbol: st_name(4) st_value(4) st_size(4) st_info(1) st_other(1) st_shndx(2)
				stName = r.u32(off);
				stValue = BigInt(r.u32(off + 4));
				stSize = r.u32(off + 8);
				stInfo = buffer[off + 12];
				stShndx = r.u16(off + 14);
			}

			const binding = stInfo >> 4;
			const type = stInfo & 0xf;

			const name = strTab ? readStringFromTable(strTab, stName) : '';

			// Resolve section name for the symbol
			let sectionName: string;
			if (stShndx === 0) {
				sectionName = 'UND';
			} else if (stShndx === 0xfff1) {
				sectionName = 'ABS';
			} else if (stShndx === 0xfff2) {
				sectionName = 'COM';
			} else {
				sectionName = stShndx.toString();
			}

			symbols.push({
				name,
				value: toHex(stValue),
				size: stSize,
				type: STT_MAP[type] ?? ('Unknown (' + type + ')'),
				binding: STB_MAP[binding] ?? ('Unknown (' + binding + ')'),
				section: sectionName,
			});
		}
	}

	return symbols;
}

// ============================================================================
// DYNAMIC SECTION PARSING
// ============================================================================

/**
 * Parses the dynamic section (.dynamic) for linking information.
 *
 * Reads entries from the SHT_DYNAMIC section, mapping each tag to its
 * human-readable name and formatting the value as hex.
 *
 * @param buffer - The full file buffer.
 * @param is64 - Whether this is a 64-bit ELF.
 * @param isLittle - Whether the byte order is little-endian.
 * @param rawSections - Pre-parsed raw section headers.
 * @returns Array of parsed dynamic entries.
 */
function parseDynamicSection(
	buffer: Buffer,
	is64: boolean,
	isLittle: boolean,
	rawSections: RawSectionHeader[],
): ELFDynamic[] {
	const r = getReaders(buffer, isLittle);
	const entries: ELFDynamic[] = [];
	const dynEntrySize = is64 ? 16 : 8;

	// Find the SHT_DYNAMIC section
	const dynSection = rawSections.find(s => s.type === SHT_DYNAMIC);
	if (!dynSection) {
		return [];
	}

	// Validate section data fits in buffer
	if (dynSection.offset + dynSection.size > buffer.length) {
		return [];
	}

	const entSize = dynSection.entSize > 0 ? dynSection.entSize : dynEntrySize;
	const numEntries = Math.floor(dynSection.size / entSize);

	for (let i = 0; i < numEntries; i++) {
		const off = dynSection.offset + i * entSize;

		if (off + entSize > buffer.length) {
			break;
		}

		let dTag: number;
		let dVal: bigint;

		if (is64) {
			// ELF64 dynamic entry: d_tag(8) d_val(8)
			dTag = Number(r.u64(off));
			dVal = r.u64(off + 8);
		} else {
			// ELF32 dynamic entry: d_tag(4) d_val(4)
			dTag = r.u32(off);
			dVal = BigInt(r.u32(off + 4));
		}

		// DT_NULL marks end of dynamic section
		if (dTag === DT_NULL) {
			break;
		}

		entries.push({
			tag: DT_TAG_MAP[dTag] ?? ('Unknown (0x' + dTag.toString(16) + ')'),
			value: toHex(dVal),
		});
	}

	return entries;
}

// ============================================================================
// IMPORT PARSING
// ============================================================================

/**
 * Extracts imported function/symbol names from the ELF binary.
 *
 * Imports are identified as symbols from .dynsym with GLOBAL or WEAK binding
 * and value 0 (undefined/imported). Library names come from DT_NEEDED entries
 * in the dynamic section, resolved via the dynamic string table.
 *
 * @param buffer - The full file buffer.
 * @param is64 - Whether this is a 64-bit ELF.
 * @param isLittle - Whether the byte order is little-endian.
 * @param rawSections - Pre-parsed raw section headers.
 * @param symbols - Pre-parsed symbol table.
 * @param dynamicEntries - Pre-parsed dynamic entries (raw tag/value pairs).
 * @returns Array of imported symbols with library names.
 */
function parseImports(
	buffer: Buffer,
	is64: boolean,
	isLittle: boolean,
	rawSections: RawSectionHeader[],
	symbols: ELFSymbol[],
	dynamicEntries: ELFDynamic[],
): ELFImport[] {
	const r = getReaders(buffer, isLittle);

	// --- Resolve DT_NEEDED library names from the dynamic string table ---
	const libraries: string[] = [];

	// Find the dynamic section to get raw tag/value pairs for DT_NEEDED and DT_STRTAB
	const dynSection = rawSections.find(s => s.type === SHT_DYNAMIC);
	if (dynSection && dynSection.offset + dynSection.size <= buffer.length) {
		const dynEntrySize = is64 ? 16 : 8;
		const entSize = dynSection.entSize > 0 ? dynSection.entSize : dynEntrySize;
		const numEntries = Math.floor(dynSection.size / entSize);

		// First pass: find DT_STRTAB address
		let strTabAddr = 0n;
		for (let i = 0; i < numEntries; i++) {
			const off = dynSection.offset + i * entSize;
			if (off + entSize > buffer.length) {
				break;
			}
			const dTag = is64 ? Number(r.u64(off)) : r.u32(off);
			if (dTag === DT_NULL) {
				break;
			}
			if (dTag === DT_STRTAB) {
				strTabAddr = is64 ? r.u64(off + 8) : BigInt(r.u32(off + 4));
				break;
			}
		}

		// Resolve DT_STRTAB virtual address to file offset using LOAD segments
		let strTabFileOffset = -1;
		if (strTabAddr > 0n) {
			// Try to find a matching section first (more reliable)
			for (const sec of rawSections) {
				if (sec.type === SHT_STRTAB) {
					// Check if this strtab section is the dynamic string table
					// by matching its offset with what we can derive
					const secEnd = sec.offset + sec.size;
					if (secEnd <= buffer.length) {
						// Use the section linked from .dynsym as the dynamic strtab
						const dynsymSection = rawSections.find(s => s.type === SHT_DYNSYM);
						if (dynsymSection && dynsymSection.link < rawSections.length) {
							const linkedStrTab = rawSections[dynsymSection.link];
							strTabFileOffset = linkedStrTab.offset;
							break;
						}
					}
				}
			}

			// Fallback: try to find a LOAD segment that maps this address
			if (strTabFileOffset < 0) {
				let phOff: number;
				let phEntSize: number;
				let phNum: number;

				if (is64) {
					phOff = Number(r.u64(32));
					phEntSize = r.u16(54);
					phNum = r.u16(56);
				} else {
					phOff = r.u32(28);
					phEntSize = r.u16(42);
					phNum = r.u16(44);
				}

				for (let i = 0; i < phNum; i++) {
					const off = phOff + i * phEntSize;
					if (off + phEntSize > buffer.length) {
						break;
					}
					const pType = r.u32(off);
					if (pType !== PT_LOAD) {
						continue;
					}

					let pOffset: number;
					let pVaddr: bigint;
					let pFilesz: number;

					if (is64) {
						pOffset = Number(r.u64(off + 8));
						pVaddr = r.u64(off + 16);
						pFilesz = Number(r.u64(off + 32));
					} else {
						pOffset = r.u32(off + 4);
						pVaddr = BigInt(r.u32(off + 8));
						pFilesz = r.u32(off + 16);
					}

					if (strTabAddr >= pVaddr && strTabAddr < pVaddr + BigInt(pFilesz)) {
						strTabFileOffset = pOffset + Number(strTabAddr - pVaddr);
						break;
					}
				}
			}
		}

		// Second pass: resolve DT_NEEDED entries
		if (strTabFileOffset >= 0) {
			for (let i = 0; i < numEntries; i++) {
				const off = dynSection.offset + i * entSize;
				if (off + entSize > buffer.length) {
					break;
				}
				const dTag = is64 ? Number(r.u64(off)) : r.u32(off);
				if (dTag === DT_NULL) {
					break;
				}
				if (dTag === DT_NEEDED) {
					const nameOffset = is64 ? Number(r.u64(off + 8)) : r.u32(off + 4);
					const libName = readStringFromTable(buffer, strTabFileOffset + nameOffset);
					if (libName) {
						libraries.push(libName);
					}
				}
			}
		}
	}

	// --- Find imported symbols from .dynsym ---
	// Imported symbols have GLOBAL or WEAK binding and value 0x0 (undefined)
	const imports: ELFImport[] = [];
	const libraryStr = libraries.join(', ') || 'unknown';

	for (const sym of symbols) {
		if (sym.name === '') {
			continue;
		}
		if (sym.section !== 'UND') {
			continue;
		}
		if (sym.binding !== 'GLOBAL' && sym.binding !== 'WEAK') {
			continue;
		}

		imports.push({
			name: sym.name,
			library: libraryStr,
		});
	}

	return imports;
}

// ============================================================================
// SECTION HEADER PARSING
// ============================================================================

/**
 * Parses all section headers from the ELF file buffer.
 *
 * Reads the section header table, resolves section names from the string table
 * section (shstrndx), and calculates Shannon entropy for each section that has
 * data in the file (i.e., not SHT_NOBITS).
 *
 * @param buffer - The full file buffer.
 * @param is64 - Whether this is a 64-bit ELF.
 * @param isLittle - Whether the byte order is little-endian.
 * @param shOff - Offset of the section header table in the file.
 * @param shEntSize - Size of each section header entry.
 * @param shNum - Number of section header entries.
 * @param shStrNdx - Index of the section name string table section.
 * @returns Array of parsed ELF sections.
 */
function parseSectionHeaders(
	buffer: Buffer,
	is64: boolean,
	isLittle: boolean,
	shOff: number,
	shEntSize: number,
	shNum: number,
	shStrNdx: number,
): ELFSection[] {
	if (shOff === 0 || shNum === 0) {
		return [];
	}

	// Validate that the section header table fits within the file
	const shTableEnd = shOff + shNum * shEntSize;
	if (shTableEnd > buffer.length) {
		return [];
	}

	const r = getReaders(buffer, isLittle);

	// --- Read the string table section first to resolve names ---
	let strTabBuffer: Buffer | null = null;
	if (shStrNdx > 0 && shStrNdx < shNum) {
		const strTabEntryOff = shOff + shStrNdx * shEntSize;
		let strTabOffset: number;
		let strTabSize: number;

		if (is64) {
			strTabOffset = Number(r.u64(strTabEntryOff + 24));
			strTabSize = Number(r.u64(strTabEntryOff + 32));
		} else {
			strTabOffset = r.u32(strTabEntryOff + 16);
			strTabSize = r.u32(strTabEntryOff + 20);
		}

		if (strTabOffset + strTabSize <= buffer.length) {
			strTabBuffer = buffer.subarray(strTabOffset, strTabOffset + strTabSize);
		}
	}

	// --- Parse each section header ---
	const sections: ELFSection[] = [];

	for (let i = 0; i < shNum; i++) {
		const off = shOff + i * shEntSize;

		if (off + shEntSize > buffer.length) {
			break;
		}

		const nameIdx = r.u32(off);
		const shType = r.u32(off + 4);

		let shFlags: number;
		let shAddr: bigint;
		let shOffset: number;
		let shSize: number;

		if (is64) {
			shFlags = Number(r.u64(off + 8));
			shAddr = r.u64(off + 16);
			shOffset = Number(r.u64(off + 24));
			shSize = Number(r.u64(off + 32));
		} else {
			shFlags = r.u32(off + 8);
			shAddr = BigInt(r.u32(off + 12));
			shOffset = r.u32(off + 16);
			shSize = r.u32(off + 20);
		}

		// Resolve section name from string table
		const name = strTabBuffer ? readStringFromTable(strTabBuffer, nameIdx) : '';

		// Calculate entropy for sections that have file data
		let entropy = 0;
		if (shType !== SHT_NULL && shType !== SHT_NOBITS && shSize > 0) {
			const dataEnd = shOffset + shSize;
			if (shOffset >= 0 && dataEnd <= buffer.length) {
				const sectionData = buffer.subarray(shOffset, dataEnd);
				entropy = calculateEntropy(sectionData);
			}
		}

		sections.push({
			name,
			type: SHT_TYPE_MAP[shType] ?? ('Unknown (' + shType + ')'),
			address: toHex(shAddr),
			offset: shOffset,
			size: shSize,
			flags: parseSectionFlags(shFlags),
			entropy,
		});
	}

	return sections;
}
