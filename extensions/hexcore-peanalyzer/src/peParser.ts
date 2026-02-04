/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as fs from 'fs';

// ============================================================================
// TYPE DEFINITIONS
// ============================================================================

export interface PEAnalysis {
	fileName: string;
	fileSize: number;
	filePath: string;
	isPE: boolean;
	error?: string;

	// Headers
	dosHeader?: DOSHeader;
	peHeader?: PEHeader;
	optionalHeader?: OptionalHeader;
	richHeader?: RichHeader;

	// Sections
	sections: SectionHeader[];

	// Imports/Exports
	imports: ImportEntry[];
	exports: ExportEntry[];

	// Advanced Analysis
	resources: ResourceEntry[];
	tlsCallbacks: number[];
	exceptions: ExceptionEntry[];
	relocations: RelocationEntry[];
	debugInfo: DebugEntry[];

	// Security Analysis
	entropy: number;
	suspiciousStrings: string[];
	packerSignatures: string[];
	antiDebug: AntiDebugTechnique[];
	mitigations: SecurityMitigation[];

	timestamps: TimestampInfo;
}

export interface DOSHeader {
	magic: string;           // MZ
	lastPageBytes: number;
	pagesInFile: number;
	relocations: number;
	headerSizeInParagraphs: number;
	peHeaderOffset: number;  // e_lfanew
}

export interface PEHeader {
	signature: string;       // PE\0\0
	machine: string;
	machineRaw: number;
	numberOfSections: number;
	timeDateStamp: number;
	timeDateStampHuman: string;
	pointerToSymbolTable: number;
	numberOfSymbols: number;
	sizeOfOptionalHeader: number;
	characteristics: string[];
	characteristicsRaw: number;
}

export interface OptionalHeader {
	magic: string;           // PE32 or PE32+
	is64Bit: boolean;
	majorLinkerVersion: number;
	minorLinkerVersion: number;
	sizeOfCode: number;
	sizeOfInitializedData: number;
	sizeOfUninitializedData: number;
	addressOfEntryPoint: number;
	baseOfCode: number;
	imageBase: bigint;
	sectionAlignment: number;
	fileAlignment: number;
	majorOSVersion: number;
	minorOSVersion: number;
	majorImageVersion: number;
	minorImageVersion: number;
	majorSubsystemVersion: number;
	minorSubsystemVersion: number;
	sizeOfImage: number;
	sizeOfHeaders: number;
	checksum: number;
	subsystem: string;
	subsystemRaw: number;
	dllCharacteristics: string[];
	dllCharacteristicsRaw: number;
	sizeOfStackReserve: bigint;
	sizeOfStackCommit: bigint;
	sizeOfHeapReserve: bigint;
	sizeOfHeapCommit: bigint;
	numberOfRvaAndSizes: number;
	dataDirectories: DataDirectory[];
}

export interface DataDirectory {
	name: string;
	virtualAddress: number;
	size: number;
}

export interface SectionHeader {
	name: string;
	virtualSize: number;
	virtualAddress: number;
	sizeOfRawData: number;
	pointerToRawData: number;
	characteristics: string[];
	characteristicsRaw: number;
	entropy: number;
}

export interface ImportEntry {
	dllName: string;
	functions: ImportFunctionEntry[];
}

export interface ImportFunctionEntry {
	name: string;
	ordinal?: number;
	address: number; // IAT address
}

export interface ExportEntry {
	ordinal: number;
	name: string;
	address: number;
}

export interface TimestampInfo {
	compile: string;
	compileUnix: number;
}

export interface RichHeader {
	valid: boolean;
	entries: Array<{ compId: number; count: number; productName?: string }>;
	xorKey: number;
}

export interface ResourceEntry {
	type: string;
	name: string | number;
	langId: number;
	size: number;
	offset: number;
	data?: Buffer;
}

export interface ExceptionEntry {
	beginAddress: number;
	endAddress: number;
	unwindInfoAddress: number;
}

export interface RelocationEntry {
	pageRVA: number;
	type: string;
	offset: number;
}

export interface DebugEntry {
	type: string;
	size: number;
	address: number;
	pointer: number;
}

export interface AntiDebugTechnique {
	name: string;
	description: string;
	severity: 'low' | 'medium' | 'high';
	indicators: string[];
}

export interface SecurityMitigation {
	name: string;
	enabled: boolean;
	description: string;
}

// ============================================================================
// CONSTANTS
// ============================================================================

const MACHINE_TYPES: Record<number, string> = {
	0x0: 'Unknown',
	0x14c: 'i386 (x86)',
	0x8664: 'AMD64 (x64)',
	0x1c0: 'ARM',
	0xaa64: 'ARM64',
	0x1c4: 'ARM Thumb-2',
	0x200: 'IA64 (Itanium)',
};

const SUBSYSTEMS: Record<number, string> = {
	0: 'Unknown',
	1: 'Native',
	2: 'Windows GUI',
	3: 'Windows Console',
	5: 'OS/2 Console',
	7: 'POSIX Console',
	9: 'Windows CE GUI',
	10: 'EFI Application',
	11: 'EFI Boot Service Driver',
	12: 'EFI Runtime Driver',
	13: 'EFI ROM',
	14: 'Xbox',
	16: 'Windows Boot Application',
};

const PE_CHARACTERISTICS: Record<number, string> = {
	0x0001: 'RELOCS_STRIPPED',
	0x0002: 'EXECUTABLE_IMAGE',
	0x0004: 'LINE_NUMS_STRIPPED',
	0x0008: 'LOCAL_SYMS_STRIPPED',
	0x0010: 'AGGRESSIVE_WS_TRIM',
	0x0020: 'LARGE_ADDRESS_AWARE',
	0x0080: 'BYTES_REVERSED_LO',
	0x0100: '32BIT_MACHINE',
	0x0200: 'DEBUG_STRIPPED',
	0x0400: 'REMOVABLE_RUN_FROM_SWAP',
	0x0800: 'NET_RUN_FROM_SWAP',
	0x1000: 'SYSTEM',
	0x2000: 'DLL',
	0x4000: 'UP_SYSTEM_ONLY',
	0x8000: 'BYTES_REVERSED_HI',
};

const SECTION_CHARACTERISTICS: Record<number, string> = {
	0x00000020: 'CODE',
	0x00000040: 'INITIALIZED_DATA',
	0x00000080: 'UNINITIALIZED_DATA',
	0x02000000: 'DISCARDABLE',
	0x04000000: 'NOT_CACHED',
	0x08000000: 'NOT_PAGED',
	0x10000000: 'SHARED',
	0x20000000: 'EXECUTE',
	0x40000000: 'READ',
	0x80000000: 'WRITE',
};

const DLL_CHARACTERISTICS: Record<number, string> = {
	0x0020: 'HIGH_ENTROPY_VA',
	0x0040: 'DYNAMIC_BASE (ASLR)',
	0x0080: 'FORCE_INTEGRITY',
	0x0100: 'NX_COMPAT (DEP)',
	0x0200: 'NO_ISOLATION',
	0x0400: 'NO_SEH',
	0x0800: 'NO_BIND',
	0x1000: 'APPCONTAINER',
	0x2000: 'WDM_DRIVER',
	0x4000: 'GUARD_CF',
	0x8000: 'TERMINAL_SERVER_AWARE',
};

const DATA_DIRECTORY_NAMES = [
	'Export Table',
	'Import Table',
	'Resource Table',
	'Exception Table',
	'Certificate Table',
	'Base Relocation Table',
	'Debug',
	'Architecture',
	'Global Ptr',
	'TLS Table',
	'Load Config Table',
	'Bound Import',
	'IAT',
	'Delay Import Descriptor',
	'CLR Runtime Header',
	'Reserved',
];

const PACKER_SIGNATURES: Array<{ name: string; pattern: RegExp | string }> = [
	{ name: 'UPX', pattern: 'UPX0' },
	{ name: 'UPX', pattern: 'UPX1' },
	{ name: 'UPX', pattern: 'UPX!' },
	{ name: 'ASPack', pattern: '.aspack' },
	{ name: 'ASPack', pattern: 'ByDwing' },
	{ name: 'PECompact', pattern: 'PEC2' },
	{ name: 'Themida', pattern: '.themida' },
	{ name: 'VMProtect', pattern: '.vmp0' },
	{ name: 'VMProtect', pattern: '.vmp1' },
	{ name: 'Enigma', pattern: '.enigma' },
	{ name: 'MPRESS', pattern: '.MPRESS' },
	{ name: 'Petite', pattern: '.petite' },
	{ name: 'NSPack', pattern: '.nsp0' },
	{ name: 'PELock', pattern: 'PELock' },
	{ name: 'Armadillo', pattern: '.text1' },
	{ name: '.NET', pattern: 'mscoree.dll' },
];

// ============================================================================
// MAIN PARSER
// ============================================================================

export async function analyzePEFile(filePath: string): Promise<PEAnalysis> {
	const stats = fs.statSync(filePath);
	const fileName = filePath.split(/[\\/]/).pop() || 'Unknown';

	const analysis: PEAnalysis = {
		fileName,
		fileSize: stats.size,
		filePath,
		isPE: false,
		sections: [],
		imports: [],
		exports: [],
		resources: [],
		tlsCallbacks: [],
		exceptions: [],
		relocations: [],
		debugInfo: [],
		antiDebug: [],
		mitigations: [],
		entropy: 0,
		suspiciousStrings: [],
		packerSignatures: [],
		timestamps: { compile: 'Unknown', compileUnix: 0 },
	};

	try {
		const fd = fs.openSync(filePath, 'r');
		const buffer = Buffer.alloc(Math.min(stats.size, 1024 * 1024)); // Read up to 1MB
		fs.readSync(fd, buffer, 0, buffer.length, 0);

		// Parse DOS Header
		if (buffer.length < 64) {
			analysis.error = 'File too small to be a valid PE';
			fs.closeSync(fd);
			return analysis;
		}

		const dosHeader = parseDOSHeader(buffer);
		if (dosHeader.magic !== 'MZ') {
			analysis.error = 'Invalid DOS header (not MZ)';
			fs.closeSync(fd);
			return analysis;
		}
		analysis.dosHeader = dosHeader;

		// Check PE signature
		const peOffset = dosHeader.peHeaderOffset;
		if (peOffset + 4 > buffer.length) {
			analysis.error = 'PE header offset beyond file size';
			fs.closeSync(fd);
			return analysis;
		}

		const peSignature = buffer.toString('ascii', peOffset, peOffset + 4);
		if (peSignature !== 'PE\x00\x00') {
			analysis.error = 'Invalid PE signature';
			fs.closeSync(fd);
			return analysis;
		}

		analysis.isPE = true;

		// Parse PE Header (COFF)
		const peHeader = parsePEHeader(buffer, peOffset + 4);
		analysis.peHeader = peHeader;
		analysis.timestamps = {
			compile: peHeader.timeDateStampHuman,
			compileUnix: peHeader.timeDateStamp,
		};

		// Parse Optional Header
		const optionalHeaderOffset = peOffset + 24;
		if (peHeader.sizeOfOptionalHeader > 0) {
			const optionalHeader = parseOptionalHeader(buffer, optionalHeaderOffset, peHeader.sizeOfOptionalHeader);
			analysis.optionalHeader = optionalHeader;
		}

		// Parse Section Headers
		const sectionOffset = optionalHeaderOffset + peHeader.sizeOfOptionalHeader;
		analysis.sections = parseSectionHeaders(buffer, sectionOffset, peHeader.numberOfSections, fd);

		// Parse Imports
		if (analysis.optionalHeader && analysis.optionalHeader.dataDirectories[1]?.size > 0) {
			analysis.imports = parseImports(fd, buffer, analysis.optionalHeader.dataDirectories[1], analysis.sections, analysis.optionalHeader.is64Bit);
		}

		// Calculate overall entropy
		analysis.entropy = calculateEntropy(buffer);

		// Detect packers
		analysis.packerSignatures = detectPackers(buffer, analysis.sections);

		// Extract suspicious strings
		analysis.suspiciousStrings = extractSuspiciousStrings(buffer);

		fs.closeSync(fd);
	} catch (error: any) {
		analysis.error = error.message;
	}

	return analysis;
}

// ============================================================================
// HEADER PARSERS
// ============================================================================

function parseDOSHeader(buffer: Buffer): DOSHeader {
	return {
		magic: buffer.toString('ascii', 0, 2),
		lastPageBytes: buffer.readUInt16LE(2),
		pagesInFile: buffer.readUInt16LE(4),
		relocations: buffer.readUInt16LE(6),
		headerSizeInParagraphs: buffer.readUInt16LE(8),
		peHeaderOffset: buffer.readUInt32LE(60), // e_lfanew
	};
}

function parsePEHeader(buffer: Buffer, offset: number): PEHeader {
	const machine = buffer.readUInt16LE(offset);
	const characteristics = buffer.readUInt16LE(offset + 18);
	const timestamp = buffer.readUInt32LE(offset + 4);

	return {
		signature: 'PE',
		machine: MACHINE_TYPES[machine] || `Unknown (0x${machine.toString(16)})`,
		machineRaw: machine,
		numberOfSections: buffer.readUInt16LE(offset + 2),
		timeDateStamp: timestamp,
		timeDateStampHuman: timestamp > 0 ? new Date(timestamp * 1000).toISOString() : 'Invalid',
		pointerToSymbolTable: buffer.readUInt32LE(offset + 8),
		numberOfSymbols: buffer.readUInt32LE(offset + 12),
		sizeOfOptionalHeader: buffer.readUInt16LE(offset + 16),
		characteristics: parseFlags(characteristics, PE_CHARACTERISTICS),
		characteristicsRaw: characteristics,
	};
}

function parseOptionalHeader(buffer: Buffer, offset: number, size: number): OptionalHeader {
	const magic = buffer.readUInt16LE(offset);
	const is64Bit = magic === 0x20b;

	const subsystem = buffer.readUInt16LE(offset + (is64Bit ? 68 : 68));
	const dllCharacteristics = buffer.readUInt16LE(offset + (is64Bit ? 70 : 70));

	// Parse data directories
	const numberOfRvaAndSizes = buffer.readUInt32LE(offset + (is64Bit ? 108 : 92));
	const dataDirectoriesOffset = offset + (is64Bit ? 112 : 96);
	const dataDirectories: DataDirectory[] = [];

	for (let i = 0; i < Math.min(numberOfRvaAndSizes, 16); i++) {
		const ddOffset = dataDirectoriesOffset + i * 8;
		if (ddOffset + 8 <= buffer.length) {
			dataDirectories.push({
				name: DATA_DIRECTORY_NAMES[i] || `Directory ${i}`,
				virtualAddress: buffer.readUInt32LE(ddOffset),
				size: buffer.readUInt32LE(ddOffset + 4),
			});
		}
	}

	return {
		magic: is64Bit ? 'PE32+ (64-bit)' : 'PE32 (32-bit)',
		is64Bit,
		majorLinkerVersion: buffer.readUInt8(offset + 2),
		minorLinkerVersion: buffer.readUInt8(offset + 3),
		sizeOfCode: buffer.readUInt32LE(offset + 4),
		sizeOfInitializedData: buffer.readUInt32LE(offset + 8),
		sizeOfUninitializedData: buffer.readUInt32LE(offset + 12),
		addressOfEntryPoint: buffer.readUInt32LE(offset + 16),
		baseOfCode: buffer.readUInt32LE(offset + 20),
		imageBase: is64Bit ? buffer.readBigUInt64LE(offset + 24) : BigInt(buffer.readUInt32LE(offset + 28)),
		sectionAlignment: buffer.readUInt32LE(offset + (is64Bit ? 32 : 32)),
		fileAlignment: buffer.readUInt32LE(offset + (is64Bit ? 36 : 36)),
		majorOSVersion: buffer.readUInt16LE(offset + (is64Bit ? 40 : 40)),
		minorOSVersion: buffer.readUInt16LE(offset + (is64Bit ? 42 : 42)),
		majorImageVersion: buffer.readUInt16LE(offset + (is64Bit ? 44 : 44)),
		minorImageVersion: buffer.readUInt16LE(offset + (is64Bit ? 46 : 46)),
		majorSubsystemVersion: buffer.readUInt16LE(offset + (is64Bit ? 48 : 48)),
		minorSubsystemVersion: buffer.readUInt16LE(offset + (is64Bit ? 50 : 50)),
		sizeOfImage: buffer.readUInt32LE(offset + (is64Bit ? 56 : 56)),
		sizeOfHeaders: buffer.readUInt32LE(offset + (is64Bit ? 60 : 60)),
		checksum: buffer.readUInt32LE(offset + (is64Bit ? 64 : 64)),
		subsystem: SUBSYSTEMS[subsystem] || `Unknown (${subsystem})`,
		subsystemRaw: subsystem,
		dllCharacteristics: parseFlags(dllCharacteristics, DLL_CHARACTERISTICS),
		dllCharacteristicsRaw: dllCharacteristics,
		sizeOfStackReserve: is64Bit ? buffer.readBigUInt64LE(offset + 72) : BigInt(buffer.readUInt32LE(offset + 72)),
		sizeOfStackCommit: is64Bit ? buffer.readBigUInt64LE(offset + 80) : BigInt(buffer.readUInt32LE(offset + 76)),
		sizeOfHeapReserve: is64Bit ? buffer.readBigUInt64LE(offset + 88) : BigInt(buffer.readUInt32LE(offset + 80)),
		sizeOfHeapCommit: is64Bit ? buffer.readBigUInt64LE(offset + 96) : BigInt(buffer.readUInt32LE(offset + 84)),
		numberOfRvaAndSizes,
		dataDirectories,
	};
}

function parseSectionHeaders(buffer: Buffer, offset: number, count: number, fd: number): SectionHeader[] {
	const sections: SectionHeader[] = [];

	for (let i = 0; i < count; i++) {
		const secOffset = offset + i * 40;
		if (secOffset + 40 > buffer.length) {
			break;
		}

		const name = buffer.toString('ascii', secOffset, secOffset + 8).replace(/\x00/g, '');
		const characteristics = buffer.readUInt32LE(secOffset + 36);
		const pointerToRawData = buffer.readUInt32LE(secOffset + 20);
		const sizeOfRawData = buffer.readUInt32LE(secOffset + 16);

		// Calculate section entropy
		let entropy = 0;
		if (sizeOfRawData > 0 && pointerToRawData > 0) {
			try {
				const sectionBuffer = Buffer.alloc(Math.min(sizeOfRawData, 65536));
				fs.readSync(fd, sectionBuffer, 0, sectionBuffer.length, pointerToRawData);
				entropy = calculateEntropy(sectionBuffer);
			} catch (e) {
				entropy = 0;
			}
		}

		sections.push({
			name,
			virtualSize: buffer.readUInt32LE(secOffset + 8),
			virtualAddress: buffer.readUInt32LE(secOffset + 12),
			sizeOfRawData,
			pointerToRawData,
			characteristics: parseFlags(characteristics, SECTION_CHARACTERISTICS),
			characteristicsRaw: characteristics,
			entropy,
		});
	}

	return sections;
}

// ============================================================================
// IMPORT PARSER
// ============================================================================

function parseImports(fd: number, headerBuffer: Buffer, importDir: DataDirectory, sections: SectionHeader[], is64Bit: boolean): ImportEntry[] {
	const imports: ImportEntry[] = [];
	const pointerSize = is64Bit ? 8 : 4;

	if (importDir.virtualAddress === 0 || importDir.size === 0) {
		return imports;
	}

	// Find section containing import directory
	const fileOffset = rvaToFileOffset(importDir.virtualAddress, sections);
	if (fileOffset === 0) {
		return imports;
	}

	try {
		const importBuffer = Buffer.alloc(Math.min(importDir.size, 16384));
		fs.readSync(fd, importBuffer, 0, importBuffer.length, fileOffset);

		let offset = 0;
		while (offset + 20 <= importBuffer.length && imports.length < 200) {
			const originalFirstThunk = importBuffer.readUInt32LE(offset); // ILT RVA
			const nameRVA = importBuffer.readUInt32LE(offset + 12);
			const firstThunk = importBuffer.readUInt32LE(offset + 16); // IAT RVA (Base for addresses)

			if (nameRVA === 0 && firstThunk === 0) {
				break;
			} // End of imports

			// Read DLL name
			const nameOffset = rvaToFileOffset(nameRVA, sections);
			let dllName = `Unknown_0x${nameRVA.toString(16)}`;

			if (nameOffset > 0) {
				const nameBuffer = Buffer.alloc(256);
				fs.readSync(fd, nameBuffer, 0, 256, nameOffset);
				dllName = readNullTerminatedString(nameBuffer);
			}

			// Parse imported functions from ILT or IAT
			const functions: ImportFunctionEntry[] = [];
			const thunkRVA = originalFirstThunk || firstThunk;

			if (thunkRVA > 0) {
				const thunkOffset = rvaToFileOffset(thunkRVA, sections);
				if (thunkOffset > 0) {
					// Read enough for a reasonable number of imports
					const thunkBuffer = Buffer.alloc(4096);
					fs.readSync(fd, thunkBuffer, 0, thunkBuffer.length, thunkOffset);

					let thunkPos = 0;
					let functionIndex = 0;
					while (thunkPos + pointerSize <= thunkBuffer.length && functions.length < 200) {
						let thunkValue: number | bigint;
						if (is64Bit) {
							thunkValue = thunkBuffer.readBigUInt64LE(thunkPos);
						} else {
							thunkValue = thunkBuffer.readUInt32LE(thunkPos);
						}

						if (thunkValue === 0 || (typeof thunkValue === 'bigint' && thunkValue === 0n)) {
							break;
						}

						const iatAddress = firstThunk + (functionIndex * pointerSize); // RVA of this import slot

						// Check if import by ordinal
						const isOrdinal = is64Bit
							? (BigInt(thunkValue) & 0x8000000000000000n) !== 0n
							: (Number(thunkValue) & 0x80000000) !== 0;

						if (isOrdinal) {
							const ordinal = is64Bit
								? Number(BigInt(thunkValue) & 0xFFFFn)
								: Number(thunkValue) & 0xFFFF;

							functions.push({
								name: `Ordinal_${ordinal}`,
								ordinal,
								address: iatAddress
							});
						} else {
							// Import by name - thunkValue is RVA to IMAGE_IMPORT_BY_NAME
							// Mask off high bits just in case
							const nameRefRVA = is64Bit
								? Number(BigInt(thunkValue) & 0x7FFFFFFFn)
								: Number(thunkValue) & 0x7FFFFFFF;

							const hintNameOffset = rvaToFileOffset(nameRefRVA, sections);
							if (hintNameOffset > 0) {
								const hintNameBuffer = Buffer.alloc(256);
								fs.readSync(fd, hintNameBuffer, 0, 256, hintNameOffset);
								// Skip 2-byte hint, read name
								const funcName = readNullTerminatedString(hintNameBuffer.subarray(2));
								if (funcName.length > 0) {
									functions.push({
										name: funcName,
										address: iatAddress
									});
								} else {
									functions.push({ name: `Func_0x${nameRefRVA.toString(16)}`, address: iatAddress });
								}
							} else {
								functions.push({ name: `Func_0x${nameRefRVA.toString(16)}`, address: iatAddress });
							}
						}

						thunkPos += pointerSize;
						functionIndex++;
					}
				}
			}

			imports.push({
				dllName,
				functions: functions // No limit, allow Disassembler to handle limiting if needed
			});

			offset += 20; // Size of IMAGE_IMPORT_DESCRIPTOR
		}
	} catch (e) {
		console.error('Import parse error:', e);
	}

	return imports;
}

// ============================================================================
// UTILITIES
// ============================================================================

function parseFlags(value: number, flagMap: Record<number, string>): string[] {
	const flags: string[] = [];
	for (const [flag, name] of Object.entries(flagMap)) {
		if (value & parseInt(flag)) {
			flags.push(name);
		}
	}
	return flags;
}

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

function rvaToFileOffset(rva: number, sections: SectionHeader[]): number {
	for (const section of sections) {
		if (rva >= section.virtualAddress && rva < section.virtualAddress + section.virtualSize) {
			return section.pointerToRawData + (rva - section.virtualAddress);
		}
	}
	return 0;
}

function readNullTerminatedString(buffer: Buffer): string {
	let end = buffer.indexOf(0);
	if (end === -1) {
		end = buffer.length;
	}
	return buffer.toString('ascii', 0, end);
}

function detectPackers(buffer: Buffer, sections: SectionHeader[]): string[] {
	const detected: Set<string> = new Set();
	const bufferStr = buffer.toString('binary');

	for (const sig of PACKER_SIGNATURES) {
		if (typeof sig.pattern === 'string') {
			if (bufferStr.includes(sig.pattern)) {
				detected.add(sig.name);
			}
		}
	}

	// Check section names for packer signatures
	for (const section of sections) {
		const name = section.name.toLowerCase();
		if (name.includes('upx')) {
			detected.add('UPX');
		}
		if (name.includes('aspack')) {
			detected.add('ASPack');
		}
		if (name.includes('vmp')) {
			detected.add('VMProtect');
		}
		if (name.includes('themida')) {
			detected.add('Themida');
		}
		if (name.includes('enigma')) {
			detected.add('Enigma');
		}
	}

	return Array.from(detected);
}

function extractSuspiciousStrings(buffer: Buffer): string[] {
	const suspicious: string[] = [];
	const patterns = [
		/https?:\/\/[^\s"'<>]+/gi,                    // URLs
		/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g,   // IP addresses
		/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g, // Emails
		/\\\\[^\\]+\\[^\\]+/g,                        // UNC paths
		/HKEY_[A-Z_]+\\[^\0]+/gi,                     // Registry keys
		/cmd\.exe|powershell|wscript|cscript/gi,     // Suspicious executables
		/password|passwd|secret|token|api[_-]?key/gi, // Sensitive keywords
	];

	// Use latin1 encoding instead of binary for cleaner string extraction
	const bufferStr = buffer.toString('latin1');

	for (const pattern of patterns) {
		const matches = bufferStr.match(pattern);
		if (matches) {
			for (const match of matches.slice(0, 10)) { // Limit to 10 per pattern
				// Filter: must be mostly printable ASCII characters
				if (match.length > 5 && match.length < 200 && isCleanString(match)) {
					suspicious.push(match);
				}
			}
		}
	}

	return [...new Set(suspicious)].slice(0, 50); // Dedupe and limit
}

/**
 * Check if a string is clean (mostly printable ASCII)
 */
function isCleanString(str: string): boolean {
	let printableCount = 0;
	for (let i = 0; i < str.length; i++) {
		const code = str.charCodeAt(i);
		// Printable ASCII range: 0x20-0x7E
		if (code >= 0x20 && code <= 0x7E) {
			printableCount++;
		}
	}
	// At least 80% of characters must be printable
	return (printableCount / str.length) >= 0.8;
}

// ============================================================================
// RICH HEADER PARSER
// ============================================================================

function parseRichHeader(buffer: Buffer): RichHeader {
	// Rich header is located between DOS stub and PE header
	// It starts with 'DanS' and ends with 'Rich'

	const result: RichHeader = {
		valid: false,
		entries: [],
		xorKey: 0
	};

	try {
		// Search for 'DanS' signature (start of rich header)
		let danSOffset = -1;
		for (let i = 64; i < Math.min(buffer.length - 4, 1024); i++) {
			if (buffer.readUInt32LE(i) === 0x536E6144) { // 'DanS'
				danSOffset = i;
				break;
			}
		}

		if (danSOffset === -1) {
			return result;
		}

		// Find 'Rich' signature (end of rich header)
		let richOffset = -1;
		for (let i = danSOffset; i < Math.min(buffer.length - 8, 2048); i += 4) {
			if (buffer.readUInt32LE(i) === 0x68636952) { // 'Rich'
				richOffset = i;
				break;
			}
		}

		if (richOffset === -1) {
			return result;
		}

		// XOR key is the DWORD after 'Rich'
		const xorKey = buffer.readUInt32LE(richOffset + 4);
		result.xorKey = xorKey;

		// Parse entries (between DanS and Rich)
		// Skip 'DanS' + 4 DWORDs of padding
		const entriesStart = danSOffset + 16;
		const entriesEnd = richOffset;

		for (let offset = entriesStart; offset < entriesEnd; offset += 8) {
			if (offset + 8 > entriesEnd) {
				break;
			}

			const compId = buffer.readUInt32LE(offset) ^ xorKey;
			const count = buffer.readUInt32LE(offset + 4) ^ xorKey;

			if (count > 0 && count < 0xFFFF && compId > 0) {
				const buildNumber = compId >> 16;
				const prodId = compId & 0xFFFF;
				result.entries.push({
					compId,
					count,
					productName: getRichProductName(prodId, buildNumber)
				});
			}
		}

		result.valid = result.entries.length > 0;
	} catch (e) {
		// Invalid rich header
	}

	return result;
}

function getRichProductName(prodId: number, buildNumber: number): string {
	const products: Record<number, string> = {
		0x0000: 'Unknown',
		0x0001: 'Import0',
		0x0002: 'Linker510',
		0x0003: 'Cvtomf510',
		0x0004: 'Lnk510',
		0x0005: 'Masm510',
		0x0006: 'H2Inc',
		0x0007: 'CvtRes',
		0x0008: 'Utc11_Basic',
		0x0009: 'Utc11_C',
		0x000A: 'Utc12_Basic',
		0x000B: 'Utc12_C',
		0x000C: 'Utc12_CPP',
		0x000D: 'AliasObj60',
		0x000E: 'VisualBasic60',
		0x000F: 'Masm610',
		0x0010: 'Masm620',
		0x0011: 'Linker600',
		0x0012: 'Cvtomf600',
		0x0013: 'CvtRes500',
		0x0014: 'Utc13_Basic',
		0x0015: 'Utc13_C',
		0x0016: 'Utc13_CPP',
		0x0017: 'Linker610',
		0x0018: 'Cvtomf610',
		0x0019: 'Linker620',
		0x001A: 'Cvtomf620',
		0x001B: 'Asm',
		0x001C: 'Utc12_1_Basic',
		0x001D: 'Utc12_1_C',
		0x001E: 'Utc12_1_CPP',
		0x001F: 'Linker621',
		0x0020: 'Linker700',
		0x0021: 'Export',
		0x0022: 'ImpLib',
		0x0023: 'Masm700',
		0x0024: 'Utc13_LTCG_C',
		0x0025: 'Utc13_LTCG_CPP',
		0x0026: 'Utc13_POGO_I_C',
		0x0027: 'Utc13_POGO_I_CPP',
		0x0028: 'CvtPGD',
		0x0029: 'Linker710',
		0x002A: 'Cvtomf710',
		0x002B: 'Utc14_Basic',
		0x002C: 'Utc14_C',
		0x002D: 'Utc14_CPP',
		0x002E: 'Utc14_LTCG_C',
		0x002F: 'Utc14_LTCG_CPP',
		0x0030: 'Utc14_POGO_I_C',
		0x0031: 'Utc14_POGO_I_CPP',
		0x0032: 'CvtPGD',
	};

	return products[prodId] || `Product_${prodId.toString(16).toUpperCase()}`;
}

// ============================================================================
// ANTI-DEBUG DETECTION
// ============================================================================

function detectAntiDebug(buffer: Buffer, imports: ImportEntry[]): AntiDebugTechnique[] {
	const techniques: AntiDebugTechnique[] = [];

	// Anti-debugging APIs
	const antiDebugApis = [
		{ dll: 'kernel32.dll', api: 'IsDebuggerPresent', severity: 'low' as const },
		{ dll: 'kernel32.dll', api: 'CheckRemoteDebuggerPresent', severity: 'low' as const },
		{ dll: 'ntdll.dll', api: 'NtQueryInformationProcess', severity: 'medium' as const },
		{ dll: 'kernel32.dll', api: 'OutputDebugString', severity: 'low' as const },
		{ dll: 'ntdll.dll', api: 'NtSetInformationThread', severity: 'medium' as const },
		{ dll: 'kernel32.dll', api: 'CloseHandle', severity: 'low' as const },
		{ dll: 'ntdll.dll', api: 'NtClose', severity: 'low' as const },
		{ dll: 'user32.dll', api: 'BlockInput', severity: 'high' as const },
		{ dll: 'kernel32.dll', api: 'SetUnhandledExceptionFilter', severity: 'medium' as const },
	];

	for (const api of antiDebugApis) {
		const dll = imports.find(i => i.dllName.toLowerCase() === api.dll);
		if (dll && dll.functions.some(f => f.name.toLowerCase().includes(api.api.toLowerCase()))) {
			techniques.push({
				name: api.api,
				description: `Uses ${api.api} API for debugger detection`,
				severity: api.severity,
				indicators: [`${api.dll}: ${api.api}`]
			});
		}
	}

	// Check for suspicious strings
	const bufferStr = buffer.toString('binary').toLowerCase();
	const suspiciousStrings = [
		{ name: 'PEB.IsDebugged', pattern: 'isdebugged', severity: 'low' as const },
		{ name: 'PEB.NtGlobalFlag', pattern: 'ntglobalflag', severity: 'medium' as const },
		{ name: 'Heap.Flags', pattern: 'heap', severity: 'medium' as const },
		{ name: 'Timing Check', pattern: 'rdtsc', severity: 'low' as const },
		{ name: 'Int3 Detection', pattern: 'int 3', severity: 'low' as const },
		{ name: 'Int2D Detection', pattern: 'int 2d', severity: 'medium' as const },
	];

	for (const check of suspiciousStrings) {
		if (bufferStr.includes(check.pattern)) {
			// Check if not already added
			if (!techniques.some(t => t.name === check.name)) {
				techniques.push({
					name: check.name,
					description: `Contains ${check.name} anti-debug pattern`,
					severity: check.severity,
					indicators: [`Pattern: ${check.pattern}`]
				});
			}
		}
	}

	return techniques;
}

// ============================================================================
// SECURITY MITIGATIONS ANALYSIS
// ============================================================================

function analyzeMitigations(optionalHeader?: OptionalHeader): SecurityMitigation[] {
	const mitigations: SecurityMitigation[] = [];

	if (!optionalHeader) {
		return mitigations;
	}

	mitigations.push({
		name: 'ASLR (Address Space Layout Randomization)',
		enabled: optionalHeader.dllCharacteristics.some(c => c.includes('DYNAMIC_BASE')),
		description: 'Randomizes memory addresses'
	});

	mitigations.push({
		name: 'DEP/NX (Data Execution Prevention)',
		enabled: optionalHeader.dllCharacteristics.some(c => c.includes('NX_COMPAT')),
		description: 'Prevents execution of data pages'
	});

	mitigations.push({
		name: 'SEH (Structured Exception Handling)',
		enabled: !optionalHeader.dllCharacteristics.some(c => c.includes('NO_SEH')),
		description: 'Exception handling support'
	});

	mitigations.push({
		name: 'CFG (Control Flow Guard)',
		enabled: optionalHeader.dllCharacteristics.some(c => c.includes('GUARD_CF')),
		description: 'Control flow integrity protection'
	});

	mitigations.push({
		name: 'Stack Cookie (GS)',
		enabled: optionalHeader.dllCharacteristics.some(c => c.includes('FORCE_INTEGRITY')),
		description: 'Stack buffer overrun protection'
	});

	mitigations.push({
		name: 'High Entropy ASLR',
		enabled: optionalHeader.dllCharacteristics.some(c => c.includes('HIGH_ENTROPY_VA')),
		description: '64-bit address space randomization'
	});

	return mitigations;
}

// ============================================================================
// RESOURCE PARSER
// ============================================================================

function parseResources(fd: number, buffer: Buffer, resourceDir: DataDirectory, sections: SectionHeader[]): ResourceEntry[] {
	const resources: ResourceEntry[] = [];

	try {
		if (resourceDir.virtualAddress === 0 || resourceDir.size === 0) {
			return resources;
		}

		const fileOffset = rvaToFileOffset(resourceDir.virtualAddress, sections);
		if (fileOffset === 0) {
			return resources;
		}

		// Resource types
		const resourceTypes: Record<number, string> = {
			1: 'CURSOR',
			2: 'BITMAP',
			3: 'ICON',
			4: 'MENU',
			5: 'DIALOG',
			6: 'STRING',
			7: 'FONTDIR',
			8: 'FONT',
			9: 'ACCELERATOR',
			10: 'RCDATA',
			11: 'MESSAGETABLE',
			12: 'GROUP_CURSOR',
			14: 'GROUP_ICON',
			16: 'VERSION',
			17: 'DLGINCLUDE',
			19: 'PLUGPLAY',
			20: 'VXD',
			21: 'ANICURSOR',
			22: 'ANIICON',
			23: 'HTML',
			24: 'MANIFEST',
		};

		// Parse resource directory (simplified)
		const resourceBuffer = Buffer.alloc(Math.min(resourceDir.size, 65536));
		fs.readSync(fd, resourceBuffer, 0, resourceBuffer.length, fileOffset);

		// Look for common resource patterns
		for (let i = 0; i < resourceBuffer.length - 8; i += 4) {
			// Check for RT_VERSION (16)
			if (resourceBuffer.readUInt32LE(i) === 16) {
				resources.push({
					type: 'VERSION',
					name: 'VS_VERSION_INFO',
					langId: 0,
					size: 0,
					offset: fileOffset + i
				});
			}
			// Check for RT_MANIFEST (24)
			else if (resourceBuffer.readUInt32LE(i) === 24) {
				resources.push({
					type: 'MANIFEST',
					name: '1',
					langId: 0,
					size: 0,
					offset: fileOffset + i
				});
			}
			// Check for RT_ICON (3)
			else if (resourceBuffer.readUInt32LE(i) === 3) {
				resources.push({
					type: 'ICON',
					name: '1',
					langId: 0,
					size: 0,
					offset: fileOffset + i
				});
			}
		}

		// Deduplicate
		const seen = new Set<string>();
		return resources.filter(r => {
			const key = r.type + r.name;
			if (seen.has(key)) {
				return false;
			}
			seen.add(key);
			return true;
		});
	} catch (e) {
		// Resource parsing failed
	}

	return resources;
}

// ============================================================================
// TLS CALLBACKS PARSER
// ============================================================================

function parseTLSDirectory(fd: number, buffer: Buffer, tlsDir: DataDirectory, sections: SectionHeader[]): number[] {
	const callbacks: number[] = [];

	try {
		if (tlsDir.virtualAddress === 0 || tlsDir.size === 0) {
			return callbacks;
		}

		const fileOffset = rvaToFileOffset(tlsDir.virtualAddress, sections);
		if (fileOffset === 0) {
			return callbacks;
		}

		// TLS directory structure:
		// 0x00: StartAddressOfRawData
		// 0x04/0x08: EndAddressOfRawData
		// 0x08/0x10: AddressOfIndex
		// 0x0C/0x18: AddressOfCallbacks
		// ...

		const is64Bit = buffer.readUInt16LE(buffer.readUInt32LE(60) + 24 + 4) === 0x20b;
		const tlsBuffer = Buffer.alloc(64);
		fs.readSync(fd, tlsBuffer, 0, 64, fileOffset);

		const callbacksRVAOffset = is64Bit ? 0x18 : 0x0C;
		const callbacksRVA = is64Bit
			? Number(tlsBuffer.readBigUInt64LE(callbacksRVAOffset))
			: tlsBuffer.readUInt32LE(callbacksRVAOffset);

		if (callbacksRVA === 0) {
			return callbacks;
		}

		// Read callback array
		const callbacksOffset = rvaToFileOffset(callbacksRVA, sections);
		if (callbacksOffset === 0) {
			return callbacks;
		}

		const callbackBuffer = Buffer.alloc(256);
		fs.readSync(fd, callbackBuffer, 0, 256, callbacksOffset);

		// Read until null terminator
		for (let i = 0; i < 32; i++) {
			const callback = is64Bit
				? Number(callbackBuffer.readBigUInt64LE(i * 8))
				: callbackBuffer.readUInt32LE(i * 4);

			if (callback === 0) {
				break;
			}
			if (callback !== 0 && callback !== 0xCCCCCCCC) {
				callbacks.push(callback);
			}
		}
	} catch (e) {
		// TLS parsing failed
	}

	return callbacks;
}

// ============================================================================
// EXCEPTION HANDLERS PARSER
// ============================================================================

function parseExceptions(fd: number, buffer: Buffer, exceptionDir: DataDirectory, sections: SectionHeader[]): ExceptionEntry[] {
	const exceptions: ExceptionEntry[] = [];

	try {
		if (exceptionDir.virtualAddress === 0 || exceptionDir.size === 0) {
			return exceptions;
		}

		const fileOffset = rvaToFileOffset(exceptionDir.virtualAddress, sections);
		if (fileOffset === 0) {
			return exceptions;
		}

		// Runtime Function entry (x64 unwind info)
		// Each entry is 12 bytes (32-bit) or 12 bytes (64-bit)
		const entryCount = Math.min(exceptionDir.size / 12, 100); // Limit to 100 entries

		const exceptionBuffer = Buffer.alloc(entryCount * 12);
		fs.readSync(fd, exceptionBuffer, 0, exceptionBuffer.length, fileOffset);

		for (let i = 0; i < entryCount; i++) {
			const offset = i * 12;
			const beginAddress = exceptionBuffer.readUInt32LE(offset);
			const endAddress = exceptionBuffer.readUInt32LE(offset + 4);
			const unwindInfo = exceptionBuffer.readUInt32LE(offset + 8);

			if (beginAddress !== 0 && endAddress !== 0) {
				exceptions.push({
					beginAddress,
					endAddress,
					unwindInfoAddress: unwindInfo
				});
			}
		}
	} catch (e) {
		// Exception parsing failed
	}

	return exceptions;
}

