/*---------------------------------------------------------------------------------------------
 *  HexCore Debugger - PE Loader
 *  Maps PE sections, resolves imports, patches IAT, sets up TEB/PEB
 *  Copyright (c) HikariSystem. All rights reserved.
 *--------------------------------------------------------------------------------------------*/

import { UnicornWrapper, ArchitectureType } from './unicornWrapper';
import { MemoryManager } from './memoryManager';

export interface ImportEntry {
	dll: string;
	name: string;
	ordinal?: number;
	iatAddress: bigint;
	stubAddress: bigint;
}

export interface PESection {
	name: string;
	virtualAddress: bigint;
	virtualSize: number;
	rawOffset: number;
	rawSize: number;
	permissions: string;
}

export interface PEInfo {
	is64Bit: boolean;
	imageBase: bigint;
	entryPoint: bigint;
	sections: PESection[];
	imports: ImportEntry[];
	sizeOfImage: number;
}

// Stub region for API hooks
const STUB_BASE = 0x70000000n;
const STUB_SIZE = 0x00100000; // 1MB for stubs
const STUB_ENTRY_SIZE = 16; // Each stub is 16 bytes (RET instruction + padding)

// v3.8.0-nightly: Data import region (HEXCORE_DEFEAT instruction-398 crash).
// MSVC C++ binaries import data exports like `std::cout` (`?cout@std@@3V?...`)
// from MSVCP140.dll. Treating these as functions and writing a `RET` (0xC3) at
// their IAT entries causes the binary to crash when it dereferences the import
// as an object pointer (e.g. `mov rax, [imp_cout]; movsxd rcx, [rax+4]`).
// Each data import gets its own 4KB self-referential block instead.
const DATA_IMPORT_BASE = 0x71000000n;
const DATA_IMPORT_SIZE = 0x00800000;       // 8 MB region
const DATA_IMPORT_BLOCK_SIZE = 0x1000;     // 4 KB per data import
const DATA_IMPORT_VTABLE_OFFSET = 0x100;   // fake vtable inside the same block

// TEB/PEB addresses
const TEB_ADDRESS = 0x7FFDE000n;
const TEB_SIZE = 0x2000;
const PEB_ADDRESS = 0x7FFD0000n;
const PEB_SIZE = 0x1000;

// v3.8.0-nightly — Synthetic module region for hash-resolved imports.
// Malware that walks PEB->Ldr->InMemoryOrderModuleList then reads each
// module's export table (Ashaka v5 "Mirage" pattern) needs to find
// DllBases pointing at REAL PE headers. We manufacture one tiny PE per
// stubbed DLL at a fixed address in this region; each has a synthetic
// DOS header, NT header, and export directory populated with the APIs
// we stub. `PEB_LDR_DATA` entries below point to these bases.
const SYNTHETIC_DLL_BASE = 0x72000000n;
const SYNTHETIC_DLL_STRIDE = 0x1000;           // 4 KB per fake DLL
const SYNTHETIC_DLL_REGION_SIZE = 0x40000;     // 256 KB (room for 64 DLLs)

// v3.8.0-nightly — KUSER_SHARED_DATA (system-wide shared page).
// Windows maps this at a fixed userland address, read-only. Malware
// reads it to dodge rdtsc/cpuid hooks: InterruptTime / SystemTime /
// TickCount all come directly from this page, no instruction signature
// for our anti-analysis scanner to match against. We map a synthetic
// copy with monotonically-advancing time fields so v5 "Ashaka Mirage"
// and similar timing checks complete the same way they would on a real
// host. Values are re-populated before each emulation start.
const KUSER_SHARED_DATA_ADDRESS = 0x7FFE0000n;
const KUSER_SHARED_DATA_SIZE = 0x1000;
const TLS_STORAGE_BASE = 0x7FFB0000n;
const TLS_STORAGE_SIZE = 0x10000;
const TLS_VECTOR_ADDRESS = 0x7FFC0000n;
const TLS_VECTOR_SIZE = 0x10000;

// Keep these aligned with DebugEngine.loadPE()/setupStack().
const DEFAULT_STACK_BASE = 0x7FFF0000n;
const DEFAULT_STACK_SIZE = 0x100000n;
const DEFAULT_STACK_LIMIT = DEFAULT_STACK_BASE;
const DEFAULT_STACK_TOP = DEFAULT_STACK_BASE + DEFAULT_STACK_SIZE;

/**
 * v3.8.0-nightly — Detect MSVC C++ data exports by mangled name.
 *
 * MSVC mangling: a qualified name like `?cout@std@@3V?$basic_ostream@D...`
 * encodes the storage class as a single character right after the `@@`
 * qualified-name terminator. Digits 0-9 mean "data" (static member, global,
 * vtable, vbtable, etc.); letters mean "function" (Y = free function,
 * Q = public member, U/V/X = others).
 *
 * Patterns this matches (correctly identified as data):
 *   ?cout@std@@3V?$basic_ostream@D...               — std::cout
 *   ?cerr@std@@3V?$basic_ostream@D...               — std::cerr
 *   ?_Fac_tidy_reg@std@@3U_Fac_tidy_reg_t@1@A       — std::_Fac_tidy_reg
 *
 * Patterns this rejects (correctly identified as function):
 *   ?uncaught_exception@std@@YA_NXZ                 — std::uncaught_exception (Y)
 *   ??6?$basic_ostream@D...@std@@QEAA...            — operator<< (?? prefix)
 *   ?_Init@_Locinfo@std@@QEAA@XZ                    — _Locinfo::_Init (Q)
 *
 * Operator names start with `??` and are always functions, so we reject them
 * up-front before the regex check.
 */
function isDataImport(mangledName: string): boolean {
	if (!mangledName.startsWith('?')) { return false; }
	if (mangledName.startsWith('??')) { return false; }
	return /^\?[A-Za-z_]\w*(?:@[A-Za-z_]\w*)*@@[0-9]/.test(mangledName);
}

export class PELoader {
	private emulator: UnicornWrapper;
	private memoryManager: MemoryManager;
	private stubMap: Map<bigint, ImportEntry> = new Map();
	private nextStubOffset: number = 0;
	private nextDataImportOffset: number = 0;
	private dataImportMap: Map<bigint, ImportEntry> = new Map();
	private peInfo?: PEInfo;
	// v3.8.0-nightly: name → synthetic DllBase map. Populated by
	// setupSyntheticDlls so LoadLibrary/GetModuleHandle can return the
	// right base for hash-resolving shellcode.
	private syntheticModules: Map<string, bigint> = new Map();

	/** Returns the synth DllBase map so winApiHooks can pre-seed moduleHandles. */
	getSyntheticModules(): Map<string, bigint> {
		return this.syntheticModules;
	}

	constructor(emulator: UnicornWrapper, memoryManager: MemoryManager) {
		this.emulator = emulator;
		this.memoryManager = memoryManager;
	}

	/**
	 * Load a PE file into the emulator
	 */
	load(fileBuffer: Buffer, arch: ArchitectureType): PEInfo {
		if (fileBuffer[0] !== 0x4D || fileBuffer[1] !== 0x5A) {
			throw new Error('Not a valid PE file');
		}

		const peOffset = fileBuffer.readUInt32LE(0x3C);
		if (peOffset + 4 > fileBuffer.length) {
			throw new Error('Invalid PE offset');
		}

		const peSig = fileBuffer.readUInt32LE(peOffset);
		if (peSig !== 0x00004550) { // "PE\0\0"
			throw new Error('Invalid PE signature');
		}

		const optHeaderOffset = peOffset + 24;
		const magic = fileBuffer.readUInt16LE(optHeaderOffset);
		const is64Bit = magic === 0x20B;

		// Parse COFF header
		const numberOfSections = fileBuffer.readUInt16LE(peOffset + 6);
		const sizeOfOptionalHeader = fileBuffer.readUInt16LE(peOffset + 20);

		// Parse optional header
		const imageBase = is64Bit
			? fileBuffer.readBigUInt64LE(optHeaderOffset + 24)
			: BigInt(fileBuffer.readUInt32LE(optHeaderOffset + 28));

		const entryPointRVA = fileBuffer.readUInt32LE(optHeaderOffset + 16);
		const sizeOfImage = fileBuffer.readUInt32LE(optHeaderOffset + 56);

		// Data directories
		const dataDirectoryOffset = is64Bit ? optHeaderOffset + 112 : optHeaderOffset + 96;

		// Import directory RVA and size
		const importDirRVA = fileBuffer.readUInt32LE(dataDirectoryOffset + 8);
		const importDirSize = fileBuffer.readUInt32LE(dataDirectoryOffset + 12);

		// Base relocation directory
		const relocDirRVA = fileBuffer.readUInt32LE(dataDirectoryOffset + 40);
		const relocDirSize = fileBuffer.readUInt32LE(dataDirectoryOffset + 44);

		// TLS directory (IMAGE_DIRECTORY_ENTRY_TLS = 9)
		const tlsDirRVA = fileBuffer.readUInt32LE(dataDirectoryOffset + 72);
		const tlsDirSize = fileBuffer.readUInt32LE(dataDirectoryOffset + 76);

		// Parse sections
		const sectionTableOffset = peOffset + 24 + sizeOfOptionalHeader;
		const sections = this.parseSections(fileBuffer, sectionTableOffset, numberOfSections, imageBase);

		// Map stub region for API hooks
		this.emulator.mapMemoryRaw(STUB_BASE, STUB_SIZE, 7); // RWX
		this.memoryManager.trackAllocation(STUB_BASE, STUB_SIZE, 7, 'api-stubs');

		// v3.8.0-nightly: Map data import region for C++ data exports
		// (std::cout, std::cerr, std::cin, vtables, etc). See createDataImportBlock().
		this.emulator.mapMemoryRaw(DATA_IMPORT_BASE, DATA_IMPORT_SIZE, 3); // RW
		this.memoryManager.trackAllocation(DATA_IMPORT_BASE, DATA_IMPORT_SIZE, 3, 'data-imports');

		// v3.8.0-nightly: Map synthetic DLL region. Each fake module's base
		// must be readable as a PE image so shellcode that parses the export
		// table (Ashaka v5 "Mirage") finds the APIs it's looking for.
		this.emulator.mapMemoryRaw(SYNTHETIC_DLL_BASE, SYNTHETIC_DLL_REGION_SIZE, 5); // R+X
		this.memoryManager.trackAllocation(SYNTHETIC_DLL_BASE, SYNTHETIC_DLL_REGION_SIZE, 5, 'synthetic-dlls');

		// Map all sections into emulator memory
		this.mapSections(fileBuffer, sections, imageBase, sizeOfImage);

		// Parse and resolve imports
		const imports = this.resolveImports(fileBuffer, importDirRVA, importDirSize, sections, imageBase, is64Bit);

		// Apply base relocations if needed
		if (relocDirRVA > 0 && relocDirSize > 0) {
			this.applyRelocations(fileBuffer, relocDirRVA, relocDirSize, sections, imageBase, is64Bit);
		}

		// Setup TEB and PEB
		this.setupTebPeb(is64Bit, imageBase);

		// Setup KUSER_SHARED_DATA so timing-check shellcode that reads
		// 0x7FFE0008 / 0x7FFE0014 / 0x7FFE0320 doesn't hit UC_ERR_READ_UNMAPPED.
		this.setupKuserSharedData();

		// Populate synthetic DLL bases so PEB-walking shellcode that does
		// hash-based export resolution finds valid DOS/NT headers and a
		// populated export directory for common Win32 APIs.
		this.setupSyntheticDlls();

		// Setup a minimal static TLS block if the image declares one.
		if (tlsDirRVA > 0 && tlsDirSize > 0) {
			this.setupStaticTls(fileBuffer, tlsDirRVA, tlsDirSize, sections, imageBase, is64Bit);
		}

		this.peInfo = {
			is64Bit,
			imageBase,
			entryPoint: imageBase + BigInt(entryPointRVA),
			sections,
			imports,
			sizeOfImage
		};

		console.log(`PE loaded: ${is64Bit ? 'x64' : 'x86'}, base=0x${imageBase.toString(16)}, entry=0x${this.peInfo.entryPoint.toString(16)}, ${sections.length} sections, ${imports.length} imports`);

		return this.peInfo;
	}

	/**
	 * Parse section headers
	 */
	private parseSections(buf: Buffer, sectionTableOffset: number, count: number, imageBase: bigint): PESection[] {
		const sections: PESection[] = [];

		for (let i = 0; i < count; i++) {
			const off = sectionTableOffset + (i * 40);
			if (off + 40 > buf.length) {
				break;
			}

			const name = buf.toString('ascii', off, off + 8).replace(/\0/g, '');
			const virtualSize = buf.readUInt32LE(off + 8);
			const virtualAddress = BigInt(buf.readUInt32LE(off + 12));
			const rawSize = buf.readUInt32LE(off + 16);
			const rawOffset = buf.readUInt32LE(off + 20);
			const characteristics = buf.readUInt32LE(off + 36);

			let permissions = '';
			if (characteristics & 0x40000000) { permissions += 'r'; } // IMAGE_SCN_MEM_READ
			if (characteristics & 0x80000000) { permissions += 'w'; } // IMAGE_SCN_MEM_WRITE
			if (characteristics & 0x20000000) { permissions += 'x'; } // IMAGE_SCN_MEM_EXECUTE
			if (!permissions) { permissions = 'r'; }

			sections.push({
				name,
				virtualAddress: imageBase + virtualAddress,
				virtualSize,
				rawOffset,
				rawSize,
				permissions
			});
		}

		return sections;
	}

	/**
	 * Map all sections into emulator memory
	 */
	private mapSections(buf: Buffer, sections: PESection[], imageBase: bigint, sizeOfImage: number): void {
		const pageSize = this.emulator.getPageSize();

		// Map the full image range first (covers headers and gaps between sections)
		const alignedImageSize = Math.ceil(sizeOfImage / pageSize) * pageSize;
		this.emulator.mapMemoryRaw(imageBase, alignedImageSize, 7); // RWX initially
		this.memoryManager.trackAllocation(imageBase, alignedImageSize, 7, 'pe-image');

		// Write PE headers
		const headerSize = Math.min(buf.length, sizeOfImage);
		const headerData = buf.subarray(0, Math.min(headerSize, 0x1000));
		this.emulator.writeMemory(imageBase, headerData);

		// Write section data
		for (const section of sections) {
			if (section.rawSize > 0 && section.rawOffset + section.rawSize <= buf.length) {
				const sectionData = buf.subarray(section.rawOffset, section.rawOffset + section.rawSize);
				this.emulator.writeMemory(section.virtualAddress, sectionData);
			}
		}
	}

	/**
	 * Resolve imports and create API stubs
	 */
	private resolveImports(
		buf: Buffer,
		importDirRVA: number,
		_importDirSize: number,
		sections: PESection[],
		imageBase: bigint,
		is64Bit: boolean
	): ImportEntry[] {
		if (importDirRVA === 0) {
			return [];
		}

		const imports: ImportEntry[] = [];
		const importDirFileOffset = this.rvaToFileOffset(importDirRVA, sections, imageBase);
		if (importDirFileOffset < 0) {
			return [];
		}

		// Walk import directory entries (IMAGE_IMPORT_DESCRIPTOR)
		let descriptorOffset = importDirFileOffset;
		while (descriptorOffset + 20 <= buf.length) {
			const originalFirstThunk = buf.readUInt32LE(descriptorOffset);
			const nameRVA = buf.readUInt32LE(descriptorOffset + 12);
			const firstThunk = buf.readUInt32LE(descriptorOffset + 16);

			// End of import directory (all zeros)
			if (nameRVA === 0 && firstThunk === 0) {
				break;
			}

			// Read DLL name
			const nameFileOffset = this.rvaToFileOffset(nameRVA, sections, imageBase);
			let dllName = 'unknown.dll';
			if (nameFileOffset >= 0 && nameFileOffset < buf.length) {
				const nameEnd = buf.indexOf(0, nameFileOffset);
				dllName = buf.toString('ascii', nameFileOffset, nameEnd > nameFileOffset ? nameEnd : nameFileOffset + 64).toLowerCase();
			}

			// Walk the thunk entries (use OriginalFirstThunk if available, else FirstThunk)
			const lookupRVA = originalFirstThunk !== 0 ? originalFirstThunk : firstThunk;
			const lookupFileOffset = this.rvaToFileOffset(lookupRVA, sections, imageBase);
			if (lookupFileOffset < 0) {
				descriptorOffset += 20;
				continue;
			}

			let thunkIdx = 0;
			const thunkSize = is64Bit ? 8 : 4;
			while (true) {
				const thunkFileOffset = lookupFileOffset + thunkIdx * thunkSize;
				if (thunkFileOffset + thunkSize > buf.length) {
					break;
				}

				const thunkValue = is64Bit
					? buf.readBigUInt64LE(thunkFileOffset)
					: BigInt(buf.readUInt32LE(thunkFileOffset));

				if (thunkValue === 0n) {
					break;
				}

				const ordinalFlag = is64Bit ? 0x8000000000000000n : 0x80000000n;
				let importName = '';
				let ordinal: number | undefined;

				if (thunkValue & ordinalFlag) {
					// Import by ordinal
					ordinal = Number(thunkValue & 0xFFFFn);
					importName = `Ordinal_${ordinal}`;
				} else {
					// Import by name
					const hintNameRVA = Number(thunkValue & 0x7FFFFFFFn);
					const hintNameFileOffset = this.rvaToFileOffset(hintNameRVA, sections, imageBase);
					if (hintNameFileOffset >= 0 && hintNameFileOffset + 2 < buf.length) {
						const nameStart = hintNameFileOffset + 2; // Skip hint
						const nameEndIdx = buf.indexOf(0, nameStart);
						importName = buf.toString('ascii', nameStart, nameEndIdx > nameStart ? nameEndIdx : nameStart + 128);
					}
				}

				// v3.8.0-nightly: distinguish C++ data imports from function imports.
				// Data exports like `?cout@std@@3V?...` (std::cout) must NOT be replaced
				// by a `RET` stub — the binary dereferences them as object pointers.
				const isData = isDataImport(importName);
				const stubAddress = isData
					? this.createDataImportBlock()
					: this.createStub();
				const iatAddress = imageBase + BigInt(firstThunk) + BigInt(thunkIdx * thunkSize);

				const entry: ImportEntry = {
					dll: dllName,
					name: importName,
					ordinal,
					iatAddress,
					stubAddress
				};
				imports.push(entry);
				if (isData) {
					this.dataImportMap.set(stubAddress, entry);
				} else {
					this.stubMap.set(stubAddress, entry);
				}

				// Patch IAT: write stub address into the IAT entry in emulator memory
				if (is64Bit) {
					const patchBuf = Buffer.alloc(8);
					patchBuf.writeBigUInt64LE(stubAddress);
					this.emulator.writeMemory(iatAddress, patchBuf);
				} else {
					const patchBuf = Buffer.alloc(4);
					patchBuf.writeUInt32LE(Number(stubAddress & 0xFFFFFFFFn));
					this.emulator.writeMemory(iatAddress, patchBuf);
				}

				thunkIdx++;
			}

			descriptorOffset += 20;
		}

		return imports;
	}

	/**
	 * Create a stub entry in the stub region.
	 * Each stub is just a single RET instruction so that if
	 * we fail to intercept, the emulation at least doesn't crash.
	 */
	/**
	 * v3.8.0-nightly — Build synthetic PE headers + export directory for
	 * each fake module exposed via PEB_LDR_DATA.
	 *
	 * Shellcode that does hash-based export resolution (Ashaka v5 Mirage,
	 * typical Metasploit-style loaders) walks PEB->Ldr->InMemoryOrderLinks
	 * then, for each module, parses its DOS + NT + Export directory. The
	 * existing empty PEB_LDR_DATA made the list walk return zero modules;
	 * we now expose real entries, each pointing at a synthetic PE here so
	 * the export walk succeeds and the caller ends up with a pointer into
	 * this region. We also publish that pointer into `stubMap` so the
	 * existing CODE hook + winApiHooks dispatch path handles the call.
	 */
	private setupSyntheticDlls(): void {
		// (DLL index in the SYNTHETIC_DLL_BASE region, lowercase name, APIs exported)
		// Index must match the `fakeModules[].index` list in setupTebPeb above.
		const moduleDefs: { index: number; dll: string; apis: string[] }[] = [
			{
				index: 0, dll: 'ntdll.dll', apis: [
					'NtQueryInformationProcess', 'NtQuerySystemInformation',
					'LdrLoadDll', 'LdrGetProcedureAddress', 'RtlGetVersion', 'NtClose',
				]
			},
			{
				index: 1, dll: 'kernel32.dll', apis: [
					'LoadLibraryA', 'LoadLibraryW', 'LoadLibraryExA', 'LoadLibraryExW',
					'GetProcAddress', 'GetModuleHandleA', 'GetModuleHandleW',
					'VirtualAlloc', 'VirtualFree', 'VirtualProtect',
					'GetCurrentProcessId', 'GetCurrentThreadId',
					'GetTickCount', 'GetTickCount64', 'QueryPerformanceCounter',
					'GetSystemTimeAsFileTime', 'Sleep',
					'IsDebuggerPresent', 'CheckRemoteDebuggerPresent',
					'GetComputerNameA', 'GetComputerNameW',
					'GetCommandLineA', 'GetCommandLineW',
					'GetEnvironmentStringsW', 'FreeEnvironmentStringsW',
					'ExitProcess',
				]
			},
			{
				index: 2, dll: 'KERNELBASE.dll', apis: [
					'GetThreadContext', 'SetThreadContext', 'GetCurrentProcess',
				]
			},
			{
				index: 3, dll: 'ucrtbase.dll', apis: [
					'exit', '_exit', 'abort', 'malloc', 'free', '_initterm', '_initterm_e',
				]
			},
			{
				index: 4, dll: 'msvcp140.dll', apis: []
			},
			{
				index: 5, dll: 'shell32.dll', apis: [
					'ShellExecuteA', 'ShellExecuteW', 'ShellExecuteExA', 'ShellExecuteExW',
				]
			},
			{
				index: 6, dll: 'advapi32.dll', apis: [
					'RegOpenKeyA', 'RegOpenKeyExA', 'RegOpenKeyW', 'RegOpenKeyExW',
					'RegQueryValueExA', 'RegQueryValueExW', 'RegCloseKey',
				]
			},
			{
				index: 7, dll: 'user32.dll', apis: [
					'MessageBoxA', 'MessageBoxW', 'GetForegroundWindow',
				]
			},
		];

		// Layout within each 4 KB DLL page — with explicit gaps so no region
		// can stomp another when a module has many APIs.
		//   0x000  DOS + NT headers
		//   0x1E0..0x207  Export directory header (40 bytes)
		//   0x220..0x27F  DLL name string (up to 96 bytes, plenty)
		//   0x280..0x33F  AddressOfFunctions array (up to 48 APIs × 4)
		//   0x340..0x3FF  AddressOfNames array      (up to 48 APIs × 4)
		//   0x400..0x43F  AddressOfNameOrdinals     (up to 48 APIs × 2)
		//   0x440..0x7FF  API name string pool      (up to 960 bytes)
		//   0x800..0xFFF  RET stub region           (up to 128 stubs × 16)
		const DLL_NAME_RVA = 0x220;
		const FUNCS_RVA    = 0x280;
		const NAMES_RVA    = 0x340;
		const ORDS_RVA     = 0x400;
		const STRINGS_RVA  = 0x440;
		const STUB_RVA_BASE = 0x800;
		const STUB_STRIDE = 0x10;

		for (const mod of moduleDefs) {
			const dllBase = SYNTHETIC_DLL_BASE + BigInt(mod.index * SYNTHETIC_DLL_STRIDE);
			// Track the DllBase under several aliases winApiHooks will look up.
			// Windows LoadLibrary accepts both with and without .dll suffix and
			// is case-insensitive; we normalise to lowercase here.
			const lower = mod.dll.toLowerCase();
			this.syntheticModules.set(lower, dllBase);
			if (lower.endsWith('.dll')) {
				this.syntheticModules.set(lower.slice(0, -4), dllBase);
			}
			const page = Buffer.alloc(SYNTHETIC_DLL_STRIDE);

			// DOS header (64 bytes)
			page[0] = 0x4D; page[1] = 0x5A; // "MZ"
			page.writeUInt32LE(0x40, 0x3C);  // e_lfanew → NT header at offset 0x40

			// NT header at 0x40
			const ntOff = 0x40;
			page.writeUInt32LE(0x00004550, ntOff + 0x00);  // "PE\0\0"
			// File header (20 bytes)
			page.writeUInt16LE(0x8664, ntOff + 0x04);      // Machine AMD64
			page.writeUInt16LE(0, ntOff + 0x06);            // NumberOfSections
			page.writeUInt32LE(0, ntOff + 0x08);            // TimeDateStamp
			page.writeUInt32LE(0, ntOff + 0x0C);            // PointerToSymbolTable
			page.writeUInt32LE(0, ntOff + 0x10);            // NumberOfSymbols
			page.writeUInt16LE(0xF0, ntOff + 0x14);         // SizeOfOptionalHeader (PE32+ = 240)
			page.writeUInt16LE(0x2022, ntOff + 0x16);       // Characteristics: DLL + EXECUTABLE_IMAGE

			// Optional header PE32+ at ntOff + 0x18 (240 bytes)
			const ohOff = ntOff + 0x18;
			page.writeUInt16LE(0x020B, ohOff + 0x00);       // Magic PE32+
			// AddressOfEntryPoint = 0, ImageBase = dllBase, etc left zero (unused)
			// DataDirectory starts at ohOff + 0x70 for PE32+
			// First entry (index 0) is Export Table
			const exportDirRva = 0x1E0;
			page.writeUInt32LE(exportDirRva, ohOff + 0x70); // ExportTable.VirtualAddress
			page.writeUInt32LE(40, ohOff + 0x74);            // ExportTable.Size

			// Export directory at RVA 0x1E0 (40 bytes)
			const edOff = exportDirRva;
			const apiCount = mod.apis.length;
			// Leave most fields zero; populate what the walker uses.
			// We'll fill Name, Base=1, NumberOfFunctions, NumberOfNames,
			// AddressOfFunctions, AddressOfNames, AddressOfNameOrdinals.

			// Table layout (references the constants above).
			const nameRvaDll = DLL_NAME_RVA;
			const funcsRva = FUNCS_RVA;
			const namesRva = NAMES_RVA;
			const ordsRva  = ORDS_RVA;
			const nameStringsRva = STRINGS_RVA;

			// DLL name (null-terminated ASCII, up to 96 bytes).
			const dllNameBytes = Buffer.from(mod.dll + '\0', 'ascii');
			dllNameBytes.copy(page, nameRvaDll, 0, Math.min(dllNameBytes.length, 96));

			page.writeUInt32LE(0, edOff + 0x00);                     // Characteristics
			page.writeUInt32LE(0, edOff + 0x04);                     // TimeDateStamp
			page.writeUInt16LE(0, edOff + 0x08);                     // MajorVersion
			page.writeUInt16LE(0, edOff + 0x0A);                     // MinorVersion
			page.writeUInt32LE(nameRvaDll, edOff + 0x0C);            // Name
			page.writeUInt32LE(1, edOff + 0x10);                     // Base (ordinal start)
			page.writeUInt32LE(apiCount, edOff + 0x14);              // NumberOfFunctions
			page.writeUInt32LE(apiCount, edOff + 0x18);              // NumberOfNames
			page.writeUInt32LE(funcsRva, edOff + 0x1C);              // AddressOfFunctions
			page.writeUInt32LE(namesRva, edOff + 0x20);              // AddressOfNames
			page.writeUInt32LE(ordsRva,  edOff + 0x24);              // AddressOfNameOrdinals

			// Populate per-API entries.
			let stringCursor = nameStringsRva;
			for (let i = 0; i < apiCount; i++) {
				const apiName = mod.apis[i];
				const stubRva = STUB_RVA_BASE + i * STUB_STRIDE;
				const stubAddr = dllBase + BigInt(stubRva);

				// Function RVA
				page.writeUInt32LE(stubRva, funcsRva + i * 4);
				// Name RVA → string cursor
				page.writeUInt32LE(stringCursor, namesRva + i * 4);
				// Ordinal (0-based)
				page.writeUInt16LE(i, ordsRva + i * 2);

				// Write API name at stringCursor (null-terminated)
				const nameBytes = Buffer.from(apiName + '\0', 'ascii');
				nameBytes.copy(page, stringCursor);
				stringCursor += nameBytes.length;

				// Write RET stub at stubRva
				page[stubRva] = 0xC3; // RET

				// Register stub → importInfo so the CODE hook in DebugEngine
				// dispatches through winApiHooks the same as IAT-patched stubs.
				// iatAddress is zero because the stub is NOT reached via the IAT
				// (hash-resolved call enters the exported function directly).
				this.stubMap.set(stubAddr, {
					dll: mod.dll,
					name: apiName,
					iatAddress: 0n,
					stubAddress: stubAddr,
				});
			}

			// Write the synthetic DLL page into emulator memory.
			this.emulator.writeMemorySync(dllBase, page);
		}
	}

	private createStub(): bigint {
		const address = STUB_BASE + BigInt(this.nextStubOffset);

		// Write a RET instruction (0xC3) as fallback
		const stubCode = Buffer.alloc(STUB_ENTRY_SIZE);
		stubCode[0] = 0xC3; // RET
		this.emulator.writeMemory(address, stubCode);

		this.nextStubOffset += STUB_ENTRY_SIZE;
		return address;
	}

	/**
	 * v3.8.0-nightly — Allocate a self-referential 4 KB block for a C++ data
	 * import (std::cout, std::cerr, std::cin, vtables, vbtables, etc).
	 *
	 * Layout:
	 *   [0x000]      qword pointing to (this_block + 0x100)  — the fake vptr/vbptr
	 *   [0x008..]    zero-filled (real data fields)
	 *   [0x100..]    zero-filled fake vtable area
	 *
	 * Why this works for the canonical MSVC C++ access pattern
	 *     mov  rax, [rcx]            ; rax = vbtable_ptr (= block + 0x100)
	 *     movsxd rcx, [rax+4]        ; rcx = displacement at vbtable+4 (= 0)
	 *     mov  rcx, [rcx+rsi+0x28]   ; rcx = [rsi + 0x28] (= 0, in same block)
	 *     test rcx, rcx
	 *     jz   handle_null           ; ← branch taken, virtual call skipped
	 *
	 * Every dereference lands in mapped, zero-filled memory inside the same
	 * data import block. The MSVC compiler emits null-checks before most
	 * stream method calls, so the binary gracefully falls through to the
	 * "stream is null / nothing to do" path instead of crashing.
	 */
	private createDataImportBlock(): bigint {
		const address = DATA_IMPORT_BASE + BigInt(this.nextDataImportOffset);

		const block = Buffer.alloc(DATA_IMPORT_BLOCK_SIZE);
		// Self-pointer at offset 0 — the "vptr" pointing to a zero-filled vtable
		// inside the same block at offset 0x100.
		block.writeBigUInt64LE(address + BigInt(DATA_IMPORT_VTABLE_OFFSET), 0);
		this.emulator.writeMemory(address, block);

		this.nextDataImportOffset += DATA_IMPORT_BLOCK_SIZE;
		return address;
	}

	/**
	 * Apply base relocations
	 */
	private applyRelocations(
		buf: Buffer,
		relocDirRVA: number,
		relocDirSize: number,
		sections: PESection[],
		imageBase: bigint,
		is64Bit: boolean
	): void {
		const relocFileOffset = this.rvaToFileOffset(relocDirRVA, sections, imageBase);
		if (relocFileOffset < 0) {
			return;
		}

		// Relocations are applied relative to the preferred base.
		// Since we load at the preferred imageBase, delta is 0 - no relocation needed.
		// This method exists for future support of rebased loading.
		const _delta = 0n;
		if (_delta === 0n) {
			return;
		}
	}

	/**
	 * Setup minimal TEB (Thread Environment Block) and PEB (Process Environment Block)
	 */
	private setupTebPeb(is64Bit: boolean, imageBase: bigint): void {
		// Map a minimal TLS pointer vector so gs:[0x58]/fs:[0x2c] lookups do not
		// collapse into low-page reads during CRT/runtime initialization.
		this.emulator.mapMemoryRaw(TLS_VECTOR_ADDRESS, TLS_VECTOR_SIZE, 3); // RW
		this.memoryManager.trackAllocation(TLS_VECTOR_ADDRESS, TLS_VECTOR_SIZE, 3, 'TLS-vector');

		// Map TEB
		this.emulator.mapMemoryRaw(TEB_ADDRESS, TEB_SIZE, 3); // RW
		this.memoryManager.trackAllocation(TEB_ADDRESS, TEB_SIZE, 3, 'TEB');

		// Map PEB
		this.emulator.mapMemoryRaw(PEB_ADDRESS, PEB_SIZE, 3); // RW
		this.memoryManager.trackAllocation(PEB_ADDRESS, PEB_SIZE, 3, 'PEB');

		const teb = Buffer.alloc(TEB_SIZE);
		const peb = Buffer.alloc(PEB_SIZE);
		const tlsVector = Buffer.alloc(TLS_VECTOR_SIZE);

		if (is64Bit) {
			// NT_TIB64
			teb.writeBigUInt64LE(DEFAULT_STACK_TOP, 0x08);   // StackBase
			teb.writeBigUInt64LE(DEFAULT_STACK_LIMIT, 0x10); // StackLimit

			// TEB64: offset 0x30 = pointer to self (TEB)
			teb.writeBigUInt64LE(TEB_ADDRESS, 0x30);
			// TEB64: offset 0x40 = ProcessId (fake)
			teb.writeUInt32LE(0x1000, 0x40);
			// TEB64: offset 0x48 = ThreadId (fake)
			teb.writeUInt32LE(0x1004, 0x48);
			// TEB64: offset 0x58 = ThreadLocalStoragePointer
			teb.writeBigUInt64LE(TLS_VECTOR_ADDRESS, 0x58);
			// TEB64: offset 0x60 = pointer to PEB
			teb.writeBigUInt64LE(PEB_ADDRESS, 0x60);

			// PEB64: offset 0x02 = BeingDebugged (FALSE - anti-anti-debug)
			peb[0x02] = 0;
			// PEB64: offset 0x10 = ImageBaseAddress
			peb.writeBigUInt64LE(imageBase, 0x10);
			// v3.8.0-nightly: PEB64 offset 0x18 = PEB_LDR_DATA*
			// Hand-rolled PEB walkers (HEXCORE_DEFEAT v3 "Ashaka Shadow" and
			// v5 "Ashaka Mirage" that hash-resolves exports) dereference this
			// field to iterate loaded modules.
			// Layout:
			//   PEB+0x200: PEB_LDR_DATA (0x58 bytes)
			//   PEB+0x300..0x7FF: LDR_DATA_TABLE_ENTRY array (one per stubbed DLL)
			//   PEB+0x800..0xFFF: wide-string name buffers for each entry
			const ldrDataOffset = 0x200;
			const ldrDataAddress = PEB_ADDRESS + BigInt(ldrDataOffset);
			peb.writeBigUInt64LE(ldrDataAddress, 0x18);

			// PEB_LDR_DATA layout (x64):
			//   [0x00] Length = 0x58
			//   [0x04] Initialized = 1
			//   [0x08] SsHandle = NULL
			//   [0x10] InLoadOrderModuleList    (LIST_ENTRY)
			//   [0x20] InMemoryOrderModuleList
			//   [0x30] InInitializationOrderModuleList
			peb.writeUInt32LE(0x58, ldrDataOffset + 0x00); // Length
			peb[ldrDataOffset + 0x04] = 1;                 // Initialized
			peb.writeBigUInt64LE(0n, ldrDataOffset + 0x08); // SsHandle

			// Fake modules to expose. Order = load order (ntdll always first).
			// DllBase comes from the synthetic-module region; each fake DLL
			// gets its own 4 KB page (populated by setupSyntheticDllBases).
			const fakeModules: { name: string; index: number }[] = [
				{ name: 'ntdll.dll',     index: 0 },
				{ name: 'kernel32.dll',  index: 1 },
				{ name: 'KERNELBASE.dll', index: 2 },
				{ name: 'ucrtbase.dll',  index: 3 },
				{ name: 'msvcp140.dll',  index: 4 },
				{ name: 'shell32.dll',   index: 5 },
				{ name: 'advapi32.dll',  index: 6 },
				{ name: 'user32.dll',    index: 7 },
			];

			const entryBase = ldrDataOffset + 0x100;   // entries start at PEB+0x300
			const ENTRY_SIZE = 0x80;
			const nameBufferBase = ldrDataOffset + 0x600; // strings start at PEB+0x800
			let nameCursor = nameBufferBase;

			// Pre-compute absolute addresses for every entry's InLoadOrderLinks.
			// Flink/Blink addresses for the circular lists are entry+0 (InLoad),
			// entry+0x10 (InMemory), entry+0x20 (InInit).
			const entryAddr = (i: number): bigint => PEB_ADDRESS + BigInt(entryBase + i * ENTRY_SIZE);

			for (let i = 0; i < fakeModules.length; i++) {
				const mod = fakeModules[i];
				const eOff = entryBase + i * ENTRY_SIZE;
				const eAddr = entryAddr(i);
				const next = fakeModules[(i + 1) % fakeModules.length];
				const prev = fakeModules[(i - 1 + fakeModules.length) % fakeModules.length];
				const nextAddr = entryAddr(next.index);
				const prevAddr = entryAddr(prev.index);
				// Note: for circular list, the first entry's Blink must point to the
				// list HEAD (ldrDataAddress + 0x10 etc.), and the last entry's Flink
				// must point to the HEAD too. For simplicity we still do entry→entry
				// links and the HEAD's Flink/Blink point to the first/last entry.
				const isFirst = i === 0;
				const isLast = i === fakeModules.length - 1;

				// InLoadOrderLinks (entry+0x00)
				peb.writeBigUInt64LE(isLast ? (ldrDataAddress + 0x10n) : nextAddr, eOff + 0x00);
				peb.writeBigUInt64LE(isFirst ? (ldrDataAddress + 0x10n) : prevAddr, eOff + 0x08);
				// InMemoryOrderLinks (entry+0x10)
				peb.writeBigUInt64LE(isLast ? (ldrDataAddress + 0x20n) : (nextAddr + 0x10n), eOff + 0x10);
				peb.writeBigUInt64LE(isFirst ? (ldrDataAddress + 0x20n) : (prevAddr + 0x10n), eOff + 0x18);
				// InInitializationOrderLinks (entry+0x20)
				peb.writeBigUInt64LE(isLast ? (ldrDataAddress + 0x30n) : (nextAddr + 0x20n), eOff + 0x20);
				peb.writeBigUInt64LE(isFirst ? (ldrDataAddress + 0x30n) : (prevAddr + 0x20n), eOff + 0x28);

				// DllBase (entry+0x30) — point at a synthetic PE we'll build later
				const dllBase = SYNTHETIC_DLL_BASE + BigInt(mod.index * SYNTHETIC_DLL_STRIDE);
				peb.writeBigUInt64LE(dllBase, eOff + 0x30);
				// EntryPoint (entry+0x38) — unused, zero
				peb.writeBigUInt64LE(0n, eOff + 0x38);
				// SizeOfImage (entry+0x40)
				peb.writeUInt32LE(SYNTHETIC_DLL_STRIDE, eOff + 0x40);

				// FullDllName UNICODE_STRING at entry+0x48 (16 bytes)
				// BaseDllName UNICODE_STRING at entry+0x58
				// Layout: Length(u16) MaxLen(u16) Pad(u32) Buffer(u64)
				const fullPath = 'C:\\Windows\\System32\\' + mod.name;
				const fullWide = Buffer.alloc((fullPath.length + 1) * 2);
				for (let j = 0; j < fullPath.length; j++) { fullWide.writeUInt16LE(fullPath.charCodeAt(j), j * 2); }
				const baseWide = Buffer.alloc((mod.name.length + 1) * 2);
				for (let j = 0; j < mod.name.length; j++) { baseWide.writeUInt16LE(mod.name.charCodeAt(j), j * 2); }

				// Copy strings into the PEB page and record their absolute addresses.
				fullWide.copy(peb, nameCursor);
				const fullAddr = PEB_ADDRESS + BigInt(nameCursor);
				nameCursor += fullWide.length;
				baseWide.copy(peb, nameCursor);
				const baseAddr = PEB_ADDRESS + BigInt(nameCursor);
				nameCursor += baseWide.length;

				peb.writeUInt16LE(fullPath.length * 2, eOff + 0x48);     // FullDllName.Length
				peb.writeUInt16LE(fullPath.length * 2 + 2, eOff + 0x4A); // MaximumLength
				peb.writeBigUInt64LE(fullAddr, eOff + 0x50);              // Buffer

				peb.writeUInt16LE(mod.name.length * 2, eOff + 0x58);     // BaseDllName.Length
				peb.writeUInt16LE(mod.name.length * 2 + 2, eOff + 0x5A); // MaximumLength
				peb.writeBigUInt64LE(baseAddr, eOff + 0x60);              // Buffer

				// Flags (entry+0x68), LoadCount, TlsIndex — leave zero
			}

			// Heads: Flink = first entry's corresponding LIST_ENTRY offset,
			//        Blink = last entry's corresponding LIST_ENTRY offset.
			const firstAddr = entryAddr(fakeModules[0].index);
			const lastAddr  = entryAddr(fakeModules[fakeModules.length - 1].index);
			// InLoadOrderModuleList head
			peb.writeBigUInt64LE(firstAddr,          ldrDataOffset + 0x10); // Flink
			peb.writeBigUInt64LE(lastAddr,           ldrDataOffset + 0x18); // Blink
			// InMemoryOrderModuleList head
			peb.writeBigUInt64LE(firstAddr + 0x10n,  ldrDataOffset + 0x20); // Flink
			peb.writeBigUInt64LE(lastAddr  + 0x10n,  ldrDataOffset + 0x28); // Blink
			// InInitializationOrderModuleList head
			peb.writeBigUInt64LE(firstAddr + 0x20n,  ldrDataOffset + 0x30); // Flink
			peb.writeBigUInt64LE(lastAddr  + 0x20n,  ldrDataOffset + 0x38); // Blink
		} else {
			// NT_TIB32
			teb.writeUInt32LE(Number(DEFAULT_STACK_TOP & 0xFFFFFFFFn), 0x04);   // StackBase
			teb.writeUInt32LE(Number(DEFAULT_STACK_LIMIT & 0xFFFFFFFFn), 0x08); // StackLimit

			// TEB32: offset 0x18 = pointer to self
			teb.writeUInt32LE(Number(TEB_ADDRESS & 0xFFFFFFFFn), 0x18);
			// TEB32: offset 0x20 = ProcessId
			teb.writeUInt32LE(0x1000, 0x20);
			// TEB32: offset 0x24 = ThreadId
			teb.writeUInt32LE(0x1004, 0x24);
			// TEB32: offset 0x2C = ThreadLocalStoragePointer
			teb.writeUInt32LE(Number(TLS_VECTOR_ADDRESS & 0xFFFFFFFFn), 0x2C);
			// TEB32: offset 0x30 = pointer to PEB
			teb.writeUInt32LE(Number(PEB_ADDRESS & 0xFFFFFFFFn), 0x30);

			// PEB32: offset 0x02 = BeingDebugged (FALSE)
			peb[0x02] = 0;
			// PEB32: offset 0x08 = ImageBaseAddress
			peb.writeUInt32LE(Number(imageBase & 0xFFFFFFFFn), 0x08);
			// v3.8.0-nightly: PEB32 offset 0x0C = PEB_LDR_DATA*
			const ldrDataOffset32 = 0x200;
			const ldrDataAddress32 = Number((PEB_ADDRESS + BigInt(ldrDataOffset32)) & 0xFFFFFFFFn);
			peb.writeUInt32LE(ldrDataAddress32, 0x0C);
			// PEB_LDR_DATA32 layout: lists at 0x0C, 0x14, 0x1C (each 8 bytes: Flink+Blink)
			peb.writeUInt32LE(0x30, ldrDataOffset32 + 0x00); // Length
			peb[ldrDataOffset32 + 0x04] = 1;                  // Initialized
			peb.writeUInt32LE(0, ldrDataOffset32 + 0x08);    // SsHandle
			// Empty self-referential lists (InLoad / InMemory / InInit)
			peb.writeUInt32LE(ldrDataAddress32 + 0x0C, ldrDataOffset32 + 0x0C);
			peb.writeUInt32LE(ldrDataAddress32 + 0x0C, ldrDataOffset32 + 0x10);
			peb.writeUInt32LE(ldrDataAddress32 + 0x14, ldrDataOffset32 + 0x14);
			peb.writeUInt32LE(ldrDataAddress32 + 0x14, ldrDataOffset32 + 0x18);
			peb.writeUInt32LE(ldrDataAddress32 + 0x1C, ldrDataOffset32 + 0x1C);
			peb.writeUInt32LE(ldrDataAddress32 + 0x1C, ldrDataOffset32 + 0x20);
		}

		this.emulator.writeMemory(TLS_VECTOR_ADDRESS, tlsVector);
		this.emulator.writeMemory(TEB_ADDRESS, teb);
		this.emulator.writeMemory(PEB_ADDRESS, peb);

		// Set FS/GS base to TEB for Windows API compatibility
		const regConsts = this.emulator.getX86RegConstants();
		if (regConsts) {
			if (is64Bit) {
				// GS base points to TEB on x64 Windows.
				try {
					this.emulator.setRegisterSync('gs_base', TEB_ADDRESS);
				} catch {
					// GS_BASE register may not be directly writable on all Unicorn builds.
				}
			} else {
				// FS base points to TEB on x86 Windows.
				try {
					this.emulator.setRegisterSync('fs_base', TEB_ADDRESS);
				} catch {
					// FS_BASE register may not be directly writable on all Unicorn builds.
				}
			}
		}
	}

	/**
	 * v3.8.0-nightly — Setup KUSER_SHARED_DATA at 0x7FFE0000.
	 *
	 * Malware (v5 "Ashaka Mirage" and similar) reads time via direct mov
	 * from this page to dodge our rdtsc/cpuid instruction-level hooks.
	 * Windows maps this page read-only at a fixed address system-wide;
	 * we publish a synthetic copy with realistic, monotonically advancing
	 * values so `while (delta < threshold)` style checks behave like they
	 * would on a real host.
	 *
	 * Offsets populated (per MS public KSYSTEM_TIME / KUSER_SHARED_DATA):
	 *   0x00  TickCountLowDeprecated   (ULONG)
	 *   0x04  TickCountMultiplier      (ULONG, 0x0FA00000 default)
	 *   0x08  InterruptTime            (KSYSTEM_TIME: LowPart/High1/High2)
	 *   0x14  SystemTime               (KSYSTEM_TIME)
	 *   0x20  TimeZoneBias             (KSYSTEM_TIME) — kept zero
	 *   0x2C  ImageNumberLow           (0x8664 for AMD64 images)
	 *   0x2E  ImageNumberHigh          (0x8664)
	 *   0x30  NtSystemRoot             (wide string, kept empty — unused)
	 *   0x260 NtProductType            (1 = WinNt)
	 *   0x264 ProductTypeIsValid       (1)
	 *   0x268 NativeProcessorArchitecture  (9 = AMD64)
	 *   0x26C NtMajorVersion           (10)
	 *   0x270 NtMinorVersion           (0)
	 *   0x2D4 KdDebuggerEnabled        (0 — pretend no kernel debugger)
	 *   0x320 TickCount                (KSYSTEM_TIME — Win10+ addition)
	 */
	private setupKuserSharedData(): void {
		this.emulator.mapMemoryRaw(KUSER_SHARED_DATA_ADDRESS, KUSER_SHARED_DATA_SIZE, 1); // R only
		this.memoryManager.trackAllocation(KUSER_SHARED_DATA_ADDRESS, KUSER_SHARED_DATA_SIZE, 1, 'KUSER_SHARED_DATA');

		const page = Buffer.alloc(KUSER_SHARED_DATA_SIZE);

		// 100ns-unit clock. Seed with current wall time so timing checks
		// that reference SystemTime get plausible values; subsequent
		// re-maps (per emulation start) will advance this naturally.
		// InterruptTime is the time since system boot — use a fabricated
		// "uptime" so the low 32 bits don't wrap during one emulation run.
		const EPOCH_DELTA_100NS = 11644473600n * 10000000n; // 1601→1970 in 100ns
		const sysTime100ns = BigInt(Date.now()) * 10000n + EPOCH_DELTA_100NS;
		// Fake boot was 1 hour ago → InterruptTime = 36,000,000,000 × 100ns
		const interruptTime100ns = 36000000000n;

		// TickCountLowDeprecated + TickCountMultiplier
		page.writeUInt32LE(Number(interruptTime100ns / 10000n) & 0xFFFFFFFF, 0x00);
		page.writeUInt32LE(0x0FA00000, 0x04);

		// InterruptTime KSYSTEM_TIME: LowPart / High1 / High2
		const itLow = Number(interruptTime100ns & 0xFFFFFFFFn);
		const itHigh = Number((interruptTime100ns >> 32n) & 0xFFFFFFFFn);
		page.writeUInt32LE(itLow, 0x08);
		page.writeUInt32LE(itHigh, 0x0C);
		page.writeUInt32LE(itHigh, 0x10); // High2 = High1 (stable)

		// SystemTime KSYSTEM_TIME
		const stLow = Number(sysTime100ns & 0xFFFFFFFFn);
		const stHigh = Number((sysTime100ns >> 32n) & 0xFFFFFFFFn);
		page.writeUInt32LE(stLow, 0x14);
		page.writeUInt32LE(stHigh, 0x18);
		page.writeUInt32LE(stHigh, 0x1C);

		// ImageNumber AMD64
		page.writeUInt16LE(0x8664, 0x2C);
		page.writeUInt16LE(0x8664, 0x2E);

		// NtProductType = NtProductWinNt
		page.writeUInt32LE(1, 0x260);
		page.writeUInt32LE(1, 0x264); // ProductTypeIsValid
		page.writeUInt32LE(9, 0x268); // PROCESSOR_ARCHITECTURE_AMD64
		page.writeUInt32LE(10, 0x26C); // NtMajorVersion — Win10
		page.writeUInt32LE(0, 0x270);  // NtMinorVersion
		page.writeUInt32LE(19045, 0x274); // NtBuildNumber (Win10 22H2)

		// KdDebuggerEnabled = 0 (no kernel debugger)
		page.writeUInt8(0, 0x2D4);

		// TickCount (Win10+) — mirrors InterruptTime / TickCountMultiplier
		page.writeUInt32LE(itLow, 0x320);
		page.writeUInt32LE(itHigh, 0x324);
		page.writeUInt32LE(itHigh, 0x328);

		this.emulator.writeMemorySync(KUSER_SHARED_DATA_ADDRESS, page);
	}

	/**
	 * Setup a minimal static TLS block for PE images that use IMAGE_TLS_DIRECTORY.
	 * This mirrors the loader behavior enough for gs:[0x58]/fs:[0x2c] consumers:
	 * slot 0 is populated and the module's _tls_index is set to 0.
	 */
	private setupStaticTls(
		buf: Buffer,
		tlsDirRVA: number,
		_tlsDirSize: number,
		sections: PESection[],
		imageBase: bigint,
		is64Bit: boolean
	): void {
		const tlsDirOffset = this.rvaToFileOffset(tlsDirRVA, sections, imageBase);
		if (tlsDirOffset < 0) {
			return;
		}

		let startAddressOfRawData = 0n;
		let endAddressOfRawData = 0n;
		let addressOfIndex = 0n;
		let sizeOfZeroFill = 0;

		if (is64Bit) {
			if (tlsDirOffset + 40 > buf.length) {
				return;
			}
			startAddressOfRawData = buf.readBigUInt64LE(tlsDirOffset);
			endAddressOfRawData = buf.readBigUInt64LE(tlsDirOffset + 8);
			addressOfIndex = buf.readBigUInt64LE(tlsDirOffset + 16);
			sizeOfZeroFill = buf.readUInt32LE(tlsDirOffset + 32);
		} else {
			if (tlsDirOffset + 24 > buf.length) {
				return;
			}
			startAddressOfRawData = BigInt(buf.readUInt32LE(tlsDirOffset));
			endAddressOfRawData = BigInt(buf.readUInt32LE(tlsDirOffset + 4));
			addressOfIndex = BigInt(buf.readUInt32LE(tlsDirOffset + 8));
			sizeOfZeroFill = buf.readUInt32LE(tlsDirOffset + 16);
		}

		let template = Buffer.alloc(0);
		const rawSizeBig = endAddressOfRawData > startAddressOfRawData ? endAddressOfRawData - startAddressOfRawData : 0n;
		if (rawSizeBig > 0n) {
			const rawSize = Number(rawSizeBig);
			if (rawSize > 0 && rawSize <= TLS_STORAGE_SIZE) {
				try {
					template = Buffer.from(this.emulator.readMemorySync(startAddressOfRawData, rawSize));
				} catch {
					template = Buffer.alloc(0);
				}
			}
		}

		const pageSize = this.emulator.getPageSize();
		const tlsDataBytes = Math.max(pageSize, Math.ceil((template.length + sizeOfZeroFill) / pageSize) * pageSize);
		this.emulator.mapMemoryRaw(TLS_STORAGE_BASE, tlsDataBytes, 3); // RW
		this.memoryManager.trackAllocation(TLS_STORAGE_BASE, tlsDataBytes, 3, 'TLS-data');

		const tlsData = Buffer.alloc(tlsDataBytes);
		template.copy(tlsData, 0);
		this.emulator.writeMemory(TLS_STORAGE_BASE, tlsData);

		const vectorEntry = Buffer.alloc(is64Bit ? 8 : 4);
		if (is64Bit) {
			vectorEntry.writeBigUInt64LE(TLS_STORAGE_BASE, 0);
		} else {
			vectorEntry.writeUInt32LE(Number(TLS_STORAGE_BASE & 0xFFFFFFFFn), 0);
		}
		this.emulator.writeMemory(TLS_VECTOR_ADDRESS, vectorEntry);

		if (addressOfIndex !== 0n) {
			const indexBuf = Buffer.alloc(4);
			indexBuf.writeUInt32LE(0, 0);
			this.emulator.writeMemorySync(addressOfIndex, indexBuf);
		}
	}

	/**
	 * Convert RVA to file offset using section table
	 */
	private rvaToFileOffset(rva: number, sections: PESection[], imageBase: bigint): number {
		for (const section of sections) {
			const sectionRVA = Number(section.virtualAddress - imageBase);
			if (rva >= sectionRVA && rva < sectionRVA + section.virtualSize) {
				return section.rawOffset + (rva - sectionRVA);
			}
		}
		// If not in any section, treat as header (file offset == RVA for headers)
		return rva;
	}

	/**
	 * Check if an address falls within the API stub region
	 */
	isStubAddress(address: bigint): boolean {
		if (address >= STUB_BASE && address < STUB_BASE + BigInt(STUB_SIZE)) { return true; }
		// v3.8.0-nightly: synthetic DLL region stubs are valid API call
		// targets too — hash-resolving shellcode (Ashaka v5) calls function
		// pointers inside this region, and the code-hook dispatcher needs to
		// recognise them so winApiHooks fires.
		if (address >= SYNTHETIC_DLL_BASE && address < SYNTHETIC_DLL_BASE + BigInt(SYNTHETIC_DLL_REGION_SIZE)) { return true; }
		return false;
	}

	/**
	 * Look up which import corresponds to a stub address
	 */
	lookupStub(address: bigint): ImportEntry | undefined {
		return this.stubMap.get(address);
	}

	/**
	 * Get all resolved imports
	 */
	getImports(): ImportEntry[] {
		return this.peInfo?.imports ?? [];
	}

	/**
	 * Get PE info
	 */
	getPEInfo(): PEInfo | undefined {
		return this.peInfo;
	}

	/**
	 * Get the stub region base address
	 */
	getStubBase(): bigint {
		return STUB_BASE;
	}

	/**
	 * Get the TEB address
	 */
	getTebAddress(): bigint {
		return TEB_ADDRESS;
	}

	/**
	 * Get the PEB address
	 */
	getPebAddress(): bigint {
		return PEB_ADDRESS;
	}
}
