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

// TEB/PEB addresses
const TEB_ADDRESS = 0x7FFDE000n;
const TEB_SIZE = 0x2000;
const PEB_ADDRESS = 0x7FFD0000n;
const PEB_SIZE = 0x1000;

export class PELoader {
	private emulator: UnicornWrapper;
	private memoryManager: MemoryManager;
	private stubMap: Map<bigint, ImportEntry> = new Map();
	private nextStubOffset: number = 0;
	private peInfo?: PEInfo;

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

		// Parse sections
		const sectionTableOffset = peOffset + 24 + sizeOfOptionalHeader;
		const sections = this.parseSections(fileBuffer, sectionTableOffset, numberOfSections, imageBase);

		// Map stub region for API hooks
		this.emulator.mapMemoryRaw(STUB_BASE, STUB_SIZE, 7); // RWX
		this.memoryManager.trackAllocation(STUB_BASE, STUB_SIZE, 7, 'api-stubs');

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

				// Create stub for this import
				const stubAddress = this.createStub();
				const iatAddress = imageBase + BigInt(firstThunk) + BigInt(thunkIdx * thunkSize);

				const entry: ImportEntry = {
					dll: dllName,
					name: importName,
					ordinal,
					iatAddress,
					stubAddress
				};
				imports.push(entry);
				this.stubMap.set(stubAddress, entry);

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
		// Map TEB
		this.emulator.mapMemoryRaw(TEB_ADDRESS, TEB_SIZE, 3); // RW
		this.memoryManager.trackAllocation(TEB_ADDRESS, TEB_SIZE, 3, 'TEB');

		// Map PEB
		this.emulator.mapMemoryRaw(PEB_ADDRESS, PEB_SIZE, 3); // RW
		this.memoryManager.trackAllocation(PEB_ADDRESS, PEB_SIZE, 3, 'PEB');

		const teb = Buffer.alloc(TEB_SIZE);
		const peb = Buffer.alloc(PEB_SIZE);

		if (is64Bit) {
			// TEB64: offset 0x30 = pointer to self (TEB)
			teb.writeBigUInt64LE(TEB_ADDRESS, 0x30);
			// TEB64: offset 0x60 = pointer to PEB
			teb.writeBigUInt64LE(PEB_ADDRESS, 0x60);
			// TEB64: offset 0x48 = ProcessId (fake)
			teb.writeUInt32LE(0x1000, 0x48);
			// TEB64: offset 0x40 = ThreadId (fake)
			teb.writeUInt32LE(0x1004, 0x40);

			// PEB64: offset 0x02 = BeingDebugged (FALSE - anti-anti-debug)
			peb[0x02] = 0;
			// PEB64: offset 0x10 = ImageBaseAddress
			peb.writeBigUInt64LE(imageBase, 0x10);
		} else {
			// TEB32: offset 0x18 = pointer to self
			teb.writeUInt32LE(Number(TEB_ADDRESS & 0xFFFFFFFFn), 0x18);
			// TEB32: offset 0x30 = pointer to PEB
			teb.writeUInt32LE(Number(PEB_ADDRESS & 0xFFFFFFFFn), 0x30);
			// TEB32: offset 0x24 = ProcessId
			teb.writeUInt32LE(0x1000, 0x24);
			// TEB32: offset 0x20 = ThreadId
			teb.writeUInt32LE(0x1004, 0x20);

			// PEB32: offset 0x02 = BeingDebugged (FALSE)
			peb[0x02] = 0;
			// PEB32: offset 0x08 = ImageBaseAddress
			peb.writeUInt32LE(Number(imageBase & 0xFFFFFFFFn), 0x08);
		}

		this.emulator.writeMemory(TEB_ADDRESS, teb);
		this.emulator.writeMemory(PEB_ADDRESS, peb);

		// Set FS/GS base to TEB for Windows API compatibility
		const regConsts = this.emulator.getX86RegConstants();
		if (regConsts) {
			if (is64Bit) {
				this.emulator.setRegister('rsp', 0n); // Will be set by setupStack
				// GS base points to TEB on x64 Windows
				try {
					// GS_BASE is used by x64 Windows for TEB access
					this.emulator.setRegister('rax', 0n); // Temp - GS_BASE set below
				} catch {
					// GS_BASE register may not be directly writable on all unicorn versions
				}
			}
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
		return address >= STUB_BASE && address < STUB_BASE + BigInt(STUB_SIZE);
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
