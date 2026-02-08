/*---------------------------------------------------------------------------------------------
 *  HexCore Debugger - ELF Loader
 *  Loads ELF binaries into emulator memory with correct segment permissions
 *  Supports PIE (ET_DYN) binaries with base relocation and PLT/GOT stub creation
 *  Copyright (c) HikariSystem. All rights reserved.
 *--------------------------------------------------------------------------------------------*/

import { UnicornWrapper, ArchitectureType } from './unicornWrapper';
import { MemoryManager } from './memoryManager';

export interface ELFSection {
	name: string;
	address: bigint;
	size: number;
	offset: number;
	permissions: string;
	type?: number;
	link?: number;
	entsize?: number;
}

export interface ELFImportEntry {
	library: string;
	name: string;
	pltAddress: bigint;
	gotAddress: bigint;
	stubAddress: bigint;
}

export interface ELFInfo {
	is64Bit: boolean;
	isPIE: boolean;
	entryPoint: bigint;
	baseAddress: bigint;
	sections: ELFSection[];
	programHeaders: ELFSegment[];
	imports: ELFImportEntry[];
}

interface ELFSegment {
	type: number;
	offset: number;
	virtualAddress: bigint;
	fileSize: number;
	memSize: number;
	flags: number;
	permissions: string;
}

// ELF constants
const PT_LOAD = 1;
const PT_DYNAMIC = 2;
const PF_X = 1;
const PF_W = 2;
const PF_R = 4;

// ELF types
const ET_EXEC = 2;
const ET_DYN = 3;

// Section header types
const SHT_DYNSYM = 11;
const SHT_DYNAMIC = 6;
const SHT_RELA = 4;
const SHT_REL = 9;

// Dynamic tags
const DT_NULL = 0;
const DT_NEEDED = 1;
const DT_PLTGOT = 3;
const DT_JMPREL = 23;
const DT_PLTRELSZ = 2;
const DT_PLTREL = 20;
const DT_STRTAB = 5;
const DT_SYMTAB = 6;
const DT_STRSZ = 10;
const DT_SYMENT = 11;

// Relocation types (x86_64)
const R_X86_64_GLOB_DAT = 6;
const R_X86_64_JUMP_SLOT = 7;

// Unicorn PROT constants
const PROT_READ = 1;
const PROT_WRITE = 2;
const PROT_EXEC = 4;

// Stub region for API hooks (shared with PE loader)
const STUB_BASE = 0x70000000n;
const STUB_SIZE = 0x00100000; // 1MB for stubs
const STUB_ENTRY_SIZE = 16;

// PIE default base addresses
const PIE_BASE_X64 = 0x555555554000n;
const PIE_BASE_X86 = 0x56555000n;

export class ELFLoader {
	private emulator: UnicornWrapper;
	private memoryManager: MemoryManager;
	private elfInfo?: ELFInfo;
	private stubMap: Map<bigint, ELFImportEntry> = new Map();
	private nextStubOffset: number = 0;
	private pieBase: bigint = 0n;
	private is64Bit: boolean = true;

	constructor(emulator: UnicornWrapper, memoryManager: MemoryManager) {
		this.emulator = emulator;
		this.memoryManager = memoryManager;
	}

	/**
	 * Load an ELF file into the emulator
	 */
	load(fileBuffer: Buffer, arch?: ArchitectureType): ELFInfo {
		// Verify ELF magic
		if (fileBuffer[0] !== 0x7F || fileBuffer.toString('ascii', 1, 4) !== 'ELF') {
			throw new Error('Not a valid ELF file');
		}

		this.is64Bit = fileBuffer[4] === 2;
		const isLittleEndian = fileBuffer[5] === 1;

		if (!isLittleEndian) {
			throw new Error('Big-endian ELF files are not currently supported');
		}

		// Detect ELF type
		const eType = fileBuffer.readUInt16LE(16);
		const isPIE = eType === ET_DYN;

		const rawEntryPoint = this.is64Bit
			? fileBuffer.readBigUInt64LE(24)
			: BigInt(fileBuffer.readUInt32LE(24));

		// Parse program headers
		const segments = this.parseProgramHeaders(fileBuffer);

		// Determine base address for PIE
		if (isPIE) {
			// Find lowest LOAD segment vaddr
			let lowestVaddr = BigInt('0xFFFFFFFFFFFFFFFF');
			for (const seg of segments) {
				if (seg.type === PT_LOAD && seg.virtualAddress < lowestVaddr) {
					lowestVaddr = seg.virtualAddress;
				}
			}

			if (lowestVaddr === 0n || lowestVaddr < 0x10000n) {
				// PIE binary with vaddr starting at 0 - choose conventional base
				this.pieBase = this.is64Bit ? PIE_BASE_X64 : PIE_BASE_X86;
			}
		}

		// Calculate actual entry point
		const entryPoint = rawEntryPoint + this.pieBase;

		// Map LOAD segments with PIE adjustment
		for (const seg of segments) {
			if (seg.type !== PT_LOAD) {
				continue;
			}

			const adjustedVaddr = seg.virtualAddress + this.pieBase;
			const perms = this.elfFlagsToUnicorn(seg.flags);
			const pageSize = this.emulator.getPageSize();
			const alignedAddr = (adjustedVaddr / BigInt(pageSize)) * BigInt(pageSize);
			const alignedEnd = ((adjustedVaddr + BigInt(seg.memSize) + BigInt(pageSize) - 1n) / BigInt(pageSize)) * BigInt(pageSize);
			const alignedSize = Number(alignedEnd - alignedAddr);

			if (alignedSize <= 0) { continue; }

			this.emulator.mapMemoryRaw(alignedAddr, alignedSize, perms);
			this.memoryManager.trackAllocation(alignedAddr, alignedSize, perms, `elf-segment`);

			// Write segment data from file
			if (seg.fileSize > 0 && seg.offset + seg.fileSize <= fileBuffer.length) {
				const data = fileBuffer.subarray(seg.offset, seg.offset + seg.fileSize);
				this.emulator.writeMemory(adjustedVaddr, data);
			}
		}

		// Map stub region for API hooks
		this.emulator.mapMemoryRaw(STUB_BASE, STUB_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC);
		this.memoryManager.trackAllocation(STUB_BASE, STUB_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC, 'api-stubs');

		// Parse section headers for names/metadata
		const sections = this.parseSectionHeaders(fileBuffer);

		// Resolve imports: parse .dynsym, .rela.plt, patch GOT entries
		const imports = this.resolveImports(fileBuffer, sections);

		const baseAddress = isPIE ? this.pieBase : (segments.find(s => s.type === PT_LOAD)?.virtualAddress ?? 0x400000n);

		this.elfInfo = {
			is64Bit: this.is64Bit,
			isPIE,
			entryPoint,
			baseAddress,
			sections,
			programHeaders: segments,
			imports
		};

		console.log(`ELF loaded: ${this.is64Bit ? '64-bit' : '32-bit'}, PIE=${isPIE}, base=0x${baseAddress.toString(16)}, entry=0x${entryPoint.toString(16)}, ${segments.filter(s => s.type === PT_LOAD).length} LOAD segments, ${imports.length} imports`);

		return this.elfInfo;
	}

	/**
	 * Resolve ELF imports by parsing .dynsym + .rela.plt + .rela.dyn,
	 * creating stubs and patching GOT entries.
	 *
	 * Modern binaries (GCC -fno-plt, or certain linker optimizations) use
	 * "direct GOT calls" — `call [rip+GOT_offset]` — instead of going through
	 * PLT stubs. These are resolved via R_X86_64_GLOB_DAT relocations in
	 * .rela.dyn (not .rela.plt). We must patch BOTH .rela.plt (JUMP_SLOT)
	 * AND .rela.dyn (GLOB_DAT) GOT entries to intercept all import calls.
	 */
	private resolveImports(buf: Buffer, sections: ELFSection[]): ELFImportEntry[] {
		const imports: ELFImportEntry[] = [];

		// Find relevant sections
		const dynsymSec = sections.find(s => s.type === SHT_DYNSYM);
		if (!dynsymSec) { return imports; }

		// Find .dynstr (linked from .dynsym)
		const dynstrSec = dynsymSec.link !== undefined ? sections[dynsymSec.link] : undefined;
		if (!dynstrSec) { return imports; }

		// Find .rela.plt or .rel.plt
		const relaPltSec = sections.find(s => s.name === '.rela.plt' || s.name === '.rel.plt');
		// Find .rela.dyn or .rel.dyn (for GLOB_DAT relocations / direct GOT calls)
		const relaDynSec = sections.find(s => s.name === '.rela.dyn' || s.name === '.rel.dyn');
		// Find .plt section
		const pltSec = sections.find(s => s.name === '.plt' || s.name === '.plt.got' || s.name === '.plt.sec');

		// Parse DT_NEEDED for library names
		const neededLibs: string[] = [];
		const dynSec = sections.find(s => s.type === SHT_DYNAMIC);
		if (dynSec) {
			const entrySize = this.is64Bit ? 16 : 8;
			const numEntries = Math.floor(dynSec.size / entrySize);
			for (let i = 0; i < numEntries; i++) {
				const entOff = dynSec.offset + i * entrySize;
				if (entOff + entrySize > buf.length) { break; }
				const dTag = this.is64Bit
					? Number(buf.readBigUInt64LE(entOff))
					: buf.readUInt32LE(entOff);
				const dVal = this.is64Bit
					? Number(buf.readBigUInt64LE(entOff + 8))
					: buf.readUInt32LE(entOff + 4);
				if (dTag === DT_NULL) { break; }
				if (dTag === DT_NEEDED) {
					const nameOff = dynstrSec.offset + dVal;
					let name = '';
					if (nameOff < buf.length) {
						for (let j = nameOff; j < buf.length && buf[j] !== 0; j++) {
							name += String.fromCharCode(buf[j]);
							if (name.length > 256) { break; }
						}
					}
					if (name) { neededLibs.push(name); }
				}
			}
		}

		const symEntSize = this.is64Bit ? 24 : 16;
		const defaultLib = neededLibs.length > 0 ? neededLibs[0] : 'libc.so.6';

		// Track which GOT addresses we've already patched (to avoid duplicates
		// when the same symbol appears in both .rela.plt and .rela.dyn)
		const patchedGotAddrs = new Set<bigint>();

		// Helper: process a relocation section and create stubs + patch GOT
		const processRelocSection = (relSec: ELFSection, isPlt: boolean): void => {
			const isRela = relSec.name.startsWith('.rela');
			const relEntSize = isRela ? (this.is64Bit ? 24 : 12) : (this.is64Bit ? 16 : 8);
			const numRel = relEntSize > 0 ? Math.floor(relSec.size / relEntSize) : 0;

			// Relocation types we want to patch:
			// R_X86_64_JUMP_SLOT (7) - from .rela.plt (traditional PLT)
			// R_X86_64_GLOB_DAT  (6) - from .rela.dyn (direct GOT calls)
			// R_386_JMP_SLOT    (7) - x86 PLT
			// R_386_GLOB_DAT    (6) - x86 direct GOT
			const JUMP_SLOT_TYPE = 7;
			const GLOB_DAT_TYPE = 6;

			for (let i = 0; i < numRel && i < 4096; i++) {
				const relOff = relSec.offset + i * relEntSize;
				if (relOff + relEntSize > buf.length) { break; }

				// r_offset = GOT entry address (pre-PIE)
				const rOffset = this.is64Bit
					? buf.readBigUInt64LE(relOff)
					: BigInt(buf.readUInt32LE(relOff));
				// r_info contains symbol index and relocation type
				const rInfo = this.is64Bit
					? buf.readBigUInt64LE(relOff + 8)
					: BigInt(buf.readUInt32LE(relOff + 4));

				const symIdx = this.is64Bit ? Number(rInfo >> 32n) : Number(rInfo >> 8n);
				const relType = this.is64Bit ? Number(rInfo & 0xFFFFFFFFn) : Number(rInfo & 0xFFn);

				// Only patch JUMP_SLOT and GLOB_DAT relocations
				// For .rela.plt, all entries are typically JUMP_SLOT
				// For .rela.dyn, we only want GLOB_DAT (skip RELATIVE, COPY, etc.)
				if (!isPlt && relType !== GLOB_DAT_TYPE) { continue; }
				if (isPlt && relType !== JUMP_SLOT_TYPE && relType !== GLOB_DAT_TYPE) {
					// In .rela.plt, also accept entries without a specific filter
					// (some linkers mix types)
				}

				if (symIdx === 0) { continue; }

				// Read symbol name from .dynsym
				const symOff = dynsymSec.offset + symIdx * symEntSize;
				if (symOff + symEntSize > buf.length) { continue; }

				const stName = buf.readUInt32LE(symOff);
				let symName = '';
				const symNameOff = dynstrSec.offset + stName;
				if (symNameOff < buf.length) {
					for (let j = symNameOff; j < buf.length && buf[j] !== 0; j++) {
						symName += String.fromCharCode(buf[j]);
						if (symName.length > 256) { break; }
					}
				}
				if (symName.length === 0) { continue; }

				// GOT address adjusted for PIE
				const gotAddr = rOffset + this.pieBase;

				// Skip if we already patched this GOT address
				if (patchedGotAddrs.has(gotAddr)) { continue; }
				patchedGotAddrs.add(gotAddr);

				// PLT address (only meaningful for .rela.plt entries)
				const pltEntrySize = 16;
				const pltAddr = (isPlt && pltSec)
					? pltSec.address + BigInt((imports.length + 1) * pltEntrySize)
					: 0n;

				// Create a stub for this import
				const stubAddress = this.createStub();

				const entry: ELFImportEntry = {
					library: defaultLib,
					name: symName,
					pltAddress: pltAddr,
					gotAddress: gotAddr,
					stubAddress
				};
				imports.push(entry);
				this.stubMap.set(stubAddress, entry);

				// Patch GOT entry to point to our stub
				try {
					if (this.is64Bit) {
						const patchBuf = Buffer.alloc(8);
						patchBuf.writeBigUInt64LE(stubAddress);
						this.emulator.writeMemory(gotAddr, patchBuf);
					} else {
						const patchBuf = Buffer.alloc(4);
						patchBuf.writeUInt32LE(Number(stubAddress & 0xFFFFFFFFn));
						this.emulator.writeMemory(gotAddr, patchBuf);
					}
				} catch (e) {
					console.warn(`Failed to patch GOT for ${symName} at 0x${gotAddr.toString(16)}: ${e}`);
				}
			}
		};

		// Process .rela.plt first (JUMP_SLOT relocations — traditional PLT stubs)
		if (relaPltSec && relaPltSec.offset > 0 && relaPltSec.size > 0) {
			processRelocSection(relaPltSec, true);
		}

		// Process .rela.dyn (GLOB_DAT relocations — direct GOT calls, -fno-plt style)
		// This is critical for binaries that use `call [rip+GOT_offset]` instead of PLT
		if (relaDynSec && relaDynSec.offset > 0 && relaDynSec.size > 0) {
			processRelocSection(relaDynSec, false);
		}

		// If neither relocation section was found, fallback to .dynsym parsing
		if (!relaPltSec && !relaDynSec) {
			const fallbackSymEntSize = dynsymSec.entsize || (this.is64Bit ? 24 : 16);
			const symCount = fallbackSymEntSize > 0 ? Math.floor(dynsymSec.size / fallbackSymEntSize) : 0;

			for (let i = 1; i < symCount && i < 4096; i++) {
				const symOff = dynsymSec.offset + i * fallbackSymEntSize;
				if (symOff + fallbackSymEntSize > buf.length) { break; }

				let stName: number, stInfo: number, stShndx: number;

				if (this.is64Bit) {
					stName = buf.readUInt32LE(symOff);
					stInfo = buf[symOff + 4];
					stShndx = buf.readUInt16LE(symOff + 6);
				} else {
					stName = buf.readUInt32LE(symOff);
					stInfo = buf[symOff + 12];
					stShndx = buf.readUInt16LE(symOff + 14);
				}

				const stBind = stInfo >> 4;
				const stType = stInfo & 0xF;
				const isUndefined = stShndx === 0;

				// Only process undefined function/notype symbols
				if (!isUndefined || (stBind !== 1 && stBind !== 2)) { continue; }
				if (stType !== 0 && stType !== 2) { continue; } // STT_NOTYPE or STT_FUNC

				let symName = '';
				const symNameOff = dynstrSec.offset + stName;
				if (symNameOff < buf.length) {
					for (let j = symNameOff; j < buf.length && buf[j] !== 0; j++) {
						symName += String.fromCharCode(buf[j]);
						if (symName.length > 256) { break; }
					}
				}
				if (symName.length === 0) { continue; }

				const stubAddress = this.createStub();

				const entry: ELFImportEntry = {
					library: defaultLib,
					name: symName,
					pltAddress: 0n,
					gotAddress: 0n,
					stubAddress
				};
				imports.push(entry);
				this.stubMap.set(stubAddress, entry);
			}
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
	 * Parse ELF program headers
	 */
	private parseProgramHeaders(buf: Buffer): ELFSegment[] {
		const segments: ELFSegment[] = [];

		const phOff = this.is64Bit
			? Number(buf.readBigUInt64LE(32))
			: buf.readUInt32LE(28);

		const phEntSize = buf.readUInt16LE(this.is64Bit ? 54 : 42);
		const phNum = buf.readUInt16LE(this.is64Bit ? 56 : 44);

		for (let i = 0; i < phNum; i++) {
			const off = phOff + i * phEntSize;
			if (off + phEntSize > buf.length) {
				break;
			}

			let segment: ELFSegment;

			if (this.is64Bit) {
				const type = buf.readUInt32LE(off);
				const flags = buf.readUInt32LE(off + 4);
				const offset = Number(buf.readBigUInt64LE(off + 8));
				const virtualAddress = buf.readBigUInt64LE(off + 16);
				const fileSize = Number(buf.readBigUInt64LE(off + 32));
				const memSize = Number(buf.readBigUInt64LE(off + 40));

				segment = {
					type, offset, virtualAddress, fileSize, memSize, flags,
					permissions: this.elfFlagsToString(flags)
				};
			} else {
				const type = buf.readUInt32LE(off);
				const offset = buf.readUInt32LE(off + 4);
				const virtualAddress = BigInt(buf.readUInt32LE(off + 8));
				const fileSize = buf.readUInt32LE(off + 16);
				const memSize = buf.readUInt32LE(off + 20);
				const flags = buf.readUInt32LE(off + 24);

				segment = {
					type, offset, virtualAddress, fileSize, memSize, flags,
					permissions: this.elfFlagsToString(flags)
				};
			}

			segments.push(segment);
		}

		return segments;
	}

	/**
	 * Parse ELF section headers (for metadata/display and import resolution)
	 */
	private parseSectionHeaders(buf: Buffer): ELFSection[] {
		const sections: ELFSection[] = [];

		const shOff = this.is64Bit
			? Number(buf.readBigUInt64LE(40))
			: buf.readUInt32LE(32);

		if (shOff === 0) {
			return sections;
		}

		const shEntSize = buf.readUInt16LE(this.is64Bit ? 58 : 46);
		const shNum = buf.readUInt16LE(this.is64Bit ? 60 : 48);
		const shStrIdx = buf.readUInt16LE(this.is64Bit ? 62 : 50);

		// Get string table offset
		let strTableOff = 0;
		if (shStrIdx < shNum) {
			const strSectOff = shOff + shStrIdx * shEntSize;
			strTableOff = this.is64Bit
				? Number(buf.readBigUInt64LE(strSectOff + 24))
				: buf.readUInt32LE(strSectOff + 16);
		}

		for (let i = 0; i < shNum; i++) {
			const off = shOff + i * shEntSize;
			if (off + shEntSize > buf.length) {
				break;
			}

			const nameIdx = buf.readUInt32LE(off);
			const type = buf.readUInt32LE(off + 4);
			const flags = this.is64Bit
				? Number(buf.readBigUInt64LE(off + 8))
				: buf.readUInt32LE(off + 8);
			const address = this.is64Bit
				? buf.readBigUInt64LE(off + 16)
				: BigInt(buf.readUInt32LE(off + 12));
			const offset = this.is64Bit
				? Number(buf.readBigUInt64LE(off + 24))
				: buf.readUInt32LE(off + 16);
			const size = this.is64Bit
				? Number(buf.readBigUInt64LE(off + 32))
				: buf.readUInt32LE(off + 20);
			const link = buf.readUInt32LE(this.is64Bit ? off + 40 : off + 24);
			const entsize = this.is64Bit
				? Number(buf.readBigUInt64LE(off + 56))
				: buf.readUInt32LE(off + 36);

			// Read section name from string table
			let name = '';
			if (strTableOff > 0 && strTableOff + nameIdx < buf.length) {
				const nameEnd = buf.indexOf(0, strTableOff + nameIdx);
				name = buf.toString('ascii', strTableOff + nameIdx, nameEnd > strTableOff + nameIdx ? nameEnd : strTableOff + nameIdx + 32);
			}

			// Adjust address for PIE
			const adjustedAddress = address + this.pieBase;

			let permissions = '';
			if (flags & 0x1) { permissions += 'w'; } // SHF_WRITE
			if (flags & 0x2) { permissions += 'r'; } // SHF_ALLOC (implies readable)
			if (flags & 0x4) { permissions += 'x'; } // SHF_EXECINSTR
			if (!permissions) { permissions = 'r'; }

			sections.push({ name, address: adjustedAddress, size, offset, permissions, type, link, entsize });
		}

		return sections;
	}

	private elfFlagsToUnicorn(flags: number): number {
		let perms = 0;
		if (flags & PF_R) { perms |= PROT_READ; }
		if (flags & PF_W) { perms |= PROT_WRITE; }
		if (flags & PF_X) { perms |= PROT_EXEC; }
		return perms || PROT_READ;
	}

	private elfFlagsToString(flags: number): string {
		let perms = '';
		if (flags & PF_R) { perms += 'r'; }
		if (flags & PF_W) { perms += 'w'; }
		if (flags & PF_X) { perms += 'x'; }
		return perms || '---';
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
	lookupStub(address: bigint): ELFImportEntry | undefined {
		return this.stubMap.get(address);
	}

	/**
	 * Get all resolved imports
	 */
	getImports(): ELFImportEntry[] {
		return this.elfInfo?.imports ?? [];
	}

	/**
	 * Get the PIE base address (0 if not PIE)
	 */
	getPieBase(): bigint {
		return this.pieBase;
	}

	getELFInfo(): ELFInfo | undefined {
		return this.elfInfo;
	}
}
