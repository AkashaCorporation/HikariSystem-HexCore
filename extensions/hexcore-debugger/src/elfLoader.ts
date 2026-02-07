/*---------------------------------------------------------------------------------------------
 *  HexCore Debugger - ELF Loader
 *  Loads ELF binaries into emulator memory with correct segment permissions
 *  Copyright (c) HikariSystem. All rights reserved.
 *--------------------------------------------------------------------------------------------*/

import { UnicornWrapper } from './unicornWrapper';
import { MemoryManager } from './memoryManager';

export interface ELFSection {
	name: string;
	address: bigint;
	size: number;
	offset: number;
	permissions: string;
}

export interface ELFInfo {
	is64Bit: boolean;
	entryPoint: bigint;
	sections: ELFSection[];
	programHeaders: ELFSegment[];
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
const PF_X = 1;
const PF_W = 2;
const PF_R = 4;

// Unicorn PROT constants
const PROT_READ = 1;
const PROT_WRITE = 2;
const PROT_EXEC = 4;

export class ELFLoader {
	private emulator: UnicornWrapper;
	private memoryManager: MemoryManager;
	private elfInfo?: ELFInfo;

	constructor(emulator: UnicornWrapper, memoryManager: MemoryManager) {
		this.emulator = emulator;
		this.memoryManager = memoryManager;
	}

	/**
	 * Load an ELF file into the emulator
	 */
	load(fileBuffer: Buffer): ELFInfo {
		// Verify ELF magic
		if (fileBuffer[0] !== 0x7F || fileBuffer.toString('ascii', 1, 4) !== 'ELF') {
			throw new Error('Not a valid ELF file');
		}

		const is64Bit = fileBuffer[4] === 2;
		const isLittleEndian = fileBuffer[5] === 1;

		if (!isLittleEndian) {
			throw new Error('Big-endian ELF files are not currently supported');
		}

		const entryPoint = is64Bit
			? fileBuffer.readBigUInt64LE(24)
			: BigInt(fileBuffer.readUInt32LE(24));

		// Parse program headers
		const segments = this.parseProgramHeaders(fileBuffer, is64Bit);

		// Map LOAD segments
		for (const seg of segments) {
			if (seg.type !== PT_LOAD) {
				continue;
			}

			const perms = this.elfFlagsToUnicorn(seg.flags);
			const pageSize = this.emulator.getPageSize();
			const alignedAddr = (seg.virtualAddress / BigInt(pageSize)) * BigInt(pageSize);
			const alignedEnd = ((seg.virtualAddress + BigInt(seg.memSize) + BigInt(pageSize) - 1n) / BigInt(pageSize)) * BigInt(pageSize);
			const alignedSize = Number(alignedEnd - alignedAddr);

			this.emulator.mapMemoryRaw(alignedAddr, alignedSize, perms);
			this.memoryManager.trackAllocation(alignedAddr, alignedSize, perms, `elf-segment`);

			// Write segment data from file
			if (seg.fileSize > 0 && seg.offset + seg.fileSize <= fileBuffer.length) {
				const data = fileBuffer.subarray(seg.offset, seg.offset + seg.fileSize);
				this.emulator.writeMemory(seg.virtualAddress, data);
			}
		}

		// Parse section headers for names/metadata
		const sections = this.parseSectionHeaders(fileBuffer, is64Bit);

		this.elfInfo = {
			is64Bit,
			entryPoint,
			sections,
			programHeaders: segments
		};

		console.log(`ELF loaded: ${is64Bit ? '64-bit' : '32-bit'}, entry=0x${entryPoint.toString(16)}, ${segments.filter(s => s.type === PT_LOAD).length} LOAD segments`);

		return this.elfInfo;
	}

	/**
	 * Parse ELF program headers
	 */
	private parseProgramHeaders(buf: Buffer, is64Bit: boolean): ELFSegment[] {
		const segments: ELFSegment[] = [];

		const phOff = is64Bit
			? Number(buf.readBigUInt64LE(32))
			: buf.readUInt32LE(28);

		const phEntSize = buf.readUInt16LE(is64Bit ? 54 : 42);
		const phNum = buf.readUInt16LE(is64Bit ? 56 : 44);

		for (let i = 0; i < phNum; i++) {
			const off = phOff + i * phEntSize;
			if (off + phEntSize > buf.length) {
				break;
			}

			let segment: ELFSegment;

			if (is64Bit) {
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
	 * Parse ELF section headers (for metadata/display only)
	 */
	private parseSectionHeaders(buf: Buffer, is64Bit: boolean): ELFSection[] {
		const sections: ELFSection[] = [];

		const shOff = is64Bit
			? Number(buf.readBigUInt64LE(40))
			: buf.readUInt32LE(32);

		if (shOff === 0) {
			return sections;
		}

		const shEntSize = buf.readUInt16LE(is64Bit ? 58 : 46);
		const shNum = buf.readUInt16LE(is64Bit ? 60 : 48);
		const shStrIdx = buf.readUInt16LE(is64Bit ? 62 : 50);

		// Get string table offset
		let strTableOff = 0;
		if (shStrIdx < shNum) {
			const strSectOff = shOff + shStrIdx * shEntSize;
			strTableOff = is64Bit
				? Number(buf.readBigUInt64LE(strSectOff + 24))
				: buf.readUInt32LE(strSectOff + 16);
		}

		for (let i = 0; i < shNum; i++) {
			const off = shOff + i * shEntSize;
			if (off + shEntSize > buf.length) {
				break;
			}

			const nameIdx = buf.readUInt32LE(off);
			const flags = is64Bit
				? Number(buf.readBigUInt64LE(off + 8))
				: buf.readUInt32LE(off + 8);
			const address = is64Bit
				? buf.readBigUInt64LE(off + 16)
				: BigInt(buf.readUInt32LE(off + 12));
			const offset = is64Bit
				? Number(buf.readBigUInt64LE(off + 24))
				: buf.readUInt32LE(off + 16);
			const size = is64Bit
				? Number(buf.readBigUInt64LE(off + 32))
				: buf.readUInt32LE(off + 20);

			// Read section name from string table
			let name = '';
			if (strTableOff > 0 && strTableOff + nameIdx < buf.length) {
				const nameEnd = buf.indexOf(0, strTableOff + nameIdx);
				name = buf.toString('ascii', strTableOff + nameIdx, nameEnd > strTableOff + nameIdx ? nameEnd : strTableOff + nameIdx + 32);
			}

			let permissions = '';
			if (flags & 0x1) { permissions += 'w'; } // SHF_WRITE
			if (flags & 0x2) { permissions += 'r'; } // SHF_ALLOC (implies readable)
			if (flags & 0x4) { permissions += 'x'; } // SHF_EXECINSTR
			if (!permissions) { permissions = 'r'; }

			sections.push({ name, address, size, offset, permissions });
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

	getELFInfo(): ELFInfo | undefined {
		return this.elfInfo;
	}
}
