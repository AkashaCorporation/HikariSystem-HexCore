/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import * as fs from 'fs';
import * as path from 'path';
import * as vscode from 'vscode'; // Added for extension interaction
import { CapstoneWrapper, ArchitectureConfig, DisassembledInstruction } from './capstoneWrapper';
import { LlvmMcWrapper, PatchResult, AssembleResult } from './llvmMcWrapper';

// Types
export interface Instruction {
	address: number;
	bytes: Buffer;
	mnemonic: string;
	opStr: string;
	size: number;
	comment?: string;
	isCall: boolean;
	isJump: boolean;
	isRet: boolean;
	isConditional: boolean;
	targetAddress?: number;
}

export interface Function {
	address: number;
	name: string;
	size: number;
	endAddress: number;
	instructions: Instruction[];
	callers: number[];
	callees: number[];
}

export interface StringReference {
	address: number;
	string: string;
	encoding: 'ascii' | 'unicode';
	references: number[];
}

export interface XRef {
	from: number;
	to: number;
	type: 'call' | 'jump' | 'data' | 'string';
}

// Section information
export interface Section {
	name: string;
	virtualAddress: number;
	virtualSize: number;
	rawAddress: number;
	rawSize: number;
	characteristics: number;
	permissions: string;  // "r-x", "rw-", etc
	isCode: boolean;
	isData: boolean;
	isReadable: boolean;
	isWritable: boolean;
	isExecutable: boolean;
}

// Import information
export interface ImportFunction {
	name: string;
	ordinal?: number;
	address: number;  // IAT address
	hint?: number;
}

export interface ImportLibrary {
	name: string;
	functions: ImportFunction[];
}

// Export information
export interface ExportFunction {
	name: string;
	ordinal: number;
	address: number;
	isForwarder: boolean;
	forwarderName?: string;
}

// File header info
export interface FileInfo {
	format: 'PE' | 'PE64' | 'ELF32' | 'ELF64' | 'MachO' | 'Raw';
	architecture: ArchitectureConfig;
	entryPoint: number;
	baseAddress: number;
	imageSize: number;
	timestamp?: Date;
	subsystem?: string;
	characteristics?: string[];
}

export interface DisassemblyOptions {
	architecture: ArchitectureConfig;
	baseAddress: number;
	entryPoint?: number;
}

export class DisassemblerEngine {
	private currentFile?: string;
	private fileBuffer?: Buffer;
	private baseAddress: number = 0x400000;
	private architecture: ArchitectureConfig = 'x64';
	private instructions: Map<number, Instruction> = new Map();
	private functions: Map<number, Function> = new Map();
	private strings: Map<number, StringReference> = new Map();
	private comments: Map<number, string> = new Map();
	private xrefs: XRef[] = [];

	// File analysis data
	private fileInfo?: FileInfo;
	private sections: Section[] = [];
	private imports: ImportLibrary[] = [];
	private exports: ExportFunction[] = [];

	// Capstone Engine
	private capstone: CapstoneWrapper;
	private capstoneInitialized: boolean = false;
	private capstoneError?: string;

	// LLVM MC Assembler (for patching)
	private llvmMc: LlvmMcWrapper;
	private llvmMcInitialized: boolean = false;
	private llvmMcError?: string;

	constructor() {
		this.capstone = new CapstoneWrapper();
		this.llvmMc = new LlvmMcWrapper();
	}

	/**
	 * Initialize Capstone for the given architecture
	 */
	private async ensureCapstoneInitialized(): Promise<void> {
		if (!this.capstoneInitialized) {
			try {
				await this.capstone.initialize(this.architecture);
				this.capstoneInitialized = true;
				this.capstoneError = undefined;
				console.log(`Capstone initialized for ${this.architecture}`);
			} catch (error) {
				const message = error instanceof Error ? error.message : String(error);
				this.capstoneInitialized = false;
				this.capstoneError = message;
				console.warn('Capstone initialization failed, falling back to basic decoder:', error);
				// Continue without Capstone - we'll use fallback
			}
		} else if (this.capstone.getArchitecture() !== this.architecture) {
			// Re-initialize if architecture changed
			await this.capstone.setArchitecture(this.architecture);
		}
	}

	async loadFile(filePath: string): Promise<boolean> {
		try {
			// Check if file exists
			if (!fs.existsSync(filePath)) {
				return false;
			}

			// Read file buffer
			this.currentFile = filePath;
			this.fileBuffer = fs.readFileSync(filePath);
			// Reset state
			this.sections = [];
			this.imports = [];
			this.exports = [];
			this.functions.clear();
			this.instructions.clear();
			this.comments.clear();
			this.xrefs = [];
			this.strings.clear();
			this.baseAddress = this.detectBaseAddress();

			// Initialize architecture
			this.architecture = this.detectArchitecture();
			await this.ensureCapstoneInitialized();

			// Parse file structure (sections, imports, exports)
			if (this.isPEFile()) {
				await this.analyzePEWithExtension();
			} else if (this.isELFFile()) {
				this.parseELFStructure();
			} else {
				this.parseRawFile();
			}

			// Initial analysis
			const entryPoint = this.detectEntryPoint();
			if (entryPoint) {
				await this.analyzeFunction(entryPoint, 'entry_point');
			}

			// Find strings
			this.findStrings();

			return true;
		} catch (error) {
			console.error('Failed to load file:', error);
			return false;
		}
	}

	/**
	 * Detect architecture from file headers
	 */
	private detectArchitecture(): ArchitectureConfig {
		if (!this.fileBuffer) {
			return 'x64';
		}

		// PE file detection
		if (this.isPEFile()) {
			const peOffset = this.fileBuffer.readUInt32LE(0x3C);
			if (peOffset + 6 < this.fileBuffer.length) {
				const machine = this.fileBuffer.readUInt16LE(peOffset + 4);
				switch (machine) {
					case 0x014c: return 'x86';   // IMAGE_FILE_MACHINE_I386
					case 0x8664: return 'x64';   // IMAGE_FILE_MACHINE_AMD64
					case 0x01c0: return 'arm';   // IMAGE_FILE_MACHINE_ARM
					case 0xaa64: return 'arm64'; // IMAGE_FILE_MACHINE_ARM64
				}
			}
		}

		// ELF file detection
		if (this.isELFFile()) {
			const elfClass = this.fileBuffer[4];
			const machine = this.fileBuffer.readUInt16LE(18);
			switch (machine) {
				case 0x03: return elfClass === 2 ? 'x64' : 'x86'; // EM_386 / EM_X86_64
				case 0x3E: return 'x64';  // EM_X86_64
				case 0x28: return 'arm';  // EM_ARM
				case 0xB7: return 'arm64'; // EM_AARCH64
				case 0x08: return 'mips'; // EM_MIPS
			}
		}

		return 'x64'; // Default
	}

	async disassembleRange(startAddr: number, size: number): Promise<Instruction[]> {
		await this.ensureCapstoneInitialized();

		const offset = this.addressToOffset(startAddr);
		if (offset < 0 || offset >= this.fileBuffer!.length) {
			return [];
		}

		const endOffset = Math.min(offset + size, this.fileBuffer!.length);
		const bytesToDisasm = this.fileBuffer!.subarray(offset, endOffset);

		// Use Capstone if available (async to avoid blocking)
		if (this.capstoneInitialized) {
			const rawInstructions = await this.capstone.disassemble(bytesToDisasm, startAddr, 1000);
			return rawInstructions.map(inst => this.convertCapstoneInstruction(inst));
		}

		// Fallback to basic decoder
		return this.disassembleRangeFallback(startAddr, size);
	}

	/**
	 * Convert Capstone instruction to our Instruction format
	 */
	private convertCapstoneInstruction(inst: DisassembledInstruction): Instruction {
		const instruction: Instruction = {
			address: inst.address,
			bytes: inst.bytes,
			mnemonic: inst.mnemonic,
			opStr: inst.opStr,
			size: inst.size,
			comment: this.comments.get(inst.address),
			isCall: inst.isCall,
			isJump: inst.isJump,
			isRet: inst.isRet,
			isConditional: inst.isConditional,
			targetAddress: inst.targetAddress
		};

		// Store in cache
		this.instructions.set(inst.address, instruction);

		return instruction;
	}

	/**
	 * Fallback disassembly for when Capstone is not available
	 * Uses basic opcode tables (limited support)
	 */
	private disassembleRangeFallback(startAddr: number, size: number): Instruction[] {
		const instructions: Instruction[] = [];
		let offset = this.addressToOffset(startAddr);
		let addr = startAddr;
		const endOffset = Math.min(offset + size, this.fileBuffer!.length);

		while (offset < endOffset && instructions.length < 1000) {
			const inst = this.disassembleInstructionFallback(offset, addr);
			if (inst) {
				instructions.push(inst);
				this.instructions.set(addr, inst);
				offset += inst.size;
				addr += inst.size;
			} else {
				// Invalid instruction - treat as data byte
				const dataByte = this.fileBuffer![offset];
				instructions.push({
					address: addr,
					bytes: Buffer.from([dataByte]),
					mnemonic: 'db',
					opStr: `0x${dataByte.toString(16).padStart(2, '0').toUpperCase()}`,
					size: 1,
					isCall: false,
					isJump: false,
					isRet: false,
					isConditional: false
				});
				offset++;
				addr++;
			}
		}

		return instructions;
	}

	/**
	 * Basic fallback instruction decoder (simplified x86)
	 */
	private disassembleInstructionFallback(offset: number, addr: number): Instruction | null {
		if (offset >= this.fileBuffer!.length) {
			return null;
		}

		const byte = this.fileBuffer![offset];

		// Common patterns
		if (byte === 0x90) {
			return this.createInstruction(addr, Buffer.from([byte]), 'nop', '', 1, false, false, false, false);
		}
		if (byte === 0xC3) {
			return this.createInstruction(addr, Buffer.from([byte]), 'ret', '', 1, false, false, true, false);
		}
		if (byte === 0xCC) {
			return this.createInstruction(addr, Buffer.from([byte]), 'int3', '', 1, false, false, false, false);
		}

		// CALL rel32
		if (byte === 0xE8 && offset + 5 <= this.fileBuffer!.length) {
			const rel = this.fileBuffer!.readInt32LE(offset + 1);
			const target = addr + 5 + rel;
			return this.createInstruction(
				addr,
				this.fileBuffer!.subarray(offset, offset + 5),
				'call',
				`0x${target.toString(16).toUpperCase()}`,
				5, true, false, false, false, target
			);
		}

		// JMP rel32
		if (byte === 0xE9 && offset + 5 <= this.fileBuffer!.length) {
			const rel = this.fileBuffer!.readInt32LE(offset + 1);
			const target = addr + 5 + rel;
			return this.createInstruction(
				addr,
				this.fileBuffer!.subarray(offset, offset + 5),
				'jmp',
				`0x${target.toString(16).toUpperCase()}`,
				5, false, true, false, false, target
			);
		}

		// JMP rel8
		if (byte === 0xEB && offset + 2 <= this.fileBuffer!.length) {
			const rel = this.fileBuffer!.readInt8(offset + 1);
			const target = addr + 2 + rel;
			return this.createInstruction(
				addr,
				this.fileBuffer!.subarray(offset, offset + 2),
				'jmp',
				`0x${target.toString(16).toUpperCase()}`,
				2, false, true, false, false, target
			);
		}

		// PUSH r64 (0x50-0x57)
		if (byte >= 0x50 && byte <= 0x57) {
			const regs = ['rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi'];
			return this.createInstruction(
				addr,
				Buffer.from([byte]),
				'push',
				regs[byte - 0x50],
				1, false, false, false, false
			);
		}

		// POP r64 (0x58-0x5F)
		if (byte >= 0x58 && byte <= 0x5F) {
			const regs = ['rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi'];
			return this.createInstruction(
				addr,
				Buffer.from([byte]),
				'pop',
				regs[byte - 0x58],
				1, false, false, false, false
			);
		}

		// Conditional jumps (0x70-0x7F)
		if (byte >= 0x70 && byte <= 0x7F && offset + 2 <= this.fileBuffer!.length) {
			const conditions = ['o', 'no', 'b', 'nb', 'z', 'nz', 'be', 'nbe', 's', 'ns', 'p', 'np', 'l', 'nl', 'le', 'nle'];
			const rel = this.fileBuffer!.readInt8(offset + 1);
			const target = addr + 2 + rel;
			return this.createInstruction(
				addr,
				this.fileBuffer!.subarray(offset, offset + 2),
				`j${conditions[byte - 0x70]}`,
				`0x${target.toString(16).toUpperCase()}`,
				2, false, true, false, true, target
			);
		}

		return null;
	}

	private createInstruction(
		address: number,
		bytes: Buffer,
		mnemonic: string,
		opStr: string,
		size: number,
		isCall: boolean = false,
		isJump: boolean = false,
		isRet: boolean = false,
		isConditional: boolean = false,
		targetAddress?: number
	): Instruction {
		return {
			address,
			bytes,
			mnemonic,
			opStr,
			size,
			comment: this.comments.get(address),
			isCall,
			isJump,
			isRet,
			isConditional,
			targetAddress
		};
	}

	async findStrings(): Promise<void> {
		if (!this.fileBuffer) {
			return;
		}

		// ASCII strings (min 4 chars)
		const asciiPattern = /[\x20-\x7E]{4,}/g;
		const text = this.fileBuffer.toString('binary');
		let match;

		while ((match = asciiPattern.exec(text)) !== null) {
			if (match[0].length <= 256) { // Reasonable limit
				const offset = match.index;
				const str = match[0];
				const addr = this.offsetToAddress(offset);

				this.strings.set(addr, {
					address: addr,
					string: str,
					encoding: 'ascii',
					references: []
				});
			}
		}

		// Unicode strings (UTF-16 LE)
		for (let i = 0; i < this.fileBuffer.length - 8; i += 2) {
			let len = 0;
			while (i + len * 2 < this.fileBuffer.length - 1) {
				const char = this.fileBuffer.readUInt16LE(i + len * 2);
				if (char === 0 || char > 0x7E) {
					break;
				}
				len++;
			}
			if (len >= 4 && len <= 128) {
				const str = this.fileBuffer.toString('utf16le', i, i + len * 2);
				const addr = this.offsetToAddress(i);
				if (!this.strings.has(addr)) {
					this.strings.set(addr, {
						address: addr,
						string: str,
						encoding: 'unicode',
						references: []
					});
				}
				i += len * 2;
			}
		}
	}

	async analyzeEntryPoint(): Promise<void> {
		const ep = this.detectEntryPoint();
		if (ep) {
			await this.analyzeFunction(ep, '_start');
		}
	}

	private isPEFile(): boolean {
		if (!this.fileBuffer || this.fileBuffer.length < 64) {
			return false;
		}
		return this.fileBuffer[0] === 0x4D && this.fileBuffer[1] === 0x5A; // MZ
	}

	private isELFFile(): boolean {
		if (!this.fileBuffer || this.fileBuffer.length < 16) {
			return false;
		}
		return this.fileBuffer[0] === 0x7F &&
			this.fileBuffer[1] === 0x45 &&
			this.fileBuffer[2] === 0x4C &&
			this.fileBuffer[3] === 0x46; // \x7FELF
	}

	// ============================================================================
	// PE/ELF Structure Parsing
	// ============================================================================



	private parseELFStructure(): void {
		if (!this.fileBuffer) {
			return;
		}

		const is64Bit = this.fileBuffer[4] === 2;
		const isLittleEndian = this.fileBuffer[5] === 1;

		// For now, only support little-endian
		if (!isLittleEndian) {
			return;
		}

		const entryPoint = is64Bit
			? Number(this.fileBuffer.readBigUInt64LE(24))
			: this.fileBuffer.readUInt32LE(24);

		const phoff = is64Bit
			? Number(this.fileBuffer.readBigUInt64LE(32))
			: this.fileBuffer.readUInt32LE(28);

		const shoff = is64Bit
			? Number(this.fileBuffer.readBigUInt64LE(40))
			: this.fileBuffer.readUInt32LE(32);

		const phentsize = this.fileBuffer.readUInt16LE(is64Bit ? 54 : 42);
		const phnum = this.fileBuffer.readUInt16LE(is64Bit ? 56 : 44);
		const shentsize = this.fileBuffer.readUInt16LE(is64Bit ? 58 : 46);
		const shnum = this.fileBuffer.readUInt16LE(is64Bit ? 60 : 48);
		const shstrndx = this.fileBuffer.readUInt16LE(is64Bit ? 62 : 50);

		// File info
		this.fileInfo = {
			format: is64Bit ? 'ELF64' : 'ELF32',
			architecture: this.architecture,
			entryPoint: entryPoint,
			baseAddress: this.baseAddress,
			imageSize: this.fileBuffer.length,
			characteristics: ['ELF']
		};

		// Parse section headers
		if (shoff > 0 && shnum > 0 && shstrndx < shnum) {
			// Get section name string table
			const shstrtabOffset = shoff + (shstrndx * shentsize);
			const shstrtabFileOffset = is64Bit
				? Number(this.fileBuffer.readBigUInt64LE(shstrtabOffset + 24))
				: this.fileBuffer.readUInt32LE(shstrtabOffset + 16);

			for (let i = 0; i < shnum; i++) {
				const sectionOffset = shoff + (i * shentsize);
				if (sectionOffset + shentsize > this.fileBuffer.length) {
					break;
				}

				const nameOffset = this.fileBuffer.readUInt32LE(sectionOffset);
				const type = this.fileBuffer.readUInt32LE(sectionOffset + 4);
				const flags = is64Bit
					? Number(this.fileBuffer.readBigUInt64LE(sectionOffset + 8))
					: this.fileBuffer.readUInt32LE(sectionOffset + 8);
				const addr = is64Bit
					? Number(this.fileBuffer.readBigUInt64LE(sectionOffset + 16))
					: this.fileBuffer.readUInt32LE(sectionOffset + 12);
				const offset = is64Bit
					? Number(this.fileBuffer.readBigUInt64LE(sectionOffset + 24))
					: this.fileBuffer.readUInt32LE(sectionOffset + 16);
				const size = is64Bit
					? Number(this.fileBuffer.readBigUInt64LE(sectionOffset + 32))
					: this.fileBuffer.readUInt32LE(sectionOffset + 20);

				// Read section name
				let name = '';
				if (shstrtabFileOffset + nameOffset < this.fileBuffer.length) {
					for (let j = shstrtabFileOffset + nameOffset; j < this.fileBuffer.length && this.fileBuffer[j] !== 0; j++) {
						name += String.fromCharCode(this.fileBuffer[j]);
					}
				}

				if (name.length === 0) {
					name = `section_${i}`;
				}

				const isWritable = (flags & 0x1) !== 0;
				const isAlloc = (flags & 0x2) !== 0;
				const isExecutable = (flags & 0x4) !== 0;

				// Skip non-allocated sections (debug, etc)
				if (!isAlloc && type !== 1) {
					continue;
				}

				let permissions = 'r';
				permissions += isWritable ? 'w' : '-';
				permissions += isExecutable ? 'x' : '-';

				this.sections.push({
					name,
					virtualAddress: addr,
					virtualSize: size,
					rawAddress: offset,
					rawSize: size,
					characteristics: flags,
					permissions,
					isCode: isExecutable,
					isData: !isExecutable && isWritable,
					isReadable: true,
					isWritable,
					isExecutable
				});
			}
		}
	}

	private parseRawFile(): void {
		if (!this.fileBuffer) {
			return;
		}

		this.fileInfo = {
			format: 'Raw',
			architecture: this.architecture,
			entryPoint: this.baseAddress,
			baseAddress: this.baseAddress,
			imageSize: this.fileBuffer.length
		};

		this.sections.push({
			name: '.code',
			virtualAddress: this.baseAddress,
			virtualSize: this.fileBuffer.length,
			rawAddress: 0,
			rawSize: this.fileBuffer.length,
			characteristics: 0,
			permissions: 'rwx',
			isCode: true,
			isData: false,
			isReadable: true,
			isWritable: true,
			isExecutable: true
		});
	}

	private rvaToFileOffset(rva: number): number {
		if (!this.fileBuffer) {
			return -1;
		}

		// Find section containing this RVA
		for (const section of this.sections) {
			const sectionRVA = section.virtualAddress - this.baseAddress;
			if (rva >= sectionRVA && rva < sectionRVA + section.virtualSize) {
				return section.rawAddress + (rva - sectionRVA);
			}
		}

		// Fallback: assume 1:1 mapping (headers)
		return rva;
	}

	// Getters for new data
	getFileInfo(): FileInfo | undefined {
		return this.fileInfo;
	}

	getSections(): Section[] {
		return this.sections;
	}

	getImports(): ImportLibrary[] {
		return this.imports;
	}

	getExports(): ExportFunction[] {
		return this.exports;
	}

	getFileName(): string {
		return this.currentFile ? path.basename(this.currentFile) : 'Unknown';
	}

	getFilePath(): string | undefined {
		return this.currentFile;
	}

	private async analyzePEWithExtension(): Promise<void> {
		if (!this.fileBuffer) {
			return;
		}

		const ext = vscode.extensions.getExtension('hikarisystem.hexcore-peanalyzer');
		if (!ext) {
			console.warn('HexCore PE Analyzer extension not found');
			return;
		}

		if (!ext.isActive) {
			await ext.activate();
		}

		const api = ext.exports;
		if (!api || !api.analyzePEFile) {
			console.warn('HexCore PE Analyzer API not available');
			return;
		}

		try {
			if (!this.currentFile) {
				console.warn('HexCore PE Analyzer: no file path available');
				return;
			}

			const analysis = await api.analyzePEFile(this.currentFile);

			// Map Basic Info
			const is64 = analysis.optionalHeader?.is64Bit === true;
			const imageBase = analysis.optionalHeader?.imageBase;
			this.baseAddress = imageBase !== undefined
				? Number(imageBase)
				: (is64 ? 0x140000000 : 0x400000);
			// Architecture is likely already set by detectArchitecture, but let's confirm
			// this.architecture = is64 ? 'x64' : 'x86';

			this.fileInfo = {
				format: is64 ? 'PE64' : 'PE',
				architecture: this.architecture,
				entryPoint: (analysis.optionalHeader?.addressOfEntryPoint || 0) + this.baseAddress,
				baseAddress: this.baseAddress,
				imageSize: analysis.optionalHeader?.sizeOfImage || 0,
				timestamp: analysis.fileHeader?.timeDateStamp ? new Date(analysis.fileHeader.timeDateStamp * 1000) : undefined,
				subsystem: analysis.optionalHeader?.subsystem?.toString()
			};

			// Map Sections
			if (analysis.sections) {
				this.sections = analysis.sections.map((s: any) => {
					const characteristicsRaw = typeof s.characteristicsRaw === 'number'
						? s.characteristicsRaw
						: (typeof s.characteristics === 'number' ? s.characteristics : 0);

					return {
						name: s.name,
						virtualAddress: s.virtualAddress + this.baseAddress,
						virtualSize: s.virtualSize,
						rawAddress: s.pointerToRawData,
						rawSize: s.sizeOfRawData,
						characteristics: characteristicsRaw,
						permissions: s.permissions || 'r-x', // Fallback
						isCode: (characteristicsRaw & 0x00000020) !== 0,
						isData: (characteristicsRaw & 0x00000040) !== 0,
						isReadable: (characteristicsRaw & 0x40000000) !== 0,
						isWritable: (characteristicsRaw & 0x80000000) !== 0,
						isExecutable: (characteristicsRaw & 0x20000000) !== 0
					};
				});
			}

			// Map Imports
			if (analysis.imports) {
				this.imports = analysis.imports.map((imp: any) => ({
					name: imp.dllName,
					functions: imp.functions.map((f: any) => ({
						name: f.name,
						ordinal: f.ordinal,
						address: f.address + this.baseAddress, // IAT Address (RVA -> VA)
						hint: 0
					}))
				}));
			}

			// Map Exports
			if (analysis.exports) {
				this.exports = analysis.exports.map((exp: any) => ({
					name: exp.name,
					ordinal: exp.ordinal,
					address: exp.rva + this.baseAddress,
					isForwarder: !!exp.forwarder,
					forwarderName: exp.forwarder
				}));
			}

		} catch (e) {
			console.error('Failed to analyze PE with extension:', e);
		}
	}

	private async analyzeELFFile(): Promise<void> {
		// Basic ELF analysis - can be expanded
		if (!this.fileBuffer) {
			return;
		}

		const is64Bit = this.fileBuffer[4] === 2;
		const entryPointOffset = is64Bit ? 24 : 24;

		if (entryPointOffset + 8 < this.fileBuffer.length) {
			const entryPoint = is64Bit
				? Number(this.fileBuffer.readBigUInt64LE(entryPointOffset))
				: this.fileBuffer.readUInt32LE(entryPointOffset);

			if (entryPoint > 0) {
				await this.analyzeFunction(entryPoint, '_start');
			}
		}
	}



	async analyzeFunction(address: number, name?: string): Promise<Function> {
		const existing = this.functions.get(address);
		if (existing) {
			return existing;
		}

		const instructions = await this.disassembleRange(address, 4096);

		if (instructions.length === 0) {
			const offset = this.addressToOffset(address);
			if (offset >= 0 && offset < this.fileBuffer!.length) {
				const byteCount = Math.min(16, this.fileBuffer!.length - offset);
				instructions.push({
					address,
					bytes: this.fileBuffer!.subarray(offset, offset + byteCount),
					mnemonic: 'db',
					opStr: Array.from(this.fileBuffer!.subarray(offset, offset + byteCount))
						.map(b => `0x${b.toString(16).padStart(2, '0').toUpperCase()}`).join(', '),
					size: byteCount,
					isCall: false,
					isJump: false,
					isRet: false,
					isConditional: false
				});
			}
		}

		// Find function end (RET or unconditional JMP)
		let endIdx = instructions.length;
		for (let i = 0; i < instructions.length; i++) {
			if (instructions[i].isRet) {
				endIdx = i + 1;
				break;
			}
			if (instructions[i].isJump && !instructions[i].isConditional) {
				if (instructions[i].targetAddress &&
					(instructions[i].targetAddress! < address || instructions[i].targetAddress! > address + 4096)) {
					endIdx = i + 1;
					break;
				}
			}
		}

		const funcInstructions = instructions.slice(0, endIdx);

		const func: Function = {
			address,
			name: name || `sub_${address.toString(16).toUpperCase()}`,
			size: funcInstructions.length > 0
				? (funcInstructions[funcInstructions.length - 1].address + funcInstructions[funcInstructions.length - 1].size - address)
				: 0,
			endAddress: funcInstructions.length > 0
				? (funcInstructions[funcInstructions.length - 1].address + funcInstructions[funcInstructions.length - 1].size)
				: address,
			instructions: funcInstructions,
			callers: [],
			callees: []
		};

		this.functions.set(address, func);

		// Recursively analyze called functions (limit depth)
		for (const inst of funcInstructions) {
			if (inst.isCall && inst.targetAddress && this.functions.size < 100) {
				func.callees.push(inst.targetAddress);
				this.xrefs.push({ from: inst.address, to: inst.targetAddress, type: 'call' });

				// Don't await to avoid deep recursion
				this.analyzeFunction(inst.targetAddress);
			}
		}

		return func;
	}

	async findCrossReferences(address: number): Promise<XRef[]> {
		return this.xrefs.filter(x => x.to === address);
	}

	async searchStringReferences(query: string): Promise<StringReference[]> {
		const results: StringReference[] = [];
		const lowerQuery = query.toLowerCase();

		for (const strRef of this.strings.values()) {
			if (strRef.string.toLowerCase().includes(lowerQuery)) {
				results.push(strRef);
			}
		}

		return results;
	}

	async exportAssembly(filePath: string): Promise<void> {
		const lines: string[] = [];
		lines.push(`; Disassembly of ${path.basename(this.currentFile || 'unknown')}`);
		lines.push(`; Generated by HexCore Disassembler (Capstone Engine)`);
		lines.push(`; Architecture: ${this.architecture}`);
		lines.push('');
		lines.push(this.architecture.includes('64') ? 'BITS 64' : 'BITS 32');
		lines.push(`ORG 0x${this.baseAddress.toString(16).toUpperCase()}`);
		lines.push('');

		for (const func of this.functions.values()) {
			lines.push(`; ============================================`);
			lines.push(`; Function: ${func.name}`);
			lines.push(`; Address: 0x${func.address.toString(16).toUpperCase()}`);
			lines.push(`; Size: ${func.size} bytes`);
			lines.push(`; ============================================`);
			lines.push(`${func.name}:`);

			for (const inst of func.instructions) {
				const addrStr = inst.address.toString(16).toUpperCase().padStart(16, '0');
				const bytesStr = Array.from(inst.bytes).map(b => b.toString(16).padStart(2, '0')).join(' ');
				const comment = inst.comment ? ` ; ${inst.comment}` : '';
				lines.push(`    ${inst.mnemonic.toLowerCase().padEnd(10)} ${inst.opStr.padEnd(30)} ; 0x${addrStr} | ${bytesStr}${comment}`);
			}
			lines.push('');
		}

		fs.writeFileSync(filePath, lines.join('\n'));
	}

	addComment(address: number, comment: string): void {
		this.comments.set(address, comment);
		const inst = this.instructions.get(address);
		if (inst) {
			inst.comment = comment;
		}
	}

	renameFunction(address: number, name: string): void {
		const func = this.functions.get(address);
		if (func) {
			func.name = name;
		}
	}

	getFunctionName(address: number): string | undefined {
		return this.functions.get(address)?.name;
	}

	getFunctions(): Function[] {
		return Array.from(this.functions.values()).sort((a, b) => a.address - b.address);
	}

	getStrings(): StringReference[] {
		return Array.from(this.strings.values()).sort((a, b) => a.address - b.address);
	}

	getFunctionAt(address: number): Function | undefined {
		return this.functions.get(address);
	}

	getArchitecture(): ArchitectureConfig {
		return this.architecture;
	}

	getBaseAddress(): number {
		return this.baseAddress;
	}

	private addressToOffset(address: number): number {
		// Convert virtual address to file offset
		const rva = address - this.baseAddress;

		// For PE files, we need to map RVA to file offset using section headers
		if (this.isPEFile() && this.fileBuffer) {
			return this.rvaToFileOffset(rva);
		}

		// For ELF or raw files, simple subtraction
		return rva;
	}

	private offsetToAddress(offset: number): number {
		return offset + this.baseAddress;
	}

	private detectBaseAddress(): number {
		if (this.fileInfo) {
			return this.fileInfo.baseAddress;
		}
		// Fallback defaults if extension hasn't run yet
		if (this.isPEFile()) {
			return 0x400000;
		}
		return 0x400000;
	}

	private detectEntryPoint(): number | undefined {
		if (this.fileInfo) {
			return this.fileInfo.entryPoint;
		}

		// Fallback for ELF (since we don't have an extension for it yet)
		if (this.isELFFile() && this.fileBuffer) {
			const is64Bit = this.fileBuffer[4] === 2;
			if (is64Bit) {
				return Number(this.fileBuffer.readBigUInt64LE(24));
			} else {
				return this.fileBuffer.readUInt32LE(24);
			}
		}

		return this.baseAddress;
	}


	// ============================================================================
	// Assembly & Patching (LLVM MC)
	// ============================================================================

	/**
	 * Initialize LLVM MC assembler
	 */
	private async ensureLlvmMcInitialized(): Promise<void> {
		if (!this.llvmMcInitialized) {
			try {
				await this.llvmMc.initialize(this.architecture);
				this.llvmMcInitialized = true;
				this.llvmMcError = undefined;
				console.log(`LLVM MC initialized for ${this.architecture}`);
			} catch (error) {
				const message = error instanceof Error ? error.message : String(error);
				this.llvmMcInitialized = false;
				this.llvmMcError = message;
				console.warn('LLVM MC initialization failed:', error);
			}
		} else if (this.llvmMc.getArchitecture() !== this.architecture) {
			await this.llvmMc.setArchitecture(this.architecture);
		}
	}

	async getDisassemblerAvailability(): Promise<{ available: boolean; error?: string }> {
		await this.ensureCapstoneInitialized();
		return {
			available: this.capstoneInitialized,
			error: this.capstoneError ?? this.capstone.getLastError()
		};
	}

	async getAssemblerAvailability(): Promise<{ available: boolean; error?: string }> {
		await this.ensureLlvmMcInitialized();
		return {
			available: this.llvmMcInitialized,
			error: this.llvmMcError ?? this.llvmMc.getLastError()
		};
	}

	/**
	 * Assemble an instruction
	 */
	async assemble(code: string, address?: number): Promise<AssembleResult> {
		await this.ensureLlvmMcInitialized();
		if (!this.llvmMcInitialized) {
			return {
				success: false,
				bytes: Buffer.alloc(0),
				size: 0,
				statement: code,
				error: this.llvmMcError ?? 'LLVM MC not available'
			};
		}
		return this.llvmMc.assemble(code, address ? BigInt(address) : undefined);
	}

	/**
	 * Assemble multiple instructions
	 */
	async assembleMultiple(instructions: string[], startAddress?: number): Promise<AssembleResult[]> {
		await this.ensureLlvmMcInitialized();
		if (!this.llvmMcInitialized) {
			return instructions.map(code => ({
				success: false,
				bytes: Buffer.alloc(0),
				size: 0,
				statement: code,
				error: this.llvmMcError ?? 'LLVM MC not available'
			}));
		}
		return this.llvmMc.assembleMultiple(instructions, startAddress ? BigInt(startAddress) : undefined);
	}

	/**
	 * Patch instruction at address
	 * Returns the patch bytes, padded with NOPs if smaller than original
	 */
	async patchInstruction(address: number, newInstruction: string): Promise<PatchResult> {
		await this.ensureLlvmMcInitialized();
		if (!this.llvmMcInitialized) {
			return {
				success: false,
				bytes: Buffer.alloc(0),
				size: 0,
				originalSize: 0,
				nopPadding: 0,
				error: this.llvmMcError ?? 'LLVM MC not available'
			};
		}

		// Get original instruction to know its size
		let original = this.instructions.get(address);
		if (!original) {
			// Disassemble to find original instruction size
			const disasm = await this.disassembleRange(address, 16);
			if (disasm.length === 0) {
				return {
					success: false,
					bytes: Buffer.alloc(0),
					size: 0,
					originalSize: 0,
					nopPadding: 0,
					error: 'Could not find instruction at address'
				};
			}
			original = disasm[0];
			this.instructions.set(original.address, original);
		}

		const originalSize = original.size;
		return this.llvmMc.createPatch(newInstruction, originalSize, BigInt(address));
	}

	/**
	 * Apply patch to file buffer (in memory)
	 */
	applyPatch(address: number, patchBytes: Buffer): boolean {
		if (!this.fileBuffer) {
			return false;
		}

		const offset = this.addressToOffset(address);
		if (offset < 0 || offset + patchBytes.length > this.fileBuffer.length) {
			return false;
		}

		patchBytes.copy(this.fileBuffer, offset);

		// Invalidate cached instructions at this address
		for (let i = 0; i < patchBytes.length; i++) {
			this.instructions.delete(address + i);
		}

		return true;
	}

	/**
	 * Replace instruction with NOPs
	 */
	async nopInstruction(address: number): Promise<boolean> {
		await this.ensureLlvmMcInitialized();
		if (!this.llvmMcInitialized) {
			return false;
		}

		const original = this.instructions.get(address);
		if (!original) {
			return false;
		}

		const nopSled = this.llvmMc.createNopSled(original.size);
		return this.applyPatch(address, nopSled);
	}

	/**
	 * Save patched file to disk
	 */
	savePatched(outputPath: string): void {
		if (!this.fileBuffer) {
			throw new Error('No file loaded');
		}
		fs.writeFileSync(outputPath, this.fileBuffer);
	}

	/**
	 * Validate assembly instruction
	 */
	async validateInstruction(code: string): Promise<{ valid: boolean; error?: string }> {
		await this.ensureLlvmMcInitialized();
		if (!this.llvmMcInitialized) {
			return { valid: false, error: this.llvmMcError ?? 'LLVM MC not available' };
		}
		return this.llvmMc.validate(code);
	}

	/**
	 * Get NOP instruction for current architecture
	 */
	getNop(): Buffer {
		if (!this.llvmMcInitialized) {
			// Fallback NOPs
			switch (this.architecture) {
				case 'x86':
				case 'x64':
					return Buffer.from([0x90]);
				case 'arm':
					return Buffer.from([0x00, 0x00, 0xA0, 0xE1]);
				case 'arm64':
					return Buffer.from([0x1F, 0x20, 0x03, 0xD5]);
				default:
					return Buffer.from([0x90]);
			}
		}
		return this.llvmMc.getNop();
	}

	/**
	 * Get LLVM MC version
	 */
	getLlvmVersion(): string {
		if (!this.llvmMcInitialized) {
			return 'not initialized';
		}
		return this.llvmMc.getVersion();
	}

	/**
	 * Set assembly syntax (intel/att) for x86
	 */
	setAssemblySyntax(syntax: 'intel' | 'att'): void {
		if (this.llvmMcInitialized) {
			this.llvmMc.setSyntax(syntax);
		}
	}

	/**
	 * Dispose of resources
	 */
	dispose(): void {
		this.capstone.dispose();
		this.capstoneInitialized = false;
		this.llvmMc.dispose();
		this.llvmMcInitialized = false;
	}
}

