/*---------------------------------------------------------------------------------------------
 *  HexCore Disassembler Engine
 *  Core disassembly logic - Capstone Edition
 *  Copyright (c) HikariSystem. All rights reserved.
 *--------------------------------------------------------------------------------------------*/

import * as fs from 'fs';
import * as path from 'path';
import { CapstoneWrapper, ArchitectureConfig, DisassembledInstruction } from './capstoneWrapper';

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

	// Capstone Engine
	private capstone: CapstoneWrapper;
	private capstoneInitialized: boolean = false;

	constructor() {
		this.capstone = new CapstoneWrapper();
	}

	/**
	 * Initialize Capstone for the given architecture
	 */
	private async ensureCapstoneInitialized(): Promise<void> {
		if (!this.capstoneInitialized) {
			try {
				await this.capstone.initialize(this.architecture);
				this.capstoneInitialized = true;
				console.log(`Capstone initialized for ${this.architecture}`);
			} catch (error) {
				console.warn('Capstone initialization failed, falling back to basic decoder:', error);
				// Continue without Capstone - we'll use fallback
			}
		} else if (this.capstone.getArchitecture() !== this.architecture) {
			// Re-initialize if architecture changed
			await this.capstone.setArchitecture(this.architecture);
		}
	}

	async loadFile(filePath: string, options?: Partial<DisassemblyOptions>): Promise<void> {
		this.currentFile = filePath;
		this.fileBuffer = fs.readFileSync(filePath);

		// Detect architecture and base address
		this.architecture = options?.architecture || this.detectArchitecture();
		this.baseAddress = options?.baseAddress || this.detectBaseAddress();

		// Initialize Capstone
		await this.ensureCapstoneInitialized();

		// Clear previous analysis
		this.instructions.clear();
		this.functions.clear();
		this.strings.clear();
		this.xrefs = [];

		// Perform initial analysis
		await this.analyzeStrings();
		await this.analyzeEntryPoint();

		// If PE file, analyze exports and entry points
		if (this.isPEFile()) {
			await this.analyzePEFile();
		} else if (this.isELFFile()) {
			await this.analyzeELFFile();
		}
	}

	/**
	 * Detect architecture from file headers
	 */
	private detectArchitecture(): ArchitectureConfig {
		if (!this.fileBuffer) return 'x64';

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

		// Use Capstone if available
		if (this.capstoneInitialized) {
			const rawInstructions = this.capstone.disassemble(bytesToDisasm, startAddr, 1000);
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
		if (offset >= this.fileBuffer!.length) return null;

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

	async analyzeStrings(): Promise<void> {
		if (!this.fileBuffer) return;

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
				if (char === 0 || char > 0x7E) break;
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
		if (!this.fileBuffer || this.fileBuffer.length < 64) return false;
		return this.fileBuffer[0] === 0x4D && this.fileBuffer[1] === 0x5A; // MZ
	}

	private isELFFile(): boolean {
		if (!this.fileBuffer || this.fileBuffer.length < 16) return false;
		return this.fileBuffer[0] === 0x7F &&
			this.fileBuffer[1] === 0x45 &&
			this.fileBuffer[2] === 0x4C &&
			this.fileBuffer[3] === 0x46; // \x7FELF
	}

	private async analyzePEFile(): Promise<void> {
		if (!this.fileBuffer) return;

		const peOffset = this.fileBuffer.readUInt32LE(0x3C);
		if (peOffset + 24 < this.fileBuffer.length) {
			const optionalHeaderOffset = peOffset + 24;
			const magic = this.fileBuffer.readUInt16LE(optionalHeaderOffset);
			const is64Bit = magic === 0x20B;
			const addrOfEntryPoint = this.fileBuffer.readUInt32LE(optionalHeaderOffset + 16);

			if (addrOfEntryPoint > 0) {
				const entryPointVA = this.baseAddress + addrOfEntryPoint;
				await this.analyzeFunction(entryPointVA, 'entry');
			}

			// Parse exports
			const dataDirOffset = optionalHeaderOffset + (is64Bit ? 112 : 96);
			if (dataDirOffset + 8 < this.fileBuffer.length) {
				const exportRVA = this.fileBuffer.readUInt32LE(dataDirOffset);
				if (exportRVA > 0) {
					await this.analyzeExports(exportRVA);
				}
			}
		}
	}

	private async analyzeELFFile(): Promise<void> {
		// Basic ELF analysis - can be expanded
		if (!this.fileBuffer) return;

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

	private async analyzeExports(_exportRVA: number): Promise<void> {
		// PE export table analysis - placeholder
	}

	async analyzeFunction(address: number, name?: string): Promise<Function> {
		const existing = this.functions.get(address);
		if (existing) return existing;

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
		return address - this.baseAddress;
	}

	private offsetToAddress(offset: number): number {
		return offset + this.baseAddress;
	}

	private detectBaseAddress(): number {
		if (!this.fileBuffer) return 0x400000;

		// PE file
		if (this.isPEFile()) {
			try {
				const peOffset = this.fileBuffer.readUInt32LE(0x3C);
				if (this.fileBuffer[peOffset] === 0x50 && this.fileBuffer[peOffset + 1] === 0x45) {
					const optHeaderOffset = peOffset + 24;
					const magic = this.fileBuffer.readUInt16LE(optHeaderOffset);
					if (magic === 0x20B) { // PE32+
						return Number(this.fileBuffer.readBigUInt64LE(optHeaderOffset + 24));
					} else {
						return this.fileBuffer.readUInt32LE(optHeaderOffset + 28);
					}
				}
			} catch {
				// Fall through
			}
			return 0x140000000; // Default 64-bit PE
		}

		// ELF file
		if (this.isELFFile()) {
			// Base address usually 0x400000 for 64-bit Linux executables
			return 0x400000;
		}

		return 0x400000;
	}

	private detectEntryPoint(): number | undefined {
		if (!this.fileBuffer) return undefined;

		// PE
		if (this.isPEFile()) {
			const peOffset = this.fileBuffer.readUInt32LE(0x3C);
			if (this.fileBuffer[peOffset] === 0x50 && this.fileBuffer[peOffset + 1] === 0x45) {
				const optHeaderOffset = peOffset + 24;
				const addrOfEntryPoint = this.fileBuffer.readUInt32LE(optHeaderOffset + 16);
				return this.baseAddress + addrOfEntryPoint;
			}
		}

		// ELF
		if (this.isELFFile()) {
			const is64Bit = this.fileBuffer[4] === 2;
			if (is64Bit) {
				return Number(this.fileBuffer.readBigUInt64LE(24));
			} else {
				return this.fileBuffer.readUInt32LE(24);
			}
		}

		return this.baseAddress;
	}

	/**
	 * Dispose of resources
	 */
	dispose(): void {
		this.capstone.dispose();
		this.capstoneInitialized = false;
	}
}
