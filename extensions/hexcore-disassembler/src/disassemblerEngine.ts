/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import * as fs from 'fs';
import * as path from 'path';
import * as vscode from 'vscode';
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

	// Configurable limits
	private maxFunctions: number = 5000;
	private maxFunctionSize: number = 65536;

	constructor() {
		this.capstone = new CapstoneWrapper();
		this.llvmMc = new LlvmMcWrapper();
		this.loadConfig();
	}

	private loadConfig(): void {
		const config = vscode.workspace.getConfiguration('hexcore.disassembler');
		this.maxFunctions = this.normalizePositiveInteger(config.get<number>('maxFunctions', 5000), 5000, 100, 50000);
		this.maxFunctionSize = this.normalizePositiveInteger(config.get<number>('maxFunctionSize', 65536), 65536, 1024, 1048576);
	}

	public reloadConfig(): void {
		this.loadConfig();
	}

	public getAnalysisLimits(): { maxFunctions: number; maxFunctionSize: number } {
		return {
			maxFunctions: this.maxFunctions,
			maxFunctionSize: this.maxFunctionSize
		};
	}

	public setAnalysisLimits(maxFunctions?: number, maxFunctionSize?: number): void {
		if (typeof maxFunctions === 'number') {
			this.maxFunctions = this.normalizePositiveInteger(maxFunctions, this.maxFunctions, 100, 50000);
		}
		if (typeof maxFunctionSize === 'number') {
			this.maxFunctionSize = this.normalizePositiveInteger(maxFunctionSize, this.maxFunctionSize, 1024, 1048576);
		}
	}

	private normalizePositiveInteger(
		value: number | undefined,
		fallback: number,
		minValue: number,
		maxValue: number
	): number {
		if (typeof value !== 'number' || !Number.isFinite(value)) {
			return fallback;
		}
		const normalized = Math.floor(value);
		if (normalized < minValue) {
			return minValue;
		}
		if (normalized > maxValue) {
			return maxValue;
		}
		return normalized;
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
			}
		} else if (this.capstone.getArchitecture() !== this.architecture) {
			await this.capstone.setArchitecture(this.architecture);
		}
	}

	async loadFile(filePath: string): Promise<boolean> {
		try {
			this.loadConfig();

			if (!fs.existsSync(filePath)) {
				return false;
			}

			const stats = fs.statSync(filePath);
			const MAX_FILE_SIZE = 512 * 1024 * 1024; // 512MB
			if (stats.size > MAX_FILE_SIZE) {
				throw new Error(`File too large (${(stats.size / (1024 * 1024)).toFixed(0)}MB). Maximum supported size is 512MB.`);
			}

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

			// Initialize architecture first (needed for base address detection in PE)
			this.architecture = this.detectArchitecture();

			// Parse file structure (sets baseAddress, fileInfo, sections, imports, exports)
			if (this.isPEFile()) {
				this.parsePEStructure();
			} else if (this.isELFFile()) {
				this.parseELFStructure();
			} else {
				this.baseAddress = 0x400000;
				this.parseRawFile();
			}

			await this.ensureCapstoneInitialized();

			// Initial analysis from entry point
			const entryPoint = this.detectEntryPoint();
			if (entryPoint) {
				await this.analyzeFunction(entryPoint, 'entry_point');
			}

			// Analyze functions from exports
			for (const exp of this.exports) {
				if (!exp.isForwarder && exp.address > 0 && !this.functions.has(exp.address)) {
					await this.analyzeFunction(exp.address, exp.name);
				}
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
	 * Full analysis: entry point + exports + prolog scan + re-analyze empty functions
	 */
	async analyzeAll(): Promise<number> {
		if (!this.fileBuffer) {
			return 0;
		}

		const countBefore = this.functions.size;

		// Scan for function prologs in code sections
		await this.scanForFunctionPrologs();

		// Re-analyze functions that ended up with 0 bytes (failed disassembly)
		const emptyFuncs = Array.from(this.functions.values()).filter(f => f.size === 0);
		for (const func of emptyFuncs) {
			// Remove and re-analyze with fresh attempt
			this.functions.delete(func.address);
			try {
				await this.analyzeFunction(func.address, func.name);
			} catch {
				// If still fails, restore the empty entry so we don't lose the name
				if (!this.functions.has(func.address)) {
					this.functions.set(func.address, func);
				}
			}
		}

		// Build string cross-references
		this.buildStringXrefs();

		return this.functions.size - countBefore;
	}

	/**
	 * Detect architecture from file headers
	 */
	private detectArchitecture(): ArchitectureConfig {
		if (!this.fileBuffer) {
			return 'x64';
		}

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

		if (this.isELFFile()) {
			const elfClass = this.fileBuffer[4];
			const isLE = this.fileBuffer[5] === 1;
			const machine = isLE
				? this.fileBuffer.readUInt16LE(18)
				: this.fileBuffer.readUInt16BE(18);
			switch (machine) {
				case 0x03: return elfClass === 2 ? 'x64' : 'x86';
				case 0x3E: return 'x64';
				case 0x28: return 'arm';
				case 0xB7: return 'arm64';
				case 0x08: return 'mips';
			}
		}

		return 'x64';
	}

	async disassembleRange(startAddr: number, size: number): Promise<Instruction[]> {
		await this.ensureCapstoneInitialized();

		const offset = this.addressToOffset(startAddr);
		if (offset < 0 || offset >= this.fileBuffer!.length) {
			return [];
		}

		const endOffset = Math.min(offset + size, this.fileBuffer!.length);
		const bytesToDisasm = this.fileBuffer!.subarray(offset, endOffset);

		if (this.capstoneInitialized) {
			const rawInstructions = await this.capstone.disassemble(bytesToDisasm, startAddr, 1000);
			return rawInstructions.map(inst => this.convertCapstoneInstruction(inst));
		}

		return this.disassembleRangeFallback(startAddr, size);
	}

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

		this.instructions.set(inst.address, instruction);
		return instruction;
	}

	/**
	 * Fallback disassembly for when Capstone is not available.
	 * Supports x86/x64 and basic ARM64/ARM32 decoding.
	 */
	private disassembleRangeFallback(startAddr: number, size: number): Instruction[] {
		const instructions: Instruction[] = [];
		let offset = this.addressToOffset(startAddr);
		let addr = startAddr;
		const endOffset = Math.min(offset + size, this.fileBuffer!.length);
		const isARM64 = this.architecture === 'arm64';
		const isARM32 = this.architecture === 'arm';

		if (isARM64 || isARM32) {
			// ARM: Fixed-width 4-byte instructions
			while (offset + 4 <= endOffset && instructions.length < 1000) {
				const word = this.fileBuffer!.readUInt32LE(offset);
				const bytes = this.fileBuffer!.subarray(offset, offset + 4);
				const inst = isARM64
					? this.decodeARM64Fallback(word, addr, bytes)
					: this.decodeARM32Fallback(word, addr, bytes);
				instructions.push(inst);
				this.instructions.set(addr, inst);
				offset += 4;
				addr += 4;
			}
		} else {
			// x86/x64: Variable-length instructions
			while (offset < endOffset && instructions.length < 1000) {
				const inst = this.disassembleInstructionFallback(offset, addr);
				if (inst) {
					instructions.push(inst);
					this.instructions.set(addr, inst);
					offset += inst.size;
					addr += inst.size;
				} else {
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
		}

		return instructions;
	}

	/**
	 * Basic ARM64 (AArch64) instruction decoder fallback.
	 * Only decodes the most common instructions for function discovery.
	 */
	private decodeARM64Fallback(word: number, addr: number, bytes: Buffer): Instruction {
		// NOP: 0xD503201F
		if (word === 0xD503201F) {
			return this.createInstruction(addr, bytes, 'nop', '', 4, false, false, false, false);
		}

		// RET: 0xD65F03C0 (ret x30)
		if ((word & 0xFFFFFC1F) === 0xD65F0000) {
			const rn = (word >> 5) & 0x1F;
			return this.createInstruction(addr, bytes, 'ret', rn === 30 ? '' : `x${rn}`, 4, false, false, true, false);
		}

		// BL imm26 (call): 1001_01ii_iiii_iiii_iiii_iiii_iiii_iiii
		if ((word & 0xFC000000) === 0x94000000) {
			let imm26 = word & 0x03FFFFFF;
			if (imm26 & 0x02000000) { imm26 |= ~0x03FFFFFF; } // sign extend
			const target = addr + (imm26 << 2);
			return this.createInstruction(addr, bytes, 'bl', `#0x${(target >>> 0).toString(16).toUpperCase()}`, 4, true, false, false, false, target);
		}

		// B imm26 (jump): 0001_01ii_iiii_iiii_iiii_iiii_iiii_iiii
		if ((word & 0xFC000000) === 0x14000000) {
			let imm26 = word & 0x03FFFFFF;
			if (imm26 & 0x02000000) { imm26 |= ~0x03FFFFFF; }
			const target = addr + (imm26 << 2);
			return this.createInstruction(addr, bytes, 'b', `#0x${(target >>> 0).toString(16).toUpperCase()}`, 4, false, true, false, false, target);
		}

		// B.cond imm19: 0101_0100_iiii_iiii_iiii_iiii_iii0_cccc
		if ((word & 0xFF000010) === 0x54000000) {
			const cond = word & 0xF;
			const condNames = ['eq', 'ne', 'hs', 'lo', 'mi', 'pl', 'vs', 'vc', 'hi', 'ls', 'ge', 'lt', 'gt', 'le', 'al', 'nv'];
			let imm19 = (word >> 5) & 0x7FFFF;
			if (imm19 & 0x40000) { imm19 |= ~0x7FFFF; }
			const target = addr + (imm19 << 2);
			return this.createInstruction(addr, bytes, `b.${condNames[cond]}`, `#0x${(target >>> 0).toString(16).toUpperCase()}`, 4, false, true, false, cond !== 14, target);
		}

		// CBZ/CBNZ: x011_010x_iiii_iiii_iiii_iiii_iiit_tttt
		if ((word & 0x7E000000) === 0x34000000) {
			const is64 = (word >> 31) & 1;
			const isNZ = (word >> 24) & 1;
			const rt = word & 0x1F;
			let imm19 = (word >> 5) & 0x7FFFF;
			if (imm19 & 0x40000) { imm19 |= ~0x7FFFF; }
			const target = addr + (imm19 << 2);
			const regPrefix = is64 ? 'x' : 'w';
			return this.createInstruction(addr, bytes, isNZ ? 'cbnz' : 'cbz', `${regPrefix}${rt}, #0x${(target >>> 0).toString(16).toUpperCase()}`, 4, false, true, false, true, target);
		}

		// STP x29, x30, [sp, #imm] — common prolog (any addressing mode)
		if ((word & 0xFC407FFF) === 0xA8007BFD) {
			const imm7 = (word >> 15) & 0x7F;
			const offset = ((imm7 & 0x40) ? (imm7 | ~0x7F) : imm7) * 8;
			return this.createInstruction(addr, bytes, 'stp', `x29, x30, [sp, #${offset}]!`, 4, false, false, false, false);
		}

		// LDP x29, x30, [sp], #imm — common epilog
		if ((word & 0xFFFF83FF) === 0xA8C003FD) {
			const imm7 = (word >> 15) & 0x7F;
			const offset = ((imm7 & 0x40) ? (imm7 | ~0x7F) : imm7) * 8;
			return this.createInstruction(addr, bytes, 'ldp', `x29, x30, [sp], #${offset}`, 4, false, false, false, false);
		}

		// BLR Xn (indirect call): 1101_0110_0011_1111_0000_00nn_nnn0_0000
		if ((word & 0xFFFFFC1F) === 0xD63F0000) {
			const rn = (word >> 5) & 0x1F;
			return this.createInstruction(addr, bytes, 'blr', `x${rn}`, 4, true, false, false, false);
		}

		// BR Xn (indirect jump): 1101_0110_0001_1111_0000_00nn_nnn0_0000
		if ((word & 0xFFFFFC1F) === 0xD61F0000) {
			const rn = (word >> 5) & 0x1F;
			return this.createInstruction(addr, bytes, 'br', `x${rn}`, 4, false, true, false, false);
		}

		// Default: emit as .word
		return this.createInstruction(addr, bytes, '.word', `0x${word.toString(16).padStart(8, '0').toUpperCase()}`, 4, false, false, false, false);
	}

	/**
	 * Basic ARM32 instruction decoder fallback.
	 */
	private decodeARM32Fallback(word: number, addr: number, bytes: Buffer): Instruction {
		const cond = (word >>> 28) & 0xF;

		// NOP: E320F000 or E1A00000 (mov r0, r0)
		if (word === 0xE320F000 || word === 0xE1A00000) {
			return this.createInstruction(addr, bytes, 'nop', '', 4, false, false, false, false);
		}

		// BX LR (return): cond_0001_0010_1111_1111_1111_0001_1110 = xxE12FFF1E
		if ((word & 0x0FFFFFFF) === 0x012FFF1E) {
			return this.createInstruction(addr, bytes, 'bx', 'lr', 4, false, false, true, false);
		}

		// POP {pc} or LDM SP!, {... pc} — also a return
		// LDMIA SP!, {reglist} with bit 15 set (PC): cond_1000_1011_1101_RRRR_RRRR_RRRR_RRRR
		if ((word & 0x0FFF0000) === 0x08BD0000 && (word & (1 << 15)) !== 0) {
			return this.createInstruction(addr, bytes, 'pop', '{..., pc}', 4, false, false, true, false);
		}

		// BL imm24 (call): cond_1011_iiii_iiii_iiii_iiii_iiii_iiii
		if ((word & 0x0F000000) === 0x0B000000) {
			let imm24 = word & 0x00FFFFFF;
			if (imm24 & 0x00800000) { imm24 |= ~0x00FFFFFF; }
			const target = addr + 8 + (imm24 << 2); // ARM32: PC+8 pipeline
			return this.createInstruction(addr, bytes, 'bl', `#0x${(target >>> 0).toString(16).toUpperCase()}`, 4, true, false, false, false, target);
		}

		// B imm24 (jump): cond_1010_iiii_iiii_iiii_iiii_iiii_iiii
		if ((word & 0x0F000000) === 0x0A000000) {
			let imm24 = word & 0x00FFFFFF;
			if (imm24 & 0x00800000) { imm24 |= ~0x00FFFFFF; }
			const target = addr + 8 + (imm24 << 2);
			const isConditional = cond !== 0xE; // 0xE = always
			return this.createInstruction(addr, bytes, 'b', `#0x${(target >>> 0).toString(16).toUpperCase()}`, 4, false, true, false, isConditional, target);
		}

		// PUSH {reglist}: STMDB SP!, {reglist} = cond_1001_0010_1101_RRRR_RRRR_RRRR_RRRR
		if ((word & 0x0FFF0000) === 0x092D0000) {
			return this.createInstruction(addr, bytes, 'push', '{...}', 4, false, false, false, false);
		}

		// Default: emit as .word
		return this.createInstruction(addr, bytes, '.word', `0x${word.toString(16).padStart(8, '0').toUpperCase()}`, 4, false, false, false, false);
	}

	private disassembleInstructionFallback(offset: number, addr: number): Instruction | null {
		if (offset >= this.fileBuffer!.length) {
			return null;
		}

		const byte = this.fileBuffer![offset];

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
				addr, this.fileBuffer!.subarray(offset, offset + 5),
				'call', `0x${target.toString(16).toUpperCase()}`,
				5, true, false, false, false, target
			);
		}

		// JMP rel32
		if (byte === 0xE9 && offset + 5 <= this.fileBuffer!.length) {
			const rel = this.fileBuffer!.readInt32LE(offset + 1);
			const target = addr + 5 + rel;
			return this.createInstruction(
				addr, this.fileBuffer!.subarray(offset, offset + 5),
				'jmp', `0x${target.toString(16).toUpperCase()}`,
				5, false, true, false, false, target
			);
		}

		// JMP rel8
		if (byte === 0xEB && offset + 2 <= this.fileBuffer!.length) {
			const rel = this.fileBuffer!.readInt8(offset + 1);
			const target = addr + 2 + rel;
			return this.createInstruction(
				addr, this.fileBuffer!.subarray(offset, offset + 2),
				'jmp', `0x${target.toString(16).toUpperCase()}`,
				2, false, true, false, false, target
			);
		}

		// PUSH r64 (0x50-0x57)
		if (byte >= 0x50 && byte <= 0x57) {
			const regs = ['rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi'];
			return this.createInstruction(addr, Buffer.from([byte]), 'push', regs[byte - 0x50], 1, false, false, false, false);
		}

		// POP r64 (0x58-0x5F)
		if (byte >= 0x58 && byte <= 0x5F) {
			const regs = ['rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi'];
			return this.createInstruction(addr, Buffer.from([byte]), 'pop', regs[byte - 0x58], 1, false, false, false, false);
		}

		// Conditional jumps (0x70-0x7F)
		if (byte >= 0x70 && byte <= 0x7F && offset + 2 <= this.fileBuffer!.length) {
			const conditions = ['o', 'no', 'b', 'nb', 'z', 'nz', 'be', 'nbe', 's', 'ns', 'p', 'np', 'l', 'nl', 'le', 'nle'];
			const rel = this.fileBuffer!.readInt8(offset + 1);
			const target = addr + 2 + rel;
			return this.createInstruction(
				addr, this.fileBuffer!.subarray(offset, offset + 2),
				`j${conditions[byte - 0x70]}`, `0x${target.toString(16).toUpperCase()}`,
				2, false, true, false, true, target
			);
		}

		// MOV reg, imm (0xB8-0xBF for 32/64-bit)
		if (byte >= 0xB8 && byte <= 0xBF && offset + 5 <= this.fileBuffer!.length) {
			const regs = ['eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi'];
			const imm = this.fileBuffer!.readUInt32LE(offset + 1);
			return this.createInstruction(
				addr, this.fileBuffer!.subarray(offset, offset + 5),
				'mov', `${regs[byte - 0xB8]}, 0x${imm.toString(16).toUpperCase()}`,
				5, false, false, false, false
			);
		}

		// SUB RSP, imm8 (0x48 0x83 0xEC imm8) - common x64 prolog
		if (byte === 0x48 && offset + 4 <= this.fileBuffer!.length) {
			const byte2 = this.fileBuffer![offset + 1];
			const byte3 = this.fileBuffer![offset + 2];
			if (byte2 === 0x83 && byte3 === 0xEC) {
				const imm = this.fileBuffer![offset + 3];
				return this.createInstruction(
					addr, this.fileBuffer!.subarray(offset, offset + 4),
					'sub', `rsp, 0x${imm.toString(16).toUpperCase()}`,
					4, false, false, false, false
				);
			}
			// MOV RBP, RSP (0x48 0x89 0xE5)
			if (byte2 === 0x89 && byte3 === 0xE5) {
				return this.createInstruction(
					addr, this.fileBuffer!.subarray(offset, offset + 3),
					'mov', 'rbp, rsp',
					3, false, false, false, false
				);
			}
		}

		// 2-byte conditional jumps (0x0F 0x80-0x8F)
		if (byte === 0x0F && offset + 6 <= this.fileBuffer!.length) {
			const byte2 = this.fileBuffer![offset + 1];
			if (byte2 >= 0x80 && byte2 <= 0x8F) {
				const conditions = ['o', 'no', 'b', 'nb', 'z', 'nz', 'be', 'nbe', 's', 'ns', 'p', 'np', 'l', 'nl', 'le', 'nle'];
				const rel = this.fileBuffer!.readInt32LE(offset + 2);
				const target = addr + 6 + rel;
				return this.createInstruction(
					addr, this.fileBuffer!.subarray(offset, offset + 6),
					`j${conditions[byte2 - 0x80]}`, `0x${target.toString(16).toUpperCase()}`,
					6, false, true, false, true, target
				);
			}
		}

		return null;
	}

	private createInstruction(
		address: number, bytes: Buffer, mnemonic: string, opStr: string, size: number,
		isCall: boolean = false, isJump: boolean = false, isRet: boolean = false,
		isConditional: boolean = false, targetAddress?: number
	): Instruction {
		return { address, bytes, mnemonic, opStr, size, comment: this.comments.get(address), isCall, isJump, isRet, isConditional, targetAddress };
	}

	// ============================================================================
	// String Analysis
	// ============================================================================

	async findStrings(): Promise<void> {
		if (!this.fileBuffer) {
			return;
		}

		// ASCII strings (min 4 chars)
		const asciiPattern = /[\x20-\x7E]{4,}/g;
		const text = this.fileBuffer.toString('binary');
		let match;

		while ((match = asciiPattern.exec(text)) !== null) {
			if (match[0].length <= 16384) {
				const offset = match.index;
				const str = match[0];
				const addr = this.offsetToAddress(offset);
				this.strings.set(addr, { address: addr, string: str, encoding: 'ascii', references: [] });
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
			if (len >= 4 && len <= 512) {
				const str = this.fileBuffer.toString('utf16le', i, i + len * 2);
				const addr = this.offsetToAddress(i);
				if (!this.strings.has(addr)) {
					this.strings.set(addr, { address: addr, string: str, encoding: 'unicode', references: [] });
				}
				i += len * 2;
			}
		}
	}

	/**
	 * Build string cross-references from disassembled instructions
	 */
	private buildStringXrefs(): void {
		const addrRegex = /0x([0-9a-fA-F]+)/g;

		for (const inst of this.instructions.values()) {
			if (!inst.opStr) {
				continue;
			}
			let addrMatch;
			while ((addrMatch = addrRegex.exec(inst.opStr)) !== null) {
				const targetAddr = parseInt(addrMatch[1], 16);
				const strRef = this.strings.get(targetAddr);
				if (strRef) {
					if (!strRef.references.includes(inst.address)) {
						strRef.references.push(inst.address);
					}
					this.xrefs.push({ from: inst.address, to: targetAddr, type: 'string' });
				}
			}
			addrRegex.lastIndex = 0;

			// Data xrefs: any address reference to non-string data
			if (inst.targetAddress && !inst.isCall && !inst.isJump) {
				this.xrefs.push({ from: inst.address, to: inst.targetAddress, type: 'data' });
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
		return this.fileBuffer[0] === 0x4D && this.fileBuffer[1] === 0x5A;
	}

	private isELFFile(): boolean {
		if (!this.fileBuffer || this.fileBuffer.length < 16) {
			return false;
		}
		return this.fileBuffer[0] === 0x7F &&
			this.fileBuffer[1] === 0x45 &&
			this.fileBuffer[2] === 0x4C &&
			this.fileBuffer[3] === 0x46;
	}

	// ============================================================================
	// PE Structure Parsing (inline - no external extension dependency)
	// ============================================================================

	private parsePEStructure(): void {
		if (!this.fileBuffer || this.fileBuffer.length < 64) {
			return;
		}

		const peOffset = this.fileBuffer.readUInt32LE(0x3C);
		if (peOffset + 24 >= this.fileBuffer.length) {
			return;
		}

		// Verify PE signature
		const peSignature = this.fileBuffer.readUInt32LE(peOffset);
		if (peSignature !== 0x00004550) { // "PE\0\0"
			return;
		}

		// COFF Header (20 bytes after signature)
		const coffOffset = peOffset + 4;
		const machine = this.fileBuffer.readUInt16LE(coffOffset);
		const numberOfSections = this.fileBuffer.readUInt16LE(coffOffset + 2);
		const timeDateStamp = this.fileBuffer.readUInt32LE(coffOffset + 4);
		const sizeOfOptionalHeader = this.fileBuffer.readUInt16LE(coffOffset + 16);

		// Optional Header
		const optOffset = coffOffset + 20;
		if (optOffset + 2 >= this.fileBuffer.length) {
			return;
		}
		const magic = this.fileBuffer.readUInt16LE(optOffset);
		const is64 = magic === 0x20B; // PE32+

		let imageBase: number;
		let entryPointRVA: number;
		let sizeOfImage: number;
		let numberOfRvaAndSizes: number;
		let dataDirectoryOffset: number;
		let subsystem: number;

		if (is64) {
			entryPointRVA = this.fileBuffer.readUInt32LE(optOffset + 16);
			imageBase = Number(this.fileBuffer.readBigUInt64LE(optOffset + 24));
			sizeOfImage = this.fileBuffer.readUInt32LE(optOffset + 56);
			subsystem = this.fileBuffer.readUInt16LE(optOffset + 68);
			numberOfRvaAndSizes = this.fileBuffer.readUInt32LE(optOffset + 108);
			dataDirectoryOffset = optOffset + 112;
		} else {
			entryPointRVA = this.fileBuffer.readUInt32LE(optOffset + 16);
			imageBase = this.fileBuffer.readUInt32LE(optOffset + 28);
			sizeOfImage = this.fileBuffer.readUInt32LE(optOffset + 56);
			subsystem = this.fileBuffer.readUInt16LE(optOffset + 68);
			numberOfRvaAndSizes = this.fileBuffer.readUInt32LE(optOffset + 92);
			dataDirectoryOffset = optOffset + 96;
		}

		this.baseAddress = imageBase;

		// Decode subsystem name
		const subsystemNames: Record<number, string> = {
			1: 'Native', 2: 'Windows GUI', 3: 'Windows CUI',
			5: 'OS/2 CUI', 7: 'POSIX CUI', 9: 'Windows CE GUI',
			10: 'EFI Application', 14: 'Xbox'
		};

		this.fileInfo = {
			format: is64 ? 'PE64' : 'PE',
			architecture: this.architecture,
			entryPoint: entryPointRVA + imageBase,
			baseAddress: imageBase,
			imageSize: sizeOfImage,
			timestamp: timeDateStamp > 0 ? new Date(timeDateStamp * 1000) : undefined,
			subsystem: subsystemNames[subsystem] || subsystem.toString()
		};

		// Parse section table
		const sectionTableOffset = optOffset + sizeOfOptionalHeader;
		this.parsePESections(sectionTableOffset, numberOfSections);

		// Parse imports (DataDirectory[1])
		if (numberOfRvaAndSizes > 1) {
			const importDirRVA = this.fileBuffer.readUInt32LE(dataDirectoryOffset + 8);
			const importDirSize = this.fileBuffer.readUInt32LE(dataDirectoryOffset + 12);
			if (importDirRVA > 0 && importDirSize > 0) {
				this.parsePEImports(importDirRVA, is64);
			}
		}

		// Parse exports (DataDirectory[0])
		if (numberOfRvaAndSizes > 0) {
			const exportDirRVA = this.fileBuffer.readUInt32LE(dataDirectoryOffset);
			const exportDirSize = this.fileBuffer.readUInt32LE(dataDirectoryOffset + 4);
			if (exportDirRVA > 0 && exportDirSize > 0) {
				this.parsePEExports(exportDirRVA, exportDirSize);
			}
		}
	}

	private parsePESections(offset: number, count: number): void {
		if (!this.fileBuffer) {
			return;
		}

		for (let i = 0; i < count; i++) {
			const secOffset = offset + i * 40;
			if (secOffset + 40 > this.fileBuffer.length) {
				break;
			}

			// Section name (8 bytes, null-padded)
			let name = '';
			for (let j = 0; j < 8; j++) {
				const ch = this.fileBuffer[secOffset + j];
				if (ch === 0) { break; }
				name += String.fromCharCode(ch);
			}

			const virtualSize = this.fileBuffer.readUInt32LE(secOffset + 8);
			const virtualAddress = this.fileBuffer.readUInt32LE(secOffset + 12);
			const rawSize = this.fileBuffer.readUInt32LE(secOffset + 16);
			const rawAddress = this.fileBuffer.readUInt32LE(secOffset + 20);
			const characteristics = this.fileBuffer.readUInt32LE(secOffset + 36);

			const isReadable = (characteristics & 0x40000000) !== 0;
			const isWritable = (characteristics & 0x80000000) !== 0;
			const isExecutable = (characteristics & 0x20000000) !== 0;
			const isCode = (characteristics & 0x00000020) !== 0;
			const isData = (characteristics & 0x00000040) !== 0;

			let permissions = isReadable ? 'r' : '-';
			permissions += isWritable ? 'w' : '-';
			permissions += isExecutable ? 'x' : '-';

			this.sections.push({
				name,
				virtualAddress: virtualAddress + this.baseAddress,
				virtualSize,
				rawAddress,
				rawSize,
				characteristics,
				permissions,
				isCode,
				isData,
				isReadable,
				isWritable,
				isExecutable
			});
		}
	}

	private parsePEImports(importDirRVA: number, is64: boolean): void {
		if (!this.fileBuffer) {
			return;
		}

		const importDirOffset = this.rvaToFileOffset(importDirRVA);
		if (importDirOffset < 0 || importDirOffset >= this.fileBuffer.length) {
			return;
		}

		// Each IMAGE_IMPORT_DESCRIPTOR is 20 bytes
		let descOffset = importDirOffset;
		for (let i = 0; i < 256; i++) { // Safety limit
			if (descOffset + 20 > this.fileBuffer.length) {
				break;
			}

			const originalFirstThunk = this.fileBuffer.readUInt32LE(descOffset);     // ILT RVA
			const nameRVA = this.fileBuffer.readUInt32LE(descOffset + 12);            // DLL name RVA
			const firstThunk = this.fileBuffer.readUInt32LE(descOffset + 16);         // IAT RVA

			// Null terminator
			if (nameRVA === 0 && firstThunk === 0) {
				break;
			}

			// Read DLL name
			const nameOffset = this.rvaToFileOffset(nameRVA);
			let dllName = '';
			if (nameOffset >= 0 && nameOffset < this.fileBuffer.length) {
				for (let j = nameOffset; j < this.fileBuffer.length && this.fileBuffer[j] !== 0; j++) {
					dllName += String.fromCharCode(this.fileBuffer[j]);
					if (dllName.length > 256) { break; }
				}
			}

			if (dllName.length === 0) {
				descOffset += 20;
				continue;
			}

			// Walk the ILT (or IAT if ILT is zero)
			const thunkRVA = originalFirstThunk > 0 ? originalFirstThunk : firstThunk;
			const functions: ImportFunction[] = [];
			const entrySize = is64 ? 8 : 4;

			let thunkOffset = this.rvaToFileOffset(thunkRVA);
			let iatRVA = firstThunk;

			for (let j = 0; j < 4096; j++) { // Safety limit
				if (thunkOffset < 0 || thunkOffset + entrySize > this.fileBuffer.length) {
					break;
				}

				let entry: number;
				let isOrdinal: boolean;

				if (is64) {
					const val = this.fileBuffer.readBigUInt64LE(thunkOffset);
					if (val === 0n) { break; }
					isOrdinal = (val & 0x8000000000000000n) !== 0n;
					entry = Number(isOrdinal ? (val & 0xFFFFn) : val);
				} else {
					entry = this.fileBuffer.readUInt32LE(thunkOffset);
					if (entry === 0) { break; }
					isOrdinal = (entry & 0x80000000) !== 0;
					if (isOrdinal) {
						entry = entry & 0xFFFF;
					}
				}

				if (isOrdinal) {
					functions.push({
						name: `Ordinal_${entry}`,
						ordinal: entry,
						address: iatRVA + this.baseAddress,
						hint: 0
					});
				} else {
					// Name import: entry is RVA to IMAGE_IMPORT_BY_NAME (hint + name)
					const nameEntryOffset = this.rvaToFileOffset(entry);
					if (nameEntryOffset >= 0 && nameEntryOffset + 2 < this.fileBuffer.length) {
						const hint = this.fileBuffer.readUInt16LE(nameEntryOffset);
						let funcName = '';
						for (let k = nameEntryOffset + 2; k < this.fileBuffer.length && this.fileBuffer[k] !== 0; k++) {
							funcName += String.fromCharCode(this.fileBuffer[k]);
							if (funcName.length > 256) { break; }
						}
						functions.push({
							name: funcName || `Unknown_${j}`,
							ordinal: undefined,
							address: iatRVA + this.baseAddress,
							hint
						});
					}
				}

				thunkOffset += entrySize;
				iatRVA += entrySize;
			}

			if (functions.length > 0) {
				this.imports.push({ name: dllName, functions });
			}

			descOffset += 20;
		}
	}

	private parsePEExports(exportDirRVA: number, exportDirSize: number): void {
		if (!this.fileBuffer) {
			return;
		}

		const exportOffset = this.rvaToFileOffset(exportDirRVA);
		if (exportOffset < 0 || exportOffset + 40 > this.fileBuffer.length) {
			return;
		}

		const numberOfFunctions = this.fileBuffer.readUInt32LE(exportOffset + 20);
		const numberOfNames = this.fileBuffer.readUInt32LE(exportOffset + 24);
		const addressOfFunctions = this.fileBuffer.readUInt32LE(exportOffset + 28);   // RVA
		const addressOfNames = this.fileBuffer.readUInt32LE(exportOffset + 32);       // RVA
		const addressOfOrdinals = this.fileBuffer.readUInt32LE(exportOffset + 36);    // RVA
		const ordinalBase = this.fileBuffer.readUInt32LE(exportOffset + 16);

		// Sanity check: corrupt export table (e.g. LARA.dll has numFuncs=281000)
		// Max reasonable: 16384 exports. Also validate against file size.
		const maxReasonableExports = 16384;
		if (numberOfFunctions > maxReasonableExports || numberOfNames > maxReasonableExports) {
			console.warn(`Export table looks corrupt: numFuncs=${numberOfFunctions}, numNames=${numberOfNames} - skipping`);
			return;
		}
		if (numberOfNames > numberOfFunctions) {
			console.warn(`Export table invalid: numNames(${numberOfNames}) > numFuncs(${numberOfFunctions}) - skipping`);
			return;
		}

		const funcTableOffset = this.rvaToFileOffset(addressOfFunctions);
		const nameTableOffset = this.rvaToFileOffset(addressOfNames);
		const ordTableOffset = this.rvaToFileOffset(addressOfOrdinals);

		if (funcTableOffset < 0 || nameTableOffset < 0 || ordTableOffset < 0) {
			return;
		}

		// Validate table offsets are within file bounds
		if (funcTableOffset + numberOfFunctions * 4 > this.fileBuffer.length ||
			nameTableOffset + numberOfNames * 4 > this.fileBuffer.length ||
			ordTableOffset + numberOfNames * 2 > this.fileBuffer.length) {
			console.warn('Export table extends beyond file bounds - skipping');
			return;
		}

		// Build name → ordinal mapping
		const nameMap = new Map<number, string>();
		for (let i = 0; i < numberOfNames && i < 4096; i++) {
			const nameRVAOff = nameTableOffset + i * 4;
			const ordOff = ordTableOffset + i * 2;
			if (nameRVAOff + 4 > this.fileBuffer.length || ordOff + 2 > this.fileBuffer.length) {
				break;
			}

			const nameRVA = this.fileBuffer.readUInt32LE(nameRVAOff);
			const ordinal = this.fileBuffer.readUInt16LE(ordOff);

			const nameFileOffset = this.rvaToFileOffset(nameRVA);
			if (nameFileOffset >= 0 && nameFileOffset < this.fileBuffer.length) {
				let name = '';
				for (let j = nameFileOffset; j < this.fileBuffer.length && this.fileBuffer[j] !== 0; j++) {
					name += String.fromCharCode(this.fileBuffer[j]);
					if (name.length > 256) { break; }
				}
				nameMap.set(ordinal, name);
			}
		}

		// Build export entries
		for (let i = 0; i < numberOfFunctions && i < 4096; i++) {
			const funcRVAOff = funcTableOffset + i * 4;
			if (funcRVAOff + 4 > this.fileBuffer.length) {
				break;
			}

			const funcRVA = this.fileBuffer.readUInt32LE(funcRVAOff);
			if (funcRVA === 0) {
				continue;
			}

			// Check if forwarder (RVA falls within export directory)
			const isForwarder = funcRVA >= exportDirRVA && funcRVA < exportDirRVA + exportDirSize;
			let forwarderName: string | undefined;

			if (isForwarder) {
				const fwdOffset = this.rvaToFileOffset(funcRVA);
				if (fwdOffset >= 0 && fwdOffset < this.fileBuffer.length) {
					forwarderName = '';
					for (let j = fwdOffset; j < this.fileBuffer.length && this.fileBuffer[j] !== 0; j++) {
						forwarderName += String.fromCharCode(this.fileBuffer[j]);
						if (forwarderName.length > 256) { break; }
					}
				}
			}

			const name = nameMap.get(i) || '';
			this.exports.push({
				name: name || `Ordinal_${i + ordinalBase}`,
				ordinal: i + ordinalBase,
				address: isForwarder ? 0 : funcRVA + this.baseAddress,
				isForwarder,
				forwarderName
			});
		}
	}

	// ============================================================================
	// ELF Structure Parsing
	// ============================================================================

	private parseELFStructure(): void {
		if (!this.fileBuffer) {
			return;
		}

		const is64Bit = this.fileBuffer[4] === 2;
		const isLittleEndian = this.fileBuffer[5] === 1;

		// Helper for endian-aware reads
		const readU16 = (off: number): number =>
			isLittleEndian ? this.fileBuffer!.readUInt16LE(off) : this.fileBuffer!.readUInt16BE(off);
		const readU32 = (off: number): number =>
			isLittleEndian ? this.fileBuffer!.readUInt32LE(off) : this.fileBuffer!.readUInt32BE(off);
		const readU64 = (off: number): bigint =>
			isLittleEndian ? this.fileBuffer!.readBigUInt64LE(off) : this.fileBuffer!.readBigUInt64BE(off);
		const readAddr = (off: number): number =>
			is64Bit ? Number(readU64(off)) : readU32(off);

		const entryPoint = readAddr(24);
		const phoff = is64Bit ? Number(readU64(32)) : readU32(28);
		const shoff = is64Bit ? Number(readU64(40)) : readU32(32);
		const phentsize = readU16(is64Bit ? 54 : 42);
		const phnum = readU16(is64Bit ? 56 : 44);
		const shentsize = readU16(is64Bit ? 58 : 46);
		const shnum = readU16(is64Bit ? 60 : 48);
		const shstrndx = readU16(is64Bit ? 62 : 50);

		// Detect ELF type: ET_EXEC=2 (fixed base), ET_DYN=3 (PIE or shared object)
		const eType = readU16(16);
		const isPIE = eType === 3; // ET_DYN - Position Independent Executable

		// Detect base address from first LOAD segment
		let baseAddr = 0x400000;
		if (phoff > 0 && phnum > 0) {
			// First pass: find lowest LOAD segment vaddr to detect PIE
			let lowestVaddr = Number.MAX_SAFE_INTEGER;
			for (let i = 0; i < phnum; i++) {
				const phOff = phoff + i * phentsize;
				if (phOff + phentsize > this.fileBuffer.length) { break; }
				const pType = readU32(phOff);
				if (pType === 1) { // PT_LOAD
					const pVaddr = is64Bit ? Number(readU64(phOff + 16)) : readU32(phOff + 8);
					if (pVaddr < lowestVaddr) {
						lowestVaddr = pVaddr;
					}
				}
			}

			if (lowestVaddr !== Number.MAX_SAFE_INTEGER) {
				if (isPIE && lowestVaddr === 0) {
					// PIE binary: virtual addresses start at 0, use conventional base
					// Linux kernel typically loads PIE at 0x555555554000 for x64, 0x56555000 for x86
					baseAddr = is64Bit ? 0x555555554000 : 0x56555000;
				} else if (lowestVaddr > 0) {
					baseAddr = lowestVaddr;
				}
				// If lowestVaddr is 0 and NOT PIE, keep default 0x400000
			}
		}
		this.baseAddress = baseAddr;

		// For PIE binaries, adjust entry point by adding the chosen base address
		const adjustedEntryPoint = (isPIE && entryPoint < this.baseAddress) ? entryPoint + this.baseAddress : entryPoint;

		this.fileInfo = {
			format: is64Bit ? 'ELF64' : 'ELF32',
			architecture: this.architecture,
			entryPoint: adjustedEntryPoint,
			baseAddress: this.baseAddress,
			imageSize: this.fileBuffer.length,
			characteristics: isPIE ? ['ELF', 'PIE'] : ['ELF']
		};

		// Parse section headers - collect raw info for symbol parsing
		interface ElfSection {
			name: string;
			type: number;
			flags: number;
			addr: number;
			offset: number;
			size: number;
			link: number;
			entsize: number;
		}
		const elfSections: ElfSection[] = [];

		if (shoff > 0 && shnum > 0 && shstrndx < shnum) {
			// Get section name string table
			const shstrtabOff = shoff + shstrndx * shentsize;
			const shstrtabFileOff = is64Bit
				? Number(readU64(shstrtabOff + 24))
				: readU32(shstrtabOff + 16);

			for (let i = 0; i < shnum; i++) {
				const secOff = shoff + i * shentsize;
				if (secOff + shentsize > this.fileBuffer.length) {
					break;
				}

				const nameIdx = readU32(secOff);
				const type = readU32(secOff + 4);
				const flags = is64Bit ? Number(readU64(secOff + 8)) : readU32(secOff + 8);
				const addr = is64Bit ? Number(readU64(secOff + 16)) : readU32(secOff + 12);
				const offset = is64Bit ? Number(readU64(secOff + 24)) : readU32(secOff + 16);
				const size = is64Bit ? Number(readU64(secOff + 32)) : readU32(secOff + 20);
				const link = readU32(is64Bit ? secOff + 40 : secOff + 24);
				const entsize = is64Bit ? Number(readU64(secOff + 56)) : readU32(secOff + 36);

				// Read section name
				let name = '';
				if (shstrtabFileOff + nameIdx < this.fileBuffer.length) {
					for (let j = shstrtabFileOff + nameIdx; j < this.fileBuffer.length && this.fileBuffer[j] !== 0; j++) {
						name += String.fromCharCode(this.fileBuffer[j]);
					}
				}
				if (name.length === 0) {
					name = `section_${i}`;
				}

				// For PIE: adjust section addresses by adding base
				const adjustedAddr = (isPIE && addr > 0 && addr < this.baseAddress) ? addr + this.baseAddress : addr;

				elfSections.push({ name, type, flags, addr: adjustedAddr, offset, size, link, entsize });

				const isWritable = (flags & 0x1) !== 0;
				const isAlloc = (flags & 0x2) !== 0;
				const isExecutable = (flags & 0x4) !== 0;

				if (!isAlloc && type !== 1) {
					continue;
				}

				let permissions = 'r';
				permissions += isWritable ? 'w' : '-';
				permissions += isExecutable ? 'x' : '-';

				this.sections.push({
					name,
					virtualAddress: adjustedAddr,
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

		// Parse symbol tables (SHT_SYMTAB=2 and SHT_DYNSYM=11)
		for (const sec of elfSections) {
			if (sec.type !== 2 && sec.type !== 11) {
				continue;
			}
			if (sec.entsize === 0 || sec.size === 0) {
				continue;
			}

			// Get associated string table
			const strTabSec = elfSections[sec.link];
			if (!strTabSec) {
				continue;
			}

			const symCount = Math.floor(sec.size / sec.entsize);
			const isDynSym = sec.type === 11;

			for (let i = 0; i < symCount && i < 8192; i++) {
				const symOff = sec.offset + i * sec.entsize;
				if (symOff + sec.entsize > this.fileBuffer.length) {
					break;
				}

				let stName: number, stInfo: number, stShndx: number, stValue: number, stSize: number;

				if (is64Bit) {
					stName = readU32(symOff);
					stInfo = this.fileBuffer[symOff + 4];
					stShndx = readU16(symOff + 6);
					stValue = Number(readU64(symOff + 8));
					stSize = Number(readU64(symOff + 16));
				} else {
					stName = readU32(symOff);
					stValue = readU32(symOff + 4);
					stSize = readU32(symOff + 8);
					stInfo = this.fileBuffer[symOff + 12];
					stShndx = readU16(symOff + 14);
				}

				const stBind = stInfo >> 4;   // STB_LOCAL=0, STB_GLOBAL=1, STB_WEAK=2
				const stType = stInfo & 0xF;  // STT_FUNC=2, STT_OBJECT=1

				// Read symbol name
				let symName = '';
				const nameOff = strTabSec.offset + stName;
				if (nameOff < this.fileBuffer.length) {
					for (let j = nameOff; j < this.fileBuffer.length && this.fileBuffer[j] !== 0; j++) {
						symName += String.fromCharCode(this.fileBuffer[j]);
						if (symName.length > 256) { break; }
					}
				}

				if (symName.length === 0) {
					continue;
				}

				const SHN_UNDEF = 0;
				const isUndefined = stShndx === SHN_UNDEF;

				if (isUndefined && (stBind === 1 || stBind === 2)) {
					// Import: undefined global/weak symbol
					// Group by library name (use "external" as fallback since ELF doesn't specify per-symbol)
					let libEntry = this.imports.find(lib => lib.name === 'external');
					if (!libEntry) {
						libEntry = { name: 'external', functions: [] };
						this.imports.push(libEntry);
					}
					libEntry.functions.push({
						name: symName,
						ordinal: i,
						address: stValue || 0,
						hint: 0
					});
				} else if (!isUndefined && (stBind === 1 || stBind === 2) && stType === 2) {
					// Export: defined global/weak function symbol
					const adjustedSymAddr = (isPIE && stValue > 0 && stValue < this.baseAddress) ? stValue + this.baseAddress : stValue;
					this.exports.push({
						name: symName,
						ordinal: i,
						address: adjustedSymAddr,
						isForwarder: false
					});
				}
			}
		}

		// Parse .dynamic section for NEEDED entries (shared library names)
		for (const sec of elfSections) {
			if (sec.type !== 6) { // SHT_DYNAMIC
				continue;
			}

			const dynStrSec = elfSections[sec.link];
			if (!dynStrSec) {
				continue;
			}

			const entrySize = is64Bit ? 16 : 8;
			const numEntries = Math.floor(sec.size / entrySize);

			for (let i = 0; i < numEntries; i++) {
				const entOff = sec.offset + i * entrySize;
				if (entOff + entrySize > this.fileBuffer.length) {
					break;
				}

				const dTag = is64Bit ? Number(readU64(entOff)) : readU32(entOff);
				const dVal = is64Bit ? Number(readU64(entOff + 8)) : readU32(entOff + 4);

				if (dTag === 0) { break; } // DT_NULL
				if (dTag === 1) { // DT_NEEDED
					let libName = '';
					const nameOff = dynStrSec.offset + dVal;
					if (nameOff < this.fileBuffer.length) {
						for (let j = nameOff; j < this.fileBuffer.length && this.fileBuffer[j] !== 0; j++) {
							libName += String.fromCharCode(this.fileBuffer[j]);
							if (libName.length > 256) { break; }
						}
					}
					// Re-group import symbols under their actual library name
					if (libName) {
						const existing = this.imports.find(lib => lib.name === libName);
						if (!existing) {
							this.imports.push({ name: libName, functions: [] });
						}
					}
				}
			}
		}

		// Parse PLT section to get actual call addresses for imports
		// PLT entries are small stubs that indirect through GOT
		const pltSection = elfSections.find(s => s.name === '.plt' || s.name === '.plt.got' || s.name === '.plt.sec');
		if (pltSection && pltSection.addr > 0) {
			// Parse .rela.plt to map GOT slots to symbol names
			const relaPlt = elfSections.find(s => s.name === '.rela.plt' || s.name === '.rel.plt');
			const dynsymSec = elfSections.find(s => s.type === 11); // SHT_DYNSYM
			const dynstrSec = dynsymSec ? elfSections[dynsymSec.link] : undefined;

			if (relaPlt && dynsymSec && dynstrSec) {
				const isRela = relaPlt.name.startsWith('.rela');
				const relEntSize = isRela ? (is64Bit ? 24 : 12) : (is64Bit ? 16 : 8);
				const numRel = relEntSize > 0 ? Math.floor(relaPlt.size / relEntSize) : 0;

				for (let i = 0; i < numRel && i < 4096; i++) {
					const relOff = relaPlt.offset + i * relEntSize;
					if (relOff + relEntSize > this.fileBuffer.length) { break; }

					const rOffset = is64Bit ? Number(readU64(relOff)) : readU32(relOff);
					const rInfo = is64Bit ? Number(readU64(relOff + 8)) : readU32(relOff + 4);

					// Extract symbol index from r_info
					const symIdx = is64Bit ? (rInfo >> 32) : (rInfo >> 8);

					// Read symbol name from .dynsym
					const symEntSize = is64Bit ? 24 : 16;
					const symOff = dynsymSec.offset + symIdx * symEntSize;
					if (symOff + symEntSize > this.fileBuffer.length) { continue; }

					const stName = readU32(symOff);
					let symName = '';
					const symNameOff = dynstrSec.offset + stName;
					if (symNameOff < this.fileBuffer.length) {
						for (let j = symNameOff; j < this.fileBuffer.length && this.fileBuffer[j] !== 0; j++) {
							symName += String.fromCharCode(this.fileBuffer[j]);
							if (symName.length > 256) { break; }
						}
					}

					if (symName.length === 0) { continue; }

					// PLT entry address: PLT base + (i+1) * PLT entry size (first entry is stub)
					// Standard PLT entry size is 16 bytes on x86-64
					const pltEntrySize = is64Bit ? 16 : 16;
					const pltAddr = pltSection.addr + (i + 1) * pltEntrySize;

					// Adjust for PIE
					const adjustedPltAddr = (isPIE && pltAddr > 0 && pltAddr < this.baseAddress) ? pltAddr + this.baseAddress : pltAddr;
					const adjustedGotAddr = (isPIE && rOffset > 0 && rOffset < this.baseAddress) ? rOffset + this.baseAddress : rOffset;

					// Update import entries with PLT addresses
					for (const lib of this.imports) {
						const func = lib.functions.find(f => f.name === symName);
						if (func) {
							func.address = adjustedPltAddr;
							break;
						}
					}
				}
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

		for (const section of this.sections) {
			const sectionRVA = section.virtualAddress - this.baseAddress;
			if (rva >= sectionRVA && rva < sectionRVA + section.virtualSize) {
				return section.rawAddress + (rva - sectionRVA);
			}
		}

		return rva;
	}

	// ============================================================================
	// Function Analysis
	// ============================================================================

	async analyzeFunction(address: number, name?: string): Promise<Function> {
		const existing = this.functions.get(address);
		if (existing) {
			return existing;
		}

		const instructions = await this.disassembleRange(address, this.maxFunctionSize);

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

		// Find function end - handle multiple RETs, look for the last one followed by
		// padding or another function prolog. Architecture-aware detection.
		const isARM = this.architecture === 'arm64' || this.architecture === 'arm';

		let endIdx = instructions.length;
		let lastRetIdx = -1;
		for (let i = 0; i < instructions.length; i++) {
			if (instructions[i].isRet) {
				lastRetIdx = i;
				// Check if next instruction is padding or unreachable
				if (i + 1 < instructions.length) {
					const next = instructions[i + 1];

					if (isARM) {
						// ARM/ARM64: Check if next instruction is a new function prolog or padding
						if (next.bytes.length >= 4) {
							const nextWord = next.bytes.readUInt32LE(0);
							const isARM64Prolog =
								(nextWord & 0xFC407FFF) === 0xA8007BFD ||  // STP x29, x30, [sp, #off]
								nextWord === 0xD503233F ||                  // PACIASP
								((nextWord & 0xFF0003FF) === 0xD10003FF && ((nextWord >> 5) & 0x1F) === 31); // SUB SP, SP, #N
							const isARM32Prolog =
								(nextWord & 0xFFFF0000) === 0xE92D0000 && (nextWord & (1 << 14)) !== 0; // PUSH {..., lr}
							const isNop =
								nextWord === 0xD503201F ||  // ARM64 NOP
								nextWord === 0xE320F000 ||  // ARM32 NOP (mov r0, r0)
								nextWord === 0xE1A00000;    // ARM32 NOP (mov r0, r0 alt)
							const isUDF = (nextWord & 0xFFFF0000) === 0x00000000; // UDF (undefined) as padding

							if (isARM64Prolog || isARM32Prolog || isNop || isUDF) {
								endIdx = i + 1;
								break;
							}
						}
					} else {
						// x86/x64: INT3 (0xCC), NOP (0x90), or push rbp (0x55)
						const nextByte = next.bytes[0];
						if (nextByte === 0xCC || nextByte === 0x90 || nextByte === 0x55) {
							endIdx = i + 1;
							break;
						}
					}

					// If next instruction is a jump target from within the function, continue
					const isJumpTarget = instructions.slice(0, i).some(
						inst => inst.targetAddress === next.address
					);
					if (!isJumpTarget) {
						endIdx = i + 1;
						break;
					}
					// Otherwise continue (this RET is in a branch, not the end)
				} else {
					endIdx = i + 1;
					break;
				}
			}
			if (instructions[i].isJump && !instructions[i].isConditional) {
				if (instructions[i].targetAddress &&
					(instructions[i].targetAddress! < address ||
						instructions[i].targetAddress! > address + this.maxFunctionSize)) {
					// Check if there are more reachable instructions after
					if (i + 1 < instructions.length) {
						const nextIsTarget = instructions.slice(0, i).some(
							inst => inst.targetAddress === instructions[i + 1].address
						);
						if (!nextIsTarget) {
							endIdx = i + 1;
							break;
						}
					} else {
						endIdx = i + 1;
						break;
					}
				}
			}
		}

		// If we never found a clear end, use last RET if found
		if (endIdx === instructions.length && lastRetIdx >= 0) {
			endIdx = lastRetIdx + 1;
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

		// Collect child targets for analysis (calls + trampoline jumps)
		const childTargets: number[] = [];

		for (const inst of funcInstructions) {
			if (inst.isCall && inst.targetAddress && this.functions.size < this.maxFunctions) {
				func.callees.push(inst.targetAddress);
				this.xrefs.push({ from: inst.address, to: inst.targetAddress, type: 'call' });

				// Track caller in target function
				const target = this.functions.get(inst.targetAddress);
				if (target) {
					if (!target.callers.includes(inst.address)) {
						target.callers.push(inst.address);
					}
				}

				if (!this.functions.has(inst.targetAddress)) {
					childTargets.push(inst.targetAddress);
				}
			}

			// Record jump xrefs and follow unconditional jump targets as new functions
			if (inst.isJump && inst.targetAddress) {
				this.xrefs.push({ from: inst.address, to: inst.targetAddress, type: 'jump' });

				// Follow unconditional jumps whose targets are outside this function
				// (trampolines, tail calls, thunks) — treat target as a new function
				if (!inst.isConditional &&
					inst.targetAddress !== address &&
					!this.functions.has(inst.targetAddress) &&
					this.functions.size < this.maxFunctions) {
					childTargets.push(inst.targetAddress);
				}
			}
		}

		// Await child analysis to avoid race conditions with floating promises
		for (const target of childTargets) {
			if (!this.functions.has(target) && this.functions.size < this.maxFunctions) {
				await this.analyzeFunction(target);
			}
		}

		return func;
	}

	/**
	 * Scan code sections for function prologs.
	 * Supports x86/x64 and ARM64/ARM32 prolog patterns.
	 */
	private async scanForFunctionPrologs(): Promise<void> {
		if (!this.fileBuffer) {
			return;
		}

		const isARM64 = this.architecture === 'arm64';
		const isARM32 = this.architecture === 'arm';

		for (const section of this.sections) {
			if (!section.isCode && !section.isExecutable) {
				continue;
			}

			const secOffset = section.rawAddress;
			const secEnd = secOffset + section.rawSize;

			if (isARM64) {
				// ARM64: Fixed-width 4-byte instructions, must be 4-byte aligned
				for (let off = secOffset; off < secEnd - 4 && this.functions.size < this.maxFunctions; off += 4) {
					if (off + 4 > this.fileBuffer.length) { break; }
					const word = this.fileBuffer.readUInt32LE(off);

					// Pattern 1: STP X29, X30, [SP, #imm] (any addressing mode)
					// Encoding: 10 101 0 0mm iiiiiii 11110 11111 11101
					// mm = addressing mode (01=signed-offset, 10=post-index, 11=pre-index)
					// Check: opc=10, fixed=101, V=0, L=0(store), Rt2=30, Rn=31(SP), Rt=29
					// Mask out: mode bits[25:23], imm7 bits[21:15]
					// Mask: 0xFC407FFF  Value: 0xA8007BFD
					if ((word & 0xFC407FFF) === 0xA8007BFD) {
						// STP x29, x30, [sp, #off] — classic ARM64 prolog
						const addr = this.sectionOffsetToAddress(off, section);
						if (addr > 0 && !this.functions.has(addr)) {
							await this.analyzeFunction(addr);
						}
						continue;
					}

					// Pattern 2: SUB SP, SP, #imm (frame setup without STP)
					// Encoding: 1101_0001_00ii_iiii_iiii_ii11_111x_xxxx
					// Check: bits[31]=1(64-bit), [30]=1(SUB), [29]=0, [28:24]=10001, Rn=SP(31), Rd=SP(31)
					if ((word & 0xFF0003FF) === 0xD10003FF && ((word >> 5) & 0x1F) === 31) {
						const addr = this.sectionOffsetToAddress(off, section);
						if (addr > 0 && !this.functions.has(addr)) {
							await this.analyzeFunction(addr);
						}
						continue;
					}

					// Pattern 3: PACIASP (pointer auth prolog, common in hardened ARM64)
					// Encoding: 0xD503233F
					if (word === 0xD503233F) {
						const addr = this.sectionOffsetToAddress(off, section);
						if (addr > 0 && !this.functions.has(addr)) {
							await this.analyzeFunction(addr);
						}
						continue;
					}
				}
			} else if (isARM32) {
				// ARM32: Fixed-width 4-byte instructions
				for (let off = secOffset; off < secEnd - 4 && this.functions.size < this.maxFunctions; off += 4) {
					if (off + 4 > this.fileBuffer.length) { break; }
					const word = this.fileBuffer.readUInt32LE(off);

					// Pattern 1: PUSH {fp, lr} or PUSH {r4-r11, lr} — STMDB SP!, {...}
					// ARM32 PUSH is STMDB SP! with cond=1110(always)
					// Encoding: 1110_1001_0010_1101_RRRR_RRRR_RRRR_RRRR
					// Mask: 0xFFFF0000 = 0xE92D, reglist includes LR(bit14)
					if ((word & 0xFFFF0000) === 0xE92D0000 && (word & (1 << 14)) !== 0) {
						const addr = this.sectionOffsetToAddress(off, section);
						if (addr > 0 && !this.functions.has(addr)) {
							await this.analyzeFunction(addr);
						}
						continue;
					}

					// Pattern 2: PUSH {r11, lr} — short form: 0xE52DE004 style or STR LR, [SP, #-4]!
					// Simpler check: MOV R11, SP (0xE1A0B00D) often follows PUSH
					if ((word & 0xFFFFF000) === 0xE52DE000) {
						// STR LR, [SP, #-imm]!
						const addr = this.sectionOffsetToAddress(off, section);
						if (addr > 0 && !this.functions.has(addr)) {
							await this.analyzeFunction(addr);
						}
						continue;
					}
				}
			} else {
				// x86/x64: Variable-length instructions
				for (let off = secOffset; off < secEnd - 4 && this.functions.size < this.maxFunctions; off++) {
					const byte = this.fileBuffer[off];

					// x64: push rbp (0x55) followed by mov rbp, rsp (0x48 0x89 0xE5)
					if (byte === 0x55 && off + 3 < secEnd) {
						if (this.fileBuffer[off + 1] === 0x48 &&
							this.fileBuffer[off + 2] === 0x89 &&
							this.fileBuffer[off + 3] === 0xE5) {
							const addr = this.sectionOffsetToAddress(off, section);
							if (addr > 0 && !this.functions.has(addr)) {
								await this.analyzeFunction(addr);
							}
							continue;
						}
						// x86: push ebp (0x55) followed by mov ebp, esp (0x89 0xE5)
						if (this.fileBuffer[off + 1] === 0x89 &&
							this.fileBuffer[off + 2] === 0xE5) {
							const addr = this.sectionOffsetToAddress(off, section);
							if (addr > 0 && !this.functions.has(addr)) {
								await this.analyzeFunction(addr);
							}
							continue;
						}
					}

					// x64: sub rsp, imm8 (0x48 0x83 0xEC imm8) - frameless function
					if (byte === 0x48 && off + 3 < secEnd) {
						if (this.fileBuffer[off + 1] === 0x83 &&
							this.fileBuffer[off + 2] === 0xEC) {
							const addr = this.sectionOffsetToAddress(off, section);
							if (addr > 0 && !this.functions.has(addr)) {
								await this.analyzeFunction(addr);
							}
						}
					}
				}
			}
		}
	}

	private sectionOffsetToAddress(fileOffset: number, section: Section): number {
		return section.virtualAddress + (fileOffset - section.rawAddress);
	}

	// ============================================================================
	// Getters
	// ============================================================================

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

	/**
	 * Returns true when a file has been loaded into the engine.
	 */
	isFileLoaded(): boolean {
		return this.fileBuffer !== undefined && this.fileBuffer.length > 0;
	}

	/**
	 * Returns the size of the loaded file buffer in bytes, or 0 if no file is loaded.
	 */
	getBufferSize(): number {
		return this.fileBuffer?.length ?? 0;
	}

	/**
	 * Extract raw bytes from the loaded file at the given virtual address.
	 * Returns undefined if no file is loaded or the address is out of bounds.
	 */
	getBytes(address: number, size: number): Buffer | undefined {
		if (!this.fileBuffer) {
			return undefined;
		}
		const offset = this.addressToOffset(address);
		if (offset < 0 || offset >= this.fileBuffer.length) {
			return undefined;
		}
		const end = Math.min(offset + size, this.fileBuffer.length);
		return this.fileBuffer.subarray(offset, end);
	}

	private addressToOffset(address: number): number {
		const rva = address - this.baseAddress;

		if (this.isPEFile() && this.fileBuffer) {
			return this.rvaToFileOffset(rva);
		}

		// For ELF, use section mapping
		if (this.isELFFile()) {
			for (const section of this.sections) {
				if (address >= section.virtualAddress &&
					address < section.virtualAddress + section.virtualSize) {
					return section.rawAddress + (address - section.virtualAddress);
				}
			}
		}

		return rva;
	}

	private offsetToAddress(offset: number): number {
		// For PE/ELF, try section-based mapping
		for (const section of this.sections) {
			if (offset >= section.rawAddress && offset < section.rawAddress + section.rawSize) {
				return section.virtualAddress + (offset - section.rawAddress);
			}
		}
		return offset + this.baseAddress;
	}

	private detectBaseAddress(): number {
		if (this.fileInfo) {
			return this.fileInfo.baseAddress;
		}
		if (this.isPEFile()) {
			return 0x400000;
		}
		return 0x400000;
	}

	private detectEntryPoint(): number | undefined {
		if (this.fileInfo) {
			return this.fileInfo.entryPoint;
		}

		if (this.isELFFile() && this.fileBuffer) {
			const is64Bit = this.fileBuffer[4] === 2;
			const isLE = this.fileBuffer[5] === 1;
			if (is64Bit) {
				return Number(isLE ? this.fileBuffer.readBigUInt64LE(24) : this.fileBuffer.readBigUInt64BE(24));
			} else {
				return isLE ? this.fileBuffer.readUInt32LE(24) : this.fileBuffer.readUInt32BE(24);
			}
		}

		return this.baseAddress;
	}

	// ============================================================================
	// Assembly & Patching (LLVM MC)
	// ============================================================================

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

	async assemble(code: string, address?: number): Promise<AssembleResult> {
		await this.ensureLlvmMcInitialized();
		if (!this.llvmMcInitialized) {
			return { success: false, bytes: Buffer.alloc(0), size: 0, statement: code, error: this.llvmMcError ?? 'LLVM MC not available' };
		}
		return this.llvmMc.assemble(code, address ? BigInt(address) : undefined);
	}

	async assembleMultiple(instructions: string[], startAddress?: number): Promise<AssembleResult[]> {
		await this.ensureLlvmMcInitialized();
		if (!this.llvmMcInitialized) {
			return instructions.map(code => ({
				success: false, bytes: Buffer.alloc(0), size: 0, statement: code,
				error: this.llvmMcError ?? 'LLVM MC not available'
			}));
		}
		return this.llvmMc.assembleMultiple(instructions, startAddress ? BigInt(startAddress) : undefined);
	}

	async patchInstruction(address: number, newInstruction: string): Promise<PatchResult> {
		await this.ensureLlvmMcInitialized();
		if (!this.llvmMcInitialized) {
			return { success: false, bytes: Buffer.alloc(0), size: 0, originalSize: 0, nopPadding: 0, error: this.llvmMcError ?? 'LLVM MC not available' };
		}

		let original = this.instructions.get(address);
		if (!original) {
			const disasm = await this.disassembleRange(address, 16);
			if (disasm.length === 0) {
				return { success: false, bytes: Buffer.alloc(0), size: 0, originalSize: 0, nopPadding: 0, error: 'Could not find instruction at address' };
			}
			original = disasm[0];
			this.instructions.set(original.address, original);
		}

		return this.llvmMc.createPatch(newInstruction, original.size, BigInt(address));
	}

	applyPatch(address: number, patchBytes: Buffer): boolean {
		if (!this.fileBuffer) {
			return false;
		}

		const offset = this.addressToOffset(address);
		if (offset < 0 || offset + patchBytes.length > this.fileBuffer.length) {
			return false;
		}

		patchBytes.copy(this.fileBuffer, offset);

		for (let i = 0; i < patchBytes.length; i++) {
			this.instructions.delete(address + i);
		}

		return true;
	}

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

	savePatched(outputPath: string): void {
		if (!this.fileBuffer) {
			throw new Error('No file loaded');
		}
		fs.writeFileSync(outputPath, this.fileBuffer);
	}

	async validateInstruction(code: string): Promise<{ valid: boolean; error?: string }> {
		await this.ensureLlvmMcInitialized();
		if (!this.llvmMcInitialized) {
			return { valid: false, error: this.llvmMcError ?? 'LLVM MC not available' };
		}
		return this.llvmMc.validate(code);
	}

	getNop(): Buffer {
		if (!this.llvmMcInitialized) {
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

	getLlvmVersion(): string {
		if (!this.llvmMcInitialized) {
			return 'not initialized';
		}
		return this.llvmMc.getVersion();
	}

	setAssemblySyntax(syntax: 'intel' | 'att'): void {
		if (this.llvmMcInitialized) {
			this.llvmMc.setSyntax(syntax);
		}
	}

	dispose(): void {
		this.capstone.dispose();
		this.capstoneInitialized = false;
		this.llvmMc.dispose();
		this.llvmMcInitialized = false;
	}
}
