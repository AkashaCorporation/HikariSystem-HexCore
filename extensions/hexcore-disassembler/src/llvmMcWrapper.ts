/*---------------------------------------------------------------------------------------------
 *  HexCore Disassembler - LLVM MC Wrapper
 *  Assembly patching interface using LLVM MC
 *  Copyright (c) HikariSystem. All rights reserved.
 *--------------------------------------------------------------------------------------------*/

import * as path from 'path';

// Types from hexcore-llvm-mc
interface LlvmMcModule {
	LlvmMc: new (triple: string, cpu?: string, features?: string) => LlvmMcInstance;
	TRIPLE: TripleConstants;
	SYNTAX: SyntaxConstants;
	OPTION: OptionConstants;
	version: () => string;
	getTargets: () => TargetInfo[];
}

interface LlvmMcInstance {
	assemble(code: string, address?: bigint | number): AsmResult;
	assembleAsync(code: string, address?: bigint | number): Promise<AsmResult>;
	assembleMultiple(instructions: string[], startAddress?: bigint | number): AsmResult[];
	setOption(option: number, value: number | string): void;
	getTriple(): string;
	getCpu(): string;
	getFeatures(): string;
	close(): void;
	readonly isOpen: boolean;
}

interface AsmResult {
	bytes: Buffer;
	size: number;
	address: bigint;
	statement: string;
}

interface TargetInfo {
	name: string;
	description: string;
}

interface TripleConstants {
	X86: string;
	X86_64: string;
	I386: string;
	ARM: string;
	ARMV7: string;
	ARM64: string;
	AARCH64: string;
	MIPS: string;
	MIPSEL: string;
	MIPS64: string;
	RISCV32: string;
	RISCV64: string;
	THUMB: string;
	THUMBV7: string;
}

interface SyntaxConstants {
	INTEL: number;
	ATT: number;
}

interface OptionConstants {
	SYNTAX: number;
}

// Architecture config type (from disassemblerEngine)
export type ArchitectureConfig = 'x86' | 'x64' | 'arm' | 'arm64' | 'mips' | 'mips64' | 'riscv32' | 'riscv64' | 'thumb';

// Patch result
export interface PatchResult {
	success: boolean;
	bytes: Buffer;
	size: number;
	originalSize: number;
	nopPadding: number;
	error?: string;
}

// Assemble result with validation
export interface AssembleResult {
	success: boolean;
	bytes: Buffer;
	size: number;
	statement: string;
	error?: string;
}

export class LlvmMcWrapper {
	private llvmMcModule?: LlvmMcModule;
	private assembler?: LlvmMcInstance;
	private architecture: ArchitectureConfig = 'x64';
	private syntax: 'intel' | 'att' = 'intel';
	private initialized: boolean = false;

	/**
	 * Initialize the LLVM MC assembler
	 */
	async initialize(arch: ArchitectureConfig): Promise<void> {
		this.architecture = arch;

		// Try to load hexcore-llvm-mc from the extensions folder
		const possiblePaths = [
			path.join(__dirname, '..', '..', 'hexcore-llvm-mc'),
			path.join(__dirname, '..', '..', '..', 'hexcore-llvm-mc'),
			'hexcore-llvm-mc'
		];

		for (const modulePath of possiblePaths) {
			try {
				this.llvmMcModule = require(modulePath) as LlvmMcModule;
				break;
			} catch {
				continue;
			}
		}

		if (!this.llvmMcModule) {
			throw new Error('Failed to load hexcore-llvm-mc module');
		}

		const triple = this.getTriple(arch);
		this.assembler = new this.llvmMcModule.LlvmMc(triple);

		// Set Intel syntax for x86
		if (arch === 'x86' || arch === 'x64') {
			this.assembler.setOption(this.llvmMcModule.OPTION.SYNTAX, this.llvmMcModule.SYNTAX.INTEL);
		}

		this.initialized = true;
		console.log(`LLVM MC initialized: ${arch} (version: ${this.llvmMcModule.version()})`);
	}

	/**
	 * Get target triple for architecture
	 */
	private getTriple(arch: ArchitectureConfig): string {
		const TRIPLE = this.llvmMcModule!.TRIPLE;

		switch (arch) {
			case 'x86': return TRIPLE.I386;
			case 'x64': return TRIPLE.X86_64;
			case 'arm': return TRIPLE.ARM;
			case 'arm64': return TRIPLE.ARM64;
			case 'mips': return TRIPLE.MIPS;
			case 'mips64': return TRIPLE.MIPS64;
			case 'riscv32': return TRIPLE.RISCV32;
			case 'riscv64': return TRIPLE.RISCV64;
			case 'thumb': return TRIPLE.THUMB;
			default: return TRIPLE.X86_64;
		}
	}

	/**
	 * Set assembly syntax (intel/att)
	 */
	setSyntax(syntax: 'intel' | 'att'): void {
		if (!this.assembler || !this.llvmMcModule) return;

		this.syntax = syntax;
		if (this.architecture === 'x86' || this.architecture === 'x64') {
			const syntaxValue = syntax === 'intel'
				? this.llvmMcModule.SYNTAX.INTEL
				: this.llvmMcModule.SYNTAX.ATT;
			this.assembler.setOption(this.llvmMcModule.OPTION.SYNTAX, syntaxValue);
		}
	}

	/**
	 * Assemble a single instruction
	 */
	assemble(code: string, address?: bigint): AssembleResult {
		if (!this.assembler) {
			return { success: false, bytes: Buffer.alloc(0), size: 0, statement: code, error: 'Assembler not initialized' };
		}

		try {
			const result = this.assembler.assemble(code, address);
			return {
				success: true,
				bytes: result.bytes,
				size: result.size,
				statement: result.statement
			};
		} catch (error: any) {
			return {
				success: false,
				bytes: Buffer.alloc(0),
				size: 0,
				statement: code,
				error: error.message
			};
		}
	}

	/**
	 * Assemble multiple instructions
	 */
	assembleMultiple(instructions: string[], startAddress?: bigint): AssembleResult[] {
		if (!this.assembler) {
			return instructions.map(code => ({
				success: false,
				bytes: Buffer.alloc(0),
				size: 0,
				statement: code,
				error: 'Assembler not initialized'
			}));
		}

		try {
			const results = this.assembler.assembleMultiple(instructions, startAddress);
			return results.map(r => ({
				success: true,
				bytes: r.bytes,
				size: r.size,
				statement: r.statement
			}));
		} catch (error: any) {
			return instructions.map(code => ({
				success: false,
				bytes: Buffer.alloc(0),
				size: 0,
				statement: code,
				error: error.message
			}));
		}
	}

	/**
	 * Create a patch for an instruction
	 * Handles size differences by adding NOP padding or errors if too large
	 */
	createPatch(newCode: string, originalSize: number, address?: bigint): PatchResult {
		const result = this.assemble(newCode, address);

		if (!result.success) {
			return {
				success: false,
				bytes: Buffer.alloc(0),
				size: 0,
				originalSize,
				nopPadding: 0,
				error: result.error
			};
		}

		if (result.size > originalSize) {
			return {
				success: false,
				bytes: Buffer.alloc(0),
				size: result.size,
				originalSize,
				nopPadding: 0,
				error: `New instruction (${result.size} bytes) is larger than original (${originalSize} bytes)`
			};
		}

		// Pad with NOPs if smaller
		const nopPadding = originalSize - result.size;
		let patchBytes = result.bytes;

		if (nopPadding > 0) {
			const nopByte = this.getNopByte();
			const padding = Buffer.alloc(nopPadding, nopByte);
			patchBytes = Buffer.concat([result.bytes, padding]);
		}

		return {
			success: true,
			bytes: patchBytes,
			size: result.size,
			originalSize,
			nopPadding
		};
	}

	/**
	 * Get NOP byte for current architecture
	 */
	private getNopByte(): number {
		switch (this.architecture) {
			case 'x86':
			case 'x64':
				return 0x90; // NOP
			case 'arm':
			case 'thumb':
				return 0x00; // ARM has multi-byte NOPs
			case 'arm64':
				return 0x1F; // Part of ARM64 NOP
			default:
				return 0x00;
		}
	}

	/**
	 * Get multi-byte NOP for architecture
	 */
	getNop(): Buffer {
		switch (this.architecture) {
			case 'x86':
			case 'x64':
				return Buffer.from([0x90]); // NOP
			case 'arm':
				return Buffer.from([0x00, 0x00, 0xA0, 0xE1]); // MOV R0, R0 (NOP)
			case 'thumb':
				return Buffer.from([0x00, 0xBF]); // NOP
			case 'arm64':
				return Buffer.from([0x1F, 0x20, 0x03, 0xD5]); // NOP
			case 'mips':
			case 'mips64':
				return Buffer.from([0x00, 0x00, 0x00, 0x00]); // NOP (SLL $0, $0, 0)
			case 'riscv32':
			case 'riscv64':
				return Buffer.from([0x13, 0x00, 0x00, 0x00]); // NOP (ADDI x0, x0, 0)
			default:
				return Buffer.from([0x90]);
		}
	}

	/**
	 * Create NOP sled of specified size
	 */
	createNopSled(size: number): Buffer {
		const nop = this.getNop();
		const nopSize = nop.length;

		if (size < nopSize) {
			// Can't fit a full NOP, use single-byte NOPs if possible
			if (this.architecture === 'x86' || this.architecture === 'x64') {
				return Buffer.alloc(size, 0x90);
			}
			// For other architectures, just return zeros
			return Buffer.alloc(size, 0x00);
		}

		const numNops = Math.floor(size / nopSize);
		const remainder = size % nopSize;

		const buffers: Buffer[] = [];
		for (let i = 0; i < numNops; i++) {
			buffers.push(nop);
		}

		if (remainder > 0) {
			// For x86, use single-byte NOPs for remainder
			if (this.architecture === 'x86' || this.architecture === 'x64') {
				buffers.push(Buffer.alloc(remainder, 0x90));
			} else {
				buffers.push(Buffer.alloc(remainder, 0x00));
			}
		}

		return Buffer.concat(buffers);
	}

	/**
	 * Get available targets
	 */
	getAvailableTargets(): TargetInfo[] {
		if (!this.llvmMcModule) return [];
		return this.llvmMcModule.getTargets();
	}

	/**
	 * Get LLVM version
	 */
	getVersion(): string {
		if (!this.llvmMcModule) return 'unknown';
		return this.llvmMcModule.version();
	}

	/**
	 * Get current architecture
	 */
	getArchitecture(): ArchitectureConfig {
		return this.architecture;
	}

	/**
	 * Get current syntax
	 */
	getSyntax(): 'intel' | 'att' {
		return this.syntax;
	}

	/**
	 * Check if initialized
	 */
	isInitialized(): boolean {
		return this.initialized && this.assembler?.isOpen === true;
	}

	/**
	 * Change architecture (reinitializes assembler)
	 */
	async setArchitecture(arch: ArchitectureConfig): Promise<void> {
		this.dispose();
		await this.initialize(arch);
	}

	/**
	 * Validate instruction without assembling
	 */
	validate(code: string): { valid: boolean; error?: string } {
		const result = this.assemble(code);
		return {
			valid: result.success,
			error: result.error
		};
	}

	/**
	 * Close and cleanup
	 */
	dispose(): void {
		if (this.assembler) {
			this.assembler.close();
			this.assembler = undefined;
		}
		this.initialized = false;
	}
}
