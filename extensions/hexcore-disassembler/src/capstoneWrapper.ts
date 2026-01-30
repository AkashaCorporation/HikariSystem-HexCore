/*---------------------------------------------------------------------------------------------
 *  Capstone.js TypeScript Wrapper
 *  Native disassembly using Capstone Engine via WebAssembly
 *  Copyright (c) HikariSystem. All rights reserved.
 *--------------------------------------------------------------------------------------------*/

// Type definitions for @alexaltea/capstone-js
export const enum Architecture {
	X86 = 0,
	ARM = 1,
	ARM64 = 2,
	MIPS = 3,
	PPC = 4,
	SPARC = 5,
	SYSZ = 6,
	XCORE = 7,
	M68K = 8,
	TMS320C64X = 9,
	M680X = 10,
	EVM = 11
}

export const enum Mode {
	// x86/x64
	MODE_16 = 1 << 1,
	MODE_32 = 1 << 2,
	MODE_64 = 1 << 3,
	// ARM
	MODE_ARM = 0,
	MODE_THUMB = 1 << 4,
	// Endianness
	MODE_LITTLE_ENDIAN = 0,
	MODE_BIG_ENDIAN = 1 << 31,
	// MIPS
	MODE_MIPS32 = 1 << 2,
	MODE_MIPS64 = 1 << 3
}

export interface CapstoneInstruction {
	address: number;
	size: number;
	mnemonic: string;
	op_str: string;
	bytes: number[];
}

export interface CapstoneDisasm {
	disasm(buffer: number[] | Uint8Array, offset: number, count?: number): CapstoneInstruction[];
	close(): void;
}

// Import types from capstone-js (these match the library's exports)
declare const cs: {
	MCapstone: Promise<void>;
	Capstone: new (arch: number, mode: number) => CapstoneDisasm;
	ARCH_X86: number;
	ARCH_ARM: number;
	ARCH_ARM64: number;
	ARCH_MIPS: number;
	MODE_16: number;
	MODE_32: number;
	MODE_64: number;
	MODE_ARM: number;
	MODE_THUMB: number;
	MODE_LITTLE_ENDIAN: number;
	MODE_BIG_ENDIAN: number;
	MODE_MIPS32: number;
	MODE_MIPS64: number;
};

export type ArchitectureConfig = 'x86' | 'x64' | 'arm' | 'arm64' | 'mips' | 'mips64';

export interface DisassembledInstruction {
	address: number;
	bytes: Buffer;
	mnemonic: string;
	opStr: string;
	size: number;
	isCall: boolean;
	isJump: boolean;
	isRet: boolean;
	isConditional: boolean;
	targetAddress?: number;
}

/**
 * Capstone Engine Wrapper for TypeScript
 * Provides async initialization and typed disassembly
 */
export class CapstoneWrapper {
	private capstone: CapstoneDisasm | null = null;
	private architecture: ArchitectureConfig = 'x64';
	private initialized: boolean = false;
	private csModule: typeof cs | null = null;

	/**
	 * Initialize Capstone with the specified architecture
	 * Must be called before disassembly
	 */
	async initialize(arch: ArchitectureConfig = 'x64'): Promise<void> {
		this.architecture = arch;

		// Dynamic import of capstone-js
		// Note: capstone-js uses IIFE format (not CommonJS), need special handling
		try {
			const fs = require('fs');
			const path = require('path');
			const vm = require('vm');

			// Find the capstone.min.js file
			const capstonePath = require.resolve('@alexaltea/capstone-js/dist/capstone.min.js');
			const capstoneCode = fs.readFileSync(capstonePath, 'utf8');

			// Create a sandbox context for the script
			const sandbox: { MCapstone?: any; Capstone?: any; window?: any; document?: any; self?: any } = {
				// Provide minimal browser-like environment
				document: { currentScript: { src: capstonePath } },
				window: {},
				self: {}
			};
			sandbox.window = sandbox;
			sandbox.self = sandbox;

			// Execute the script in the sandbox
			vm.runInNewContext(capstoneCode, sandbox);

			// Wait for WebAssembly to initialize
			if (sandbox.MCapstone) {
				this.csModule = await sandbox.MCapstone;
			} else {
				throw new Error('MCapstone not found in loaded module');
			}

			const config = this.getArchConfig(arch);
			this.capstone = new this.csModule!.Capstone(config.arch, config.mode);
			this.initialized = true;
			console.log(`Capstone ${arch} initialized successfully`);
		} catch (error) {
			console.error('Failed to initialize Capstone:', error);
			throw new Error(`Capstone initialization failed: ${error}`);
		}
	}

	/**
	 * Map architecture string to Capstone constants
	 */
	private getArchConfig(arch: ArchitectureConfig): { arch: number; mode: number } {
		if (!this.csModule) {
			throw new Error('Capstone module not loaded');
		}

		const cs = this.csModule;

		switch (arch) {
			case 'x86':
				return { arch: cs.ARCH_X86, mode: cs.MODE_32 };
			case 'x64':
				return { arch: cs.ARCH_X86, mode: cs.MODE_64 };
			case 'arm':
				return { arch: cs.ARCH_ARM, mode: cs.MODE_ARM };
			case 'arm64':
				return { arch: cs.ARCH_ARM64, mode: cs.MODE_ARM };
			case 'mips':
				return { arch: cs.ARCH_MIPS, mode: cs.MODE_MIPS32 | cs.MODE_LITTLE_ENDIAN };
			case 'mips64':
				return { arch: cs.ARCH_MIPS, mode: cs.MODE_MIPS64 | cs.MODE_LITTLE_ENDIAN };
			default:
				return { arch: cs.ARCH_X86, mode: cs.MODE_64 };
		}
	}

	/**
	 * Disassemble a buffer starting at the given base address
	 */
	disassemble(buffer: Buffer | Uint8Array, baseAddress: number, maxInstructions: number = 1000): DisassembledInstruction[] {
		if (!this.initialized || !this.capstone) {
			throw new Error('Capstone not initialized. Call initialize() first.');
		}

		const bytes = buffer instanceof Buffer ? Array.from(buffer) : Array.from(buffer);
		const rawInstructions = this.capstone.disasm(bytes, baseAddress, maxInstructions);

		return rawInstructions.map(inst => this.convertInstruction(inst));
	}

	/**
	 * Disassemble a single instruction at the given offset
	 */
	disassembleOne(buffer: Buffer | Uint8Array, baseAddress: number): DisassembledInstruction | null {
		const instructions = this.disassemble(buffer, baseAddress, 1);
		return instructions.length > 0 ? instructions[0] : null;
	}

	/**
	 * Convert Capstone instruction to our format with additional analysis
	 */
	private convertInstruction(inst: CapstoneInstruction): DisassembledInstruction {
		const mnemonic = inst.mnemonic.toLowerCase();

		// Detect instruction types
		const isCall = mnemonic === 'call' || mnemonic === 'bl' || mnemonic === 'blx';
		const isRet = mnemonic === 'ret' || mnemonic === 'retn' || mnemonic === 'bx lr' ||
			mnemonic === 'retf' || mnemonic === 'iret';

		// Jump instructions
		const jumpMnemonics = [
			'jmp', 'je', 'jne', 'jz', 'jnz', 'jg', 'jge', 'jl', 'jle',
			'ja', 'jae', 'jb', 'jbe', 'jo', 'jno', 'js', 'jns', 'jp', 'jnp',
			'jcxz', 'jecxz', 'jrcxz', 'loop', 'loope', 'loopne',
			// ARM
			'b', 'beq', 'bne', 'bgt', 'blt', 'bge', 'ble', 'bhi', 'blo', 'bhs', 'bls'
		];
		const isJump = jumpMnemonics.includes(mnemonic);

		// Conditional instructions (all jumps except unconditional)
		const isConditional = isJump && mnemonic !== 'jmp' && mnemonic !== 'b';

		// Parse target address from operand
		let targetAddress: number | undefined;
		if ((isCall || isJump) && inst.op_str) {
			const match = inst.op_str.match(/0x([0-9a-fA-F]+)/);
			if (match) {
				targetAddress = parseInt(match[1], 16);
			}
		}

		return {
			address: inst.address,
			bytes: Buffer.from(inst.bytes),
			mnemonic: inst.mnemonic,
			opStr: inst.op_str,
			size: inst.size,
			isCall,
			isJump,
			isRet,
			isConditional,
			targetAddress
		};
	}

	/**
	 * Get current architecture
	 */
	getArchitecture(): ArchitectureConfig {
		return this.architecture;
	}

	/**
	 * Check if Capstone is initialized
	 */
	isInitialized(): boolean {
		return this.initialized;
	}

	/**
	 * Change architecture (requires re-initialization)
	 */
	async setArchitecture(arch: ArchitectureConfig): Promise<void> {
		if (this.capstone) {
			this.capstone.close();
			this.capstone = null;
		}
		await this.initialize(arch);
	}

	/**
	 * Clean up resources
	 */
	dispose(): void {
		if (this.capstone) {
			this.capstone.close();
			this.capstone = null;
		}
		this.initialized = false;
	}
}

// Singleton instance for convenience
let defaultInstance: CapstoneWrapper | null = null;

export function getCapstone(): CapstoneWrapper {
	if (!defaultInstance) {
		defaultInstance = new CapstoneWrapper();
	}
	return defaultInstance;
}

export async function initializeCapstone(arch: ArchitectureConfig = 'x64'): Promise<CapstoneWrapper> {
	const instance = getCapstone();
	if (!instance.isInitialized()) {
		await instance.initialize(arch);
	}
	return instance;
}
