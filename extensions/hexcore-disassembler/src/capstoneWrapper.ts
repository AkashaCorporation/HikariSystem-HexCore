/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import * as path from 'path';
import type { Instruction as CapstoneInstruction } from 'hexcore-capstone';
import { loadNativeModule } from 'hexcore-common';

type CapstoneModule = typeof import('hexcore-capstone');

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
 * Provides native N-API bindings with async disassembly
 */
export class CapstoneWrapper {
	private capstoneModule?: CapstoneModule;
	private capstone: InstanceType<CapstoneModule['Capstone']> | null = null;
	private architecture: ArchitectureConfig = 'x64';
	private initialized: boolean = false;
	private lastError?: string;

	private loadModule(): CapstoneModule | undefined {
		if (this.capstoneModule) {
			return this.capstoneModule;
		}

		const candidatePaths = [
			path.join(__dirname, '..', '..', 'hexcore-capstone'),
			path.join(__dirname, '..', '..', '..', 'hexcore-capstone')
		];

		const result = loadNativeModule<CapstoneModule>({
			moduleName: 'hexcore-capstone',
			candidatePaths
		});

		if (!result.module) {
			this.lastError = result.errorMessage;
			return undefined;
		}

		this.lastError = undefined;
		this.capstoneModule = result.module;
		return this.capstoneModule;
	}

	/**
	 * Initialize Capstone with the specified architecture
	 * Must be called before disassembly
	 */
	async initialize(arch: ArchitectureConfig = 'x64'): Promise<void> {
		this.architecture = arch;

		try {
			const module = this.loadModule();
			if (!module) {
				this.initialized = false;
				throw new Error(this.lastError ?? 'Capstone module unavailable');
			}

			// Close existing instance if any
			if (this.capstone) {
				this.capstone.close();
			}

			const config = this.getArchConfig(module, arch);
			// Native N-API - initialization is synchronous and fast (does not block like WASM)
			this.capstone = new module.Capstone(config.arch, config.mode);
			this.initialized = true;
			console.log(`Capstone ${arch} initialized successfully (native N-API)`);
		} catch (error: unknown) {
			const message = error instanceof Error ? error.message : String(error);
			this.lastError = message;
			console.error('Failed to initialize Capstone:', error);
			throw new Error(`Capstone initialization failed: ${message}`);
		}
	}

	/**
	 * Map architecture string to Capstone constants
	 */
	private getArchConfig(module: CapstoneModule, arch: ArchitectureConfig): { arch: number; mode: number } {
		const ARCH = module.ARCH;
		const MODE = module.MODE;

		switch (arch) {
			case 'x86':
				return { arch: ARCH.X86, mode: MODE.MODE_32 };
			case 'x64':
				return { arch: ARCH.X86, mode: MODE.MODE_64 };
			case 'arm':
				return { arch: ARCH.ARM, mode: MODE.ARM };
			case 'arm64':
				return { arch: ARCH.ARM64, mode: MODE.LITTLE_ENDIAN };
			case 'mips':
				return { arch: ARCH.MIPS, mode: MODE.MODE_32 | MODE.LITTLE_ENDIAN };
			case 'mips64':
				return { arch: ARCH.MIPS, mode: MODE.MODE_64 | MODE.LITTLE_ENDIAN };
			default:
				return { arch: ARCH.X86, mode: MODE.MODE_64 };
		}
	}

	/**
	 * Disassemble a buffer starting at the given base address
	 * Uses async disassembly to avoid blocking the event loop
	 */
	async disassemble(buffer: Buffer | Uint8Array, baseAddress: number, maxInstructions: number = 1000): Promise<DisassembledInstruction[]> {
		if (!this.initialized || !this.capstone) {
			throw new Error('Capstone not initialized. Call initialize() first.');
		}

		const bytes = buffer instanceof Buffer ? buffer : Buffer.from(buffer);

		// Use disasmAsync to avoid blocking the main thread
		const rawInstructions = await this.capstone.disasmAsync(bytes, baseAddress, maxInstructions);

		return rawInstructions.map(inst => this.convertInstruction(inst));
	}

	/**
	 * Disassemble a single instruction at the given offset
	 */
	async disassembleOne(buffer: Buffer | Uint8Array, baseAddress: number): Promise<DisassembledInstruction | null> {
		const instructions = await this.disassemble(buffer, baseAddress, 1);
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
		if ((isCall || isJump) && inst.opStr) {
			const match = inst.opStr.match(/0x([0-9a-fA-F]+)/);
			if (match) {
				targetAddress = parseInt(match[1], 16);
			}
		}

		return {
			address: inst.address,
			bytes: inst.bytes,
			mnemonic: inst.mnemonic,
			opStr: inst.opStr,
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

	getLastError(): string | undefined {
		return this.lastError;
	}

	/**
	 * Change architecture (requires re-initialization)
	 */
	async setArchitecture(arch: ArchitectureConfig): Promise<void> {
		if (this.capstone) {
			this.capstone.close();
			this.capstone = null;
		}
		this.initialized = false;
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

