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
	 * Convert Capstone instruction to our format with additional analysis.
	 * Supports x86/x64, ARM32, and ARM64 instruction classification.
	 */
	private convertInstruction(inst: CapstoneInstruction): DisassembledInstruction {
		const mnemonic = inst.mnemonic.toLowerCase();
		const opStr = inst.opStr.toLowerCase().trim();

		// --- Call detection ---
		// x86: call
		// ARM32: bl, blx
		// ARM64: bl, blr (register-indirect call)
		const isCall = mnemonic === 'call'
			|| mnemonic === 'bl'
			|| mnemonic === 'blx'
			|| mnemonic === 'blr'
			|| mnemonic === 'blraa' || mnemonic === 'blrab'  // ARM64 PAC variants
			|| mnemonic === 'blraaz' || mnemonic === 'blrabz';

		// --- Return detection ---
		// x86: ret, retn, retf, iret
		// ARM32: bx lr (Capstone emits mnemonic="bx" opStr="lr"), pop {pc}
		// ARM64: ret (Capstone emits mnemonic="ret"), retaa, retab (PAC variants)
		const isRet = mnemonic === 'ret' || mnemonic === 'retn'
			|| mnemonic === 'retf' || mnemonic === 'iret'
			|| mnemonic === 'retaa' || mnemonic === 'retab'
			|| (mnemonic === 'bx' && opStr === 'lr')
			|| (mnemonic === 'pop' && opStr.includes('pc'));

		// --- Jump detection ---
		// x86 jumps
		const x86Jumps = new Set([
			'jmp', 'je', 'jne', 'jz', 'jnz', 'jg', 'jge', 'jl', 'jle',
			'ja', 'jae', 'jb', 'jbe', 'jo', 'jno', 'js', 'jns', 'jp', 'jnp',
			'jcxz', 'jecxz', 'jrcxz', 'loop', 'loope', 'loopne'
		]);
		// ARM32 conditional branches (Capstone uses beq, bne, etc.)
		const arm32Jumps = new Set([
			'b', 'beq', 'bne', 'bgt', 'blt', 'bge', 'ble',
			'bhi', 'blo', 'bhs', 'bls', 'bpl', 'bmi',
			'bvs', 'bvc', 'bcc', 'bcs', 'bal'
		]);
		// ARM64 conditional branches (Capstone uses b.eq, b.ne, etc. — dot notation)
		const arm64Jumps = new Set([
			'b.eq', 'b.ne', 'b.gt', 'b.lt', 'b.ge', 'b.le',
			'b.hi', 'b.lo', 'b.hs', 'b.ls', 'b.pl', 'b.mi',
			'b.vs', 'b.vc', 'b.cs', 'b.cc', 'b.al', 'b.nv',
			'cbz', 'cbnz',   // Compare and Branch if Zero/Non-Zero
			'tbz', 'tbnz',   // Test bit and Branch if Zero/Non-Zero
			'br'              // Indirect branch (unconditional)
		]);

		const isJump = x86Jumps.has(mnemonic) || arm32Jumps.has(mnemonic) || arm64Jumps.has(mnemonic);

		// --- Conditional detection ---
		// Unconditional: jmp, b (standalone), br
		const unconditionalSet = new Set(['jmp', 'b', 'br', 'bal', 'b.al']);
		const isConditional = isJump && !unconditionalSet.has(mnemonic);

		// --- Target address parsing ---
		let targetAddress: number | undefined;
		if ((isCall || isJump) && inst.opStr) {
			// Only capture direct immediate branch/call targets.
			// Examples accepted:
			//   call 0x140001000
			//   jne 0x140001234
			//   bl #0x401000
			//
			// Examples rejected:
			//   jmp rax
			//   call qword ptr [rip + 0x10]
			//   br x8
			const directImmediate = inst.opStr.trim();
			const isIndirectTarget = directImmediate.includes('[') || directImmediate.includes(']');
			const match = !isIndirectTarget
				? directImmediate.match(/^#?0x([0-9a-fA-F]+)$/)
				: null;
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
	 * Detect function boundaries in a code buffer using native prologue scanning
	 * and call target analysis. Returns sorted array of function boundaries.
	 */
	async detectFunctions(buffer: Buffer | Uint8Array, baseAddress: number | bigint, maxFunctions: number = 5000): Promise<Array<{
		start: bigint;
		end: bigint;
		size: number;
		detectionMethod: string;
		confidence: number;
		hasReturn: boolean;
		isThunk: boolean;
	}>> {
		if (!this.initialized || !this.capstone) {
			throw new Error('Capstone not initialized. Call initialize() first.');
		}

		const bytes = buffer instanceof Buffer ? buffer : Buffer.from(buffer);

		// Check if native detectFunctions is available (requires hexcore-capstone >= 1.3.3)
		if (typeof (this.capstone as any).detectFunctions === 'function') {
			return (this.capstone as any).detectFunctions(bytes, baseAddress, maxFunctions);
		}

		// Fallback: simple prologue scan in JS for older native modules
		return this.detectFunctionsFallback(bytes, typeof baseAddress === 'bigint' ? Number(baseAddress) : baseAddress);
	}

	/**
	 * Given an address that may be in the middle of a function, find the
	 * containing function's start address by scanning backward for prologues.
	 * Returns the start address, or the original address if no function boundary found.
	 */
	async findFunctionStart(buffer: Buffer | Uint8Array, targetAddress: number | bigint, bufferBaseAddress: number | bigint): Promise<bigint> {
		const target = typeof targetAddress === 'bigint' ? targetAddress : BigInt(targetAddress);
		const base = typeof bufferBaseAddress === 'bigint' ? bufferBaseAddress : BigInt(bufferBaseAddress);

		const functions = await this.detectFunctions(buffer, bufferBaseAddress);

		// Binary search for the function containing targetAddress
		let lo = 0;
		let hi = functions.length - 1;
		let best = target; // default: return the address itself

		while (lo <= hi) {
			const mid = (lo + hi) >> 1;
			const fn = functions[mid];
			if (fn.start <= target && fn.end >= target) {
				return fn.start; // exact match
			} else if (fn.start > target) {
				hi = mid - 1;
			} else {
				// fn.start < target, this could be our function if end >= target
				best = fn.start;
				lo = mid + 1;
			}
		}

		// If best is close enough (within reasonable function size), use it
		if (target - best < 0x100000n) { // 1MB max function size
			return best;
		}
		return target;
	}

	/**
	 * Fallback JS-based prologue detection for when native detectFunctions is unavailable
	 */
	private detectFunctionsFallback(buffer: Buffer, baseAddress: number): Array<{
		start: bigint;
		end: bigint;
		size: number;
		detectionMethod: string;
		confidence: number;
		hasReturn: boolean;
		isThunk: boolean;
	}> {
		const functions: Array<{
			start: bigint; end: bigint; size: number;
			detectionMethod: string; confidence: number;
			hasReturn: boolean; isThunk: boolean;
		}> = [];

		const arch = this.architecture;
		const isX86 = arch === 'x86' || arch === 'x64';

		for (let offset = 0; offset < buffer.length - 4; offset++) {
			let isPrologue = false;

			if (isX86) {
				// push rbp (0x55)
				if (buffer[offset] === 0x55) isPrologue = true;
				// endbr64 + push rbp
				if (offset + 4 < buffer.length &&
					buffer[offset] === 0xF3 && buffer[offset + 1] === 0x0F &&
					buffer[offset + 2] === 0x1E && buffer[offset + 3] === 0xFA &&
					buffer[offset + 4] === 0x55) isPrologue = true;
			} else if (arch === 'arm64' && offset % 4 === 0) {
				const word = buffer.readUInt32LE(offset);
				// STP x29, x30, [sp, #-N]!
				if ((word & 0xFFC07FFF) === 0xA9807BFD) isPrologue = true;
			}

			if (isPrologue) {
				const addr = BigInt(baseAddress + offset);
				functions.push({
					start: addr,
					end: addr + 1n,
					size: 0,
					detectionMethod: 'prologue',
					confidence: 0.7,
					hasReturn: false,
					isThunk: false
				});
			}
		}

		return functions;
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

