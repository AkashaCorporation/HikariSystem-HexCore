/*---------------------------------------------------------------------------------------------
 *  HexCore Debugger - Debug Engine
 *  Emulation-based debugger using Unicorn engine with PE/ELF loading
 *  Copyright (c) HikariSystem. All rights reserved.
 *--------------------------------------------------------------------------------------------*/
import * as fs from 'fs';
import { UnicornWrapper, ArchitectureType, EmulationState } from './unicornWrapper';
import { MemoryManager } from './memoryManager';
import { PELoader, PEInfo } from './peLoader';
import { ELFLoader, ELFInfo } from './elfLoader';
import { WinApiHooks, ApiCallLog } from './winApiHooks';

export interface RegisterState {
	rax: bigint;
	rbx: bigint;
	rcx: bigint;
	rdx: bigint;
	rsi: bigint;
	rdi: bigint;
	rbp: bigint;
	rsp: bigint;
	r8: bigint;
	r9: bigint;
	r10: bigint;
	r11: bigint;
	r12: bigint;
	r13: bigint;
	r14: bigint;
	r15: bigint;
	rip: bigint;
	rflags: bigint;
}

export interface MemoryRegion {
	address: bigint;
	size: number;
	permissions: string;
	name?: string;
}

export class DebugEngine {
	private targetPath?: string;
	private isRunning: boolean = false;
	private registers: Partial<RegisterState> = {};
	private listeners: Array<(event: string, data?: any) => void> = [];

	// Emulation components
	private emulator?: UnicornWrapper;
	private memoryManager?: MemoryManager;
	private peLoader?: PELoader;
	private elfLoader?: ELFLoader;
	private apiHooks?: WinApiHooks;
	private emulationInitError?: string;
	private architecture: ArchitectureType = 'x64';
	private baseAddress: bigint = 0x400000n;
	private fileBuffer?: Buffer;
	private fileType: 'pe' | 'elf' | 'raw' = 'raw';

	async getEmulationAvailability(arch: ArchitectureType): Promise<{ available: boolean; error?: string }> {
		if (!this.emulator) {
			this.emulator = new UnicornWrapper();
		}

		try {
			await this.emulator.initialize(arch);
			this.emulationInitError = undefined;
			return { available: true };
		} catch (error: unknown) {
			const message = error instanceof Error ? error.message : String(error);
			this.emulationInitError = message;
			return { available: false, error: message };
		}
	}

	/**
	 * Start emulation for a binary file
	 */
	async startEmulation(filePath: string, arch?: ArchitectureType): Promise<void> {
		this.targetPath = filePath;

		// Read the file
		this.fileBuffer = fs.readFileSync(filePath);

		// Detect architecture if not specified
		this.architecture = arch || this.detectArchitecture();

		// Initialize emulator
		if (!this.emulator) {
			this.emulator = new UnicornWrapper();
		}

		try {
			await this.emulator.initialize(this.architecture);
			this.emulationInitError = undefined;
		} catch (error: unknown) {
			const message = error instanceof Error ? error.message : String(error);
			this.emulationInitError = message;
			throw new Error(message);
		}

		// Create memory manager with callback to the emulator
		this.memoryManager = new MemoryManager(
			(address, size, perms) => this.emulator!.mapMemoryRaw(address, size, perms),
			this.emulator.getPageSize()
		);

		// Set up memory fault handler
		this.emulator.setMemoryFaultHandler((type, address, size, _value) => {
			return this.memoryManager!.handlePageFault(address, size, type);
		});

		// Detect file type and load accordingly
		this.fileType = this.detectFileType();

		if (this.fileType === 'pe') {
			await this.loadPE();
		} else if (this.fileType === 'elf') {
			await this.loadELF();
		} else {
			await this.loadRawBinary();
		}

		this.isRunning = true;
		this.emit('emulation-started', {
			entryPoint: this.baseAddress,
			architecture: this.architecture,
			fileType: this.fileType
		});

		console.log(`Emulation ready: ${this.architecture}, type=${this.fileType}`);
	}

	/**
	 * Load a PE file with full section mapping and import resolution
	 */
	private async loadPE(): Promise<void> {
		this.peLoader = new PELoader(this.emulator!, this.memoryManager!);
		const peInfo = this.peLoader.load(this.fileBuffer!, this.architecture);

		this.baseAddress = peInfo.entryPoint;

		// Create API hooks for Windows PE
		this.apiHooks = new WinApiHooks(this.emulator!, this.memoryManager!, this.architecture);
		this.apiHooks.setImageBase(peInfo.imageBase);

		// Initialize heap
		this.memoryManager!.initializeHeap();

		// Setup stack
		const stackBase = 0x7FFF0000n;
		this.emulator!.setupStack(stackBase);

		// Install API call interceptor via code hook
		this.installApiInterceptor();

		// Set instruction pointer to entry point
		const ipReg = this.architecture === 'x64' ? 'rip' : 'eip';
		this.emulator!.setRegister(ipReg, peInfo.entryPoint);
		this.emulator!.setCurrentAddress(peInfo.entryPoint);

		this.emit('pe-loaded', {
			imageBase: peInfo.imageBase,
			entryPoint: peInfo.entryPoint,
			sections: peInfo.sections.length,
			imports: peInfo.imports.length
		});

		console.log(`PE loaded: entry=0x${peInfo.entryPoint.toString(16)}, ${peInfo.sections.length} sections, ${peInfo.imports.length} imports`);
	}

	/**
	 * Load an ELF file
	 */
	private async loadELF(): Promise<void> {
		this.elfLoader = new ELFLoader(this.emulator!, this.memoryManager!);
		const elfInfo = this.elfLoader.load(this.fileBuffer!);

		this.baseAddress = elfInfo.entryPoint;

		// Initialize heap
		this.memoryManager!.initializeHeap();

		// Setup stack
		const stackBase = 0x7FFF0000n;
		this.emulator!.setupStack(stackBase);

		// Set instruction pointer to entry point
		const ipReg = this.architecture === 'x64' ? 'rip' : 'eip';
		this.emulator!.setRegister(ipReg, elfInfo.entryPoint);
		this.emulator!.setCurrentAddress(elfInfo.entryPoint);

		this.emit('elf-loaded', {
			entryPoint: elfInfo.entryPoint,
			segments: elfInfo.programHeaders.length
		});

		console.log(`ELF loaded: entry=0x${elfInfo.entryPoint.toString(16)}`);
	}

	/**
	 * Load a raw binary (shellcode, firmware, etc.)
	 */
	private async loadRawBinary(): Promise<void> {
		const loadBase = 0x400000n;
		this.emulator!.loadCode(this.fileBuffer!, loadBase);
		this.baseAddress = loadBase;

		// Initialize heap
		this.memoryManager!.initializeHeap();

		// Setup stack
		const stackBase = 0x7FFF0000n;
		this.emulator!.setupStack(stackBase);

		const ipReg = this.architecture === 'x64' ? 'rip' : 'eip';
		this.emulator!.setRegister(ipReg, loadBase);
		this.emulator!.setCurrentAddress(loadBase);
	}

	/**
	 * Install a code hook that intercepts API calls to stub addresses
	 */
	private installApiInterceptor(): void {
		if (!this.emulator || !this.peLoader || !this.apiHooks) {
			return;
		}

		this.emulator.onCodeExecute((address, _size) => {
			if (!this.peLoader!.isStubAddress(address)) {
				return;
			}

			// This address is in the API stub region - it's an API call
			const importEntry = this.peLoader!.lookupStub(address);
			if (!importEntry) {
				return;
			}

			// Handle the API call
			const returnValue = this.apiHooks!.handleCall(importEntry.dll, importEntry.name);

			// Set return value
			if (this.architecture === 'x64') {
				this.emulator!.setRegister('rax', returnValue);
			} else {
				this.emulator!.setRegister('eax', returnValue);
			}

			// Pop return address from stack and set IP
			this.popReturnAddress();

			// Emit API call event for the UI
			this.emit('api-call', {
				dll: importEntry.dll,
				name: importEntry.name,
				returnValue
			});
		});
	}

	/**
	 * Pop the return address from the stack and set the instruction pointer
	 */
	private popReturnAddress(): void {
		if (!this.emulator) {
			return;
		}

		if (this.architecture === 'x64') {
			const regs = this.emulator.getRegistersX64();
			const retAddr = this.emulator.readMemory(regs.rsp, 8).readBigUInt64LE();
			this.emulator.setRegister('rsp', regs.rsp + 8n);
			this.emulator.setRegister('rip', retAddr);
			this.emulator.setCurrentAddress(retAddr);
		} else {
			const regs = this.emulator.getRegistersX86();
			const retAddr = BigInt(this.emulator.readMemory(BigInt(regs.esp), 4).readUInt32LE());
			this.emulator.setRegister('esp', BigInt(regs.esp + 4));
			this.emulator.setRegister('eip', retAddr);
			this.emulator.setCurrentAddress(retAddr);
		}
	}

	/**
	 * Detect file type from magic bytes
	 */
	private detectFileType(): 'pe' | 'elf' | 'raw' {
		if (!this.fileBuffer || this.fileBuffer.length < 4) {
			return 'raw';
		}

		if (this.fileBuffer[0] === 0x4D && this.fileBuffer[1] === 0x5A) {
			return 'pe';
		}

		if (this.fileBuffer[0] === 0x7F && this.fileBuffer.toString('ascii', 1, 4) === 'ELF') {
			return 'elf';
		}

		return 'raw';
	}

	/**
	 * Detect architecture from file headers
	 */
	private detectArchitecture(): ArchitectureType {
		if (!this.fileBuffer) {
			return 'x64';
		}

		// PE file
		if (this.fileBuffer[0] === 0x4D && this.fileBuffer[1] === 0x5A) {
			const peOffset = this.fileBuffer.readUInt32LE(0x3C);
			if (peOffset + 6 < this.fileBuffer.length) {
				const machine = this.fileBuffer.readUInt16LE(peOffset + 4);
				switch (machine) {
					case 0x014c: return 'x86';
					case 0x8664: return 'x64';
					case 0x01c0: return 'arm';
					case 0xaa64: return 'arm64';
				}
			}
		}

		// ELF file
		if (this.fileBuffer[0] === 0x7F && this.fileBuffer.toString('ascii', 1, 4) === 'ELF') {
			const elfClass = this.fileBuffer[4];
			const machine = this.fileBuffer.readUInt16LE(18);
			switch (machine) {
				case 0x03: return elfClass === 2 ? 'x64' : 'x86';
				case 0x3E: return 'x64';
				case 0x28: return 'arm';
				case 0xB7: return 'arm64';
			}
		}

		return 'x64';
	}

	/**
	 * Step one instruction in emulation mode
	 */
	async emulationStep(): Promise<void> {
		if (!this.emulator) {
			throw new Error('Emulator not initialized');
		}

		await this.emulator.step();
		await this.updateEmulationRegisters();
		this.emit('step');
	}

	/**
	 * Continue emulation until breakpoint or end
	 */
	async emulationContinue(): Promise<void> {
		if (!this.emulator) {
			throw new Error('Emulator not initialized');
		}

		await this.emulator.continue();
		await this.updateEmulationRegisters();
		this.emit('continue');
	}

	/**
	 * Set breakpoint
	 */
	emulationSetBreakpoint(address: bigint): void {
		if (!this.emulator) {
			throw new Error('Emulator not initialized');
		}
		this.emulator.addBreakpoint(address);
	}

	/**
	 * Remove breakpoint
	 */
	emulationRemoveBreakpoint(address: bigint): void {
		if (!this.emulator) {
			throw new Error('Emulator not initialized');
		}
		this.emulator.removeBreakpoint(address);
	}

	/**
	 * Read memory in emulation mode
	 */
	emulationReadMemory(address: bigint, size: number): Buffer {
		if (!this.emulator) {
			throw new Error('Emulator not initialized');
		}
		return this.emulator.readMemory(address, size);
	}

	/**
	 * Write memory in emulation mode
	 */
	emulationWriteMemory(address: bigint, data: Buffer): void {
		if (!this.emulator) {
			throw new Error('Emulator not initialized');
		}
		this.emulator.writeMemory(address, data);
	}

	/**
	 * Set register value in emulation mode
	 */
	emulationSetRegister(name: string, value: bigint): void {
		if (!this.emulator) {
			throw new Error('Emulator not initialized');
		}
		this.emulator.setRegister(name, value);
	}

	/**
	 * Update registers from emulator
	 */
	private async updateEmulationRegisters(): Promise<void> {
		if (!this.emulator) {
			return;
		}

		if (this.architecture === 'x64') {
			const regs = this.emulator.getRegistersX64();
			this.registers = regs;
		} else if (this.architecture === 'x86') {
			const regs = this.emulator.getRegistersX86();
			this.registers = {
				rax: BigInt(regs.eax),
				rbx: BigInt(regs.ebx),
				rcx: BigInt(regs.ecx),
				rdx: BigInt(regs.edx),
				rsi: BigInt(regs.esi),
				rdi: BigInt(regs.edi),
				rbp: BigInt(regs.ebp),
				rsp: BigInt(regs.esp),
				rip: BigInt(regs.eip),
				rflags: BigInt(regs.eflags)
			};
		}
	}

	/**
	 * Get emulation state
	 */
	getEmulationState(): EmulationState | null {
		if (!this.emulator) {
			return null;
		}
		return this.emulator.getState();
	}

	/**
	 * Get memory regions from emulator or memory manager
	 */
	getMemoryRegions(): MemoryRegion[] {
		if (!this.emulator) {
			return [];
		}

		// Use memory manager allocations for named regions
		if (this.memoryManager) {
			return this.memoryManager.getAllocations().map(alloc => ({
				address: alloc.address,
				size: alloc.size,
				permissions: this.permsToString(alloc.permissions),
				name: alloc.name
			}));
		}

		return this.emulator.getMemoryRegions().map(r => ({
			address: r.address,
			size: Number(r.size),
			permissions: r.permissions,
			name: undefined
		}));
	}

	/**
	 * Get the emulation memory regions from Unicorn directly
	 */
	getEmulationMemoryRegions(): MemoryRegion[] {
		return this.getMemoryRegions();
	}

	/**
	 * Get registers
	 */
	getRegisters(): Partial<RegisterState> {
		return this.registers;
	}

	/**
	 * Get API call log
	 */
	getApiCallLog(): ApiCallLog[] {
		return this.apiHooks?.getCallLog() ?? [];
	}

	/**
	 * Save emulation snapshot
	 */
	saveSnapshot(): void {
		if (!this.emulator) {
			throw new Error('Emulator not initialized');
		}
		this.emulator.saveState();
		this.emit('snapshot-saved');
	}

	/**
	 * Restore emulation snapshot
	 */
	restoreSnapshot(): void {
		if (!this.emulator) {
			throw new Error('Emulator not initialized');
		}
		this.emulator.restoreState();
		this.updateEmulationRegisters();
		this.emit('snapshot-restored');
	}

	/**
	 * Stop emulation
	 */
	stop(): void {
		if (this.emulator) {
			this.emulator.stop();
		}
		this.isRunning = false;
	}

	/**
	 * Event listener registration
	 */
	onEvent(listener: (event: string, data?: any) => void): void {
		this.listeners.push(listener);
	}

	private emit(event: string, data?: any): void {
		this.listeners.forEach(l => l(event, data));
	}

	/**
	 * Convert numeric permissions to string
	 */
	private permsToString(perms: number): string {
		let result = '';
		if (perms & 1) { result += 'r'; }
		if (perms & 2) { result += 'w'; }
		if (perms & 4) { result += 'x'; }
		return result || '---';
	}

	/**
	 * Get loaded PE info
	 */
	getPEInfo(): PEInfo | undefined {
		return this.peLoader?.getPEInfo();
	}

	/**
	 * Get loaded ELF info
	 */
	getELFInfo(): ELFInfo | undefined {
		return this.elfLoader?.getELFInfo();
	}

	/**
	 * Dispose emulator resources
	 */
	disposeEmulation(): void {
		if (this.memoryManager) {
			this.memoryManager.dispose();
			this.memoryManager = undefined;
		}
		if (this.emulator) {
			this.emulator.dispose();
			this.emulator = undefined;
		}
		this.peLoader = undefined;
		this.elfLoader = undefined;
		this.apiHooks = undefined;
	}
}
