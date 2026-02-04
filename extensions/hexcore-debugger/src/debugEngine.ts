/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import * as vscode from 'vscode';
import * as fs from 'fs';
import { spawn, ChildProcess } from 'child_process';
import * as os from 'os';
import { UnicornWrapper, ArchitectureType, X86_64Registers, EmulationState } from './unicornWrapper';

export type DebugMode = 'native' | 'emulation';

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
	private process?: ChildProcess;
	private targetPath?: string;
	private isRunning: boolean = false;
	private registers: Partial<RegisterState> = {};
	private listeners: Array<(event: string, data?: any) => void> = [];

	// Emulation mode
	private mode: DebugMode = 'native';
	private emulator?: UnicornWrapper;
	private emulationInitError?: string;
	private architecture: ArchitectureType = 'x64';
	private baseAddress: bigint = 0x400000n;
	private fileBuffer?: Buffer;

	async startDebugging(filePath: string): Promise<void> {
		this.targetPath = filePath;
		const platform = os.platform();
		const config = vscode.workspace.getConfiguration('hexcore.debugger');

		if (platform === 'win32') {
			// Use WinDbg or cdb
			const windbgPath = config.get<string>('windbgPath') || 'cdb';
			this.process = spawn(windbgPath, ['-g', '-G', filePath], {
				detached: false
			});
		} else {
			// Use GDB
			const gdbPath = config.get<string>('gdbPath') || 'gdb';
			this.process = spawn(gdbPath, ['-q', '-i', 'mi', filePath], {
				detached: false
			});
		}

		this.setupProcessHandlers();
		this.isRunning = true;

		// Initial setup commands
		if (platform !== 'win32') {
			this.sendCommand('-gdb-set mi-async on');
		}
	}

	async attach(pid: number): Promise<void> {
		const config = vscode.workspace.getConfiguration('hexcore.debugger');
		const platform = os.platform();

		if (platform === 'win32') {
			const windbgPath = config.get<string>('windbgPath') || 'cdb';
			this.process = spawn(windbgPath, ['-p', pid.toString()], { detached: false });
		} else {
			const gdbPath = config.get<string>('gdbPath') || 'gdb';
			this.process = spawn(gdbPath, ['-q', '-i', 'mi', '-p', pid.toString()], { detached: false });
		}

		this.setupProcessHandlers();
		this.isRunning = true;
	}

	async setBreakpoint(address: number): Promise<void> {
		const platform = os.platform();
		if (platform === 'win32') {
			this.sendCommand(`bp 0x${address.toString(16)}`);
		} else {
			this.sendCommand(`-break-insert *0x${address.toString(16)}`);
		}
	}

	async stepInto(): Promise<void> {
		const platform = os.platform();
		if (platform === 'win32') {
			this.sendCommand('t');
		} else {
			this.sendCommand('-exec-step');
		}
		await this.updateRegisters();
	}

	async stepOver(): Promise<void> {
		const platform = os.platform();
		if (platform === 'win32') {
			this.sendCommand('p');
		} else {
			this.sendCommand('-exec-next');
		}
		await this.updateRegisters();
	}

	async continue(): Promise<void> {
		const platform = os.platform();
		if (platform === 'win32') {
			this.sendCommand('g');
		} else {
			this.sendCommand('-exec-continue');
		}
		await this.updateRegisters();
	}

	async readMemory(address: bigint, size: number): Promise<Buffer> {
		// Simplified - in production would integrate with debugger
		return Buffer.alloc(size);
	}

	async enableAPITracing(): Promise<void> {
		// Hook common APIs
		const apis = ['CreateFileW', 'ReadFile', 'WriteFile', 'VirtualAlloc', 'LoadLibraryA'];
		for (const api of apis) {
			// Set breakpoints on API entries
			// This is simplified - real implementation would resolve API addresses
		}
	}

	getRegisters(): Partial<RegisterState> {
		return this.registers;
	}

	getMemoryRegions(): MemoryRegion[] {
		// Return memory map
		return [
			{ address: BigInt(0x10000), size: 0x1000, permissions: 'r-x', name: 'code' },
			{ address: BigInt(0x7fff0000), size: 0x10000, permissions: 'rw-', name: 'stack' }
		];
	}

	onEvent(listener: (event: string, data?: any) => void): void {
		this.listeners.push(listener);
	}

	private sendCommand(cmd: string): void {
		if (this.process?.stdin?.writable) {
			this.process.stdin.write(cmd + '\n');
		}
	}

	private setupProcessHandlers(): void {
		if (!this.process) {
			return;
		}

		this.process.stdout?.on('data', (data: Buffer) => {
			const output = data.toString();
			this.parseOutput(output);
		});

		this.process.stderr?.on('data', (data: Buffer) => {
			console.error('Debugger error:', data.toString());
		});

		this.process.on('close', (code) => {
			this.isRunning = false;
			this.emit('stopped', { code });
		});
	}

	private parseOutput(output: string): void {
		// Parse GDB-MI or WinDbg output
		// Simplified parsing
		if (output.includes('Stopped')) {
			this.emit('stopped');
		}
		if (output.includes('Breakpoint')) {
			this.emit('breakpoint-hit');
		}
	}

	private async updateRegisters(): Promise<void> {
		// In production, would query debugger for actual register values
		// This is a placeholder
		this.registers = {
			rax: BigInt(0),
			rbx: BigInt(0),
			rcx: BigInt(0),
			rdx: BigInt(0),
			rbp: BigInt(0x7fff0000),
			rsp: BigInt(0x7fff1000),
			rip: BigInt(0x401000)
		};
	}

	private emit(event: string, data?: any): void {
		this.listeners.forEach(l => l(event, data));
	}

	stop(): void {
		if (this.mode === 'emulation' && this.emulator) {
			this.emulator.stop();
		} else {
			this.process?.kill();
		}
		this.isRunning = false;
	}

	// ============================================================================
	// Emulation Mode Methods (Unicorn Engine)
	// ============================================================================

	/**
	 * Start emulation mode for a binary file
	 */
	async startEmulation(filePath: string, arch?: ArchitectureType): Promise<void> {
		this.targetPath = filePath;
		this.mode = 'emulation';

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

		// Detect base address and entry point
		const { baseAddress, entryPoint, codeOffset, codeSize } = this.analyzeFile();
		this.baseAddress = baseAddress;

		// Load code into emulator
		const codeBuffer = this.fileBuffer.subarray(codeOffset, codeOffset + codeSize);
		this.emulator.loadCode(codeBuffer, baseAddress + BigInt(codeOffset));

		// Setup stack
		const stackBase = 0x7fff0000n;
		this.emulator.setupStack(stackBase);

		// Set instruction pointer to entry point
		this.emulator.setRegister(this.architecture === 'x64' ? 'rip' : 'eip', entryPoint);

		this.isRunning = true;
		this.emit('emulation-started', { entryPoint, architecture: this.architecture });

		console.log(`Emulation started: ${this.architecture} at 0x${entryPoint.toString(16)}`);
	}

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
	 * Analyze file to get base address and entry point
	 */
	private analyzeFile(): { baseAddress: bigint; entryPoint: bigint; codeOffset: number; codeSize: number } {
		if (!this.fileBuffer) {
			return { baseAddress: 0x400000n, entryPoint: 0x401000n, codeOffset: 0, codeSize: 0x1000 };
		}

		// PE file
		if (this.fileBuffer[0] === 0x4D && this.fileBuffer[1] === 0x5A) {
			return this.analyzePE();
		}

		// ELF file
		if (this.fileBuffer[0] === 0x7F && this.fileBuffer.toString('ascii', 1, 4) === 'ELF') {
			return this.analyzeELF();
		}

		// Raw binary
		return {
			baseAddress: 0x400000n,
			entryPoint: 0x400000n,
			codeOffset: 0,
			codeSize: Math.min(this.fileBuffer.length, 0x100000)
		};
	}

	/**
	 * Analyze PE file
	 */
	private analyzePE(): { baseAddress: bigint; entryPoint: bigint; codeOffset: number; codeSize: number } {
		const buf = this.fileBuffer!;
		const peOffset = buf.readUInt32LE(0x3C);
		const optHeaderOffset = peOffset + 24;
		const magic = buf.readUInt16LE(optHeaderOffset);
		const is64Bit = magic === 0x20B;

		const imageBase = is64Bit
			? buf.readBigUInt64LE(optHeaderOffset + 24)
			: BigInt(buf.readUInt32LE(optHeaderOffset + 28));

		const entryPointRVA = buf.readUInt32LE(optHeaderOffset + 16);

		// Find .text section
		const numberOfSections = buf.readUInt16LE(peOffset + 6);
		const sizeOfOptionalHeader = buf.readUInt16LE(peOffset + 20);
		const sectionTableOffset = peOffset + 24 + sizeOfOptionalHeader;

		let codeOffset = 0x1000;
		let codeSize = 0x1000;

		for (let i = 0; i < numberOfSections; i++) {
			const sectionOffset = sectionTableOffset + (i * 40);
			const sectionName = buf.toString('ascii', sectionOffset, sectionOffset + 8).replace(/\0/g, '');

			if (sectionName === '.text' || sectionName === 'CODE') {
				codeSize = buf.readUInt32LE(sectionOffset + 16);
				codeOffset = buf.readUInt32LE(sectionOffset + 20);
				break;
			}
		}

		return {
			baseAddress: imageBase,
			entryPoint: imageBase + BigInt(entryPointRVA),
			codeOffset,
			codeSize
		};
	}

	/**
	 * Analyze ELF file
	 */
	private analyzeELF(): { baseAddress: bigint; entryPoint: bigint; codeOffset: number; codeSize: number } {
		const buf = this.fileBuffer!;
		const is64Bit = buf[4] === 2;

		const entryPoint = is64Bit
			? buf.readBigUInt64LE(24)
			: BigInt(buf.readUInt32LE(24));

		// Simplified - assume code starts after headers
		return {
			baseAddress: 0x400000n,
			entryPoint,
			codeOffset: is64Bit ? 64 : 52, // ELF header size
			codeSize: Math.min(buf.length - (is64Bit ? 64 : 52), 0x100000)
		};
	}

	/**
	 * Step one instruction in emulation mode
	 */
	async emulationStep(): Promise<void> {
		if (this.mode !== 'emulation' || !this.emulator) {
			throw new Error('Not in emulation mode');
		}

		await this.emulator.step();
		await this.updateEmulationRegisters();
		this.emit('step');
	}

	/**
	 * Continue emulation until breakpoint or end
	 */
	async emulationContinue(): Promise<void> {
		if (this.mode !== 'emulation' || !this.emulator) {
			throw new Error('Not in emulation mode');
		}

		await this.emulator.continue();
		await this.updateEmulationRegisters();
		this.emit('continue');
	}

	/**
	 * Set breakpoint in emulation mode
	 */
	emulationSetBreakpoint(address: bigint): void {
		if (this.mode !== 'emulation' || !this.emulator) {
			throw new Error('Not in emulation mode');
		}
		this.emulator.addBreakpoint(address);
	}

	/**
	 * Remove breakpoint in emulation mode
	 */
	emulationRemoveBreakpoint(address: bigint): void {
		if (this.mode !== 'emulation' || !this.emulator) {
			throw new Error('Not in emulation mode');
		}
		this.emulator.removeBreakpoint(address);
	}

	/**
	 * Read memory in emulation mode
	 */
	emulationReadMemory(address: bigint, size: number): Buffer {
		if (this.mode !== 'emulation' || !this.emulator) {
			throw new Error('Not in emulation mode');
		}
		return this.emulator.readMemory(address, size);
	}

	/**
	 * Write memory in emulation mode
	 */
	emulationWriteMemory(address: bigint, data: Buffer): void {
		if (this.mode !== 'emulation' || !this.emulator) {
			throw new Error('Not in emulation mode');
		}
		this.emulator.writeMemory(address, data);
	}

	/**
	 * Set register value in emulation mode
	 */
	emulationSetRegister(name: string, value: bigint): void {
		if (this.mode !== 'emulation' || !this.emulator) {
			throw new Error('Not in emulation mode');
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
		if (this.mode !== 'emulation' || !this.emulator) {
			return null;
		}
		return this.emulator.getState();
	}

	/**
	 * Get current debug mode
	 */
	getMode(): DebugMode {
		return this.mode;
	}

	/**
	 * Get memory regions (emulation mode)
	 */
	getEmulationMemoryRegions(): MemoryRegion[] {
		if (this.mode !== 'emulation' || !this.emulator) {
			return [];
		}
		return this.emulator.getMemoryRegions().map(r => ({
			address: r.address,
			size: Number(r.size),
			permissions: r.permissions,
			name: r.name
		}));
	}

	/**
	 * Save emulation snapshot
	 */
	saveSnapshot(): void {
		if (this.mode !== 'emulation' || !this.emulator) {
			throw new Error('Not in emulation mode');
		}
		this.emulator.saveState();
		this.emit('snapshot-saved');
	}

	/**
	 * Restore emulation snapshot
	 */
	restoreSnapshot(): void {
		if (this.mode !== 'emulation' || !this.emulator) {
			throw new Error('Not in emulation mode');
		}
		this.emulator.restoreState();
		this.updateEmulationRegisters();
		this.emit('snapshot-restored');
	}

	/**
	 * Dispose emulator resources
	 */
	disposeEmulation(): void {
		if (this.emulator) {
			this.emulator.dispose();
			this.emulator = undefined;
		}
		this.mode = 'native';
	}
}

