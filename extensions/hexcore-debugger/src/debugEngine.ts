/*---------------------------------------------------------------------------------------------
 *  HexCore Debugger Engine
 *  Debug interface abstraction
 *  Copyright (c) HikariSystem. All rights reserved.
 *--------------------------------------------------------------------------------------------*/

import * as vscode from 'vscode';
import { spawn, ChildProcess } from 'child_process';
import * as os from 'os';

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
		if (!this.process) return;

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
		this.process?.kill();
		this.isRunning = false;
	}
}
