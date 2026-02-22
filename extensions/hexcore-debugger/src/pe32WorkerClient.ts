/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

/**
 * PE32 Unicorn Worker Client
 *
 * Wraps the pe32Worker.js child process and provides a Promise-based API
 * for Unicorn operations on PE32 binaries (x86/x64).  This isolates
 * Unicorn's QEMU TCG JIT from Chromium's UtilityProcess security
 * restrictions (ACG/CFG) which cause STATUS_HEAP_CORRUPTION (0xC0000374)
 * when Unicorn allocates RWX memory for code translation inside the
 * Electron extension host.
 *
 * Unlike the ELF x64 worker which detects SYSCALL/INT 0x80, the PE32
 * worker detects WinAPI stub addresses — when the PC enters the stub
 * range, execution returns to the host for API dispatch via WinApiHooks.
 */

import * as child_process from 'child_process';
import * as path from 'path';
import * as fs from 'fs';

// ---- BigInt-safe serialization (mirrors pe32Worker.js) ----

function serialize(value: unknown): unknown {
	if (typeof value === 'bigint') {
		return 'BI:' + value.toString();
	}
	if (value === null || value === undefined) {
		return value;
	}
	if (Buffer.isBuffer(value)) {
		return { __type: 'Buffer', data: value.toString('base64') };
	}
	if (Array.isArray(value)) {
		return value.map(serialize);
	}
	if (typeof value === 'object') {
		const result: Record<string, unknown> = {};
		for (const key of Object.keys(value as Record<string, unknown>)) {
			result[key] = serialize((value as Record<string, unknown>)[key]);
		}
		return result;
	}
	return value;
}

function deserialize(value: unknown): unknown {
	if (typeof value === 'string' && value.startsWith('BI:')) {
		return BigInt(value.slice(3));
	}
	if (value === null || value === undefined) {
		return value;
	}
	if (typeof value === 'object' && (value as Record<string, unknown>).__type === 'Buffer') {
		return Buffer.from((value as Record<string, unknown>).data as string, 'base64');
	}
	if (Array.isArray(value)) {
		return value.map(deserialize);
	}
	if (typeof value === 'object') {
		const result: Record<string, unknown> = {};
		for (const key of Object.keys(value as Record<string, unknown>)) {
			result[key] = deserialize((value as Record<string, unknown>)[key]);
		}
		return result;
	}
	return value;
}

interface PendingCall {
	resolve: (value: unknown) => void;
	reject: (error: Error) => void;
}

export interface Pe32ExecuteBatchResult {
	pc: bigint;
	instructionsExecuted: number;
	stopped: boolean;
	error: string | null;
	stubHit: boolean;
	stubAddress: bigint | null;
}

export interface X64Registers {
	rax: bigint; rbx: bigint; rcx: bigint; rdx: bigint;
	rsi: bigint; rdi: bigint; rbp: bigint; rsp: bigint;
	r8: bigint; r9: bigint; r10: bigint; r11: bigint;
	r12: bigint; r13: bigint; r14: bigint; r15: bigint;
	rip: bigint; rflags: bigint;
}

export interface X86Registers {
	eax: bigint; ebx: bigint; ecx: bigint; edx: bigint;
	esi: bigint; edi: bigint; ebp: bigint; esp: bigint;
	eip: bigint; eflags: bigint;
}

export class Pe32WorkerClient {
	private worker: child_process.ChildProcess | null = null;
	private nextId = 1;
	private pending = new Map<number, PendingCall>();
	private ready = false;
	private readyPromise: Promise<void> | null = null;
	private pageSize = 0x1000;

	/**
	 * Spawn the worker process.
	 */
	async start(): Promise<void> {
		if (this.worker) {
			return;
		}

		const workerPath = path.join(__dirname, '..', 'src', 'pe32Worker.js');

		// Unicorn's QEMU TCG JIT backend allocates RWX memory for code
		// translation.  The Electron binary has Arbitrary Code Guard (ACG)
		// and Control Flow Guard (CFG) enabled in its PE header on Windows,
		// which blocks VirtualAlloc(PAGE_EXECUTE_READWRITE).  Even with
		// ELECTRON_RUN_AS_NODE=1 the ACG mitigation policy is inherited
		// from the executable image, causing STATUS_ACCESS_VIOLATION
		// (0xC0000005) when Unicorn tries to JIT-compile guest code.
		//
		// Solution: prefer a system Node.js binary (which does NOT have ACG
		// in its PE header) over the Electron binary.  Fall back to
		// Electron + ELECTRON_RUN_AS_NODE=1 if no system Node.js is found.
		const systemNode = this.findSystemNode();
		const env = { ...process.env };

		if (systemNode) {
			// Use system Node.js — no ACG restrictions on RWX allocations
			console.log(`[pe32Worker] Using system Node.js: ${systemNode}`);
			this.worker = child_process.fork(workerPath, [], {
				stdio: ['pipe', 'pipe', 'pipe', 'ipc'],
				execPath: systemNode,
				env,
				execArgv: []
			});
		} else {
			// Fallback: Electron binary with ELECTRON_RUN_AS_NODE=1
			console.warn('[pe32Worker] System Node.js not found, falling back to Electron binary');
			env.ELECTRON_RUN_AS_NODE = '1';
			this.worker = child_process.fork(workerPath, [], {
				stdio: ['pipe', 'pipe', 'pipe', 'ipc'],
				env,
				execArgv: []
			});
		}

		this.worker.on('message', (msg: Record<string, unknown>) => {
			if (msg.type === 'ready') {
				this.ready = true;
				return;
			}
			if (msg.type === 'hook-event') {
				// Hook events from native hooks (for future use)
				return;
			}

			const id = msg.id as number;
			const pending = this.pending.get(id);
			if (!pending) {
				return;
			}
			this.pending.delete(id);

			if (msg.error) {
				pending.reject(new Error(msg.error as string));
			} else {
				pending.resolve(deserialize(msg.result));
			}
		});

		// Relay worker stdout/stderr so diagnostic output is visible
		if (this.worker.stdout) {
			this.worker.stdout.on('data', (chunk: Buffer) => {
				process.stdout.write(`[pe32Worker:stdout] ${chunk}`);
			});
		}
		if (this.worker.stderr) {
			this.worker.stderr.on('data', (chunk: Buffer) => {
				process.stderr.write(`[pe32Worker:stderr] ${chunk}`);
			});
		}

		this.worker.on('exit', (code, signal) => {
			console.log(`[pe32Worker] exited: code=${code}, signal=${signal}`);
			this.worker = null;
			this.ready = false;
			// Reject all pending calls
			for (const [, p] of this.pending) {
				p.reject(new Error(`PE32 worker exited with code ${code}`));
			}
			this.pending.clear();
		});

		this.worker.on('error', (err) => {
			console.error(`[pe32Worker] error: ${err.message}`);
		});

		// Wait for the worker to be ready
		this.readyPromise = new Promise<void>((resolve) => {
			const check = () => {
				if (this.ready) {
					resolve();
				} else {
					setTimeout(check, 10);
				}
			};
			check();
		});

		await this.readyPromise;
	}

	/**
	 * Send an RPC call to the worker and return the result.
	 */
	private call(method: string, ...args: unknown[]): Promise<unknown> {
		if (!this.worker) {
			return Promise.reject(new Error('PE32 worker not started'));
		}

		const id = this.nextId++;
		return new Promise((resolve, reject) => {
			this.pending.set(id, { resolve, reject });
			this.worker!.send({
				id,
				method,
				args: args.map(serialize)
			});
		});
	}

	/**
	 * Initialize the Unicorn engine in the worker.
	 */
	async initialize(arch: number, mode: number): Promise<{ handle: bigint; pageSize: number; version: string }> {
		const result = await this.call('initialize', arch, mode) as Record<string, unknown>;
		this.pageSize = result.pageSize as number;
		return {
			handle: result.handle as bigint,
			pageSize: result.pageSize as number,
			version: result.version as string
		};
	}

	async getConstants(): Promise<Record<string, unknown>> {
		return await this.call('getConstants') as Record<string, unknown>;
	}

	async version(): Promise<{ major: number; minor: number; string: string }> {
		return await this.call('version') as { major: number; minor: number; string: string };
	}

	async memMap(address: bigint, size: number, perms: number): Promise<void> {
		await this.call('memMap', address, size, perms);
	}

	async memRead(address: bigint, size: number): Promise<Buffer> {
		return await this.call('memRead', address, size) as Buffer;
	}

	async memWrite(address: bigint, data: Buffer): Promise<void> {
		await this.call('memWrite', address, data);
	}

	async memProtect(address: bigint, size: number, perms: number): Promise<void> {
		await this.call('memProtect', address, size, perms);
	}

	async memRegions(): Promise<Array<{ begin: bigint; end: bigint; perms: number }>> {
		return await this.call('memRegions') as Array<{ begin: bigint; end: bigint; perms: number }>;
	}

	async regRead(regId: number): Promise<bigint | number> {
		return await this.call('regRead', regId) as bigint | number;
	}

	async regWrite(regId: number, value: bigint | number): Promise<void> {
		await this.call('regWrite', regId, value);
	}

	async emuStart(begin: bigint, until: bigint, timeout?: number, count?: number): Promise<void> {
		await this.call('emuStart', begin, until, timeout, count);
	}

	async emuStop(): Promise<void> {
		await this.call('emuStop');
	}

	async close(): Promise<void> {
		await this.call('close');
	}

	/**
	 * Execute a batch of instructions with WinAPI stub address detection.
	 * This is the primary execution method for PE32 — it runs N instructions
	 * in the worker, stops when the PC enters the stub address range
	 * (indicating a WinAPI call that needs dispatch on the host side),
	 * and returns to the caller for API dispatch via WinApiHooks.
	 *
	 * Unlike ELF x64 which detects SYSCALL/INT 0x80 via 2-byte opcode
	 * reading, PE32 uses stub address range detection to identify API calls.
	 */
	async executeBatch(
		startPc: bigint,
		count: number,
		terminalAddresses: bigint[],
		stubRangeStart: bigint,
		stubRangeEnd: bigint,
		terminalRanges?: Array<{ start: bigint; end: bigint }>
	): Promise<Pe32ExecuteBatchResult> {
		const result = await this.call('executeBatch', startPc, count, terminalAddresses, stubRangeStart, stubRangeEnd, terminalRanges ?? []) as Record<string, unknown>;
		return {
			pc: result.pc as bigint,
			instructionsExecuted: result.instructionsExecuted as number,
			stopped: result.stopped as boolean,
			error: result.error as string | null,
			stubHit: result.stubHit as boolean,
			stubAddress: result.stubAddress as bigint | null
		};
	}

	/**
	 * Read all x64 registers in one IPC call.
	 */
	async readAllX64Registers(): Promise<X64Registers> {
		return await this.call('readAllX64Registers') as X64Registers;
	}

	/**
	 * Read all x86 (32-bit) registers in one IPC call.
	 */
	async readAllX86Registers(): Promise<X86Registers> {
		return await this.call('readAllX86Registers') as X86Registers;
	}

	/**
	 * Write multiple registers in one IPC call.
	 */
	async writeRegisters(regWrites: Record<string, bigint>): Promise<void> {
		await this.call('writeRegisters', regWrites);
	}

	async contextSave(): Promise<number> {
		return await this.call('contextSave') as number;
	}

	async contextRestore(contextId: number): Promise<void> {
		await this.call('contextRestore', contextId);
	}

	async contextFree(contextId: number): Promise<void> {
		await this.call('contextFree', contextId);
	}

	getPageSize(): number {
		return this.pageSize;
	}

	/**
	 * Locate a system Node.js binary that does NOT have ACG/CFG mitigations.
	 * Checks common locations and the PATH environment variable.
	 */
	private findSystemNode(): string | null {
		// Common Node.js install paths on Windows
		const candidates: string[] = [];

		// nvm-windows managed installs
		const nvmHome = process.env.NVM_HOME;
		if (nvmHome) {
			try {
				const dirs = fs.readdirSync(nvmHome).filter(d => {
					try { return fs.statSync(path.join(nvmHome, d, 'node.exe')).isFile(); } catch { return false; }
				});
				for (const d of dirs) {
					candidates.push(path.join(nvmHome, d, 'node.exe'));
				}
			} catch { /* ignore */ }
		}

		// nvm symlink (current active version)
		const nvmSymlink = process.env.NVM_SYMLINK;
		if (nvmSymlink) {
			candidates.push(path.join(nvmSymlink, 'node.exe'));
		}

		// Standard install locations
		candidates.push('C:\\Program Files\\nodejs\\node.exe');
		candidates.push('C:\\Program Files (x86)\\nodejs\\node.exe');

		// PATH-based lookup
		const pathDirs = (process.env.PATH || '').split(path.delimiter);
		for (const dir of pathDirs) {
			const candidate = path.join(dir, 'node.exe');
			if (!candidates.includes(candidate)) {
				candidates.push(candidate);
			}
		}

		// Also check Linux/macOS paths for cross-platform support
		candidates.push('/usr/local/bin/node', '/usr/bin/node');

		for (const candidate of candidates) {
			try {
				if (fs.existsSync(candidate) && fs.statSync(candidate).isFile()) {
					// Verify it's not the Electron binary by checking it's not process.execPath
					if (path.resolve(candidate) !== path.resolve(process.execPath)) {
						return candidate;
					}
				}
			} catch { /* ignore */ }
		}

		return null;
	}

	/**
	 * Kill the worker process.
	 */
	dispose(): void {
		if (this.worker) {
			console.log('[pe32Worker] Disposing worker process...');
			this.worker.kill();
			this.worker = null;
			console.log('[pe32Worker] Worker process disposed.');
		}
		this.ready = false;
		for (const [, p] of this.pending) {
			p.reject(new Error('PE32 worker disposed'));
		}
		this.pending.clear();
	}

	isAlive(): boolean {
		return this.worker !== null && this.ready;
	}
}
