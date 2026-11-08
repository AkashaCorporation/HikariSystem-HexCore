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
	faultInfo?: Record<string, unknown> | null;
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

export interface Pe32WorkerDiagnostics {
	runtime: 'unstarted' | 'system-node' | 'electron-fallback';
	execPath: string | null;
	nodeVersion: string | null;
	workerPath: string | null;
	pid: number | null;
	addonResolution: string;
	stdoutTail: string;
	stderrTail: string;
	exitCode: number | null;
	signal: NodeJS.Signals | null;
}

export interface Pe32WorkerClientOptions {
	startTimeoutMs?: number;
	fork?: typeof child_process.fork;
	findSystemNode?: () => string | null;
}

export class Pe32WorkerClient {
	private worker: child_process.ChildProcess | null = null;
	private nextId = 1;
	private pending = new Map<number, PendingCall>();
	private ready = false;
	private readyPromise: Promise<void> | null = null;
	private pageSize = 0x1000;
	private lastStartError: string | null = null;
	private startCancel: ((error: Error) => void) | null = null;
	private diagnostics: Pe32WorkerDiagnostics = {
		runtime: 'unstarted', execPath: null, nodeVersion: null, workerPath: null,
		pid: null, addonResolution: 'not-attempted', stdoutTail: '', stderrTail: '',
		exitCode: null, signal: null,
	};

	private static readonly START_TIMEOUT_MS = 15000;
	private static readonly DIAGNOSTIC_TAIL_BYTES = 4096;

	constructor(private readonly options: Pe32WorkerClientOptions = {}) { }

	/**
	 * Spawn the worker process.
	 */
	async start(): Promise<void> {
		if (this.worker && this.ready) {
			return;
		}
		if (this.readyPromise) {
			return this.readyPromise;
		}

		const workerPath = path.join(__dirname, 'pe32Worker.js');

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
		const systemNode = this.options.findSystemNode
			? this.options.findSystemNode()
			: this.findSystemNode();
		const env = { ...process.env };
		const fork = this.options.fork ?? child_process.fork;
		const runtime = systemNode ? 'system-node' : 'electron-fallback';
		const execPath = systemNode ?? process.execPath;
		this.diagnostics = {
			runtime,
			execPath,
			nodeVersion: systemNode ? this.readNodeVersion(systemNode) : process.version,
			workerPath,
			pid: null,
			addonResolution: 'not-attempted',
			stdoutTail: '',
			stderrTail: '',
			exitCode: null,
			signal: null,
		};

		try {
		if (systemNode) {
			// Use system Node.js — no ACG restrictions on RWX allocations
			console.log(`[pe32Worker] Using system Node.js: ${systemNode}`);
			this.worker = fork(workerPath, [], {
				stdio: ['pipe', 'pipe', 'pipe', 'ipc'],
				execPath: systemNode,
				env,
				execArgv: []
			});
		} else {
			// Fallback: Electron binary with ELECTRON_RUN_AS_NODE=1
			console.warn('[pe32Worker] System Node.js not found, falling back to Electron binary');
			env.ELECTRON_RUN_AS_NODE = '1';
			this.worker = fork(workerPath, [], {
				stdio: ['pipe', 'pipe', 'pipe', 'ipc'],
				env,
				execArgv: []
			});
		}
		} catch (error: unknown) {
			const message = error instanceof Error ? error.message : String(error);
			const failure = new Error(`PE32 worker spawn failed: ${message}; ${this.formatDiagnostics()}`);
			this.lastStartError = failure.message;
			throw failure;
		}
		this.diagnostics.pid = this.worker!.pid ?? null;
		console.log(`[pe32Worker] bootstrap: runtime=${runtime}, execPath=${execPath}, node=${this.diagnostics.nodeVersion ?? 'unknown'}, pid=${this.worker!.pid ?? 'unknown'}, worker=${workerPath}`);
		const worker = this.worker!;

		this.ready = false;
		this.lastStartError = null;

		this.readyPromise = new Promise<void>((resolve, reject) => {
			let settled = false;
			const finish = (error?: Error) => {
				if (settled) {
					return;
				}
				settled = true;
				clearTimeout(timeoutHandle);
				this.readyPromise = null;
				this.startCancel = null;
				if (error) {
					this.lastStartError = error.message;
					reject(error);
				} else {
					this.lastStartError = null;
					resolve();
				}
			};

			const startTimeoutMs = this.options.startTimeoutMs ?? Pe32WorkerClient.START_TIMEOUT_MS;
			const timeoutHandle = setTimeout(() => {
				finish(new Error(`PE32 worker failed to become ready within ${startTimeoutMs}ms; ${this.formatDiagnostics()}`));
				this.terminateWorker(worker);
			}, startTimeoutMs);
			this.startCancel = finish;

			worker.on('message', (msg: Record<string, unknown>) => {
				if (msg.type === 'ready') {
					this.applyReadyDiagnostics(msg.diagnostics);
					this.ready = true;
					finish();
					return;
				}
				if (msg.type === 'hook-event') {
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

			if (worker.stdout) {
				worker.stdout.on('data', (chunk: Buffer) => {
					this.diagnostics.stdoutTail = this.appendDiagnosticTail(this.diagnostics.stdoutTail, chunk);
					process.stdout.write(`[pe32Worker:stdout] ${chunk}`);
				});
			}
			if (worker.stderr) {
				worker.stderr.on('data', (chunk: Buffer) => {
					this.diagnostics.stderrTail = this.appendDiagnosticTail(this.diagnostics.stderrTail, chunk);
					process.stderr.write(`[pe32Worker:stderr] ${chunk}`);
				});
			}

			worker.on('exit', (code, signal) => {
				this.diagnostics.exitCode = code;
				this.diagnostics.signal = signal;
				console.log(`[pe32Worker] exited: code=${code}, signal=${signal}; ${this.formatDiagnostics()}`);
				const wasCurrentWorker = this.worker === worker;
				if (wasCurrentWorker) {
					this.worker = null;
					this.ready = false;
				}
				if (!settled) {
					finish(new Error(`PE32 worker exited before ready (code=${code}, signal=${signal}); ${this.formatDiagnostics()}`));
				}
				if (wasCurrentWorker) {
					for (const [, p] of this.pending) {
						p.reject(new Error(`PE32 worker exited with code ${code}`));
					}
					this.pending.clear();
				}
			});

			worker.on('error', (err) => {
				this.diagnostics.stderrTail = this.appendDiagnosticTail(this.diagnostics.stderrTail, err.message);
				console.error(`[pe32Worker] error: ${err.message}; ${this.formatDiagnostics()}`);
				if (!settled) {
					finish(new Error(`PE32 worker process error: ${err.message}; ${this.formatDiagnostics()}`));
				}
			});
		});

		await this.readyPromise;
	}

	/**
	 * Send an RPC call to the worker and return the result.
	 */
	private call(method: string, ...args: unknown[]): Promise<unknown> {
		if (!this.worker) {
			const suffix = this.lastStartError ? `: ${this.lastStartError}` : '';
			return Promise.reject(new Error(`PE32 worker not started${suffix}`));
		}
		if (!this.ready) {
			const suffix = this.lastStartError ? `: ${this.lastStartError}` : '';
			return Promise.reject(new Error(`PE32 worker is not ready${suffix}`));
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
	async initialize(arch: number, mode: number): Promise<{ handle: bigint; pageSize: number; version: string; modulePath?: string }> {
		const result = await this.call('initialize', arch, mode) as Record<string, unknown>;
		this.pageSize = result.pageSize as number;
		const modulePath = typeof result.modulePath === 'string' ? result.modulePath : undefined;
		this.diagnostics.addonResolution = modulePath ?? 'resolved-without-path';
		console.log(`[pe32Worker] addon resolution: ${this.diagnostics.addonResolution}`);
		return {
			handle: result.handle as bigint,
			pageSize: result.pageSize as number,
			version: result.version as string,
			...(modulePath ? { modulePath } : {})
		};
	}

	async getConstants(): Promise<Record<string, unknown>> {
		return await this.call('getConstants') as Record<string, unknown>;
	}

	/**
	 * Set permissive memory mapping flag on the worker.
	 * When true, auto-mapped pages use RWX (UC_PROT_ALL = 7).
	 * When false, auto-mapped pages use RW only (no execute).
	 */
	async setPermissiveMapping(flag: boolean): Promise<void> {
		await this.call('setPermissiveMapping', flag);
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

	async regWriteMmr(regId: number, selector: number, base: bigint, limit: number, flags: number): Promise<void> {
		await this.call('regWriteMmr', regId, selector, base, limit, flags);
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
		terminalRanges?: Array<{ start: bigint; end: bigint }>,
		additionalStubRanges?: Array<{ start: bigint; end: bigint }>
	): Promise<Pe32ExecuteBatchResult> {
		const result = await this.call(
			'executeBatch',
			startPc,
			count,
			terminalAddresses,
			terminalRanges ?? [],
			stubRangeStart,
			stubRangeEnd,
			additionalStubRanges ?? []
		) as Record<string, unknown>;
		return {
			pc: result.pc as bigint,
			instructionsExecuted: result.instructionsExecuted as number,
			stopped: result.stopped as boolean,
			error: result.error as string | null,
			stubHit: result.stubHit as boolean,
			stubAddress: result.stubAddress as bigint | null,
			faultInfo: (result.faultInfo as Record<string, unknown> | null | undefined) ?? null
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

	getDiagnostics(): Pe32WorkerDiagnostics {
		return { ...this.diagnostics };
	}

	private applyReadyDiagnostics(value: unknown): void {
		if (!value || typeof value !== 'object' || Array.isArray(value)) {
			return;
		}
		const diagnostics = value as Record<string, unknown>;
		if (typeof diagnostics.execPath === 'string') {
			this.diagnostics.execPath = diagnostics.execPath;
		}
		if (typeof diagnostics.nodeVersion === 'string') {
			this.diagnostics.nodeVersion = diagnostics.nodeVersion;
		}
		if (typeof diagnostics.workerPath === 'string') {
			this.diagnostics.workerPath = diagnostics.workerPath;
		}
		if (typeof diagnostics.pid === 'number') {
			this.diagnostics.pid = diagnostics.pid;
		}
		if (typeof diagnostics.addonResolution === 'string') {
			this.diagnostics.addonResolution = diagnostics.addonResolution;
		}
	}

	private appendDiagnosticTail(current: string, value: Buffer | string): string {
		const appended = current + (Buffer.isBuffer(value) ? value.toString('utf8') : value);
		return appended.slice(-Pe32WorkerClient.DIAGNOSTIC_TAIL_BYTES);
	}

	private formatDiagnostics(): string {
		const value = this.diagnostics;
		const stdout = value.stdoutTail.trim() || '<empty>';
		const stderr = value.stderrTail.trim() || '<empty>';
		return `runtime=${value.runtime}, execPath=${value.execPath ?? '<unknown>'}, node=${value.nodeVersion ?? '<unknown>'}, pid=${value.pid ?? '<unknown>'}, worker=${value.workerPath ?? '<unknown>'}, addon=${value.addonResolution}, exit=${value.exitCode ?? '<none>'}, signal=${value.signal ?? '<none>'}, stdout=${JSON.stringify(stdout)}, stderr=${JSON.stringify(stderr)}`;
	}

	private readNodeVersion(execPath: string): string | null {
		try {
			return child_process.execFileSync(execPath, ['--version'], {
				encoding: 'utf8', timeout: 2000, windowsHide: true, maxBuffer: 1024,
			}).trim() || null;
		} catch {
			return null;
		}
	}

	private terminateWorker(worker: child_process.ChildProcess | null): void {
		if (!worker) {
			return;
		}
		try {
			worker.kill();
		} catch (error: unknown) {
			this.diagnostics.stderrTail = this.appendDiagnosticTail(
				this.diagnostics.stderrTail,
				`worker kill failed: ${error instanceof Error ? error.message : String(error)}`,
			);
		}
		if (this.worker === worker) {
			this.worker = null;
		}
		this.ready = false;
	}

	/**
	 * Locate a system Node.js binary that does NOT have ACG/CFG mitigations.
	 * Checks common locations and the PATH environment variable.
	 */
	private findSystemNode(): string | null {
		// Common Node.js install paths on Windows
		const candidates: string[] = [
			'C:\\Program Files\\nodejs\\node.exe',
			'C:\\Program Files (x86)\\nodejs\\node.exe',
		];

		// nvm symlink (current active version) comes before historical installs.
		const nvmSymlink = process.env.NVM_SYMLINK;
		if (nvmSymlink) {
			candidates.push(path.join(nvmSymlink, 'node.exe'));
		}

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
					const sameAsCurrentRuntime = path.resolve(candidate) === path.resolve(process.execPath);
					const currentRuntimeIsNode = /^node(?:\.exe)?$/i.test(path.basename(process.execPath));
					// Reuse the current runtime when it is genuine Node. Only reject
					// process.execPath when it is the Electron/HexCore executable.
					if (!sameAsCurrentRuntime || currentRuntimeIsNode) {
						const version = this.readNodeVersion(candidate);
						if (version) {
							return candidate;
						}
						console.warn(`[pe32Worker] Rejecting Node candidate that failed the version probe: ${candidate}`);
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
		const pendingStart = this.startCancel;
		this.startCancel = null;
		if (pendingStart) {
			pendingStart(new Error(`PE32 worker disposed before ready; ${this.formatDiagnostics()}`));
		}
		if (this.worker) {
			console.log('[pe32Worker] Disposing worker process...');
			this.terminateWorker(this.worker);
			console.log('[pe32Worker] Worker process disposed.');
		}
		this.ready = false;
		this.readyPromise = null;
		for (const [, p] of this.pending) {
			p.reject(new Error('PE32 worker disposed'));
		}
		this.pending.clear();
	}

	isAlive(): boolean {
		return this.worker !== null && this.ready;
	}

	getLastStartError(): string | null {
		return this.lastStartError;
	}
}
