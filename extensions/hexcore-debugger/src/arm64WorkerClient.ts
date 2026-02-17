/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

/**
 * ARM64 Unicorn Worker Client
 *
 * Wraps the arm64Worker.js child process and provides a Promise-based API
 * for Unicorn operations.  This isolates Unicorn's QEMU TCG JIT from
 * Chromium's UtilityProcess security restrictions (ACG/CFG) which cause
 * STATUS_STACK_BUFFER_OVERRUN (0xC0000409) when Unicorn allocates RWX
 * memory for ARM64 code translation.
 */

import * as child_process from 'child_process';
import * as path from 'path';

// ---- BigInt-safe serialization (mirrors arm64Worker.js) ----

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

interface ExecuteBatchResult {
	pc: bigint;
	instructionsExecuted: number;
	stopped: boolean;
	error: string | null;
	svcEncountered: boolean;
	svcPc: bigint | null;
}

export interface Arm64Registers {
	x0: bigint; x1: bigint; x2: bigint; x3: bigint;
	x4: bigint; x5: bigint; x6: bigint; x7: bigint;
	x8: bigint; x9: bigint; x10: bigint; x11: bigint;
	x12: bigint; x13: bigint; x14: bigint; x15: bigint;
	x16: bigint; x17: bigint; x18: bigint; x19: bigint;
	x20: bigint; x21: bigint; x22: bigint; x23: bigint;
	x24: bigint; x25: bigint; x26: bigint; x27: bigint;
	x28: bigint; x29: bigint; x30: bigint;
	sp: bigint; pc: bigint; lr: bigint; fp: bigint;
	nzcv: bigint;
}

export class Arm64WorkerClient {
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

		const workerPath = path.join(__dirname, '..', 'src', 'arm64Worker.js');

		// Run the worker using the current process.execPath (Electron binary)
		// with ELECTRON_RUN_AS_NODE=1 so it behaves as plain Node.js.
		// This bypasses Chromium's UtilityProcess security restrictions
		// (ACG/CFG) that prevent Unicorn's QEMU TCG JIT from allocating
		// executable memory.
		const env = { ...process.env, ELECTRON_RUN_AS_NODE: '1' };
		this.worker = child_process.fork(workerPath, [], {
			stdio: ['pipe', 'pipe', 'pipe', 'ipc'],
			env,
			execArgv: []
		});

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
				process.stdout.write(`[arm64worker:stdout] ${chunk}`);
			});
		}
		if (this.worker.stderr) {
			this.worker.stderr.on('data', (chunk: Buffer) => {
				process.stderr.write(`[arm64worker:stderr] ${chunk}`);
			});
		}

		this.worker.on('exit', (code, signal) => {
			console.log(`[arm64worker] exited: code=${code}, signal=${signal}`);
			this.worker = null;
			this.ready = false;
			// Reject all pending calls
			for (const [, p] of this.pending) {
				p.reject(new Error(`ARM64 worker exited with code ${code}`));
			}
			this.pending.clear();
		});

		this.worker.on('error', (err) => {
			console.error(`[arm64worker] error: ${err.message}`);
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
			return Promise.reject(new Error('ARM64 worker not started'));
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
	 * Execute a batch of instructions with SVC detection.
	 * This is the primary execution method for ARM64 — it runs N instructions
	 * in the worker, stops when SVC is encountered, and returns to the caller
	 * for syscall dispatch.
	 */
	async executeBatch(
		startPc: bigint,
		count: number,
		svcMask: number,
		svcValue: number,
		terminalAddresses: bigint[]
	): Promise<ExecuteBatchResult> {
		const result = await this.call('executeBatch', startPc, count, svcMask, svcValue, terminalAddresses) as Record<string, unknown>;
		return {
			pc: result.pc as bigint,
			instructionsExecuted: result.instructionsExecuted as number,
			stopped: result.stopped as boolean,
			error: result.error as string | null,
			svcEncountered: result.svcEncountered as boolean,
			svcPc: result.svcPc as bigint | null
		};
	}

	/**
	 * Read all ARM64 registers in one IPC call.
	 */
	async readAllRegisters(): Promise<Arm64Registers> {
		return await this.call('readAllArm64Registers') as Arm64Registers;
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
	 * Kill the worker process.
	 */
	dispose(): void {
		if (this.worker) {
			this.worker.kill();
			this.worker = null;
		}
		this.ready = false;
		for (const [, p] of this.pending) {
			p.reject(new Error('ARM64 worker disposed'));
		}
		this.pending.clear();
	}

	isAlive(): boolean {
		return this.worker !== null && this.ready;
	}
}
