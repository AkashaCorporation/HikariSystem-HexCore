/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import * as assert from 'assert';
import { DebugEngine } from './debugEngine';
import { formatLinuxSyscallTraceValue, LinuxApiHooks } from './linuxApiHooks';
import type { X86_64Registers } from './unicornWrapper';

function registers(overrides: Partial<X86_64Registers> = {}): X86_64Registers {
	return {
		rax: 0n, rbx: 0n, rcx: 0n, rdx: 0n, rsi: 0n, rdi: 0n, rbp: 0n,
		rsp: 0x80000000n, r8: 0n, r9: 0n, r10: 0n, r11: 0n, r12: 0n,
		r13: 0n, r14: 0n, r15: 0n, rip: 0x401000n, rflags: 0n,
		...overrides,
	};
}

function createHooks() {
	const calls = {
		maps: [] as Array<{ address: bigint; size: number; perms: number }>,
		allocations: [] as Array<{ address: bigint; size: number; perms: number; name: string }>,
		registers: [] as Array<{ name: string; value: bigint | number }>,
		reads: [] as Array<{ address: bigint; size: number }>,
		stops: 0,
	};
	const emulator = {
		getRegistersX64: () => { throw new Error('worker dispatch must not read host registers'); },
		readMemory: async (address: bigint, size: number) => {
			calls.reads.push({ address, size });
			return Buffer.from('hello').subarray(0, size);
		},
		mapMemoryRaw: async (address: bigint, size: number, perms: number) => {
			calls.maps.push({ address, size, perms });
		},
		setRegister: async (name: string, value: bigint | number) => {
			calls.registers.push({ name, value });
		},
		getPageSize: () => 0x1000,
		stop: () => { calls.stops++; },
	};
	const memoryManager = {
		trackAllocation: (address: bigint, size: number, perms: number, name: string) => {
			calls.allocations.push({ address, size, perms, name });
		},
	};
	return {
		calls,
		hooks: new LinuxApiHooks(emulator as never, memoryManager as never, 'x64'),
	};
}

suite('x64 ELF worker syscall bridge', () => {
	test('dispatches from the explicit worker snapshot and preserves unknown syscall identity', async () => {
		const { hooks } = createHooks();
		const traceEntries: Array<Record<string, unknown>> = [];
		hooks.setTraceManager({
			record: (entry: Record<string, unknown>) => { traceEntries.push(entry); },
		} as never);
		const result = await hooks.handleSyscallAsync(registers({
			rax: 999n,
			rdi: 1n,
			rip: 0x401234n,
		}));

		assert.strictEqual(result, -38n);
		assert.strictEqual(formatLinuxSyscallTraceValue(result), '0xffffffffffffffda');
		assert.deepStrictEqual(hooks.getLastCall(), {
			dll: 'syscall',
			name: 'sys_999',
			args: [1n, 0n, 0n],
			returnValue: -38n,
			timestamp: hooks.getLastCall()!.timestamp,
			arguments: ['0x1', '0x0', '0x0'],
			pcAddress: 0x401234n,
		});
		assert.deepStrictEqual(traceEntries, [{
			functionName: 'sys_999',
			library: 'syscall',
			arguments: ['0x1', '0x0', '0x0'],
			returnValue: '0xffffffffffffffda',
			pcAddress: '0x401234',
			timestamp: hooks.getLastCall()!.timestamp,
		}]);
	});

	test('applies worker memory, mapping, TLS, and exit effects before returning', async () => {
		const { calls, hooks } = createHooks();

		assert.strictEqual(await hooks.handleSyscallAsync(registers({
			rax: 158n, rdi: 0x1002n, rsi: 0x70000000n,
		})), 0n);
		assert.deepStrictEqual(calls.registers, [{ name: 'fs_base', value: 0x70000000n }]);

		assert.strictEqual(await hooks.handleSyscallAsync(registers({ rax: 12n })), 0x06000000n);
		assert.strictEqual(await hooks.handleSyscallAsync(registers({
			rax: 9n, rsi: 0x1800n, rdx: 3n,
		})), 0x20000000n);
		assert.deepStrictEqual(calls.maps, [{ address: 0x20000000n, size: 0x2000, perms: 3 }]);
		assert.deepStrictEqual(calls.allocations, [{
			address: 0x20000000n, size: 0x2000, perms: 3, name: 'mmap-syscall',
		}]);

		assert.strictEqual(await hooks.handleSyscallAsync(registers({
			rax: 1n, rdi: 1n, rsi: 0x600000n, rdx: 5n,
		})), 5n);
		assert.strictEqual(hooks.getStdoutBuffer(), 'hello');
		assert.deepStrictEqual(calls.reads, [{ address: 0x600000n, size: 5 }]);

		assert.strictEqual(await hooks.handleSyscallAsync(registers({ rax: 231n, rdi: 7n })), 0n);
		assert.strictEqual(calls.stops, 1);
		assert.deepStrictEqual(hooks.getCallLog().map(entry => entry.name), [
			'sys_158', 'sys_12', 'sys_9', 'sys_1', 'sys_231',
		]);
	});

	test('emits the captured syscall number instead of the return value', async () => {
		const engine = new DebugEngine() as unknown as {
			emulator: Record<string, unknown>;
			linuxApiHooks: Record<string, unknown>;
			architecture: string;
			installSyscallHandler(): void;
			onEvent(listener: (event: string, data?: unknown) => void): void;
		};
		let interruptHandler: ((intno: number) => Promise<void>) | undefined;
		const events: Array<{ event: string; data?: unknown }> = [];
		const workerRegisters = registers({ rax: 158n, rdi: 0x1002n, rsi: 0x70000000n });
		let writtenRax: bigint | number | undefined;

		engine.emulator = {
			setAsyncInterruptHandler: (handler: (intno: number) => Promise<void>) => { interruptHandler = handler; },
			setInterruptHandler: () => undefined,
			getRegistersX64Async: async () => workerRegisters,
			setRegister: async (name: string, value: bigint | number) => {
				assert.strictEqual(name, 'rax');
				writtenRax = value;
			},
		};
		engine.linuxApiHooks = {
			handleSyscallAsync: async (snapshot: X86_64Registers) => {
				assert.strictEqual(snapshot.rax, 158n);
				return -38n;
			},
			handleSyscall: () => { throw new Error('unexpected sync dispatch'); },
		};
		engine.architecture = 'x64';
		engine.onEvent((event, data) => events.push({ event, data }));
		engine.installSyscallHandler();
		assert.ok(interruptHandler);
		await interruptHandler!(2);

		assert.strictEqual(writtenRax, -38n);
		assert.deepStrictEqual(events, [{
			event: 'api-call',
			data: { dll: 'syscall', name: 'sys_158', returnValue: -38n },
		}]);
	});
});
