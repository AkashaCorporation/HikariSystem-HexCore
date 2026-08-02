import * as assert from 'assert';
import { WinApiHooks } from './winApiHooks';

suite('WinAPI anti-analysis and CRT contracts', () => {
	test('Sleep advances QPC at the advertised 10 MHz frequency', () => {
		let qpc = 0n;
		const emulator = {
			writeMemorySync: (_address: bigint, data: Buffer) => { qpc = data.readBigUInt64LE(); },
		};
		const hooks = new WinApiHooks(emulator as any, {} as any, 'x64') as any;
		const handlers = hooks.handlers as Map<string, (args: bigint[]) => bigint>;

		handlers.get('kernel32!QueryPerformanceCounter')!([0x1000n]);
		const before = qpc;
		handlers.get('kernel32!Sleep')!([250n]);
		handlers.get('kernel32!QueryPerformanceCounter')!([0x1000n]);

		assert.strictEqual(qpc - before, 2_510_000n);
	});

	test('debugger and TLS probes receive successful non-debug contracts', () => {
		const writes: Buffer[] = [];
		const emulator = {
			writeMemorySync: (_address: bigint, data: Buffer) => { writes.push(Buffer.from(data)); },
		};
		const hooks = new WinApiHooks(emulator as any, {} as any, 'x64') as any;
		const handlers = hooks.handlers as Map<string, (args: bigint[]) => bigint>;

		assert.strictEqual(handlers.get('kernel32!IsDebuggerPresent')!([]), 0n);
		assert.strictEqual(handlers.get('kernel32!CheckRemoteDebuggerPresent')!([1n, 0x2000n]), 1n);
		assert.deepStrictEqual(writes[0], Buffer.alloc(4));
		const index = handlers.get('kernel32!TlsAlloc')!([]);
		assert.strictEqual(handlers.get('kernel32!TlsSetValue')!([index, 0x1234n]), 1n);
		assert.strictEqual(handlers.get('kernel32!TlsGetValue')!([index]), 0x1234n);
	});
});
