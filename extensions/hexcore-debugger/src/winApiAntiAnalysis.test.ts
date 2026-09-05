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

	test('VCRUNTIME memory hooks preserve bytes and return the destination', () => {
		const memory = Buffer.alloc(0x400, 0xCC);
		const base = 0x1000n;
		const offsetOf = (address: bigint, size: number): number => {
			const offset = Number(address - base);
			if (offset < 0 || offset + size > memory.length) { throw new Error('test memory out of range'); }
			return offset;
		};
		const emulator = {
			readMemorySync: (address: bigint, size: number) => {
				const offset = offsetOf(address, size);
				return Buffer.from(memory.subarray(offset, offset + size));
			},
			writeMemorySync: (address: bigint, data: Buffer) => {
				const offset = offsetOf(address, data.length);
				data.copy(memory, offset);
			},
		};
		for (const architecture of ['x86', 'x64'] as const) {
			memory.fill(0xCC);
			const hooks = new WinApiHooks(emulator as any, {} as any, architecture) as any;
			const handlers = hooks.handlers as Map<string, (args: bigint[]) => bigint>;
			const destination = base + 0x40n;
			const source = base + 0x100n;
			memory.fill(0x5A, 0x100, 0x108);

			assert.strictEqual(
				handlers.get('vcruntime140.dll!memset')!([destination, 0x41n, 8n]),
				destination,
			);
			assert.deepStrictEqual(memory.subarray(0x40, 0x48), Buffer.alloc(8, 0x41));
			assert.strictEqual(
				handlers.get('vcruntime140.dll!memcpy')!([destination, source, 8n]),
				destination,
			);
			assert.deepStrictEqual(memory.subarray(0x40, 0x48), Buffer.alloc(8, 0x5A));
		}
	});

	test('CRT strlen reads a complete string across a page boundary', () => {
		const base = 0x1ff0n;
		const payload = Buffer.from('FlareAuthenticator\0', 'ascii');
		const emulator = {
			readMemorySync: (address: bigint, size: number) => {
				const offset = Number(address - base);
				if (offset < 0 || offset >= payload.length) { throw new Error('unmapped'); }
				return Buffer.from(payload.subarray(offset, Math.min(offset + size, payload.length)));
			},
		};
		const hooks = new WinApiHooks(emulator as any, {} as any, 'x64') as any;
		const handlers = hooks.handlers as Map<string, (args: bigint[]) => bigint>;
		assert.strictEqual(
			handlers.get('api-ms-win-crt-string-l1-1-0.dll!strlen')!([base]),
			18n,
		);
	});
});
