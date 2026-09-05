import * as assert from 'assert';
import * as crypto from 'crypto';
import { collectPeWorkerArgumentPointers } from './unicornWrapper';
import { decryptAesCbc, resolveWinApiCallContract, WinApiHooks } from './winApiHooks';

suite('WinAPI call contract', () => {
	test('Win32 stdcall removes the declared argument bytes', () => {
		const heapAlloc = resolveWinApiCallContract('x86', 'HeapAlloc', true);
		const multiByteToWideChar = resolveWinApiCallContract('x86', 'MultiByteToWideChar', true);

		assert.strictEqual(heapAlloc.callingConvention, 'stdcall');
		assert.strictEqual(heapAlloc.stackBytesPopped, 12);
		assert.strictEqual(multiByteToWideChar.stackBytesPopped, 24);
		assert.strictEqual(heapAlloc.stackBytesPopped + multiByteToWideChar.stackBytesPopped, 0x24);
		assert.strictEqual(heapAlloc.signatureSource, 'win32-signature-table');
	});

	test('Win64 keeps argument cleanup caller-owned', () => {
		const contract = resolveWinApiCallContract('x64', 'BCryptDecrypt', true, 'implemented');

		assert.strictEqual(contract.argumentCount, 10);
		assert.strictEqual(contract.callingConvention, 'win64');
		assert.strictEqual(contract.stackBytesPopped, 0);
		assert.strictEqual(contract.semanticLevel, 'implemented');
	});

	test('decorated Win32 exports carry their own stack size', () => {
		const contract = resolveWinApiCallContract('x86', 'Example@20', false);

		assert.strictEqual(contract.argumentCount, 5);
		assert.strictEqual(contract.stackBytesPopped, 20);
		assert.strictEqual(contract.signatureSource, 'decorated-name');
		assert.strictEqual(contract.semanticLevel, 'unsupported');
	});

	test('PE worker mirror sync includes register and stack argument pointers', () => {
		const x64Stack = Buffer.alloc(256);
		x64Stack.writeBigUInt64LE(0x72002000n, 72);
		assert.deepStrictEqual(
			collectPeWorkerArgumentPointers(true, {
				rcx: 0x71001000n,
				rdx: 16n,
				r8: 0n,
				r9: 0x71003000n,
				rsi: 0n,
				rdi: 0n,
			}, x64Stack),
			[0x71001000n, 0x71003000n, 0x72002000n],
		);

		const x86Stack = Buffer.alloc(256);
		x86Stack.writeUInt32LE(0x00502000, 68);
		assert.deepStrictEqual(
			collectPeWorkerArgumentPointers(false, {
				ecx: 0n,
				edx: 0x00401000n,
				esi: 0n,
				edi: 0n,
			}, x86Stack),
			[0x00401000n, 0x00502000n],
		);
	});

	test('BCrypt SHA-256 creates handles and writes the digest', () => {
		const memoryBase = 0x1000n;
		const memory = Buffer.alloc(0x10000);
		const registers = { rcx: 0n, rdx: 0n, r8: 0n, r9: 0n, rsp: 0x2000n, rip: 0x70000670n };
		const emulator = {
			getRegistersX64: () => ({
				rax: 0n, rbx: 0n, ...registers, rsi: 0n, rdi: 0n, rbp: 0n,
				r10: 0n, r11: 0n, r12: 0n, r13: 0n, r14: 0n, r15: 0n, rflags: 0n,
			}),
			readMemorySync: (address: bigint, size: number) =>
				Buffer.from(memory.subarray(Number(address - memoryBase), Number(address - memoryBase) + size)),
			writeMemorySync: (address: bigint, data: Buffer) =>
				data.copy(memory, Number(address - memoryBase)),
		};
		const hooks = new WinApiHooks(emulator as any, {} as any, 'x64');
		const writeWide = (address: bigint, value: string) =>
			Buffer.from(value + '\0', 'utf16le').copy(memory, Number(address - memoryBase));
		const readPointer = (address: bigint) => memory.readBigUInt64LE(Number(address - memoryBase));
		const call = (name: string, args: bigint[]) => {
			registers.rcx = args[0] ?? 0n;
			registers.rdx = args[1] ?? 0n;
			registers.r8 = args[2] ?? 0n;
			registers.r9 = args[3] ?? 0n;
			for (let i = 4; i < args.length; i++) {
				memory.writeBigUInt64LE(args[i], Number(registers.rsp + BigInt(0x28 + (i - 4) * 8) - memoryBase));
			}
			return hooks.handleCall('bcrypt.dll', name);
		};

		const algorithmName = 0x3000n;
		const algorithmSlot = 0x3100n;
		writeWide(algorithmName, 'SHA256');
		assert.strictEqual(call('BCryptOpenAlgorithmProvider', [algorithmSlot, algorithmName, 0n, 0n]), 0n);
		const algorithmHandle = readPointer(algorithmSlot);
		assert.notStrictEqual(algorithmHandle, 0n);

		const hashSlot = 0x3200n;
		assert.strictEqual(call('BCryptCreateHash', [algorithmHandle, hashSlot, 0n, 0n, 0n, 0n, 0n]), 0n);
		const hashHandle = readPointer(hashSlot);
		const input = 0x3300n;
		Buffer.from('abc').copy(memory, Number(input - memoryBase));
		assert.strictEqual(call('BCryptHashData', [hashHandle, input, 3n, 0n]), 0n);

		const output = 0x3400n;
		assert.strictEqual(call('BCryptFinishHash', [hashHandle, output, 32n, 0n]), 0n);
		const actual = memory.subarray(Number(output - memoryBase), Number(output - memoryBase) + 32);
		assert.deepStrictEqual(actual, crypto.createHash('sha256').update('abc').digest());
		assert.strictEqual(hooks.getLastCall()?.semanticLevel, 'implemented');
	});

	test('AES-256-CBC matches the ntfsm known-answer vector', () => {
		const key = crypto.createHash('sha256').update('iqg0nSeCHnOMPm2Q').digest();
		const iv = Buffer.from('81a829124fa62d0dfb28e5f1783d5c69', 'hex');
		const ciphertext = Buffer.from(
			'9cafad1c6f8ef523f1b890adb4d71e66625f85f80ff61e27d3909c0da8a05dee' +
			'12555fd4e6726c220b22709ff1676721',
			'hex',
		);

		assert.strictEqual(
			decryptAesCbc(ciphertext, key, iv, true).toString('ascii'),
			'f1n1t3_st4t3_m4ch1n3s_4r3_fun@flare-on.com',
		);
	});
});
