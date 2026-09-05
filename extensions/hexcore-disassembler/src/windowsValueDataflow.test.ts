import * as assert from 'assert';
import { analyzeWindowsValueDataflow, type ValueFlowFactSeed } from './windowsValueDataflow';

function instruction(address: number, mnemonic: string, opStr: string, options: { call?: boolean; jump?: boolean; conditional?: boolean; ret?: boolean; target?: number } = {}) {
	return {
		address, bytes: Buffer.alloc(1), mnemonic, opStr, size: 1,
		isCall: options.call === true, isJump: options.jump === true, isRet: options.ret === true,
		isConditional: options.conditional === true, ...(options.target ? { targetAddress: options.target } : {}),
	};
}

suite('Win64 deep value dataflow', () => {
	test('proves one CreateFile return flows to WriteFile and CloseHandle', () => {
		const fn = {
			address: 0x401000, name: 'write_file', size: 0x40, endAddress: 0x401040,
			callers: [], callees: [],
			instructions: [
				instruction(0x401000, 'lea', 'rcx, [rbp - 0x60]'),
				instruction(0x401001, 'call', '0x500000', { call: true, target: 0x500000 }),
				instruction(0x401002, 'mov', 'qword ptr [rbp - 0x20], rax'),
				instruction(0x401003, 'mov', 'rcx, qword ptr [rbp - 0x20]'),
				instruction(0x401004, 'call', '0x500010', { call: true, target: 0x500010 }),
				instruction(0x401005, 'mov', 'rcx, qword ptr [rbp - 0x20]'),
				instruction(0x401006, 'call', '0x500020', { call: true, target: 0x500020 }),
			],
		};
		const seeds: ValueFlowFactSeed[] = [
			{ kind: 'handle-open', functionAddress: '0x401000', functionName: 'write_file', api: 'KERNEL32.dll!CreateFileW', callSite: '0x401001' },
			{ kind: 'write-sink', functionAddress: '0x401000', functionName: 'write_file', api: 'KERNEL32.dll!WriteFile', callSite: '0x401004' },
			{ kind: 'handle-close', functionAddress: '0x401000', functionName: 'write_file', api: 'KERNEL32.dll!CloseHandle', callSite: '0x401006' },
		];
		const result = analyzeWindowsValueDataflow([fn], seeds);
		assert.strictEqual(result.status, 'assessed');
		assert.strictEqual(result.proofs.filter(proof => proof.kind === 'same-handle').length, 2);
		assert.ok(result.proofs.every(proof => proof.status === 'proven'));
		assert.strictEqual(new Set(result.proofs.map(proof => proof.canonicalIdentity)).size, 1);
		assert.match(result.proofs[0].canonicalIdentity, /^ret:401000:401001:/);
	});

	test('proves ACL and SID storage identity across Win64 arguments', () => {
		const fn = {
			address: 0x402000, name: 'build_acl', size: 0x80, endAddress: 0x402080,
			callers: [], callees: [],
			instructions: [
				instruction(0x402000, 'lea', 'rcx, [rbp - 0x80]'),
				instruction(0x402001, 'call', '0x510000', { call: true, target: 0x510000 }),
				instruction(0x402002, 'lea', 'rax, [rbp - 0x40]'),
				instruction(0x402003, 'mov', 'qword ptr [rsp + 0x50], rax'),
				instruction(0x402004, 'call', '0x510010', { call: true, target: 0x510010 }),
				instruction(0x402005, 'lea', 'rcx, [rbp - 0x80]'),
				instruction(0x402006, 'mov', 'r8d, 0x40'),
				instruction(0x402007, 'mov', 'r9, qword ptr [rbp - 0x40]'),
				instruction(0x402008, 'call', '0x510020', { call: true, target: 0x510020 }),
			],
		};
		const seeds: ValueFlowFactSeed[] = [
			{ kind: 'acl-builder', functionAddress: '0x402000', functionName: 'build_acl', api: 'ADVAPI32.dll!InitializeAcl', callSite: '0x402001' },
			{ kind: 'sid-producer', functionAddress: '0x402000', functionName: 'build_acl', api: 'ADVAPI32.dll!AllocateAndInitializeSid', callSite: '0x402004' },
			{ kind: 'acl-builder', functionAddress: '0x402000', functionName: 'build_acl', api: 'ADVAPI32.dll!AddAccessAllowedAce', callSite: '0x402008' },
		];
		const result = analyzeWindowsValueDataflow([fn], seeds);
		assert.ok(result.proofs.some(proof => proof.kind === 'same-acl' && proof.canonicalIdentity === 'storage:[rbp-0x80]'));
		assert.ok(result.proofs.some(proof => proof.kind === 'same-sid' && proof.canonicalIdentity === 'storage:[rbp-0x40]'));
	});

	test('proves a path value only when the output buffer is preserved', () => {
		const fn = {
			address: 0x403000, name: 'open_full_path', size: 0x40, endAddress: 0x403040,
			callers: [], callees: [],
			instructions: [
				instruction(0x403000, 'mov', 'edx, 0x100'),
				instruction(0x403001, 'lea', 'r8, [rsp + 0x80]'),
				instruction(0x403002, 'call', '0x520000', { call: true, target: 0x520000 }),
				instruction(0x403003, 'lea', 'rcx, [rsp + 0x80]'),
				instruction(0x403004, 'call', '0x520010', { call: true, target: 0x520010 }),
			],
		};
		const seeds: ValueFlowFactSeed[] = [
			{ kind: 'path-producer', functionAddress: '0x403000', functionName: 'open_full_path', api: 'KERNEL32.dll!GetFullPathNameW', callSite: '0x403002' },
			{ kind: 'handle-open', functionAddress: '0x403000', functionName: 'open_full_path', api: 'KERNEL32.dll!CreateFileW', callSite: '0x403004' },
		];
		const result = analyzeWindowsValueDataflow([fn], seeds);
		assert.ok(result.proofs.some(proof => proof.kind === 'same-path' && proof.canonicalIdentity === 'storage:[rsp+0x80]'));
		assert.deepStrictEqual(result.signals, []);
	});

	test('downgrades same-path when the buffer address escapes to an unsummarized callee', () => {
		const fn = {
			address: 0x404000, name: 'escaped_path', size: 0x50, endAddress: 0x404050,
			callers: [], callees: [0x404100],
			instructions: [
				instruction(0x404000, 'mov', 'edx, 0x100'),
				instruction(0x404001, 'lea', 'r8, [rsp + 0x80]'),
				instruction(0x404002, 'call', '0x520000', { call: true, target: 0x520000 }),
				instruction(0x404003, 'lea', 'rcx, [rsp + 0x80]'),
				instruction(0x404004, 'call', '0x404100', { call: true, target: 0x404100 }),
				instruction(0x404005, 'lea', 'rcx, [rsp + 0x80]'),
				instruction(0x404006, 'call', '0x520010', { call: true, target: 0x520010 }),
			],
		};
		const callee = {
			address: 0x404100, name: 'unknown_mutator', size: 1, endAddress: 0x404101,
			callers: [0x404000], callees: [], instructions: [instruction(0x404100, 'ret', '', { ret: true })],
		};
		const seeds: ValueFlowFactSeed[] = [
			{ kind: 'path-producer', functionAddress: '0x404000', functionName: 'escaped_path', api: 'KERNEL32.dll!GetFullPathNameW', callSite: '0x404002' },
			{ kind: 'handle-open', functionAddress: '0x404000', functionName: 'escaped_path', api: 'KERNEL32.dll!CreateFileW', callSite: '0x404006' },
		];
		const result = analyzeWindowsValueDataflow([fn, callee], seeds);
		assert.strictEqual(result.proofs.filter(proof => proof.kind === 'same-path').length, 0);
		assert.strictEqual(result.signals.filter(signal => signal.kind === 'same-path').length, 1);
		assert.match(result.signals[0].blockers[0], /unknown_mutator@0x404004 without a read-only summary/);
	});

	test('downgrades same-path when a direct write overlaps the tracked buffer', () => {
		const fn = {
			address: 0x405000, name: 'rewritten_path', size: 0x40, endAddress: 0x405040,
			callers: [], callees: [],
			instructions: [
				instruction(0x405000, 'mov', 'edx, 0x100'),
				instruction(0x405001, 'lea', 'r8, [rsp + 0x80]'),
				instruction(0x405002, 'call', '0x520000', { call: true, target: 0x520000 }),
				instruction(0x405003, 'mov', 'byte ptr [rsp + 0x82], 0'),
				instruction(0x405004, 'lea', 'rcx, [rsp + 0x80]'),
				instruction(0x405005, 'call', '0x520010', { call: true, target: 0x520010 }),
			],
		};
		const seeds: ValueFlowFactSeed[] = [
			{ kind: 'path-producer', functionAddress: '0x405000', functionName: 'rewritten_path', api: 'KERNEL32.dll!GetFullPathNameW', callSite: '0x405002' },
			{ kind: 'handle-open', functionAddress: '0x405000', functionName: 'rewritten_path', api: 'KERNEL32.dll!CreateFileW', callSite: '0x405005' },
		];
		const result = analyzeWindowsValueDataflow([fn], seeds);
		assert.strictEqual(result.proofs.filter(proof => proof.kind === 'same-path').length, 0);
		assert.match(result.signals[0].blockers[0], /Direct write at 0x405003 may overlap/);
	});

	test('downgrades register-alias, wide crossing, indexed, and implicit path writes', () => {
		const cases = [
			[
				instruction(0x407003, 'lea', 'rax, [rsp + 0x80]'),
				instruction(0x407004, 'mov', 'byte ptr [rax + 2], 0'),
			],
			[
				instruction(0x407003, 'mov', 'qword ptr [rsp + 0x7c], 0'),
			],
			[
				instruction(0x407003, 'mov', 'byte ptr [rsp + rax + 0x80], 0'),
			],
			[
				instruction(0x407003, 'lea', 'rdi, [rsp + 0x80]'),
				instruction(0x407004, 'stosb', ''),
			],
		];
		for (const [caseIndex, writes] of cases.entries()) {
			const base = 0x407000 + caseIndex * 0x100;
			const remap = (entry: ReturnType<typeof instruction>, index: number) => ({ ...entry, address: base + 3 + index });
			const fn = {
				address: base, name: `write_case_${caseIndex}`, size: 0x40, endAddress: base + 0x40,
				callers: [], callees: [],
				instructions: [
					instruction(base, 'mov', 'edx, 0x100'),
					instruction(base + 1, 'lea', 'r8, [rsp + 0x80]'),
					instruction(base + 2, 'call', '0x520000', { call: true, target: 0x520000 }),
					...writes.map(remap),
					instruction(base + 8, 'lea', 'rcx, [rsp + 0x80]'),
					instruction(base + 9, 'call', '0x520010', { call: true, target: 0x520010 }),
				],
			};
			const seeds: ValueFlowFactSeed[] = [
				{ kind: 'path-producer', functionAddress: toAddress(base), functionName: fn.name, api: 'KERNEL32.dll!GetFullPathNameW', callSite: toAddress(base + 2) },
				{ kind: 'handle-open', functionAddress: toAddress(base), functionName: fn.name, api: 'KERNEL32.dll!CreateFileW', callSite: toAddress(base + 9) },
			];
			const result = analyzeWindowsValueDataflow([fn], seeds);
			assert.strictEqual(result.proofs.filter(proof => proof.kind === 'same-path').length, 0, `case ${caseIndex}`);
			assert.strictEqual(result.signals.filter(signal => signal.kind === 'same-path').length, 1, `case ${caseIndex}`);
		}
	});

	test('downgrades same-path when a spilled pointer escapes to an unknown callee', () => {
		const fn = {
			address: 0x40B000, name: 'spilled_escape', size: 0x50, endAddress: 0x40B050,
			callers: [], callees: [],
			instructions: [
				instruction(0x40B000, 'mov', 'edx, 0x100'),
				instruction(0x40B001, 'lea', 'r8, [rsp + 0x80]'),
				instruction(0x40B002, 'call', '0x520000', { call: true, target: 0x520000 }),
				instruction(0x40B003, 'lea', 'rax, [rsp + 0x80]'),
				instruction(0x40B004, 'mov', 'qword ptr [rsp + 0x70], rax'),
				instruction(0x40B005, 'mov', 'rcx, qword ptr [rsp + 0x70]'),
				instruction(0x40B006, 'call', '0x40B100', { call: true, target: 0x40B100 }),
				instruction(0x40B007, 'lea', 'rcx, [rsp + 0x80]'),
				instruction(0x40B008, 'call', '0x520010', { call: true, target: 0x520010 }),
			],
		};
		const seeds: ValueFlowFactSeed[] = [
			{ kind: 'path-producer', functionAddress: '0x40B000', functionName: fn.name, api: 'KERNEL32.dll!GetFullPathNameW', callSite: '0x40B002' },
			{ kind: 'handle-open', functionAddress: '0x40B000', functionName: fn.name, api: 'KERNEL32.dll!CreateFileW', callSite: '0x40B008' },
		];
		const result = analyzeWindowsValueDataflow([fn], seeds);
		assert.strictEqual(result.proofs.filter(proof => proof.kind === 'same-path').length, 0);
		assert.match(result.signals[0].blockers[0], /Storage address escapes through argument 1/);
	});

	test('downgrades identities when producer and consumer are mutually exclusive', () => {
		const pathFn = {
			address: 0x40C000, name: 'exclusive_path', size: 0x20, endAddress: 0x40C020,
			callers: [], callees: [],
			instructions: [
				instruction(0x40C000, 'lea', 'r8, [rsp + 0x80]'),
				instruction(0x40C001, 'jne', '0x40c004', { jump: true, conditional: true, target: 0x40C004 }),
				instruction(0x40C002, 'call', '0x520000', { call: true, target: 0x520000 }),
				instruction(0x40C003, 'jmp', '0x40c006', { jump: true, target: 0x40C006 }),
				instruction(0x40C004, 'lea', 'rcx, [rsp + 0x80]'),
				instruction(0x40C005, 'call', '0x520010', { call: true, target: 0x520010 }),
				instruction(0x40C006, 'ret', '', { ret: true }),
			],
		};
		const pathSeeds: ValueFlowFactSeed[] = [
			{ kind: 'path-producer', functionAddress: '0x40C000', functionName: pathFn.name, api: 'KERNEL32.dll!GetFullPathNameW', callSite: '0x40C002' },
			{ kind: 'handle-open', functionAddress: '0x40C000', functionName: pathFn.name, api: 'KERNEL32.dll!CreateFileW', callSite: '0x40C005' },
		];
		const pathResult = analyzeWindowsValueDataflow([pathFn], pathSeeds);
		assert.strictEqual(pathResult.proofs.length, 0);
		assert.match(pathResult.signals[0].blockers[0], /does not dominate/);

		const handleFn = {
			address: 0x40D000, name: 'exclusive_handle', size: 0x20, endAddress: 0x40D020,
			callers: [], callees: [],
			instructions: [
				instruction(0x40D000, 'jne', '0x40d004', { jump: true, conditional: true, target: 0x40D004 }),
				instruction(0x40D001, 'call', '0x520010', { call: true, target: 0x520010 }),
				instruction(0x40D002, 'mov', 'qword ptr [rbp - 0x20], rax'),
				instruction(0x40D003, 'jmp', '0x40d006', { jump: true, target: 0x40D006 }),
				instruction(0x40D004, 'mov', 'rcx, qword ptr [rbp - 0x20]'),
				instruction(0x40D005, 'call', '0x520020', { call: true, target: 0x520020 }),
				instruction(0x40D006, 'ret', '', { ret: true }),
			],
		};
		const handleSeeds: ValueFlowFactSeed[] = [
			{ kind: 'handle-open', functionAddress: '0x40D000', functionName: handleFn.name, api: 'KERNEL32.dll!CreateFileW', callSite: '0x40D001' },
			{ kind: 'handle-close', functionAddress: '0x40D000', functionName: handleFn.name, api: 'KERNEL32.dll!CloseHandle', callSite: '0x40D005' },
		];
		const handleResult = analyzeWindowsValueDataflow([handleFn], handleSeeds);
		assert.strictEqual(handleResult.proofs.length, 0);
		assert.ok(handleResult.signals.some(signal => signal.kind === 'same-handle'));
	});

	test('requires producer dominance when the producer is optional', () => {
		const pathFn = {
			address: 0x40E000, name: 'optional_path', size: 0x20, endAddress: 0x40E020,
			callers: [], callees: [],
			instructions: [
				instruction(0x40E000, 'lea', 'r8, [rsp + 0x80]'),
				instruction(0x40E001, 'jne', '0x40e003', { jump: true, conditional: true, target: 0x40E003 }),
				instruction(0x40E002, 'call', '0x520000', { call: true, target: 0x520000 }),
				instruction(0x40E003, 'lea', 'rcx, [rsp + 0x80]'),
				instruction(0x40E004, 'call', '0x520010', { call: true, target: 0x520010 }),
				instruction(0x40E005, 'ret', '', { ret: true }),
			],
		};
		const pathResult = analyzeWindowsValueDataflow([pathFn], [
			{ kind: 'path-producer', functionAddress: '0x40E000', functionName: pathFn.name, api: 'KERNEL32.dll!GetFullPathNameW', callSite: '0x40E002' },
			{ kind: 'handle-open', functionAddress: '0x40E000', functionName: pathFn.name, api: 'KERNEL32.dll!CreateFileW', callSite: '0x40E004' },
		]);
		assert.strictEqual(pathResult.proofs.length, 0);
		assert.match(pathResult.signals[0].blockers[0], /does not dominate/);

		const handleFn = {
			address: 0x40F000, name: 'optional_handle', size: 0x20, endAddress: 0x40F020,
			callers: [], callees: [],
			instructions: [
				instruction(0x40F000, 'jne', '0x40f003', { jump: true, conditional: true, target: 0x40F003 }),
				instruction(0x40F001, 'call', '0x520010', { call: true, target: 0x520010 }),
				instruction(0x40F002, 'mov', 'qword ptr [rbp - 0x20], rax'),
				instruction(0x40F003, 'mov', 'rcx, qword ptr [rbp - 0x20]'),
				instruction(0x40F004, 'call', '0x520020', { call: true, target: 0x520020 }),
				instruction(0x40F005, 'ret', '', { ret: true }),
			],
		};
		const handleResult = analyzeWindowsValueDataflow([handleFn], [
			{ kind: 'handle-open', functionAddress: '0x40F000', functionName: handleFn.name, api: 'KERNEL32.dll!CreateFileW', callSite: '0x40F001' },
			{ kind: 'handle-close', functionAddress: '0x40F000', functionName: handleFn.name, api: 'KERNEL32.dll!CloseHandle', callSite: '0x40F004' },
		]);
		assert.strictEqual(handleResult.proofs.length, 0);
		assert.ok(handleResult.signals.some(signal => signal.kind === 'same-handle'));
	});

	test('finds path writes reached through a backward CFG edge', () => {
		const fn = {
			address: 0x410000, name: 'backedge_write', size: 0x20, endAddress: 0x410020,
			callers: [], callees: [],
			instructions: [
				instruction(0x410000, 'lea', 'r8, [rsp + 0x80]'),
				instruction(0x410001, 'jmp', '0x410004', { jump: true, target: 0x410004 }),
				instruction(0x410002, 'mov', 'byte ptr [rsp + 0x80], 0'),
				instruction(0x410003, 'jmp', '0x410006', { jump: true, target: 0x410006 }),
				instruction(0x410004, 'call', '0x520000', { call: true, target: 0x520000 }),
				instruction(0x410005, 'jmp', '0x410002', { jump: true, target: 0x410002 }),
				instruction(0x410006, 'lea', 'rcx, [rsp + 0x80]'),
				instruction(0x410007, 'call', '0x520010', { call: true, target: 0x520010 }),
				instruction(0x410008, 'ret', '', { ret: true }),
			],
		};
		const result = analyzeWindowsValueDataflow([fn], [
			{ kind: 'path-producer', functionAddress: '0x410000', functionName: fn.name, api: 'KERNEL32.dll!GetFullPathNameW', callSite: '0x410004' },
			{ kind: 'handle-open', functionAddress: '0x410000', functionName: fn.name, api: 'KERNEL32.dll!CreateFileW', callSite: '0x410007' },
		]);
		assert.strictEqual(result.proofs.length, 0);
		assert.match(result.signals[0].blockers[0], /Direct write at 0x410002 may overlap/);
	});

	test('preserves same-path across a summarized read-only pointer argument', () => {
		const fn = {
			address: 0x406000, name: 'inspect_then_open', size: 0x40, endAddress: 0x406040,
			callers: [], callees: [],
			instructions: [
				instruction(0x406000, 'mov', 'edx, 0x100'),
				instruction(0x406001, 'lea', 'r8, [rsp + 0x80]'),
				instruction(0x406002, 'call', '0x520000', { call: true, target: 0x520000 }),
				instruction(0x406003, 'lea', 'rcx, [rsp + 0x80]'),
				instruction(0x406004, 'call', '0x520020', { call: true, target: 0x520020 }),
				instruction(0x406005, 'lea', 'rcx, [rsp + 0x80]'),
				instruction(0x406006, 'call', '0x520010', { call: true, target: 0x520010 }),
			],
		};
		const seeds: ValueFlowFactSeed[] = [
			{ kind: 'path-producer', functionAddress: '0x406000', functionName: 'inspect_then_open', api: 'KERNEL32.dll!GetFullPathNameW', callSite: '0x406002' },
			{ kind: 'path-observer', functionAddress: '0x406000', functionName: 'inspect_then_open', api: 'KERNEL32.dll!lstrlenW', callSite: '0x406004' },
			{ kind: 'handle-open', functionAddress: '0x406000', functionName: 'inspect_then_open', api: 'KERNEL32.dll!CreateFileW', callSite: '0x406006' },
		];
		const result = analyzeWindowsValueDataflow([fn], seeds);
		assert.strictEqual(result.proofs.filter(proof => proof.kind === 'same-path').length, 1);
		assert.deepStrictEqual(result.signals, []);
	});

	test('does not assess deep identity for non-Win64 targets', () => {
		const result = analyzeWindowsValueDataflow([], [], 'x86');
		assert.strictEqual(result.status, 'not-assessed');
		assert.deepStrictEqual(result.proofs, []);
		assert.deepStrictEqual(result.signals, []);
	});
});

function toAddress(address: number): string {
	return `0x${address.toString(16).toUpperCase()}`;
}
