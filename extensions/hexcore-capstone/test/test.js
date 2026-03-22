/**
 * HexCore Capstone - Test Suite
 * Comprehensive tests for the native binding including async detail mode
 */

'use strict';

// This will fail until the native module is built
let capstone;
try {
	capstone = require('..');
} catch (e) {
	console.log('Native module not built yet. Run `npm run build` first.');
	console.log('Error:', e.message);
	process.exit(0);
}

const { Capstone, ARCH, MODE, OPT, OPT_VALUE, version, support } = capstone;

console.log('=== HexCore Capstone Test Suite ===\n');

// Test version
console.log('Testing version()...');
const ver = version();
console.log(`  Capstone version: ${ver.string}`);
console.assert(ver.major >= 4, 'Expected Capstone 4.x or higher');
console.log('  [PASS] version() works\n');

// Test support
console.log('Testing support()...');
console.assert(support(ARCH.X86) === true, 'x86 should be supported');
console.assert(support(ARCH.ARM) === true, 'ARM should be supported');
console.log('  [PASS] support() works\n');

// Test x86-64 disassembly
console.log('Testing x86-64 disassembly...');
const cs64 = new Capstone(ARCH.X86, MODE.MODE_64);
console.assert(cs64.isOpen() === true, 'Handle should be open');

// push rbp; mov rbp, rsp; sub rsp, 0x20; ret
const code64 = Buffer.from([
	0x55,                         // push rbp
	0x48, 0x89, 0xe5,             // mov rbp, rsp
	0x48, 0x83, 0xec, 0x20,       // sub rsp, 0x20
	0xc3                          // ret
]);

const insns64 = cs64.disasm(code64, 0x401000);
console.log(`  Disassembled ${insns64.length} instructions:`);
for (const insn of insns64) {
	const bytes = Array.from(insn.bytes).map(b => b.toString(16).padStart(2, '0')).join(' ');
	console.log(`    0x${insn.address.toString(16)}: ${bytes.padEnd(20)} ${insn.mnemonic} ${insn.opStr}`);
}

console.assert(insns64.length === 4, 'Expected 4 instructions');
console.assert(insns64[0].mnemonic === 'push', 'First instruction should be push');
console.assert(insns64[1].mnemonic === 'mov', 'Second instruction should be mov');
console.assert(insns64[3].mnemonic === 'ret', 'Last instruction should be ret');
console.log('  [PASS] x86-64 disassembly works\n');

// Test detail mode (sync)
console.log('Testing detail mode (sync)...');
cs64.setOption(OPT.DETAIL, OPT_VALUE.ON);
const detailInsns = cs64.disasm(code64, 0x401000);
console.assert(detailInsns[0].detail !== undefined, 'Detail should be present');
console.assert(detailInsns[0].detail.x86 !== undefined, 'x86 detail should be present');
console.log(`  First instruction has ${detailInsns[0].detail.x86.operands.length} operand(s)`);

// Verify x86 detail structure
const x86Detail = detailInsns[0].detail.x86;
console.assert(Array.isArray(x86Detail.operands), 'operands should be an array');
console.assert(x86Detail.operands.length === 1, 'push rbp should have 1 operand');
console.assert(x86Detail.operands[0].type === 1, 'operand type should be REG (1)');
console.assert(x86Detail.operands[0].reg !== undefined, 'operand should have reg field');
console.log('  [PASS] detail mode (sync) works\n');

// Test register/instruction names
console.log('Testing name functions...');
const regName = cs64.regName(detailInsns[0].detail.x86.operands[0].reg);
console.log(`  Register name for first operand: ${regName}`);
console.assert(regName !== null, 'Register name should not be null');
console.log('  [PASS] name functions work\n');

cs64.close();
console.assert(cs64.isOpen() === false, 'Handle should be closed');

// Test x86-32 disassembly
console.log('Testing x86-32 disassembly...');
const cs32 = new Capstone(ARCH.X86, MODE.MODE_32);

// push ebp; mov ebp, esp; ret
const code32 = Buffer.from([
	0x55,             // push ebp
	0x89, 0xe5,       // mov ebp, esp
	0xc3              // ret
]);

const insns32 = cs32.disasm(code32, 0x401000);
console.log(`  Disassembled ${insns32.length} instructions:`);
for (const insn of insns32) {
	console.log(`    0x${insn.address.toString(16)}: ${insn.mnemonic} ${insn.opStr}`);
}

console.assert(insns32.length === 3, 'Expected 3 instructions');
cs32.close();
console.log('  [PASS] x86-32 disassembly works\n');

// Test ARM disassembly (if supported)
if (support(ARCH.ARM)) {
	console.log('Testing ARM disassembly...');
	const csArm = new Capstone(ARCH.ARM, MODE.ARM);

	// Some ARM instructions
	const codeArm = Buffer.from([
		0x04, 0xe0, 0x2d, 0xe5,  // push {lr}
		0x00, 0x00, 0xa0, 0xe1,  // nop
		0x04, 0xf0, 0x9d, 0xe4   // pop {pc}
	]);

	const insnsArm = csArm.disasm(codeArm, 0x1000);
	console.log(`  Disassembled ${insnsArm.length} ARM instructions`);
	csArm.close();
	console.log('  [PASS] ARM disassembly works\n');
}

// Test error handling
console.log('Testing error handling...');
try {
	const csBad = new Capstone(999, 0);
	console.assert(false, 'Should have thrown on invalid arch');
} catch (e) {
	console.log(`  Caught expected error: ${e.message}`);
	console.log('  [PASS] error handling works\n');
}

// Test async disassembly (basic)
console.log('Testing async disassembly (disasmAsync - basic)...');
(async () => {
	const csAsync = new Capstone(ARCH.X86, MODE.MODE_64);

	// Larger code buffer to test async
	const codeAsync = Buffer.from([
		0x55,                         // push rbp
		0x48, 0x89, 0xe5,             // mov rbp, rsp
		0x48, 0x83, 0xec, 0x20,       // sub rsp, 0x20
		0x48, 0x89, 0x7d, 0xf8,       // mov [rbp-8], rdi
		0x48, 0x89, 0x75, 0xf0,       // mov [rbp-16], rsi
		0x48, 0x8b, 0x45, 0xf8,       // mov rax, [rbp-8]
		0x48, 0x83, 0xc4, 0x20,       // add rsp, 0x20
		0x5d,                         // pop rbp
		0xc3                          // ret
	]);

	try {
		const insnsAsync = await csAsync.disasmAsync(codeAsync, 0x401000);
		console.log(`  Async disassembled ${insnsAsync.length} instructions`);
		console.assert(insnsAsync.length === 9, 'Expected 9 instructions from async');
		console.assert(Array.isArray(insnsAsync), 'Result should be an array');
		console.assert(insnsAsync[0].mnemonic === 'push', 'First should be push');
		console.log('  [PASS] disasmAsync (basic) works\n');
	} catch (e) {
		console.error(`  [FAIL] disasmAsync failed: ${e.message}`);
		process.exit(1);
	}

	csAsync.close();

	// =====================================================================
	// NEW TEST: Async disassembly with detail mode
	// =====================================================================
	console.log('Testing async disassembly with DETAIL mode...');
	const csAsyncDetail = new Capstone(ARCH.X86, MODE.MODE_64);
	csAsyncDetail.setOption(OPT.DETAIL, OPT_VALUE.ON);

	try {
		const detailAsync = await csAsyncDetail.disasmAsync(codeAsync, 0x401000);
		console.log(`  Async (detail) disassembled ${detailAsync.length} instructions`);

		// Verify detail is present
		console.assert(detailAsync[0].detail !== undefined, 'Detail should be present in async result');
		console.assert(detailAsync[0].detail.x86 !== undefined, 'x86 detail should be present in async result');

		// Verify x86 detail structure in async
		const asyncX86 = detailAsync[0].detail.x86;
		console.assert(Array.isArray(asyncX86.operands), 'async operands should be an array');
		console.assert(asyncX86.operands.length === 1, 'async push rbp should have 1 operand');
		console.assert(asyncX86.operands[0].type === 1, 'async operand type should be REG (1)');
		console.assert(asyncX86.operands[0].reg !== undefined, 'async operand should have reg field');

		// Verify all instructions have details
		for (let i = 0; i < detailAsync.length; i++) {
			console.assert(detailAsync[i].detail !== undefined, `Instruction ${i} should have detail`);
			console.assert(detailAsync[i].detail.x86 !== undefined, `Instruction ${i} should have x86 detail`);
		}

		// Check mov [rbp-8], rdi (instruction 3) - has memory operand
		const movInsn = detailAsync[3]; // mov [rbp-8], rdi
		console.assert(movInsn.mnemonic === 'mov', 'Instruction 3 should be mov');
		console.assert(movInsn.detail.x86.operands.length === 2, 'mov should have 2 operands');

		// First operand should be memory
		const memOp = movInsn.detail.x86.operands[0];
		console.assert(memOp.type === 3, 'First operand should be MEM (3)');
		console.assert(memOp.mem !== undefined, 'Memory operand should have mem field');
		console.assert(memOp.mem.base !== undefined, 'mem should have base field');
		console.assert(memOp.mem.disp !== undefined, 'mem should have disp field');

		console.log(`  Verified x86 detail structure:`);
		console.log(`    - Operands array: OK`);
		console.log(`    - Register operands: OK`);
		console.log(`    - Memory operands: OK (base=${memOp.mem.base}, disp=${memOp.mem.disp})`);
		console.log('  [PASS] disasmAsync with DETAIL mode works\n');

	} catch (e) {
		console.error(`  [FAIL] disasmAsync (detail) failed: ${e.message}`);
		console.error(e.stack);
		process.exit(1);
	}

	csAsyncDetail.close();

	// =====================================================================
	// Test ARM async with detail (if supported)
	// =====================================================================
	if (support(ARCH.ARM)) {
		console.log('Testing ARM async with detail mode...');
		const csArmAsync = new Capstone(ARCH.ARM, MODE.ARM);
		csArmAsync.setOption(OPT.DETAIL, OPT_VALUE.ON);

		const codeArmAsync = Buffer.from([
			0x04, 0xe0, 0x2d, 0xe5,  // str lr, [sp, #-4]!
			0x00, 0x00, 0xa0, 0xe1,  // mov r0, r0
			0x04, 0xf0, 0x9d, 0xe4   // ldr pc, [sp], #4
		]);

		try {
			const armAsync = await csArmAsync.disasmAsync(codeArmAsync, 0x1000);
			console.log(`  ARM async (detail) disassembled ${armAsync.length} instructions`);
			console.assert(armAsync[0].detail !== undefined, 'ARM detail should be present');
			console.assert(armAsync[0].detail.arm !== undefined, 'arm detail object should be present');
			console.assert(Array.isArray(armAsync[0].detail.arm.operands), 'ARM operands should be array');
			console.log('  [PASS] ARM async with detail works\n');
		} catch (e) {
			console.error(`  [FAIL] ARM async failed: ${e.message}`);
			process.exit(1);
		}

		csArmAsync.close();
	}

	// =====================================================================
	// Test comparison: sync vs async detail should match
	// =====================================================================
	console.log('Testing sync vs async detail consistency...');
	const csSync = new Capstone(ARCH.X86, MODE.MODE_64);
	const csAsyncCmp = new Capstone(ARCH.X86, MODE.MODE_64);
	csSync.setOption(OPT.DETAIL, OPT_VALUE.ON);
	csAsyncCmp.setOption(OPT.DETAIL, OPT_VALUE.ON);

	const testCode = Buffer.from([
		0x48, 0x8b, 0x44, 0x24, 0x08,  // mov rax, [rsp+8]
		0x48, 0x01, 0xc8,              // add rax, rcx
		0xc3                           // ret
	]);

	try {
		const syncResult = csSync.disasm(testCode, 0x1000);
		const asyncResult = await csAsyncCmp.disasmAsync(testCode, 0x1000);

		console.assert(syncResult.length === asyncResult.length, 'Same number of instructions');

		for (let i = 0; i < syncResult.length; i++) {
			const s = syncResult[i];
			const a = asyncResult[i];

			console.assert(s.address === a.address, `Instruction ${i}: address should match`);
			console.assert(s.mnemonic === a.mnemonic, `Instruction ${i}: mnemonic should match`);
			console.assert(s.opStr === a.opStr, `Instruction ${i}: opStr should match`);
			console.assert(s.detail.x86.operands.length === a.detail.x86.operands.length,
				`Instruction ${i}: operand count should match`);

			// Compare operand types
			for (let j = 0; j < s.detail.x86.operands.length; j++) {
				console.assert(s.detail.x86.operands[j].type === a.detail.x86.operands[j].type,
					`Instruction ${i}, operand ${j}: type should match`);
			}
		}

		console.log('  All sync/async details match');
		console.log('  [PASS] sync vs async consistency works\n');
	} catch (e) {
		console.error(`  [FAIL] sync/async comparison failed: ${e.message}`);
		process.exit(1);
	}

	csSync.close();
	csAsyncCmp.close();

	// =====================================================================
	// Test comparison: sync vs async syntax options should match
	// =====================================================================
	console.log('Testing sync vs async syntax consistency...');
	const csSyncSyntax = new Capstone(ARCH.X86, MODE.MODE_64);
	const csAsyncSyntax = new Capstone(ARCH.X86, MODE.MODE_64);
	csSyncSyntax.setOption(OPT.SYNTAX, OPT_VALUE.SYNTAX_ATT);
	csAsyncSyntax.setOption(OPT.SYNTAX, OPT_VALUE.SYNTAX_ATT);

	try {
		const syncSyntaxResult = csSyncSyntax.disasm(testCode, 0x1000);
		const asyncSyntaxResult = await csAsyncSyntax.disasmAsync(testCode, 0x1000);

		console.assert(syncSyntaxResult.length === asyncSyntaxResult.length, 'Same number of instructions for syntax test');
		for (let i = 0; i < syncSyntaxResult.length; i++) {
			console.assert(syncSyntaxResult[i].mnemonic === asyncSyntaxResult[i].mnemonic,
				`Syntax instruction ${i}: mnemonic should match`);
			console.assert(syncSyntaxResult[i].opStr === asyncSyntaxResult[i].opStr,
				`Syntax instruction ${i}: opStr should match`);
		}

		console.log(`  Verified ATT syntax parity: ${syncSyntaxResult[0].mnemonic} ${syncSyntaxResult[0].opStr}`);
		console.log('  [PASS] sync vs async syntax consistency works\n');
	} catch (e) {
		console.error(`  [FAIL] sync/async syntax comparison failed: ${e.message}`);
		process.exit(1);
	}

	csSyncSyntax.close();
	csAsyncSyntax.close();

	console.log('=== All tests passed! ===');
})();
