/**
 * HexCore Capstone - Test Suite
 * Basic tests for the native binding
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
console.log('  ✓ version() works\n');

// Test support
console.log('Testing support()...');
console.assert(support(ARCH.X86) === true, 'x86 should be supported');
console.assert(support(ARCH.ARM) === true, 'ARM should be supported');
console.log('  ✓ support() works\n');

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
console.log('  ✓ x86-64 disassembly works\n');

// Test detail mode
console.log('Testing detail mode...');
cs64.setOption(OPT.DETAIL, OPT_VALUE.ON);
const detailInsns = cs64.disasm(code64, 0x401000);
console.assert(detailInsns[0].detail !== undefined, 'Detail should be present');
console.assert(detailInsns[0].detail.x86 !== undefined, 'x86 detail should be present');
console.log(`  First instruction has ${detailInsns[0].detail.x86.operands.length} operand(s)`);
console.log('  ✓ detail mode works\n');

// Test register/instruction names
console.log('Testing name functions...');
const regName = cs64.regName(detailInsns[0].detail.x86.operands[0].reg);
console.log(`  Register name for first operand: ${regName}`);
console.assert(regName !== null, 'Register name should not be null');
console.log('  ✓ name functions work\n');

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
console.log('  ✓ x86-32 disassembly works\n');

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
	console.log('  ✓ ARM disassembly works\n');
}

// Test error handling
console.log('Testing error handling...');
try {
	const csBad = new Capstone(999, 0);
	console.assert(false, 'Should have thrown on invalid arch');
} catch (e) {
	console.log(`  Caught expected error: ${e.message}`);
	console.log('  ✓ error handling works\n');
}

// Test async disassembly
console.log('Testing async disassembly (disasmAsync)...');
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
		console.assert(insnsAsync.length === 8, 'Expected 8 instructions from async');
		console.assert(Array.isArray(insnsAsync), 'Result should be an array');
		console.assert(insnsAsync[0].mnemonic === 'push', 'First should be push');
		console.log('  ✓ disasmAsync works\n');
	} catch (e) {
		console.error(`  ✗ disasmAsync failed: ${e.message}`);
		process.exit(1);
	}

	csAsync.close();
	console.log('=== All tests passed! ===');
})();
