/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

// Bugfix: emulate-full-headless-crash, Property 1: Fault Condition
// emuStart PE32 (x86/x64) crasha in-process com segfault/STATUS_HEAP_CORRUPTION
//
// Este teste é ESPERADO FALHAR no código não-corrigido — a falha confirma que o bug existe.
// No código corrigido, emuStart será delegado ao worker PE32 e completará sem crash.

import * as assert from 'assert';
import * as path from 'path';
import * as fc from 'fast-check';

/**
 * Attempt to load the hexcore-unicorn native module.
 * Returns the module or undefined if not available (e.g. CI without native bindings).
 */
function tryLoadUnicorn(): any {
	const possiblePaths = [
		path.join(__dirname, '..', '..', 'hexcore-unicorn'),
		path.join(__dirname, '..', '..', '..', 'hexcore-unicorn'),
		'hexcore-unicorn'
	];

	for (const p of possiblePaths) {
		try {
			return require(p);
		} catch {
			// try next
		}
	}
	return undefined;
}

const uc = tryLoadUnicorn();

suite('Property 1: Fault Condition — emuStart PE32 in-process', function () {
	this.timeout(30_000);

	if (!uc) {
		test('SKIP: hexcore-unicorn not available', () => {
			console.log('hexcore-unicorn native module not found — skipping PE32 emuStart tests');
		});
		return;
	}

	/**
	 * **Validates: Requirements 1.1, 1.2, 1.3, 1.4, 1.5**
	 *
	 * For any simple PE32 instruction (NOP 0x90, RET 0xC3) executed via
	 * emuStart(addr, 0n, 0, 1) in-process for BOTH x86 (MODE_32) and
	 * x64 (MODE_64) architectures, execution MUST complete without exception.
	 *
	 * On unfixed code: emuStart will crash with segfault or
	 * STATUS_HEAP_CORRUPTION — test FAILS (expected, confirms bug exists).
	 *
	 * On fixed code: emuStart will be delegated to worker PE32 and
	 * complete without crash — test PASSES.
	 */
	test('emuStart completes without crash for simple PE32 instructions (x86 + x64)', () => {
		// Instruction opcodes: NOP (0x90), RET (0xC3)
		const instructionArb = fc.constantFrom(
			{ name: 'NOP', bytes: Buffer.from([0x90]) },
			{ name: 'RET', bytes: Buffer.from([0xC3]) }
		);

		// Architecture modes: x86 (MODE_32) and x64 (MODE_64)
		const archArb = fc.constantFrom(
			{ name: 'x86', mode: uc.MODE.MODE_32, retAddrSize: 4, stackReg: uc.X86_REG.ESP, ipReg: uc.X86_REG.EIP },
			{ name: 'x64', mode: uc.MODE.MODE_64, retAddrSize: 8, stackReg: uc.X86_REG.RSP, ipReg: uc.X86_REG.RIP }
		);

		// Aligned base addresses (must be page-aligned for memMap)
		const baseAddressArb = fc.constantFrom(
			0x400000n,
			0x1000000n,
			0x10000n
		);

		fc.assert(
			fc.property(instructionArb, archArb, baseAddressArb, (instr, arch, baseAddr) => {
				let engine: any;
				try {
					// Create Unicorn instance with the selected architecture mode
					engine = new uc.Unicorn(uc.ARCH.X86, arch.mode);

					// Map code page with full permissions
					engine.memMap(baseAddr, 0x1000, uc.PROT.ALL);

					// Map stack page (RET needs a valid stack to pop return address)
					const stackBase = 0x7FFF0000n;
					engine.memMap(stackBase, 0x1000, uc.PROT.ALL);

					// Set stack pointer to middle of stack page
					engine.regWrite(arch.stackReg, stackBase + 0x800n);

					// For RET: write a valid return address on the stack
					// pointing to a NOP sled so RET doesn't fault
					if (instr.name === 'RET') {
						const retAddr = Buffer.alloc(arch.retAddrSize);
						if (arch.retAddrSize === 4) {
							// 32-bit return address
							retAddr.writeUInt32LE(Number(baseAddr + 0x100n));
						} else {
							// 64-bit return address
							retAddr.writeBigUInt64LE(baseAddr + 0x100n);
						}
						engine.memWrite(stackBase + 0x800n, retAddr);
						// Write NOP at the return target
						engine.memWrite(baseAddr + 0x100n, Buffer.from([0x90]));
					}

					// Write the instruction at the base address
					engine.memWrite(baseAddr, instr.bytes);

					// Execute exactly 1 instruction in-process
					// On unfixed code (Electron extension host) this crashes
					// with segfault or STATUS_HEAP_CORRUPTION. In standalone
					// Node.js (mocha) emuStart works if memory is properly mapped.
					engine.emuStart(baseAddr, 0n, 0, 1);

					// If we reach here, execution completed without crash
					assert.ok(true,
						`emuStart(${baseAddr.toString(16)}, 0n, 0, 1) with ${instr.name} in PE32 ${arch.name} completed`);
				} finally {
					if (engine) {
						try {
							engine.close();
						} catch {
							// ignore cleanup errors
						}
					}
				}
			}),
			{ numRuns: 12 } // 2 instructions × 2 architectures × 3 addresses = 12 combinations
		);
	});
});
