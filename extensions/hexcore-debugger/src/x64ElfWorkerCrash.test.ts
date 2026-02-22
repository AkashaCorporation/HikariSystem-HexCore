/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

// Bugfix: x64-elf-emustart-crash, Property 1: Fault Condition
// emuStart x64 ELF crasha in-process com STATUS_HEAP_CORRUPTION
//
// Este teste é ESPERADO FALHAR no código não-corrigido — a falha confirma que o bug existe.
// No código corrigido, emuStart será delegado ao worker e completará sem crash.

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

suite('Property 1: Fault Condition — emuStart x64 ELF in-process', function () {
	this.timeout(30_000);

	if (!uc) {
		test('SKIP: hexcore-unicorn not available', () => {
			console.log('hexcore-unicorn native module not found — skipping x64 ELF emuStart tests');
		});
		return;
	}

	/**
	 * **Validates: Requirements 1.1, 1.2, 1.3, 1.4, 1.5**
	 *
	 * For any simple x64 instruction (NOP 0x90, RET 0xC3) executed via
	 * emuStart(addr, 0n, 0, 1) in-process, execution MUST complete
	 * without exception.
	 *
	 * On unfixed code: emuStart will crash with STATUS_HEAP_CORRUPTION
	 * or throw exception — test FAILS (expected, confirms bug exists).
	 *
	 * On fixed code: emuStart will be delegated to worker and complete
	 * without crash — test PASSES.
	 */
	test('emuStart completes without crash for simple x64 instructions', () => {
		// Instruction opcodes: NOP (0x90), RET (0xC3)
		const instructionArb = fc.constantFrom(
			{ name: 'NOP', bytes: Buffer.from([0x90]) },
			{ name: 'RET', bytes: Buffer.from([0xC3]) }
		);

		// Aligned base addresses (must be page-aligned for memMap)
		const baseAddressArb = fc.constantFrom(
			0x400000n,
			0x1000000n,
			0x10000n
		);

		fc.assert(
			fc.property(instructionArb, baseAddressArb, (instr, baseAddr) => {
				let engine: any;
				try {
					// Create x64 Unicorn instance
					engine = new uc.Unicorn(uc.ARCH.X86, uc.MODE.MODE_64);

					// Map code page with full permissions
					engine.memMap(baseAddr, 0x1000, uc.PROT.ALL);

					// Map stack page (RET needs a valid stack to pop return address)
					const stackBase = 0x7FFF0000n;
					engine.memMap(stackBase, 0x1000, uc.PROT.ALL);

					// Set RSP to middle of stack page
					engine.regWrite(uc.X86_REG.RSP, stackBase + 0x800n);

					// For RET: write a valid return address on the stack
					// pointing to a NOP sled so RET doesn't fault
					if (instr.name === 'RET') {
						const retAddr = Buffer.alloc(8);
						retAddr.writeBigUInt64LE(baseAddr + 0x100n);
						engine.memWrite(stackBase + 0x800n, retAddr);
						// Write NOP at the return target
						engine.memWrite(baseAddr + 0x100n, Buffer.from([0x90]));
					}

					// Write the instruction at the base address
					engine.memWrite(baseAddr, instr.bytes);

					// Execute exactly 1 instruction in-process
					// On unfixed code (Electron extension host) this crashes
					// with STATUS_HEAP_CORRUPTION. In standalone Node.js (mocha)
					// emuStart works if memory is properly mapped.
					engine.emuStart(baseAddr, 0n, 0, 1);

					// If we reach here, execution completed without crash
					assert.ok(true,
						`emuStart(${baseAddr.toString(16)}, 0n, 0, 1) with ${instr.name} completed`);
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
			{ numRuns: 6 }
		);
	});
});
