/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

// Bugfix: emulate-full-headless-crash, Property 2: Preservation
// Operações de memória e registradores PE32 (x86/x64) preservadas
//
// Estes testes DEVEM PASSAR no código não-corrigido — confirmam baseline de
// comportamento a preservar. memMap/memWrite/memRead e regWrite/regRead
// funcionam corretamente in-process na fase de carregamento PE; o bug é
// apenas no emuStart.

import * as assert from 'assert';
import * as path from 'path';
import * as fc from 'fast-check';

/**
 * Attempt to load the hexcore-unicorn native module.
 * Returns the module or undefined if not available.
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

suite('Property 2: Preservation — memória e registradores PE32 (x86 + x64)', function () {
	this.timeout(30_000);

	if (!uc) {
		test('SKIP: hexcore-unicorn not available', () => {
			console.log('hexcore-unicorn native module not found — skipping preservation tests');
		});
		return;
	}

	// -----------------------------------------------------------------------
	// Arbitraries
	// -----------------------------------------------------------------------

	/** Aligned addresses: multiples of 0x1000 in [0x10000, 0x7FFF0000] */
	const alignedAddressArb = fc.integer({ min: 0x10, max: 0x7FFF0 })
		.map(n => BigInt(n) * 0x1000n);

	/** Buffer sizes: 1..256 bytes */
	const bufferArb = fc.uint8Array({ minLength: 1, maxLength: 256 })
		.map(arr => Buffer.from(arr));

	/** x64 register values: bigint in [0, 2^64 - 1] */
	const regValue64Arb = fc.bigUintN(64);

	/** x86 register values: bigint in [0, 2^32 - 1] */
	const regValue32Arb = fc.bigUintN(32);

	/** Safe x64 register IDs (exclude RSP, RBP, RIP, RFLAGS — side effects) */
	const safeRegister64Arb = fc.constantFrom(
		uc.X86_REG.RAX,
		uc.X86_REG.RBX,
		uc.X86_REG.RCX,
		uc.X86_REG.RDX,
		uc.X86_REG.RSI,
		uc.X86_REG.RDI,
		uc.X86_REG.R8,
		uc.X86_REG.R9,
		uc.X86_REG.R10,
		uc.X86_REG.R11,
		uc.X86_REG.R12,
		uc.X86_REG.R13,
		uc.X86_REG.R14,
		uc.X86_REG.R15
	);

	/** Safe x86 register IDs (exclude ESP, EBP, EIP, EFLAGS — side effects) */
	const safeRegister32Arb = fc.constantFrom(
		uc.X86_REG.EAX,
		uc.X86_REG.EBX,
		uc.X86_REG.ECX,
		uc.X86_REG.EDX,
		uc.X86_REG.ESI,
		uc.X86_REG.EDI
	);

	// -----------------------------------------------------------------------
	// Property 1: memWrite/memRead roundtrip preserves data (PE32 loading phase)
	// -----------------------------------------------------------------------

	/**
	 * **Validates: Requirements 3.5**
	 *
	 * Property 1a (memWrite/memRead roundtrip — x64 MODE_64):
	 * For any buffer `buf` and aligned address `addr`,
	 * memWrite(addr, buf) followed by memRead(addr, buf.length) returns `buf` identically.
	 * Tests the PE loading phase (in-process) for x64 architecture.
	 */
	test('memWrite/memRead roundtrip preserves data (x64 MODE_64)', () => {
		fc.assert(
			fc.property(alignedAddressArb, bufferArb, (addr, buf) => {
				let engine: any;
				try {
					engine = new uc.Unicorn(uc.ARCH.X86, uc.MODE.MODE_64);
					engine.memMap(addr, 0x1000, uc.PROT.ALL);
					engine.memWrite(addr, buf);
					const readBack: Buffer = engine.memRead(addr, buf.length);
					assert.ok(
						buf.equals(readBack),
						`memRead mismatch at 0x${addr.toString(16)} for ${buf.length} bytes (x64)`
					);
				} finally {
					if (engine) {
						try { engine.close(); } catch { /* ignore */ }
					}
				}
			}),
			{ numRuns: 20 }
		);
	});

	/**
	 * **Validates: Requirements 3.5**
	 *
	 * Property 1b (memWrite/memRead roundtrip — x86 MODE_32):
	 * For any buffer `buf` and aligned address `addr`,
	 * memWrite(addr, buf) followed by memRead(addr, buf.length) returns `buf` identically.
	 * Tests the PE loading phase (in-process) for x86 architecture.
	 */
	test('memWrite/memRead roundtrip preserves data (x86 MODE_32)', () => {
		fc.assert(
			fc.property(alignedAddressArb, bufferArb, (addr, buf) => {
				let engine: any;
				try {
					engine = new uc.Unicorn(uc.ARCH.X86, uc.MODE.MODE_32);
					engine.memMap(addr, 0x1000, uc.PROT.ALL);
					engine.memWrite(addr, buf);
					const readBack: Buffer = engine.memRead(addr, buf.length);
					assert.ok(
						buf.equals(readBack),
						`memRead mismatch at 0x${addr.toString(16)} for ${buf.length} bytes (x86)`
					);
				} finally {
					if (engine) {
						try { engine.close(); } catch { /* ignore */ }
					}
				}
			}),
			{ numRuns: 20 }
		);
	});

	// -----------------------------------------------------------------------
	// Property 2: regWrite/regRead roundtrip preserves value
	// -----------------------------------------------------------------------

	/**
	 * **Validates: Requirements 3.5**
	 *
	 * Property 2a (regWrite/regRead roundtrip — x64 registers):
	 * For any x64 register `reg` and value `val`,
	 * regWrite(reg, val) followed by regRead(reg) returns `val`.
	 * Tests RAX, RBX, RCX, RDX, RSI, RDI, R8-R15 with 64-bit values.
	 */
	test('regWrite/regRead roundtrip preserves value (x64 registers)', () => {
		fc.assert(
			fc.property(safeRegister64Arb, regValue64Arb, (reg, val) => {
				let engine: any;
				try {
					engine = new uc.Unicorn(uc.ARCH.X86, uc.MODE.MODE_64);
					engine.regWrite(reg, val);
					const readBack = BigInt(engine.regRead(reg));
					assert.strictEqual(
						readBack, val,
						`regRead mismatch for regId=${reg}: wrote ${val}, got ${readBack} (x64)`
					);
				} finally {
					if (engine) {
						try { engine.close(); } catch { /* ignore */ }
					}
				}
			}),
			{ numRuns: 20 }
		);
	});

	/**
	 * **Validates: Requirements 3.5**
	 *
	 * Property 2b (regWrite/regRead roundtrip — x86 registers):
	 * For any x86 register `reg` and value `val`,
	 * regWrite(reg, val) followed by regRead(reg) returns `val`.
	 * Tests EAX, EBX, ECX, EDX, ESI, EDI with 32-bit values.
	 */
	test('regWrite/regRead roundtrip preserves value (x86 registers)', () => {
		fc.assert(
			fc.property(safeRegister32Arb, regValue32Arb, (reg, val) => {
				let engine: any;
				try {
					engine = new uc.Unicorn(uc.ARCH.X86, uc.MODE.MODE_32);
					engine.regWrite(reg, val);
					const readBack = BigInt(engine.regRead(reg));
					assert.strictEqual(
						readBack, val,
						`regRead mismatch for regId=${reg}: wrote ${val}, got ${readBack} (x86)`
					);
				} finally {
					if (engine) {
						try { engine.close(); } catch { /* ignore */ }
					}
				}
			}),
			{ numRuns: 20 }
		);
	});

	// -----------------------------------------------------------------------
	// Property 3: memRegions consistency
	// -----------------------------------------------------------------------

	/**
	 * **Validates: Requirements 3.5**
	 *
	 * Property 3a (memRegions consistency — x64):
	 * For any sequence of memMap with non-overlapping addresses,
	 * memRegions() returns all mapped regions.
	 */
	test('memRegions returns all mapped regions (x64 MODE_64)', () => {
		const distinctAddrsArb = fc.uniqueArray(
			fc.integer({ min: 0x10, max: 0x7FFF0 }),
			{ minLength: 1, maxLength: 4 }
		).map(nums => nums.map(n => BigInt(n) * 0x1000n));

		fc.assert(
			fc.property(distinctAddrsArb, (addrs) => {
				let engine: any;
				try {
					engine = new uc.Unicorn(uc.ARCH.X86, uc.MODE.MODE_64);
					for (const addr of addrs) {
						engine.memMap(addr, 0x1000, uc.PROT.ALL);
					}
					const regions: Array<{ begin: bigint; end: bigint; perms: number }> =
						engine.memRegions();

					for (const addr of addrs) {
						const found = regions.some(
							r => r.begin <= addr && addr < r.end
						);
						assert.ok(
							found,
							`Address 0x${addr.toString(16)} not found in memRegions() (x64)`
						);
					}

					assert.ok(
						regions.length >= 1,
						`Expected at least 1 region, got ${regions.length} (x64)`
					);
				} finally {
					if (engine) {
						try { engine.close(); } catch { /* ignore */ }
					}
				}
			}),
			{ numRuns: 20 }
		);
	});

	/**
	 * **Validates: Requirements 3.5**
	 *
	 * Property 3b (memRegions consistency — x86):
	 * For any sequence of memMap with non-overlapping addresses,
	 * memRegions() returns all mapped regions.
	 */
	test('memRegions returns all mapped regions (x86 MODE_32)', () => {
		const distinctAddrsArb = fc.uniqueArray(
			fc.integer({ min: 0x10, max: 0x7FFF0 }),
			{ minLength: 1, maxLength: 4 }
		).map(nums => nums.map(n => BigInt(n) * 0x1000n));

		fc.assert(
			fc.property(distinctAddrsArb, (addrs) => {
				let engine: any;
				try {
					engine = new uc.Unicorn(uc.ARCH.X86, uc.MODE.MODE_32);
					for (const addr of addrs) {
						engine.memMap(addr, 0x1000, uc.PROT.ALL);
					}
					const regions: Array<{ begin: bigint; end: bigint; perms: number }> =
						engine.memRegions();

					for (const addr of addrs) {
						const found = regions.some(
							r => r.begin <= addr && addr < r.end
						);
						assert.ok(
							found,
							`Address 0x${addr.toString(16)} not found in memRegions() (x86)`
						);
					}

					assert.ok(
						regions.length >= 1,
						`Expected at least 1 region, got ${regions.length} (x86)`
					);
				} finally {
					if (engine) {
						try { engine.close(); } catch { /* ignore */ }
					}
				}
			}),
			{ numRuns: 20 }
		);
	});
});
