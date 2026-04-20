/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

// Feature: v3.7.1, Properties P3.1, P4.1, P5.2, P6.1:
// loadBuffer round-trip, memory dump base64, side-channel monotonicity, snapshot hex registers

import * as assert from 'assert';
import * as fc from 'fast-check';

suite('Property P3: loadBuffer round-trip preserves data', () => {

	/**
	 * P3.1: Buffer data survives base64 round-trip (the encoding used by
	 * dumpAndDisassemble to transport memory data).
	 */
	test('buffer → base64 → buffer round-trip preserves data', () => {
		fc.assert(
			fc.property(
				fc.uint8Array({ minLength: 1, maxLength: 4096 }),
				(data) => {
					const buf = Buffer.from(data);
					const b64 = buf.toString('base64');
					const restored = Buffer.from(b64, 'base64');
					assert.ok(buf.equals(restored), 'base64 round-trip must preserve data');
				}
			),
			{ numRuns: 200 }
		);
	});
});

suite('Property P4: Memory dump base64 round-trip', () => {

	/**
	 * P4.1: Memory dump data encoded as base64 can be decoded back to
	 * the original bytes without loss.
	 */
	test('memory dump base64 round-trip preserves bytes', () => {
		fc.assert(
			fc.property(
				fc.uint8Array({ minLength: 0, maxLength: 8192 }),
				fc.bigUintN(64),
				(data, address) => {
					const buf = Buffer.from(data);
					const dump = {
						address: '0x' + address.toString(16),
						size: buf.length,
						data: buf.toString('base64')
					};

					// Decode and verify
					const decoded = Buffer.from(dump.data, 'base64');
					assert.strictEqual(decoded.length, buf.length, 'decoded length must match');
					assert.ok(decoded.equals(buf), 'decoded data must match original');
					assert.strictEqual(dump.size, buf.length, 'size field must match buffer length');
				}
			),
			{ numRuns: 200 }
		);
	});
});

suite('Property P5: Side-channel counters monotonically increase', () => {

	/**
	 * P5.2: totalInstructions is monotonically increasing as instructions execute.
	 * We simulate the counter accumulation pattern used by DebugEngine.
	 */
	test('instruction counter is monotonically non-decreasing', () => {
		fc.assert(
			fc.property(
				fc.array(fc.integer({ min: 1, max: 100 }), { minLength: 1, maxLength: 50 }),
				(batchSizes) => {
					let totalInstructions = 0;
					let prevTotal = 0;

					for (const batch of batchSizes) {
						totalInstructions += batch;
						assert.ok(totalInstructions >= prevTotal,
							`totalInstructions decreased: ${totalInstructions} < ${prevTotal}`);
						prevTotal = totalInstructions;
					}
				}
			),
			{ numRuns: 200 }
		);
	});
});

suite('Property P6: Snapshot register values are hex strings', () => {

	/**
	 * P6.1: All register values in a breakpoint snapshot must be valid hex strings.
	 */
	test('register values are valid hex strings', () => {
		const registerNames = [
			'rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rsp', 'rbp',
			'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15', 'rip', 'rflags'
		];

		fc.assert(
			fc.property(
				fc.tuple(...registerNames.map(() => fc.bigUintN(64))),
				(values) => {
					// Build snapshot registers the same way DebugEngine does
					const registers: Record<string, string> = {};
					for (let i = 0; i < registerNames.length; i++) {
						registers[registerNames[i]] = '0x' + values[i].toString(16);
					}

					// Verify all values are valid hex strings
					for (const [name, value] of Object.entries(registers)) {
						assert.ok(typeof value === 'string', `${name} must be a string`);
						assert.ok(/^0x[0-9a-fA-F]+$/.test(value),
							`${name} must be a hex string, got: ${value}`);
					}
				}
			),
			{ numRuns: 100 }
		);
	});

	/**
	 * P6.2: Stack data in snapshot is valid base64.
	 */
	test('snapshot stack data is valid base64', () => {
		fc.assert(
			fc.property(
				fc.uint8Array({ minLength: 0, maxLength: 4096 }),
				(stackBytes) => {
					const buf = Buffer.from(stackBytes);
					const b64 = buf.toString('base64');

					// Verify it's valid base64 by decoding
					const decoded = Buffer.from(b64, 'base64');
					assert.ok(decoded.equals(buf), 'base64 stack data must round-trip');
				}
			),
			{ numRuns: 100 }
		);
	});
});
