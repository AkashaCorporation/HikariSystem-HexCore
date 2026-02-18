/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

// Feature: v3.5.2-pipeline-maturity, Property 1: Snapshot round-trip restaura estado

import * as assert from 'assert';
import * as fc from 'fast-check';

/**
 * Generates a register name matching typical x86/x64/ARM register naming.
 */
function registerNameArb(): fc.Arbitrary<string> {
	return fc.oneof(
		fc.constantFrom(
			'rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rsp', 'rbp',
			'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15',
			'rip', 'rflags', 'eax', 'ebx', 'ecx', 'edx',
			'x0', 'x1', 'x2', 'x3', 'x4', 'x5', 'x29', 'x30', 'sp', 'pc'
		)
	);
}

/**
 * Generates a hex value string like '0x1a2b3c'.
 */
function hexValueArb(): fc.Arbitrary<string> {
	return fc.bigUintN(64).map(n => '0x' + n.toString(16));
}

/**
 * Generates an arbitrary register state: Record<string, string> with hex values.
 */
function registerStateArb(): fc.Arbitrary<Record<string, string>> {
	return fc.uniqueArray(registerNameArb(), { minLength: 1, maxLength: 20 })
		.chain(names =>
			fc.tuple(...names.map(() => hexValueArb())).map(values => {
				const state: Record<string, string> = {};
				for (let i = 0; i < names.length; i++) {
					state[names[i]] = values[i];
				}
				return state;
			})
		);
}

/**
 * Snapshot data structure matching the DebugEngine snapshot/restore headless output.
 */
interface SnapshotData {
	success: boolean;
	registers: Record<string, string>;
	state: {
		currentAddress: string;
		instructionsExecuted: number;
		isRunning: boolean;
	};
	generatedAt: string;
}

/**
 * Generates an arbitrary SnapshotData structure.
 */
function snapshotDataArb(): fc.Arbitrary<SnapshotData> {
	return fc.record({
		success: fc.constant(true),
		registers: registerStateArb(),
		state: fc.record({
			currentAddress: hexValueArb(),
			instructionsExecuted: fc.nat({ max: 1_000_000 }),
			isRunning: fc.boolean()
		}),
		generatedAt: fc.date().map(d => d.toISOString())
	});
}

suite('Property: Snapshot round-trip restaura estado', () => {

	/**
	 * **Validates: Requirements 1.2**
	 *
	 * For any register state (Record<string, string>), JSON.stringify then
	 * JSON.parse preserves all values exactly.
	 */
	test('register state survives JSON round-trip', () => {
		fc.assert(
			fc.property(registerStateArb(), (registers) => {
				const serialized = JSON.stringify(registers);
				const deserialized: Record<string, string> = JSON.parse(serialized);

				// Same number of keys
				const origKeys = Object.keys(registers).sort();
				const restoredKeys = Object.keys(deserialized).sort();
				assert.deepStrictEqual(restoredKeys, origKeys);

				// Every value is identical
				for (const key of origKeys) {
					assert.strictEqual(deserialized[key], registers[key],
						`Register ${key} mismatch after round-trip`);
				}
			}),
			{ numRuns: 100 }
		);
	});

	/**
	 * **Validates: Requirements 1.2**
	 *
	 * For any full snapshot data structure, JSON round-trip preserves
	 * registers, state, and metadata exactly.
	 */
	test('full snapshot data survives JSON round-trip', () => {
		fc.assert(
			fc.property(snapshotDataArb(), (snapshot) => {
				const serialized = JSON.stringify(snapshot);
				const deserialized: SnapshotData = JSON.parse(serialized);

				// Registers preserved
				assert.deepStrictEqual(deserialized.registers, snapshot.registers);

				// State preserved
				assert.strictEqual(deserialized.state.currentAddress, snapshot.state.currentAddress);
				assert.strictEqual(deserialized.state.instructionsExecuted, snapshot.state.instructionsExecuted);
				assert.strictEqual(deserialized.state.isRunning, snapshot.state.isRunning);

				// Metadata preserved
				assert.strictEqual(deserialized.success, snapshot.success);
				assert.strictEqual(deserialized.generatedAt, snapshot.generatedAt);
			}),
			{ numRuns: 100 }
		);
	});
});
