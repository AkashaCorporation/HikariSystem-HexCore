/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

// Feature: v3.5.2-pipeline-maturity, Property 3: Trace entry contém todos os campos obrigatórios

import * as assert from 'assert';
import * as fc from 'fast-check';
import { TraceManager, TraceEntry } from './traceManager';

/**
 * Generates a non-empty alphanumeric string suitable for function/library names.
 */
function nonEmptyNameArb(): fc.Arbitrary<string> {
	return fc.stringOf(
		fc.constantFrom(...'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_'.split('')),
		{ minLength: 1, maxLength: 64 }
	);
}

/**
 * Generates a hex string like '0x1a2b3c'.
 */
function hexStringArb(): fc.Arbitrary<string> {
	return fc.bigUintN(64).map(n => '0x' + n.toString(16));
}

/**
 * Generates a positive timestamp (Date.now()-style).
 */
function positiveTimestampArb(): fc.Arbitrary<number> {
	return fc.integer({ min: 1, max: Number.MAX_SAFE_INTEGER });
}

/**
 * Generates an arbitrary TraceEntry with valid field constraints.
 */
function traceEntryArb(): fc.Arbitrary<TraceEntry> {
	return fc.record({
		functionName: nonEmptyNameArb(),
		library: nonEmptyNameArb(),
		arguments: fc.array(fc.string(), { minLength: 0, maxLength: 10 }),
		returnValue: hexStringArb(),
		pcAddress: hexStringArb(),
		timestamp: positiveTimestampArb(),
	});
}

suite('Property: Trace entry contém todos os campos obrigatórios', () => {

	/**
	 * **Validates: Requirements 2.1, 2.4**
	 *
	 * For any TraceEntry recorded into a TraceManager, the entry returned
	 * by getEntries() MUST contain all required fields with correct types
	 * and constraints: functionName (non-empty string), library (non-empty string),
	 * arguments (array), returnValue (hex string), pcAddress (hex string),
	 * and timestamp (positive number).
	 */
	test('recorded entry preserves all required fields with correct types', () => {
		fc.assert(
			fc.property(traceEntryArb(), (entry) => {
				const manager = new TraceManager();
				manager.record(entry);

				const entries = manager.getEntries();
				assert.strictEqual(entries.length, 1, 'Expected exactly one entry');

				const recorded = entries[0];

				// functionName: non-empty string
				assert.strictEqual(typeof recorded.functionName, 'string');
				assert.ok(recorded.functionName.length > 0, 'functionName must be non-empty');

				// library: non-empty string
				assert.strictEqual(typeof recorded.library, 'string');
				assert.ok(recorded.library.length > 0, 'library must be non-empty');

				// arguments: array
				assert.ok(Array.isArray(recorded.arguments), 'arguments must be an array');

				// returnValue: hex string (starts with 0x)
				assert.strictEqual(typeof recorded.returnValue, 'string');
				assert.ok(/^0x[0-9a-fA-F]+$/.test(recorded.returnValue),
					`returnValue must be a hex string, got: ${recorded.returnValue}`);

				// pcAddress: hex string (starts with 0x)
				assert.strictEqual(typeof recorded.pcAddress, 'string');
				assert.ok(/^0x[0-9a-fA-F]+$/.test(recorded.pcAddress),
					`pcAddress must be a hex string, got: ${recorded.pcAddress}`);

				// timestamp: positive number
				assert.strictEqual(typeof recorded.timestamp, 'number');
				assert.ok(recorded.timestamp > 0, 'timestamp must be positive');
			}),
			{ numRuns: 100 }
		);
	});

	/**
	 * **Validates: Requirements 2.1, 2.4**
	 *
	 * For any TraceEntry recorded, the values returned by getEntries()
	 * MUST be identical to the values that were recorded.
	 */
	test('recorded entry values match original input exactly', () => {
		fc.assert(
			fc.property(traceEntryArb(), (entry) => {
				const manager = new TraceManager();
				manager.record(entry);

				const recorded = manager.getEntries()[0];

				assert.strictEqual(recorded.functionName, entry.functionName);
				assert.strictEqual(recorded.library, entry.library);
				assert.deepStrictEqual(recorded.arguments, entry.arguments);
				assert.strictEqual(recorded.returnValue, entry.returnValue);
				assert.strictEqual(recorded.pcAddress, entry.pcAddress);
				assert.strictEqual(recorded.timestamp, entry.timestamp);
			}),
			{ numRuns: 100 }
		);
	});

	/**
	 * **Validates: Requirements 2.1, 2.4**
	 *
	 * For any batch of TraceEntries recorded, exportJSON() MUST produce
	 * entries where every single entry contains all required fields.
	 */
	test('exportJSON entries all contain required fields', () => {
		fc.assert(
			fc.property(fc.array(traceEntryArb(), { minLength: 1, maxLength: 20 }), (entries) => {
				const manager = new TraceManager();
				for (const entry of entries) {
					manager.record(entry);
				}

				const exported = manager.exportJSON();
				assert.strictEqual(exported.totalEntries, entries.length);

				for (const recorded of exported.entries) {
					assert.strictEqual(typeof recorded.functionName, 'string');
					assert.ok(recorded.functionName.length > 0);
					assert.strictEqual(typeof recorded.library, 'string');
					assert.ok(recorded.library.length > 0);
					assert.ok(Array.isArray(recorded.arguments));
					assert.ok(/^0x[0-9a-fA-F]+$/.test(recorded.returnValue));
					assert.ok(/^0x[0-9a-fA-F]+$/.test(recorded.pcAddress));
					assert.strictEqual(typeof recorded.timestamp, 'number');
					assert.ok(recorded.timestamp > 0);
				}
			}),
			{ numRuns: 100 }
		);
	});
});
