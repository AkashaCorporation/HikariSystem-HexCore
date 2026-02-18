/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

// Feature: v3.5.2-pipeline-maturity, Property 4: Trace mantém ordem cronológica

import * as assert from 'assert';
import * as fc from 'fast-check';
import { TraceManager, TraceEntry } from './traceManager';

/**
 * Generates a non-empty alphanumeric string for function/library names.
 */
function nonEmptyNameArb(): fc.Arbitrary<string> {
	return fc.stringOf(
		fc.constantFrom(...'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_'.split('')),
		{ minLength: 1, maxLength: 32 }
	);
}

/**
 * Generates a hex string like '0x1a2b3c'.
 */
function hexStringArb(): fc.Arbitrary<string> {
	return fc.bigUintN(64).map(n => '0x' + n.toString(16));
}

/**
 * Generates an array of TraceEntry with strictly increasing timestamps.
 * This simulates the real-world scenario where API calls are intercepted
 * sequentially during emulation.
 */
function sortedTraceEntriesArb(): fc.Arbitrary<TraceEntry[]> {
	return fc.array(
		fc.record({
			functionName: nonEmptyNameArb(),
			library: nonEmptyNameArb(),
			arguments: fc.array(fc.string(), { minLength: 0, maxLength: 5 }),
			returnValue: hexStringArb(),
			pcAddress: hexStringArb(),
			timestampDelta: fc.integer({ min: 0, max: 1000 }),
		}),
		{ minLength: 2, maxLength: 50 }
	).map(records => {
		let ts = 1000000000000; // base timestamp
		return records.map(r => {
			ts += r.timestampDelta;
			return {
				functionName: r.functionName,
				library: r.library,
				arguments: r.arguments,
				returnValue: r.returnValue,
				pcAddress: r.pcAddress,
				timestamp: ts,
			};
		});
	});
}

suite('Property: Trace mantém ordem cronológica', () => {

	/**
	 * **Validates: Requirements 2.2**
	 *
	 * For any sequence of TraceEntries recorded with increasing timestamps,
	 * getEntries() MUST return them in chronological order — for every
	 * consecutive pair (entry[i], entry[i+1]),
	 * entry[i].timestamp <= entry[i+1].timestamp.
	 */
	test('entries recorded in order are returned in chronological order', () => {
		fc.assert(
			fc.property(sortedTraceEntriesArb(), (entries) => {
				const manager = new TraceManager();
				for (const entry of entries) {
					manager.record(entry);
				}

				const result = manager.getEntries();
				assert.strictEqual(result.length, entries.length,
					'getEntries() must return all recorded entries');

				for (let i = 0; i < result.length - 1; i++) {
					assert.ok(
						result[i].timestamp <= result[i + 1].timestamp,
						`Chronological order violated at index ${i}: ` +
						`entry[${i}].timestamp (${result[i].timestamp}) > ` +
						`entry[${i + 1}].timestamp (${result[i + 1].timestamp})`
					);
				}
			}),
			{ numRuns: 100 }
		);
	});

	/**
	 * **Validates: Requirements 2.2**
	 *
	 * For entries recorded with equal timestamps (simultaneous calls),
	 * getEntries() MUST still maintain insertion order, which satisfies
	 * the <= constraint for chronological ordering.
	 */
	test('entries with equal timestamps preserve insertion order', () => {
		fc.assert(
			fc.property(
				fc.integer({ min: 1, max: Number.MAX_SAFE_INTEGER }),
				fc.array(
					fc.record({
						functionName: nonEmptyNameArb(),
						library: nonEmptyNameArb(),
						arguments: fc.array(fc.string(), { minLength: 0, maxLength: 5 }),
						returnValue: hexStringArb(),
						pcAddress: hexStringArb(),
					}),
					{ minLength: 2, maxLength: 30 }
				),
				(sharedTimestamp, partials) => {
					const manager = new TraceManager();
					const entries: TraceEntry[] = partials.map(p => ({
						...p,
						timestamp: sharedTimestamp,
					}));

					for (const entry of entries) {
						manager.record(entry);
					}

					const result = manager.getEntries();
					assert.strictEqual(result.length, entries.length);

					for (let i = 0; i < result.length - 1; i++) {
						assert.ok(
							result[i].timestamp <= result[i + 1].timestamp,
							`Chronological order violated at index ${i}`
						);
					}

					// Verify insertion order is preserved (same function names in same order)
					for (let i = 0; i < result.length; i++) {
						assert.strictEqual(result[i].functionName, entries[i].functionName,
							`Insertion order not preserved at index ${i}`);
					}
				}
			),
			{ numRuns: 100 }
		);
	});

	/**
	 * **Validates: Requirements 2.2**
	 *
	 * For any sequence of entries recorded in chronological order,
	 * exportJSON().entries MUST also maintain chronological order.
	 */
	test('exportJSON preserves chronological order', () => {
		fc.assert(
			fc.property(sortedTraceEntriesArb(), (entries) => {
				const manager = new TraceManager();
				for (const entry of entries) {
					manager.record(entry);
				}

				const exported = manager.exportJSON();
				assert.strictEqual(exported.entries.length, entries.length);

				for (let i = 0; i < exported.entries.length - 1; i++) {
					assert.ok(
						exported.entries[i].timestamp <= exported.entries[i + 1].timestamp,
						`Chronological order violated in exportJSON at index ${i}: ` +
						`${exported.entries[i].timestamp} > ${exported.entries[i + 1].timestamp}`
					);
				}
			}),
			{ numRuns: 100 }
		);
	});
});
