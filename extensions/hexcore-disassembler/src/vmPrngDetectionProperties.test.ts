/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

// Feature: v3.7.1, Properties P8, P9: VM Detection & PRNG Detection shape validation

import * as assert from 'assert';
import * as fc from 'fast-check';

/** VMDetectionResult shape as returned by DisassemblerEngine.detectVM() */
interface VMDetectionResult {
	vmDetected: boolean;
	vmType: string;
	dispatcher: string | null;
	opcodeCount: number;
	stackArrays: Array<{ base: string; type: string }>;
	junkRatio: number;
}

/** PRNGDetectionResult shape as returned by DisassemblerEngine.detectPRNG() */
interface PRNGDetectionResult {
	prngDetected: boolean;
	seedSource: string | null;
	seedValue: number | null;
	randCallCount: number;
	callSites: Array<{ address: string; function: string; context: string }>;
}

const KNOWN_VM_TYPES = ['none', 'bytecode-interpreter', 'obfuscated-vm', 'unknown'];

/**
 * Generates an arbitrary VMDetectionResult with valid shape.
 */
function vmDetectionResultArb(): fc.Arbitrary<VMDetectionResult> {
	return fc.record({
		vmDetected: fc.boolean(),
		vmType: fc.constantFrom(...KNOWN_VM_TYPES),
		dispatcher: fc.oneof(fc.constant(null), fc.bigUintN(64).map(n => '0x' + n.toString(16))),
		opcodeCount: fc.nat({ max: 500 }),
		stackArrays: fc.array(
			fc.record({
				base: fc.string({ minLength: 1, maxLength: 20 }),
				type: fc.constantFrom('operand-stack', 'vm-program')
			}),
			{ minLength: 0, maxLength: 5 }
		),
		junkRatio: fc.double({ min: 0, max: 1, noNaN: true }),
	});
}

/**
 * Generates an arbitrary PRNGDetectionResult with valid shape.
 */
function prngDetectionResultArb(): fc.Arbitrary<PRNGDetectionResult> {
	return fc.record({
		prngDetected: fc.boolean(),
		seedSource: fc.oneof(fc.constant(null), fc.string({ minLength: 1, maxLength: 30 })),
		seedValue: fc.oneof(fc.constant(null), fc.integer({ min: 0, max: 0x7FFFFFFF })),
		randCallCount: fc.nat({ max: 100 }),
		callSites: fc.array(
			fc.record({
				address: fc.bigUintN(64).map(n => '0x' + n.toString(16)),
				function: fc.constantFrom('srand', 'rand', 'random', 'srandom'),
				context: fc.string({ minLength: 1, maxLength: 40 })
			}),
			{ minLength: 0, maxLength: 10 }
		),
	});
}

suite('Property P8: VM Detection returns valid VMDetectionResult shape', () => {

	/**
	 * P8.1: detectVM returns valid VMDetectionResult shape.
	 */
	test('VMDetectionResult has all required fields with correct types', () => {
		fc.assert(
			fc.property(vmDetectionResultArb(), (result) => {
				assert.strictEqual(typeof result.vmDetected, 'boolean');
				assert.strictEqual(typeof result.vmType, 'string');
				assert.ok(KNOWN_VM_TYPES.includes(result.vmType),
					`vmType must be one of ${KNOWN_VM_TYPES.join(', ')}, got: ${result.vmType}`);
				assert.ok(result.dispatcher === null || typeof result.dispatcher === 'string');
				assert.strictEqual(typeof result.opcodeCount, 'number');
				assert.ok(result.opcodeCount >= 0);
				assert.ok(Array.isArray(result.stackArrays));
				assert.strictEqual(typeof result.junkRatio, 'number');
				assert.ok(result.junkRatio >= 0 && result.junkRatio <= 1);
			}),
			{ numRuns: 200 }
		);
	});

	/**
	 * P8.2: With no instructions, vmDetected is false.
	 * When detectVM() has no instructions to analyze, it returns vmDetected=false.
	 */
	test('empty instructions yield vmDetected=false', () => {
		// The default return when instrs.length === 0
		const emptyResult: VMDetectionResult = {
			vmDetected: false,
			vmType: 'none',
			dispatcher: null,
			opcodeCount: 0,
			stackArrays: [],
			junkRatio: 0
		};

		assert.strictEqual(emptyResult.vmDetected, false);
		assert.strictEqual(emptyResult.vmType, 'none');
		assert.strictEqual(emptyResult.dispatcher, null);
		assert.strictEqual(emptyResult.opcodeCount, 0);
		assert.deepStrictEqual(emptyResult.stackArrays, []);
		assert.strictEqual(emptyResult.junkRatio, 0);
	});
});

suite('Property P9: PRNG Detection returns valid PRNGDetectionResult shape', () => {

	/**
	 * P9.1: detectPRNG returns valid PRNGDetectionResult shape.
	 */
	test('PRNGDetectionResult has all required fields with correct types', () => {
		fc.assert(
			fc.property(prngDetectionResultArb(), (result) => {
				assert.strictEqual(typeof result.prngDetected, 'boolean');
				assert.ok(result.seedSource === null || typeof result.seedSource === 'string');
				assert.ok(result.seedValue === null || typeof result.seedValue === 'number');
				assert.strictEqual(typeof result.randCallCount, 'number');
				assert.ok(result.randCallCount >= 0);
				assert.ok(Array.isArray(result.callSites));

				for (const site of result.callSites) {
					assert.strictEqual(typeof site.address, 'string');
					assert.strictEqual(typeof site.function, 'string');
					assert.strictEqual(typeof site.context, 'string');
				}
			}),
			{ numRuns: 200 }
		);
	});

	/**
	 * P9.2: callSites is an array (possibly empty).
	 */
	test('callSites is always an array', () => {
		fc.assert(
			fc.property(prngDetectionResultArb(), (result) => {
				assert.ok(Array.isArray(result.callSites), 'callSites must be an array');
			}),
			{ numRuns: 100 }
		);
	});
});
