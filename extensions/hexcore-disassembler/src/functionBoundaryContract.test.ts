/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as assert from 'assert';
import { CapstoneWrapper, normalizeDetectedFunctionBoundary } from './capstoneWrapper';

suite('native function boundary contract', () => {
	test('normalizes the legacy inclusive end by authoritative size', () => {
		const boundary = normalizeDetectedFunctionBoundary({
			start: 0x140001200n,
			end: 0x14000120fn,
			size: 0x10,
			detectionMethod: 'heuristic',
			confidence: 0.5,
			hasReturn: true,
			isThunk: false,
		});

		assert.strictEqual(boundary.endExclusive, 0x140001210n);
		assert.strictEqual(boundary.end, 0x14000120fn);
		assert.strictEqual(boundary.size, 0x10);
	});

	test('prefers the explicit half-open endpoint from new native modules', () => {
		const boundary = normalizeDetectedFunctionBoundary({
			start: 0x140001200n,
			endExclusive: 0x140001210n,
			end: 0x1400012ffn,
			size: 0x100,
			detectionMethod: 'address_taken',
			confidence: 0.9,
			hasReturn: true,
			isThunk: false,
		});

		assert.strictEqual(boundary.endExclusive, 0x140001210n);
		assert.strictEqual(boundary.end, 0x14000120fn);
		assert.strictEqual(boundary.size, 0x10);
	});

	test('represents a one-byte ret as [start, start + 1)', () => {
		const boundary = normalizeDetectedFunctionBoundary({
			start: 0x401000n,
			end: 0x401000n,
			size: 1,
			detectionMethod: 'call_target',
			confidence: 0.75,
			hasReturn: true,
			isThunk: false,
		});

		assert.strictEqual(boundary.endExclusive, 0x401001n);
		assert.strictEqual(boundary.size, 1);
	});

	test('does not assign an uncontained address to a nearby predecessor', async () => {
		const capstone = new CapstoneWrapper();
		(capstone as any).detectFunctions = async () => [{
			start: 0x401000n,
			endExclusive: 0x401020n,
			end: 0x40101fn,
			size: 0x20,
			detectionMethod: 'prologue',
			confidence: 0.85,
			hasReturn: true,
			isThunk: false,
		}];

		assert.strictEqual(
			await capstone.findFunctionStart(Buffer.alloc(0), 0x401100, 0x401000),
			0x401100n,
		);
		assert.strictEqual(
			await capstone.findFunctionStart(Buffer.alloc(0), 0x401010, 0x401000),
			0x401000n,
		);
	});
});
