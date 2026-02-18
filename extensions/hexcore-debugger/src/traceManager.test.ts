/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as assert from 'assert';
import { TraceManager, TraceEntry, TraceExport } from './traceManager';

/**
 * Helper to create a TraceEntry with known values.
 */
function makeEntry(overrides?: Partial<TraceEntry>): TraceEntry {
	return {
		functionName: 'malloc',
		library: 'libc',
		arguments: ['0x100'],
		returnValue: '0x7fff0000',
		pcAddress: '0x401000',
		timestamp: Date.now(),
		...overrides,
	};
}

suite('TraceManager — Unit Tests', () => {

	// --- record() and getEntries() ---

	test('record() stores entry and getEntries() returns it', () => {
		const manager = new TraceManager();
		const entry = makeEntry({ functionName: 'CreateFileA', library: 'kernel32.dll' });

		manager.record(entry);

		const entries = manager.getEntries();
		assert.strictEqual(entries.length, 1);
		assert.strictEqual(entries[0].functionName, 'CreateFileA');
		assert.strictEqual(entries[0].library, 'kernel32.dll');
		assert.deepStrictEqual(entries[0].arguments, ['0x100']);
		assert.strictEqual(entries[0].returnValue, '0x7fff0000');
		assert.strictEqual(entries[0].pcAddress, '0x401000');
	});

	test('record() stores multiple entries in insertion order', () => {
		const manager = new TraceManager();
		const e1 = makeEntry({ functionName: 'open', timestamp: 1000 });
		const e2 = makeEntry({ functionName: 'read', timestamp: 2000 });
		const e3 = makeEntry({ functionName: 'close', timestamp: 3000 });

		manager.record(e1);
		manager.record(e2);
		manager.record(e3);

		const entries = manager.getEntries();
		assert.strictEqual(entries.length, 3);
		assert.strictEqual(entries[0].functionName, 'open');
		assert.strictEqual(entries[1].functionName, 'read');
		assert.strictEqual(entries[2].functionName, 'close');
	});

	test('getEntries() returns a shallow copy, not the internal array', () => {
		const manager = new TraceManager();
		manager.record(makeEntry());

		const first = manager.getEntries();
		const second = manager.getEntries();

		assert.notStrictEqual(first, second, 'getEntries() should return a new array each time');
		assert.deepStrictEqual(first, second, 'contents should be identical');

		// Mutating the returned array should not affect the manager
		first.push(makeEntry({ functionName: 'extra' }));
		assert.strictEqual(manager.getEntries().length, 1, 'internal array should be unaffected');
	});

	// --- clear() ---

	test('clear() empties the trace', () => {
		const manager = new TraceManager();
		manager.record(makeEntry({ functionName: 'malloc' }));
		manager.record(makeEntry({ functionName: 'free' }));
		assert.strictEqual(manager.getEntries().length, 2);

		manager.clear();

		assert.strictEqual(manager.getEntries().length, 0);
	});

	test('clear() on already empty trace does not throw', () => {
		const manager = new TraceManager();
		assert.doesNotThrow(() => manager.clear());
		assert.strictEqual(manager.getEntries().length, 0);
	});

	// --- exportJSON() ---

	test('exportJSON() with empty trace returns zero entries', () => {
		const manager = new TraceManager();
		const exported: TraceExport = manager.exportJSON();

		assert.deepStrictEqual(exported.entries, []);
		assert.strictEqual(exported.totalEntries, 0);
		assert.strictEqual(typeof exported.generatedAt, 'string');
		assert.ok(!isNaN(Date.parse(exported.generatedAt)), 'generatedAt should be a valid ISO date');
	});

	test('exportJSON() includes all recorded entries with correct totalEntries', () => {
		const manager = new TraceManager();
		manager.record(makeEntry({ functionName: 'write' }));
		manager.record(makeEntry({ functionName: 'close' }));

		const exported = manager.exportJSON();

		assert.strictEqual(exported.totalEntries, 2);
		assert.strictEqual(exported.entries.length, 2);
		assert.strictEqual(exported.entries[0].functionName, 'write');
		assert.strictEqual(exported.entries[1].functionName, 'close');
	});

	test('exportJSON() generatedAt is a valid ISO 8601 timestamp', () => {
		const manager = new TraceManager();
		const before = new Date().toISOString();
		const exported = manager.exportJSON();
		const after = new Date().toISOString();

		assert.ok(exported.generatedAt >= before, 'generatedAt should be >= test start');
		assert.ok(exported.generatedAt <= after, 'generatedAt should be <= test end');
	});

	// --- onEntry() listener ---

	test('onEntry() listener is notified when an entry is recorded', () => {
		const manager = new TraceManager();
		const received: TraceEntry[] = [];

		manager.onEntry((entry) => {
			received.push(entry);
		});

		const entry = makeEntry({ functionName: 'VirtualAlloc', library: 'kernel32.dll' });
		manager.record(entry);

		assert.strictEqual(received.length, 1);
		assert.strictEqual(received[0].functionName, 'VirtualAlloc');
		assert.strictEqual(received[0].library, 'kernel32.dll');
	});

	test('onEntry() multiple listeners are all notified', () => {
		const manager = new TraceManager();
		let count1 = 0;
		let count2 = 0;

		manager.onEntry(() => { count1++; });
		manager.onEntry(() => { count2++; });

		manager.record(makeEntry());
		manager.record(makeEntry());

		assert.strictEqual(count1, 2);
		assert.strictEqual(count2, 2);
	});

	test('onEntry() listener receives the exact entry that was recorded', () => {
		const manager = new TraceManager();
		let captured: TraceEntry | undefined;

		manager.onEntry((entry) => {
			captured = entry;
		});

		const entry = makeEntry({
			functionName: 'mmap',
			library: 'libc',
			arguments: ['0x0', '0x1000', '0x3', '0x22', '0xffffffff', '0x0'],
			returnValue: '0x7f000000',
			pcAddress: '0x4010a0',
			timestamp: 1700000000000,
		});
		manager.record(entry);

		assert.ok(captured, 'listener should have been called');
		assert.strictEqual(captured!.functionName, entry.functionName);
		assert.strictEqual(captured!.library, entry.library);
		assert.deepStrictEqual(captured!.arguments, entry.arguments);
		assert.strictEqual(captured!.returnValue, entry.returnValue);
		assert.strictEqual(captured!.pcAddress, entry.pcAddress);
		assert.strictEqual(captured!.timestamp, entry.timestamp);
	});

	test('onEntry() listener registered after record() is not called for past entries', () => {
		const manager = new TraceManager();
		manager.record(makeEntry());

		const received: TraceEntry[] = [];
		manager.onEntry((entry) => { received.push(entry); });

		assert.strictEqual(received.length, 0, 'listener should not be called for past entries');

		manager.record(makeEntry({ functionName: 'future_call' }));
		assert.strictEqual(received.length, 1);
		assert.strictEqual(received[0].functionName, 'future_call');
	});
});
