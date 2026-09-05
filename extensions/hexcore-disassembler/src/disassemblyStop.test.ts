import * as assert from 'assert';
import { classifyDisassemblyStop } from './disassemblyStop';

suite('disassembly stop classification', () => {
	test('marks a full page before the known function end as truncated', () => {
		const result = classifyDisassemblyStop({
			startAddress: 0x140012e50,
			requestedCount: 10000,
			effectiveCount: 10000,
			returnedCount: 10000,
			lastInstruction: { address: 0x14001e3c8, size: 1, isRet: false },
			functionExtent: { start: 0x140012e50, end: 0x140020000, size: 0xd1b0, source: 'pdata' },
			nextByteAvailable: true,
		});
		assert.strictEqual(result.truncated, true);
		assert.strictEqual(result.stopReason, 'count-limit');
		assert.strictEqual(result.nextAddress, 0x14001e3c9);
		assert.strictEqual(result.functionBoundary?.reached, false);
	});

	test('reports a return at the end of the page as a function end', () => {
		const result = classifyDisassemblyStop({
			startAddress: 0x401000,
			requestedCount: 64,
			effectiveCount: 64,
			returnedCount: 64,
			lastInstruction: { address: 0x401080, size: 1, isRet: true },
			nextByteAvailable: true,
		});
		assert.strictEqual(result.truncated, false);
		assert.strictEqual(result.stopReason, 'function-end');
		assert.strictEqual(result.nextAddress, undefined);
	});

	test('treats an exact requested half-open endpoint as complete', () => {
		const result = classifyDisassemblyStop({
			startAddress: 0x14018D720,
			requestedCount: 10000,
			effectiveCount: 10000,
			returnedCount: 521,
			lastInstruction: { address: 0x14018DF49, size: 1, isRet: false },
			requestedEndExclusive: 0x14018DF4A,
			nextByteAvailable: true,
		});
		assert.strictEqual(result.truncated, false);
		assert.strictEqual(result.stopReason, 'requested-end');
	});

	test('does not hide a linear sweep that crossed the known function boundary', () => {
		const result = classifyDisassemblyStop({
			startAddress: 0x401000,
			requestedCount: 100,
			effectiveCount: 100,
			returnedCount: 100,
			lastInstruction: { address: 0x401200, size: 2, isRet: false },
			functionExtent: { start: 0x401000, end: 0x401100, size: 0x100, source: 'function-table' },
			nextByteAvailable: true,
		});
		assert.strictEqual(result.truncated, true);
		assert.strictEqual(result.functionBoundary?.reached, true);
		assert.strictEqual(result.functionBoundary?.crossed, true);
		assert.strictEqual(result.functionBoundary?.byteCoverage, 1);
	});

	test('distinguishes a decode failure from the binary boundary', () => {
		const common = {
			startAddress: 0x401000,
			requestedCount: 64,
			effectiveCount: 64,
			returnedCount: 8,
			lastInstruction: { address: 0x401020, size: 2, isRet: false },
		};
		assert.strictEqual(classifyDisassemblyStop({ ...common, nextByteAvailable: true }).stopReason, 'decode-failure');
		assert.strictEqual(classifyDisassemblyStop({ ...common, nextByteAvailable: false }).stopReason, 'binary-boundary');
	});
});
