import * as assert from 'assert';
import { buildEmulationArtifactSummary, serializeApiTrace } from './emulationArtifact';
import type { TraceExport } from './traceManager';

function traceFixture(): TraceExport {
	return {
		entries: [{
			functionName: 'rand', library: 'libc', arguments: [], returnValue: '0x1234',
			pcAddress: '0x401000', timestamp: 1, repeatCount: 37
		}],
		totalEntries: 1,
		totalCalls: 160242,
		retainedEntries: 1,
		aggregatedCalls: 37,
		sampledOut: 160000,
		dropped: 204,
		configuration: { maxEntries: 20000, sampleEvery: 100, groupRepeated: true },
		generatedAt: '2026-08-09T00:00:00.000Z'
	};
}

suite('emulation artifact summaries', () => {
	test('serializes compact trace entries and exact counters', () => {
		const result = serializeApiTrace(traceFixture());
		assert.deepStrictEqual(result.apiCalls, [
			{ dll: 'libc', name: 'rand', returnValue: '0x1234', repeatCount: 37 }
		]);
		assert.strictEqual(result.apiCallSummary.totalCalls, 160242);
		assert.strictEqual(result.apiCallSummary.retainedEntries, 1);
	});

	test('summarizes a large state without embedding its detail arrays', () => {
		const summary = buildEmulationArtifactSummary({
			instructionsExecuted: 10_000_000,
			currentAddress: 0x401234,
			trace: traceFixture(),
			memoryRegionCount: 7,
			stdout: 'ola\n'
		});
		assert.deepStrictEqual(summary, {
			instructionsExecuted: 10_000_000,
			currentAddress: '0x401234',
			apiCallsObserved: 160242,
			apiEntriesRetained: 1,
			apiCallsAggregated: 37,
			apiCallsSampledOut: 160000,
			apiEntriesDropped: 204,
			memoryRegionCount: 7,
			stdoutBytes: 4,
		});
	});
});
