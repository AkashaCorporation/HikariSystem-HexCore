import type { TraceExport } from './traceManager';

export interface EmulationArtifactSummary {
	instructionsExecuted: number;
	currentAddress: string | null;
	apiCallsObserved: number;
	apiEntriesRetained: number;
	apiCallsAggregated: number;
	apiCallsSampledOut: number;
	apiEntriesDropped: number;
	memoryRegionCount: number;
	stdoutBytes: number;
}

export function serializeApiTrace(trace: TraceExport): {
	apiCalls: Array<{ dll: string; name: string; returnValue: string; repeatCount: number }>;
	apiCallSummary: Omit<TraceExport, 'entries' | 'totalEntries' | 'generatedAt'>;
} {
	return {
		apiCalls: trace.entries.map(entry => ({
			dll: entry.library,
			name: entry.functionName,
			returnValue: entry.returnValue,
			repeatCount: entry.repeatCount ?? 1,
		})),
		apiCallSummary: {
			totalCalls: trace.totalCalls,
			retainedEntries: trace.retainedEntries,
			aggregatedCalls: trace.aggregatedCalls,
			sampledOut: trace.sampledOut,
			dropped: trace.dropped,
			configuration: trace.configuration,
		}
	};
}

export function buildEmulationArtifactSummary(input: {
	instructionsExecuted?: number;
	currentAddress?: number | bigint;
	trace: TraceExport;
	memoryRegionCount: number;
	stdout: string;
}): EmulationArtifactSummary {
	return {
		instructionsExecuted: input.instructionsExecuted ?? 0,
		currentAddress: input.currentAddress === undefined ? null : `0x${input.currentAddress.toString(16)}`,
		apiCallsObserved: input.trace.totalCalls,
		apiEntriesRetained: input.trace.retainedEntries,
		apiCallsAggregated: input.trace.aggregatedCalls,
		apiCallsSampledOut: input.trace.sampledOut,
		apiEntriesDropped: input.trace.dropped,
		memoryRegionCount: input.memoryRegionCount,
		stdoutBytes: Buffer.byteLength(input.stdout, 'utf8'),
	};
}
