export type DisassemblyStopReason = 'count-limit' | 'requested-end' | 'function-end' | 'decode-failure' | 'binary-boundary';

export interface DisassemblyExtent {
	start: number;
	end: number;
	size: number;
	source: 'function-table' | 'pdata' | 'recommended' | 'none';
}

export interface DisassemblyStopInput {
	startAddress: number;
	requestedCount: number;
	effectiveCount: number;
	returnedCount: number;
	lastInstruction?: { address: number; size: number; isRet?: boolean };
	functionExtent?: DisassemblyExtent;
	requestedEndExclusive?: number;
	nextByteAvailable: boolean;
}

export interface DisassemblyStopSummary {
	truncated: boolean;
	stopReason: DisassemblyStopReason;
	nextAddress?: number;
	pageFillRatio: number;
	functionBoundary?: DisassemblyExtent & {
		reached: boolean;
		crossed: boolean;
		byteCoverage: number;
	};
}

export function classifyDisassemblyStop(input: DisassemblyStopInput): DisassemblyStopSummary {
	const lastEnd = input.lastInstruction
		? input.lastInstruction.address + Math.max(0, input.lastInstruction.size)
		: input.startAddress;
	const pageFillRatio = input.effectiveCount > 0
		? Math.min(1, input.returnedCount / input.effectiveCount)
		: 0;
	const extent = input.functionExtent && input.functionExtent.end > input.functionExtent.start
		? input.functionExtent
		: undefined;
	const coverageStart = extent ? Math.max(input.startAddress, extent.start) : input.startAddress;
	const functionBoundary = extent ? {
		...extent,
		reached: lastEnd >= extent.end,
		crossed: lastEnd > extent.end,
		byteCoverage: Math.max(0, Math.min(1,
			(lastEnd - coverageStart) / Math.max(1, extent.end - coverageStart)
		)),
	} : undefined;

	const endedAtKnownBoundary = functionBoundary !== undefined && lastEnd === functionBoundary.end;
	const endedAtRequestedBoundary = input.requestedEndExclusive !== undefined &&
		lastEnd === input.requestedEndExclusive;
	const endedAtReturn = input.lastInstruction?.isRet === true;
	const filledPage = input.returnedCount >= input.effectiveCount;
	const requestWasCapped = input.requestedCount > input.effectiveCount;

	if (endedAtRequestedBoundary) {
		return { truncated: false, stopReason: 'requested-end', pageFillRatio, functionBoundary };
	}

	if (endedAtKnownBoundary || (endedAtReturn && !functionBoundary?.crossed)) {
		return { truncated: false, stopReason: 'function-end', pageFillRatio, functionBoundary };
	}

	if (filledPage || requestWasCapped) {
		return {
			truncated: true,
			stopReason: 'count-limit',
			nextAddress: lastEnd,
			pageFillRatio,
			functionBoundary,
		};
	}

	if (!input.nextByteAvailable) {
		return { truncated: false, stopReason: 'binary-boundary', pageFillRatio, functionBoundary };
	}

	return {
		truncated: true,
		stopReason: 'decode-failure',
		nextAddress: lastEnd,
		pageFillRatio,
		functionBoundary,
	};
}
