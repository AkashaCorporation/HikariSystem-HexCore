import type { PropagationSolveOptions } from './wholeProgramPropagation';

export interface RecordRecoveryCommandOptions extends Omit<PropagationSolveOptions, 'generation' | 'cancellationToken' | 'now' | 'onProgress'> {
	refresh?: boolean;
}

const RECORD_RECOVERY_BUDGET_KEYS = [
	'maxIterations', 'maxMilliseconds', 'maxValues',
	'maxTypeHypothesesPerValue', 'maxPointsToPerValue',
] as const;

export function normalizeRecordRecoveryOptions(value: unknown): RecordRecoveryCommandOptions {
	if (value === undefined) { return {}; }
	if (!value || typeof value !== 'object' || Array.isArray(value)) {
		throw new Error('records.recover options must be an object.');
	}
	const input = value as Record<string, unknown>;
	const result: RecordRecoveryCommandOptions = { refresh: input.refresh === true };
	for (const key of RECORD_RECOVERY_BUDGET_KEYS) {
		const candidate = input[key];
		if (candidate === undefined) { continue; }
		if (!Number.isSafeInteger(candidate) || (candidate as number) < 1) {
			throw new Error(`records.recover ${key} must be a positive safe integer.`);
		}
		(result as unknown as Record<string, unknown>)[key] = candidate;
	}
	if (input.changedFunctions !== undefined) {
		if (!Array.isArray(input.changedFunctions) ||
			input.changedFunctions.some(item => typeof item !== 'string' || item.trim().length === 0)) {
			throw new Error('records.recover changedFunctions must contain non-empty strings.');
		}
		result.changedFunctions = [...new Set(input.changedFunctions.map(item => (item as string).trim()))].sort();
	}
	return result;
}

export function requireCurrentCommittedPropagation(
	currentGeneration: number,
	latestAcceptedGeneration: number | undefined,
	summaryCount: number,
	dirtyCount: number,
) {
	if (latestAcceptedGeneration === undefined || summaryCount === 0) {
		throw new Error('Record recovery requires committed propagation; run hexcore.propagation.solve or use refresh:true with explicit budgets.');
	}
	if (latestAcceptedGeneration !== currentGeneration) {
		throw new Error(`Record recovery propagation is stale (accepted=${latestAcceptedGeneration}, current=${currentGeneration}).`);
	}
	if (dirtyCount > 0) {
		throw new Error(`Record recovery propagation has ${dirtyCount} dirty function(s); solve them or use refresh:true.`);
	}
	return { analysisGeneration: latestAcceptedGeneration, summaryCount, dirtyCount };
}
