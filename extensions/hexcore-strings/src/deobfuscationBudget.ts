export interface BudgetableDeobfuscationResult {
	value: string;
	offset: number;
	confidence?: number;
}

export interface DeobfuscationBudgetOptions {
	minConfidence?: number;
	maxResults?: number;
	highSignalOnly?: boolean;
}

export interface DeobfuscationBudgetStats {
	generated: number;
	kept: number;
	discardedLowConfidence: number;
	discardedLowSignal: number;
	discardedBudget: number;
	minConfidence: number;
	maxResults: number;
	highSignalOnly: boolean;
}

const HIGH_SIGNAL = /(?:https?:\/\/|\\\\|[a-z]:\\|\b(?:password|passwd|token|secret|api[_-]?key|cmd\.exe|powershell|rundll32|regsvr32|msbuild|virtualalloc|writeprocessmemory)\b)/i;

export function applyDeobfuscationBudget<T extends BudgetableDeobfuscationResult>(
	results: T[],
	options: DeobfuscationBudgetOptions,
): { results: T[]; stats: DeobfuscationBudgetStats } {
	const minConfidence = Number.isFinite(options.minConfidence)
		? Math.max(0, Math.min(1, options.minConfidence!))
		: 0;
	const maxResults = Number.isFinite(options.maxResults)
		? Math.max(1, Math.floor(options.maxResults!))
		: 5000;
	const highSignalOnly = options.highSignalOnly === true;

	let discardedLowConfidence = 0;
	let discardedLowSignal = 0;
	const accepted: T[] = [];
	for (const result of results) {
		if (result.confidence !== undefined && result.confidence < minConfidence) {
			discardedLowConfidence++;
			continue;
		}
		if (highSignalOnly &&
			!(result.confidence !== undefined && result.confidence >= Math.max(0.75, minConfidence)) &&
			!HIGH_SIGNAL.test(result.value)) {
			discardedLowSignal++;
			continue;
		}
		accepted.push(result);
	}

	const kept = accepted.slice(0, maxResults);
	return {
		results: kept,
		stats: {
			generated: results.length,
			kept: kept.length,
			discardedLowConfidence,
			discardedLowSignal,
			discardedBudget: Math.max(0, accepted.length - kept.length),
			minConfidence,
			maxResults,
			highSignalOnly,
		},
	};
}
