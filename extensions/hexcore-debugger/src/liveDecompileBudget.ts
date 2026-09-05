/*---------------------------------------------------------------------------------------------
 *  Copyright (c) HikariSystem. All rights reserved.
 *--------------------------------------------------------------------------------------------*/

export const DEFAULT_LIVE_DECOMPILE_TIMEOUT_MS = 300_000;
export const LIVE_DECOMPILE_SETTLE_MARGIN_MS = 5_000;

/** Leaves time for the command result and pipeline status to settle on disk. */
export function resolveLiveDecompileWorkerBudget(
	pipelineTimeoutMs: unknown,
	elapsedMs: number,
): number {
	const outerBudget = typeof pipelineTimeoutMs === 'number' && Number.isFinite(pipelineTimeoutMs)
		? Math.max(1, Math.trunc(pipelineTimeoutMs))
		: DEFAULT_LIVE_DECOMPILE_TIMEOUT_MS;
	const elapsed = Number.isFinite(elapsedMs) ? Math.max(0, Math.trunc(elapsedMs)) : 0;
	return Math.max(1, outerBudget - elapsed - LIVE_DECOMPILE_SETTLE_MARGIN_MS);
}
