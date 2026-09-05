export interface QueueQueryContext { executionId: string; jobId?: string }

/** Query-time counts are inclusive; a status step is not a terminal queue snapshot. */
export function describeQueueObservation(
	jobs: readonly { jobId: string; status: string }[], context?: QueueQueryContext,
) {
	const tracked = context?.jobId ? jobs.find(job => job.jobId === context.jobId) : undefined;
	return {
		observationScope: 'queue-at-query-time' as const,
		terminalSnapshot: false,
		includesCurrentJob: context ? tracked?.status === 'running' : null,
		currentJobId: context?.jobId ?? null,
		currentExecutionId: context?.executionId ?? null,
		currentJobTracked: context ? Boolean(tracked) : null,
		countSemantics: 'Inclusive queue totals; the querying job may still be running. Use the terminal summary for post-job counts.',
	};
}
