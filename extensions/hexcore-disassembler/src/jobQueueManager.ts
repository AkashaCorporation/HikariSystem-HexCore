/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import * as vscode from 'vscode';

/** Stable identity for queue deduplication; Windows paths are case-insensitive. */
export function jobPathIdentity(filePath: string, platform: NodeJS.Platform = process.platform): string {
	const resolved = path.resolve(filePath);
	return platform === 'win32' ? resolved.toLowerCase() : resolved;
}

/**
 * Job priority levels.
 * High priority jobs are processed before normal and low priority jobs.
 */
export type JobPriority = 'high' | 'normal' | 'low';

/**
 * Job status values.
 * Tracks the lifecycle of a job from queue to completion.
 */
export type JobStatus = 'queued' | 'running' | 'done' | 'failed' | 'cancelled';

/**
 * Queued job interface - extends the existing pipeline job with queue metadata.
 */
export interface QueuedJob {
	jobId: string;
	priority: JobPriority;
	status: JobStatus;
	createdAt: number;
	startedAt?: number;
	completedAt?: number;
	filePath: string;
	result?: any;
	error?: string;
	abortController: AbortController;
	/**
	 * Optional keepAlive session identifier (Issue #26). When set, every job
	 * sharing this id is routed to the SAME worker for the life of the session
	 * (sticky / session-affinity). When unset, the job is stateless and runs on
	 * any free worker (the original behavior).
	 */
	sessionId?: string;
	/**
	 * The worker slot id this job ran (or is running) on. Only populated once the
	 * job has been dispatched to a worker. Useful for diagnostics and for
	 * verifying sticky routing.
	 */
	workerId?: number;
}

/**
 * Job status change event.
 * Emitted whenever a job transitions from one status to another.
 */
export interface JobStatusChangeEvent {
	jobId: string;
	oldStatus: JobStatus;
	newStatus: JobStatus;
	result?: any;
	error?: string;
}

/**
 * Queue statistics.
 */
export interface QueueStats {
	queued: number;
	running: number;
	done: number;
	failed: number;
	cancelled: number;
}

/**
 * The status contract returned by getJobStatusReport() / the
 * hexcore.pipeline.jobStatus command for a single job.
 *
 * `position` (Issue #24) is the 1-based index of the job in DISPATCH order
 * among all currently-queued jobs, accounting for priority then FIFO submit
 * order. It is present ONLY while the job is `queued`; for any other status it
 * is `null` (the field is always present so consumers can branch on it).
 *
 * `sessionId` (Issue #26) is echoed back when the job carries a keepAlive
 * session affinity, and is omitted for stateless jobs.
 */
export interface JobStatusReport {
	jobId: string;
	status: JobStatus;
	priority: JobPriority;
	position: number | null;
	submittedAt: number;
	startedAt?: number;
	completedAt?: number;
	filePath: string;
	sessionId?: string;
	workerId?: number;
	result?: any;
	error?: string;
}

/**
 * A single worker slot in the fixed-size pool (Issue #26). The pool is created
 * once at construction time with `concurrencyLimit` slots and is NOT resized
 * while live (a poolSize setting change takes effect on the next reload --
 * Issue #25). `sessionId` records which keepAlive session, if any, this worker
 * currently owns; the binding is established by the first session job and
 * released when the session is torn down.
 */
interface WorkerSlot {
	id: number;
	busy: boolean;
	/** The keepAlive session this worker is currently bound to, if any. */
	sessionId?: string;
}

/**
 * Priority queue node for min-heap implementation.
 */
interface PriorityQueueNode {
	job: QueuedJob;
	priorityValue: number;
	sequence: number;
}

/**
 * Min-heap based priority queue for job scheduling.
 * Uses priority mapping (high=0, normal=1, low=2) with FIFO within same priority.
 */
class PriorityQueue {
	private heap: PriorityQueueNode[] = [];
	private sequenceCounter = 0;

	/**
	 * Maps priority string to numeric value for comparison.
	 * Lower values have higher priority.
	 */
	private static priorityToValue(priority: JobPriority): number {
		switch (priority) {
			case 'high':
				return 0;
			case 'normal':
				return 1;
			case 'low':
				return 2;
			default:
				return 1;
		}
	}

	/**
	 * Adds a job to the priority queue.
	 */
	enqueue(job: QueuedJob): void {
		const node: PriorityQueueNode = {
			job,
			priorityValue: PriorityQueue.priorityToValue(job.priority),
			sequence: this.sequenceCounter++
		};
		this.heap.push(node);
		this.bubbleUp(this.heap.length - 1);
	}

	/**
	 * Removes and returns the highest priority job.
	 */
	dequeue(): QueuedJob | undefined {
		if (this.heap.length === 0) {
			return undefined;
		}
		const root = this.heap[0];
		const last = this.heap.pop();
		if (this.heap.length > 0 && last) {
			this.heap[0] = last;
			this.bubbleDown(0);
		}
		return root.job;
	}

	/**
	 * Returns the highest priority job without removing it.
	 */
	peek(): QueuedJob | undefined {
		return this.heap[0]?.job;
	}

	/**
	 * Returns the number of jobs in the queue.
	 */
	get size(): number {
		return this.heap.length;
	}

	/**
	 * Returns true if the queue is empty.
	 */
	isEmpty(): boolean {
		return this.heap.length === 0;
	}

	/**
	 * Removes a job by its ID.
	 */
	removeByJobId(jobId: string): boolean {
		const index = this.heap.findIndex(node => node.job.jobId === jobId);
		if (index === -1) {
			return false;
		}
		const last = this.heap.pop();
		if (index < this.heap.length && last) {
			this.heap[index] = last;
			this.bubbleUp(index);
			this.bubbleDown(index);
		}
		return true;
	}

	/**
	 * Returns all jobs in the queue (for inspection, not ordered by priority).
	 */
	getAllJobs(): QueuedJob[] {
		return this.heap.map(node => node.job);
	}

	/**
	 * Returns all queued jobs in true DISPATCH order: by priority
	 * (high -> normal -> low), then FIFO by submit sequence within a priority.
	 * Does NOT mutate the heap. Used to compute a job's 1-based queue position
	 * (Issue #24) and to drive session-aware dispatch (Issue #26).
	 */
	toSortedArray(): QueuedJob[] {
		return this.heap
			.slice()
			.sort((a, b) => this.compareNodes(a, b))
			.map(node => node.job);
	}

	/**
	 * Removes and returns the first job in dispatch order for which `accept`
	 * returns true, skipping any earlier-but-unassignable jobs (e.g. a session
	 * job whose owning worker is still busy -- Issue #26 case (a)). Returns
	 * undefined if no queued job is currently dispatchable. Heap order is
	 * preserved for the jobs that are skipped.
	 */
	dequeueFirstMatching(accept: (job: QueuedJob) => boolean): QueuedJob | undefined {
		const ordered = this.heap.slice().sort((a, b) => this.compareNodes(a, b));
		for (const node of ordered) {
			if (accept(node.job)) {
				this.removeByJobId(node.job.jobId);
				return node.job;
			}
		}
		return undefined;
	}

	/**
	 * Moves a node up the heap to maintain heap property.
	 */
	private bubbleUp(index: number): void {
		const node = this.heap[index];
		while (index > 0) {
			const parentIndex = Math.floor((index - 1) / 2);
			const parent = this.heap[parentIndex];
			if (this.compareNodes(node, parent) >= 0) {
				break;
			}
			this.heap[index] = parent;
			index = parentIndex;
		}
		this.heap[index] = node;
	}

	/**
	 * Moves a node down the heap to maintain heap property.
	 */
	private bubbleDown(index: number): void {
		const node = this.heap[index];
		const length = this.heap.length;
		while (true) {
			const leftChildIndex = 2 * index + 1;
			const rightChildIndex = 2 * index + 2;
			let smallestIndex = index;

			if (leftChildIndex < length && this.compareNodes(this.heap[leftChildIndex], this.heap[smallestIndex]) < 0) {
				smallestIndex = leftChildIndex;
			}
			if (rightChildIndex < length && this.compareNodes(this.heap[rightChildIndex], this.heap[smallestIndex]) < 0) {
				smallestIndex = rightChildIndex;
			}
			if (smallestIndex === index) {
				break;
			}
			this.heap[index] = this.heap[smallestIndex];
			index = smallestIndex;
		}
		this.heap[index] = node;
	}

	/**
	 * Compares two nodes for priority ordering.
	 * Returns negative if a has higher priority than b.
	 */
	private compareNodes(a: PriorityQueueNode, b: PriorityQueueNode): number {
		if (a.priorityValue !== b.priorityValue) {
			return a.priorityValue - b.priorityValue;
		}
		return a.sequence - b.sequence;
	}
}

/**
 * Job executor function type.
 */
export interface JobExecutionContext {
	jobId: string;
	workerId: number;
	sessionId?: string;
}

type JobExecutor = (filePath: string, abortSignal: AbortSignal, context: JobExecutionContext) => Promise<any>;

/**
 * Job Queue Manager for HexCore pipeline jobs.
 *
 * Manages a priority queue of pipeline jobs with a configurable concurrency limit.
 * Uses min-heap for priority scheduling and async execution for job processing.
 */
export class JobQueueManager {
	private queue = new PriorityQueue();
	private jobs = new Map<string, QueuedJob>();
	private runningJobs = new Map<string, AbortController>();
	private concurrencyLimit: number;
	private running = false;
	private processing = false;
	/**
	 * Issue #45 (item 2): a one-shot resolver that wakes the processLoop's
	 * all-busy / no-dispatchable park early. It is set while the loop is parked
	 * and signalled by scheduleProcessLoop when a worker frees mid-park, so a
	 * just-freed slot is dispatched immediately instead of after the remaining
	 * ~100 ms poll. The timer remains as a fail-safe re-poll -- this is purely a
	 * latency optimization, the dispatch decision is unchanged.
	 */
	private wakeup?: () => void;
	private jobExecutor?: JobExecutor;
	private readonly onJobStatusChangedEmitter = new vscode.EventEmitter<JobStatusChangeEvent>();

	/**
	 * The fixed-size worker pool (Issue #26). Created once at construction with
	 * `concurrencyLimit` slots and never resized while live (Issue #25: a
	 * poolSize setting change applies on the NEXT extension reload). Each slot
	 * carries an optional `sessionId` recording the keepAlive session it owns
	 * for sticky routing.
	 */
	private readonly workers: WorkerSlot[] = [];

	/**
	 * Tracks how many in-flight (running) jobs each keepAlive session currently
	 * has. When a session's count returns to zero AND it has no queued jobs, the
	 * session is torn down and its worker binding is released (Issue #26 case
	 * (d)). Keyed by sessionId.
	 */
	private readonly sessionActiveCounts = new Map<string, number>();

	/**
	 * Upper bound on retained TERMINAL jobs (done/failed/cancelled). The jobs Map
	 * is the long-lived singleton's master record and was previously never pruned,
	 * so a session fed by the startup auto-run + FileSystemWatcher accumulated one
	 * entry (with its full pipeline `result`) per completed run forever. We keep the
	 * most recent MAX_RETAINED_COMPLETED terminal jobs and evict the oldest; queued
	 * and running jobs are never evicted.
	 */
	private static readonly MAX_RETAINED_COMPLETED = 200;
	private readonly completedJobIds: string[] = [];

	/**
	 * Event fired when a job's status changes.
	 */
	public readonly onJobStatusChanged = this.onJobStatusChangedEmitter.event;

	/**
	 * Creates a new JobQueueManager.
	 * @param concurrencyLimit Maximum number of concurrent jobs (pool size).
	 *        Clamped to [1, 16] to match the hexcore.pipeline.queue.poolSize
	 *        setting bounds (Issue #25). Defaults to 2.
	 */
	constructor(concurrencyLimit: number = 2) {
		this.concurrencyLimit = Math.min(Math.max(1, concurrencyLimit), 16);
		// Build the fixed-size worker pool once. The pool is never resized while
		// live (Issue #25); in-flight jobs always finish on their current worker.
		for (let i = 0; i < this.concurrencyLimit; i++) {
			this.workers.push({ id: i, busy: false });
		}
	}

	/**
	 * Returns the configured pool size (number of worker slots). Read-only;
	 * resizing a live pool is out of scope (Issue #25).
	 */
	get poolSize(): number {
		return this.concurrencyLimit;
	}

	/**
	 * Sets the job executor function.
	 * This function will be called to execute each job.
	 */
	setJobExecutor(executor: JobExecutor): void {
		this.jobExecutor = executor;
	}

	/**
	 * Starts the job processing loop.
	 */
	start(): void {
		if (this.running) {
			return;
		}
		this.running = true;
		this.scheduleProcessLoop();
	}

	/**
	 * Stops the job processing loop gracefully.
	 * Waits for running jobs to complete.
	 */
	async stop(): Promise<void> {
		this.running = false;
		// Wait for all running jobs to complete
		while (this.runningJobs.size > 0) {
			await this.delay(100);
		}
	}

	/**
	 * Disposes all resources.
	 */
	dispose(): void {
		this.running = false;
		// Cancel all running jobs
		for (const [jobId, abortController] of this.runningJobs) {
			abortController.abort();
			const job = this.jobs.get(jobId);
			if (job) {
				this.updateJobStatus(job, 'cancelled');
			}
		}
		this.runningJobs.clear();
		// Release all worker bindings and session bookkeeping (Issue #26).
		for (const worker of this.workers) {
			worker.busy = false;
			worker.sessionId = undefined;
		}
		this.sessionActiveCounts.clear();
		this.onJobStatusChangedEmitter.dispose();
	}

	/**
	 * Queues a new job for execution.
	 * @param filePath Path to the .hexcore_job.json file
	 * @param priority Job priority (default: 'normal')
	 * @param sessionId Optional keepAlive session id for sticky worker routing
	 *        (Issue #26). When set, every job sharing this id is pinned to the
	 *        SAME worker for the life of the session. When unset, the job is
	 *        stateless and runs on any free worker (original behavior).
	 * @returns The job ID (UUID)
	 */
	queueJob(filePath: string, priority: JobPriority = 'normal', sessionId?: string): string {
		const jobId = crypto.randomUUID();
		const job: QueuedJob = {
			jobId,
			priority,
			status: 'queued',
			createdAt: Date.now(),
			filePath: path.resolve(filePath),
			abortController: new AbortController(),
			...(sessionId ? { sessionId } : {})
		};

		this.jobs.set(jobId, job);
		this.queue.enqueue(job);

		if (this.running) {
			this.scheduleProcessLoop();
		}

		return jobId;
	}

	/**
	 * Returns the active (queued or running) job for a given file path, if any.
	 * Used by the auto-run / FileSystemWatcher submission layer to avoid
	 * enqueueing a job whose path is already in-flight (debounce/dedup).
	 * Paths are compared after path.resolve() normalization, matching the
	 * normalization queueJob() applies on enqueue.
	 * @param filePath Path to the .hexcore_job.json file
	 * @returns The in-flight QueuedJob for the path, or undefined
	 */
	getActiveJobForPath(filePath: string): QueuedJob | undefined {
		const normalized = jobPathIdentity(filePath);
		for (const job of this.jobs.values()) {
			// A job cancelled while its executor is still running stays in-flight
			// (its worker is busy and it is still in runningJobs) until the executor
			// settles. Treat it as active so the watcher / auto-run does not enqueue a
			// duplicate run against the same file's outputs while the original is
			// still writing them.
			if (jobPathIdentity(job.filePath) === normalized &&
				(job.status === 'queued' || job.status === 'running' || this.runningJobs.has(job.jobId))) {
				return job;
			}
		}
		return undefined;
	}

	/**
	 * Queues a job for a path only if no job for that path is already queued or
	 * running. This is the de-duplicated submission entry point used by the
	 * startup auto-run and the FileSystemWatcher, which can fire repeatedly for
	 * the same file (rapid saves) and must not stack duplicate runs.
	 * @param filePath Path to the .hexcore_job.json file
	 * @param priority Job priority (default: 'normal')
	 * @returns The new job ID, or the existing in-flight job ID if a duplicate
	 *          was suppressed, or undefined if it could not be queued
	 */
	queueJobIfAbsent(filePath: string, priority: JobPriority = 'normal', sessionId?: string): { jobId: string; deduped: boolean } {
		const existing = this.getActiveJobForPath(filePath);
		if (existing) {
			return { jobId: existing.jobId, deduped: true };
		}
		return { jobId: this.queueJob(filePath, priority, sessionId), deduped: false };
	}

	/**
	 * Cancels a job by its ID.
	 * If the job is queued, it's removed from the queue.
	 * If the job is running, the abort controller is signaled.
	 * @param jobId The job ID to cancel
	 * @returns True if the job was found and cancelled
	 */
	cancelJob(jobId: string): boolean {
		const job = this.jobs.get(jobId);
		if (!job) {
			return false;
		}

		if (job.status === 'queued') {
			// Remove from queue
			const removed = this.queue.removeByJobId(jobId);
			if (removed) {
				this.updateJobStatus(job, 'cancelled');
			}
			return removed;
		}

		if (job.status === 'running') {
			// Signal abort to the running job
			job.abortController.abort();
			this.updateJobStatus(job, 'cancelled');
			return true;
		}

		// Job is already done, failed, or cancelled
		return false;
	}

	/**
	 * Gets the status of a specific job.
	 * @param jobId The job ID
	 * @returns The job object or undefined if not found
	 */
	getJobStatus(jobId: string): QueuedJob | undefined {
		return this.jobs.get(jobId);
	}

	/**
	 * Computes the 1-based DISPATCH-order position of a queued job (Issue #24).
	 * Position 1 is the next job that would be dispatched. Order is by priority
	 * (high -> normal -> low) then FIFO submit time within a priority -- i.e. a
	 * freshly-submitted `high` job jumps ahead of pending `normal` jobs.
	 *
	 * Returns `null` for any job that is not currently `queued` (running / done /
	 * failed / cancelled), or if the job id is unknown.
	 */
	getQueuePosition(jobId: string): number | null {
		const job = this.jobs.get(jobId);
		if (!job || job.status !== 'queued') {
			return null;
		}
		const ordered = this.queue.toSortedArray();
		const index = ordered.findIndex(j => j.jobId === jobId);
		return index === -1 ? null : index + 1;
	}

	/**
	 * Builds the public status report for a job (Issue #24 / #26 status
	 * contract). Includes the dispatch-order `position` when queued (else null),
	 * echoes the keepAlive `sessionId` when present, and reports the bound
	 * `workerId` once dispatched.
	 * @param jobId The job ID
	 * @returns The status report, or undefined if the job id is unknown
	 */
	getJobStatusReport(jobId: string): JobStatusReport | undefined {
		const job = this.jobs.get(jobId);
		if (!job) {
			return undefined;
		}
		const report: JobStatusReport = {
			jobId: job.jobId,
			status: job.status,
			priority: job.priority,
			position: job.status === 'queued' ? this.getQueuePosition(jobId) : null,
			submittedAt: job.createdAt,
			filePath: job.filePath
		};
		if (job.startedAt !== undefined) { report.startedAt = job.startedAt; }
		if (job.completedAt !== undefined) { report.completedAt = job.completedAt; }
		if (job.sessionId !== undefined) { report.sessionId = job.sessionId; }
		if (job.workerId !== undefined) { report.workerId = job.workerId; }
		if (job.result !== undefined) { report.result = job.result; }
		if (job.error !== undefined) { report.error = job.error; }
		return report;
	}

	/**
	 * Gets all jobs (queued, running, and completed).
	 * @returns Array of all jobs
	 */
	getAllJobs(): QueuedJob[] {
		return Array.from(this.jobs.values());
	}

	/**
	 * Gets queue statistics.
	 * @returns Statistics about job statuses
	 */
	getQueueStats(): QueueStats {
		const stats: QueueStats = {
			queued: 0,
			running: 0,
			done: 0,
			failed: 0,
			cancelled: 0
		};

		for (const job of this.jobs.values()) {
			stats[job.status]++;
		}

		return stats;
	}

	/**
	 * Main processing loop that assigns jobs to worker slots.
	 *
	 * Dispatch is session-aware (Issue #26): rather than blindly popping the
	 * single highest-priority job (which could be a session job whose owning
	 * worker is busy and would head-of-line block the whole queue), we pick the
	 * first job in dispatch order that has an assignable worker RIGHT NOW. A
	 * session job is only assignable to ITS bound worker; if that worker is busy
	 * the job waits (case (a)) while later stateless / other-session jobs may
	 * still proceed on other free workers.
	 */
	private async processLoop(): Promise<void> {
		while (this.running && !this.queue.isEmpty()) {
			// Stop early if every worker is busy -- nothing can be dispatched.
			if (!this.workers.some(w => !w.busy)) {
				await this.park();
				continue;
			}

			// Pick the highest-priority queued job that has a worker available to
			// it under the session-affinity rules. assignWorker() returns the slot
			// it would run on (without yet marking it busy) or undefined.
			let chosenWorker: WorkerSlot | undefined;
			const job = this.queue.dequeueFirstMatching(candidate => {
				const worker = this.pickWorkerFor(candidate);
				if (worker) {
					chosenWorker = worker;
					return true;
				}
				return false;
			});

			if (!job || !chosenWorker) {
				// No queued job is dispatchable right now (e.g. all remaining are
				// session jobs whose workers are busy). Wait and retry.
				await this.park();
				continue;
			}

			if (job.abortController.signal.aborted) {
				// Job was cancelled before processing
				this.updateJobStatus(job, 'cancelled');
				continue;
			}

			// Bind the job to the chosen worker. For a session job this also
			// establishes / confirms the session->worker affinity.
			this.bindJobToWorker(job, chosenWorker);

			this.updateJobStatus(job, 'running');
			this.runningJobs.set(job.jobId, job.abortController);

			// Execute job asynchronously
			this.executeJob(job);
		}
	}

	/**
	 * Selects the worker slot a queued job may run on RIGHT NOW, honoring
	 * session affinity (Issue #26). Returns undefined if the job cannot be
	 * dispatched yet.
	 *
	 * - Stateless job (no sessionId): any free worker.
	 * - Session job whose session is already bound to a worker: ONLY that worker,
	 *   and only if it is free (case (a) -- it WAITS for its worker, it never
	 *   steals a different free worker; case (b) -- a second same-session job
	 *   queued before either runs resolves to the same bound worker).
	 * - Session job with no binding yet: the first free worker, which then
	 *   becomes the owner (affinity established on first dispatch). To avoid
	 *   handing a session a worker that is already pinned to a DIFFERENT live
	 *   session, prefer a worker with no session binding; fall back to any free
	 *   worker only if none is unbound.
	 */
	private pickWorkerFor(job: QueuedJob): WorkerSlot | undefined {
		if (!job.sessionId) {
			return this.workers.find(w => !w.busy);
		}

		const owner = this.workers.find(w => w.sessionId === job.sessionId);
		if (owner) {
			// Session already bound: must use its worker, and only when free.
			return owner.busy ? undefined : owner;
		}

		// No binding yet: establish one on a free worker, preferring an unbound
		// slot so two distinct live sessions don't collide on one worker.
		const freeUnbound = this.workers.find(w => !w.busy && w.sessionId === undefined);
		if (freeUnbound) {
			return freeUnbound;
		}
		// Issue #45 (item 1): no UNBOUND free worker exists. Do NOT fall back to a
		// bound-but-free worker -- a slot that is `!busy` but still pinned to ANOTHER
		// live session (one whose sibling job is merely queued, so releaseWorker kept
		// the binding). Binding this job to it would overwrite that worker's
		// `sessionId` and destroy the other session's sticky keepAlive affinity
		// (Issue #26). Wait instead: the job stays queued and retries on the next
		// dispatch tick, and the slot becomes a generic free worker once its own
		// session fully drains. Stateless jobs (handled above) are unaffected.
		return undefined;
	}

	/**
	 * Marks a worker busy for a job and, for a session job, records / confirms
	 * the session->worker binding (Issue #26).
	 */
	private bindJobToWorker(job: QueuedJob, worker: WorkerSlot): void {
		worker.busy = true;
		job.workerId = worker.id;
		if (job.sessionId) {
			worker.sessionId = job.sessionId;
			this.sessionActiveCounts.set(
				job.sessionId,
				(this.sessionActiveCounts.get(job.sessionId) ?? 0) + 1
			);
		}
	}

	/**
	 * Releases a worker after a job finishes. For a session job, decrements the
	 * session's active count and, once it reaches zero with no queued siblings,
	 * tears the session down -- releasing the worker's session binding so a later
	 * same-sessionId job can rebind to a (possibly different) worker (case (d)).
	 */
	private releaseWorker(job: QueuedJob): void {
		const worker = job.workerId !== undefined ? this.workers[job.workerId] : undefined;
		if (worker) {
			worker.busy = false;
		}

		if (!job.sessionId) {
			return;
		}

		const remaining = (this.sessionActiveCounts.get(job.sessionId) ?? 1) - 1;
		if (remaining > 0) {
			this.sessionActiveCounts.set(job.sessionId, remaining);
			return;
		}
		this.sessionActiveCounts.delete(job.sessionId);

		// If no queued job still references this session, the session is fully
		// drained: tear it down and release the worker binding so the slot is a
		// generic free worker again.
		const hasQueuedSibling = this.queue
			.getAllJobs()
			.some(j => j.sessionId === job.sessionId && j.status === 'queued');
		if (!hasQueuedSibling && worker && worker.sessionId === job.sessionId) {
			worker.sessionId = undefined;
		}
	}

	/**
	 * Executes a job using the configured executor.
	 */
	private async executeJob(job: QueuedJob): Promise<void> {
		try {
			if (!this.jobExecutor) {
				throw new Error('No job executor configured');
			}

			const result = await this.jobExecutor(job.filePath, job.abortController.signal, {
				jobId: job.jobId,
				workerId: job.workerId ?? -1,
				...(job.sessionId ? { sessionId: job.sessionId } : {}),
			});

			if (job.status === 'cancelled') {
				return;
			}

			job.result = result;
			if (result && typeof result === 'object' && result.status === 'error') {
				job.error = 'Pipeline finished with status error';
				this.updateJobStatus(job, 'failed');
			} else {
				this.updateJobStatus(job, 'done');
			}
		} catch (error) {
			if (job.status === 'cancelled') {
				return;
			}

			job.error = error instanceof Error ? error.message : String(error);
			this.updateJobStatus(job, 'failed');
		} finally {
			this.runningJobs.delete(job.jobId);
			// Free the worker slot and, for a session job, run session-teardown /
			// binding-release bookkeeping (Issue #26).
			this.releaseWorker(job);

			// Continue processing more jobs
			if (this.running) {
				this.scheduleProcessLoop();
			}
		}
	}

	/**
	 * Schedules the process loop to run if not already processing.
	 * Ensures only one process loop is active at a time to prevent
	 * concurrency limit violations from reentrant calls.
	 */
	private scheduleProcessLoop(): void {
		if (this.processing) {
			// The loop is already running, possibly parked on the ~100 ms poll
			// timer waiting for a worker. Wake it now so a just-freed slot is
			// dispatched immediately instead of after the remaining poll (#45 item 2).
			this.wakeup?.();
			this.wakeup = undefined;
			return;
		}
		this.processing = true;
		this.processLoop().finally(() => {
			this.processing = false;
			if (this.running && !this.queue.isEmpty()) {
				this.scheduleProcessLoop();
			}
		});
	}

	/**
	 * Parks the process loop until EITHER the ~100 ms poll timer fires OR a worker
	 * frees mid-park (signalled via `wakeup` from scheduleProcessLoop -- #45 item 2).
	 * The timer is the fail-safe re-poll; the wakeup just removes the up-to-100 ms
	 * dispatch latency when a slot frees while the queue is waiting on a worker.
	 */
	private async park(): Promise<void> {
		await Promise.race([
			this.delay(100),
			new Promise<void>(resolve => { this.wakeup = resolve; }),
		]);
		this.wakeup = undefined;
	}

	/**
	 * Updates a job's status and emits the change event.
	 */
	private updateJobStatus(job: QueuedJob, newStatus: JobStatus): void {
		const oldStatus = job.status;
		// Terminal states are final. A job cancelled while its executor is still
		// running stays in runningJobs (cancelJob does not remove it), so a later
		// dispose() would otherwise re-finalize it -- overwriting completedAt and
		// firing a spurious duplicate (e.g. cancelled -> cancelled) event.
		if (oldStatus === 'done' || oldStatus === 'failed' || oldStatus === 'cancelled') {
			return;
		}
		job.status = newStatus;

		if (newStatus === 'running') {
			job.startedAt = Date.now();
		} else if (newStatus === 'done' || newStatus === 'failed' || newStatus === 'cancelled') {
			job.completedAt = Date.now();
		}

		this.onJobStatusChangedEmitter.fire({
			jobId: job.jobId,
			oldStatus,
			newStatus,
			result: job.result,
			error: job.error
		});

		if (newStatus === 'done' || newStatus === 'failed' || newStatus === 'cancelled') {
			this.retainCompletedJob(job.jobId);
		}
	}

	/**
	 * Records a freshly-finalized job and, once more than MAX_RETAINED_COMPLETED
	 * terminal jobs are retained, evicts the oldest from the jobs Map (dropping its
	 * heavy pipeline `result` + AbortController). Never evicts a queued/running job.
	 */
	private retainCompletedJob(jobId: string): void {
		this.completedJobIds.push(jobId);
		while (this.completedJobIds.length > JobQueueManager.MAX_RETAINED_COMPLETED) {
			const oldest = this.completedJobIds.shift();
			if (oldest === undefined) {
				break;
			}
			const job = this.jobs.get(oldest);
			if (job && (job.status === 'done' || job.status === 'failed' || job.status === 'cancelled')) {
				this.jobs.delete(oldest);
			}
		}
	}

	/**
	 * Utility delay function.
	 */
	private delay(ms: number): Promise<void> {
		return new Promise(resolve => setTimeout(resolve, ms));
	}
}

/**
 * Singleton instance of the JobQueueManager.
 */
let jobQueueManagerInstance: JobQueueManager | undefined;

/**
 * Gets the singleton instance of the JobQueueManager.
 * Creates it if it doesn't exist.
 * @param poolSize Optional pool size override
 * @returns The JobQueueManager instance
 */
export function getJobQueueManager(poolSize?: number): JobQueueManager {
	if (!jobQueueManagerInstance) {
		jobQueueManagerInstance = new JobQueueManager(poolSize);
	}
	return jobQueueManagerInstance;
}

/**
 * Disposes the singleton instance.
 */
export function disposeJobQueueManager(): void {
	if (jobQueueManagerInstance) {
		jobQueueManagerInstance.dispose();
		jobQueueManagerInstance = undefined;
	}
}
