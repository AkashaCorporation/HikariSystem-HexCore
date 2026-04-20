/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import * as vscode from 'vscode';

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
type JobExecutor = (filePath: string, abortSignal: AbortSignal) => Promise<any>;

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
	private jobExecutor?: JobExecutor;
	private readonly onJobStatusChangedEmitter = new vscode.EventEmitter<JobStatusChangeEvent>();

	/**
	 * Event fired when a job's status changes.
	 */
	public readonly onJobStatusChanged = this.onJobStatusChangedEmitter.event;

	/**
	 * Creates a new JobQueueManager.
	 * @param concurrencyLimit Maximum number of concurrent jobs (default: 2, max: 5)
	 */
	constructor(concurrencyLimit: number = 2) {
		this.concurrencyLimit = Math.min(Math.max(1, concurrencyLimit), 5);
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
		this.onJobStatusChangedEmitter.dispose();
	}

	/**
	 * Queues a new job for execution.
	 * @param filePath Path to the .hexcore_job.json file
	 * @param priority Job priority (default: 'normal')
	 * @returns The job ID (UUID)
	 */
	queueJob(filePath: string, priority: JobPriority = 'normal'): string {
		const jobId = crypto.randomUUID();
		const job: QueuedJob = {
			jobId,
			priority,
			status: 'queued',
			createdAt: Date.now(),
			filePath: path.resolve(filePath),
			abortController: new AbortController()
		};

		this.jobs.set(jobId, job);
		this.queue.enqueue(job);

		if (this.running) {
			this.scheduleProcessLoop();
		}

		return jobId;
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
	 * Main processing loop that assigns jobs to available slots.
	 */
	private async processLoop(): Promise<void> {
		while (this.running && !this.queue.isEmpty()) {
			// Check if we have reached the concurrency limit
			if (this.runningJobs.size >= this.concurrencyLimit) {
				await this.delay(100);
				continue;
			}

			const job = this.queue.dequeue();
			if (!job) {
				continue;
			}

			if (job.abortController.signal.aborted) {
				// Job was cancelled before processing
				this.updateJobStatus(job, 'cancelled');
				continue;
			}

			this.updateJobStatus(job, 'running');
			this.runningJobs.set(job.jobId, job.abortController);

			// Execute job asynchronously
			this.executeJob(job);
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

			const result = await this.jobExecutor(job.filePath, job.abortController.signal);

			if (job.status === 'cancelled') {
				return;
			}

			job.result = result;
			this.updateJobStatus(job, 'done');
		} catch (error) {
			if (job.status === 'cancelled') {
				return;
			}

			job.error = error instanceof Error ? error.message : String(error);
			this.updateJobStatus(job, 'failed');
		} finally {
			this.runningJobs.delete(job.jobId);

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
	 * Updates a job's status and emits the change event.
	 */
	private updateJobStatus(job: QueuedJob, newStatus: JobStatus): void {
		const oldStatus = job.status;
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
