/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

// Feature: v3.8.2 Job Queue follow-ups (#24 queue position, #25 pool size,
// #26 sessionId-based sticky worker routing). Unit tests for JobQueueManager.

import * as assert from 'assert';
import { JobQueueManager } from './jobQueueManager';

const sleep = (ms: number): Promise<void> => new Promise(resolve => setTimeout(resolve, ms));

/**
 * A controllable job executor: each job blocks until its gate is released, so
 * tests can observe dispatch / sticky-routing decisions deterministically.
 * Jobs are keyed by the basename of the (path.resolve'd) file path.
 */
function makeControllable() {
	const path = require('path') as typeof import('path');
	const gates = new Map<string, () => void>();
	const startedSet = new Set<string>();
	let draining = false;
	const exec = (filePath: string): Promise<unknown> => {
		const key = path.basename(filePath);
		startedSet.add(key);
		if (draining) { return Promise.resolve({ ok: key }); }
		return new Promise<unknown>(resolve => { gates.set(key, () => resolve({ ok: key })); });
	};
	return {
		exec,
		isRunning: (key: string): boolean => startedSet.has(key) && gates.has(key),
		release: (key: string): void => { const g = gates.get(key); if (g) { gates.delete(key); g(); } },
		releaseAll: (): void => { draining = true; for (const [, g] of gates) { g(); } gates.clear(); }
	};
}

suite('JobQueueManager #24 — queue position', () => {
	test('position reflects priority then FIFO submit order', () => {
		const m = new JobQueueManager(1);
		m.setJobExecutor(() => new Promise(() => { /* never resolves; not started */ }));
		const a = m.queueJob('A_normal', 'normal');
		const b = m.queueJob('B_normal', 'normal');
		const c = m.queueJob('C_low', 'low');
		const d = m.queueJob('D_high', 'high');
		const e = m.queueJob('E_normal', 'normal');
		// Dispatch order: D(high), A, B, E (FIFO normal), C(low)
		assert.strictEqual(m.getJobStatusReport(d)!.position, 1);
		assert.strictEqual(m.getJobStatusReport(a)!.position, 2);
		assert.strictEqual(m.getJobStatusReport(b)!.position, 3);
		assert.strictEqual(m.getJobStatusReport(e)!.position, 4);
		assert.strictEqual(m.getJobStatusReport(c)!.position, 5);
		m.dispose();
	});

	test('position is null for non-queued states; queued report shape is correct', async () => {
		const ctl = makeControllable();
		const m = new JobQueueManager(1);
		m.setJobExecutor(ctl.exec);
		m.start();
		const running = m.queueJob('run', 'normal');
		const waiting = m.queueJob('wait', 'normal');
		await sleep(50);
		const rRun = m.getJobStatusReport(running)!;
		const rWait = m.getJobStatusReport(waiting)!;
		assert.strictEqual(rRun.status, 'running');
		assert.strictEqual(rRun.position, null, 'running job position must be null');
		assert.strictEqual(rWait.status, 'queued');
		assert.strictEqual(rWait.position, 1, 'sole queued job is position 1');
		assert.strictEqual(typeof rWait.submittedAt, 'number');
		ctl.releaseAll();
		await sleep(50);
		const rDone = m.getJobStatusReport(running)!;
		assert.strictEqual(rDone.status, 'done');
		assert.strictEqual(rDone.position, null, 'done job position must be null');
		await m.stop();
		m.dispose();
	});

	test('getJobStatusReport returns undefined for unknown job id', () => {
		const m = new JobQueueManager(1);
		assert.strictEqual(m.getJobStatusReport('nope'), undefined);
		assert.strictEqual(m.getQueuePosition('nope'), null);
		m.dispose();
	});
});

suite('JobQueueManager #25 — pool size', () => {
	test('poolSize getter reflects constructor arg and clamps to [1,16]', () => {
		assert.strictEqual(new JobQueueManager(4).poolSize, 4);
		assert.strictEqual(new JobQueueManager(99).poolSize, 16);
		assert.strictEqual(new JobQueueManager(0).poolSize, 1);
	});

	test('pool size N runs exactly N jobs concurrently; the N+1th waits', async () => {
		const ctl = makeControllable();
		const m = new JobQueueManager(3);
		m.setJobExecutor(ctl.exec);
		m.start();
		m.queueJob('s1'); m.queueJob('s2'); m.queueJob('s3'); m.queueJob('s4');
		await sleep(80);
		const running = ['s1', 's2', 's3', 's4'].filter(k => ctl.isRunning(k));
		assert.strictEqual(running.length, 3, `expected 3 concurrent, got ${running.join(',')}`);
		assert.ok(!ctl.isRunning('s4'), 's4 must wait');
		ctl.release(running[0]);
		await sleep(80);
		assert.ok(ctl.isRunning('s4'), 's4 runs once a slot frees');
		ctl.releaseAll();
		await sleep(50);
		await m.stop();
		m.dispose();
	});

	test('live pool is not resizable (no setPoolSize/resize API)', () => {
		const m = new JobQueueManager(2) as unknown as Record<string, unknown>;
		assert.strictEqual(typeof m.setPoolSize, 'undefined');
		assert.strictEqual(typeof m.resize, 'undefined');
	});
});

suite('JobQueueManager #26 — sessionId sticky routing', () => {
	test('(b) two same-session jobs share ONE worker, serialized', async () => {
		const ctl = makeControllable();
		const m = new JobQueueManager(3);
		m.setJobExecutor(ctl.exec);
		m.start();
		m.queueJob('X-1', 'normal', 'X');
		m.queueJob('X-2', 'normal', 'X');
		await sleep(80);
		const run1 = ['X-1', 'X-2'].filter(k => ctl.isRunning(k));
		assert.strictEqual(run1.length, 1, 'only one same-session job runs at a time');
		const firstWorker = m.getAllJobs().find(j => j.filePath.endsWith(run1[0]))!.workerId;
		ctl.release(run1[0]);
		await sleep(80);
		const run2 = ['X-1', 'X-2'].filter(k => ctl.isRunning(k));
		assert.strictEqual(run2.length, 1, 'sibling runs after first completes');
		const siblingWorker = m.getAllJobs().find(j => j.filePath.endsWith(run2[0]))!.workerId;
		assert.strictEqual(siblingWorker, firstWorker, 'sibling lands on the SAME worker');
		ctl.releaseAll();
		await sleep(50);
		await m.stop();
		m.dispose();
	});

	test('(a) a busy session-worker makes its job WAIT, not steal a free worker', async () => {
		const ctl = makeControllable();
		const m = new JobQueueManager(3);
		m.setJobExecutor(ctl.exec);
		m.start();
		m.queueJob('Y-1', 'normal', 'Y');
		await sleep(60);
		assert.ok(ctl.isRunning('Y-1'));
		const yWorker = m.getAllJobs().find(j => j.filePath.endsWith('Y-1'))!.workerId;
		m.queueJob('Y-2', 'normal', 'Y');
		await sleep(80);
		assert.ok(!ctl.isRunning('Y-2'), 'Y-2 must wait for Y\'s worker, not steal a free one');
		m.queueJob('free', 'normal');
		await sleep(80);
		assert.ok(ctl.isRunning('free'), 'a stateless job still runs (no head-of-line block)');
		ctl.release('Y-1');
		await sleep(80);
		assert.ok(ctl.isRunning('Y-2'), 'Y-2 runs once its worker frees');
		const y2Worker = m.getAllJobs().find(j => j.filePath.endsWith('Y-2'))!.workerId;
		assert.strictEqual(y2Worker, yWorker, 'Y-2 ran on Y\'s worker');
		ctl.releaseAll();
		await sleep(50);
		await m.stop();
		m.dispose();
	});

	test('(d) teardown releases the binding; later same-session job rebinds', async () => {
		const ctl = makeControllable();
		const m = new JobQueueManager(2);
		m.setJobExecutor(ctl.exec);
		m.start();
		m.queueJob('Z-1', 'normal', 'Z');
		await sleep(60);
		assert.ok(ctl.isRunning('Z-1'));
		ctl.release('Z-1');
		await sleep(80); // Z drains -> binding released
		m.queueJob('filler', 'normal');
		await sleep(40);
		m.queueJob('Z-2', 'normal', 'Z'); // must rebind, not deadlock
		await sleep(120);
		assert.ok(ctl.isRunning('Z-2'), 'later same-session job rebinds and runs');
		ctl.releaseAll();
		await sleep(50);
		await m.stop();
		m.dispose();
	});

	test('status contract echoes sessionId; stateless omits it', () => {
		const m = new JobQueueManager(2);
		m.setJobExecutor(() => new Promise(() => { /* not started */ }));
		const s = m.queueJob('with', 'normal', 'S1');
		const n = m.queueJob('without', 'normal');
		assert.strictEqual(m.getJobStatusReport(s)!.sessionId, 'S1');
		assert.strictEqual(m.getJobStatusReport(n)!.sessionId, undefined);
		m.dispose();
	});
});

suite('JobQueueManager — stateless regression (unchanged behavior)', () => {
	test('stateless jobs dispatch within pool and reach done', async () => {
		const ctl = makeControllable();
		const m = new JobQueueManager(2);
		m.setJobExecutor(ctl.exec);
		m.start();
		const j1 = m.queueJob('r1', 'normal');
		const j2 = m.queueJob('r2', 'high');
		await sleep(60);
		assert.ok(ctl.isRunning('r1') && ctl.isRunning('r2'));
		assert.strictEqual(m.getJobStatus(j1)!.sessionId, undefined);
		ctl.releaseAll();
		await sleep(60);
		assert.strictEqual(m.getJobStatus(j1)!.status, 'done');
		assert.strictEqual(m.getJobStatus(j2)!.status, 'done');
		assert.strictEqual(m.getQueueStats().done, 2);
		await m.stop();
		m.dispose();
	});
});
