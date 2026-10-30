/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import * as assert from 'assert';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import type { PipelineRunStatus } from './automationPipelineRunner';
import { requestAgentBridge, streamAgentBridgeEvents } from './agentBridgeClient';
import { agentBridgeDiscoveryPath } from './agentBridgeProtocol';
import { AgentBridgeServer, type AgentBridgeQueue } from './agentBridgeServer';
import type { JobPriority, JobStatus, JobStatusChangeEvent, JobStatusReport, QueueStats } from './jobQueueManager';

suite('Agent Bridge server', () => {
	let root: string;
	let server: AgentBridgeServer;
	let queue: FakeQueue;
	let validationReport: { ok: boolean; [key: string]: unknown };

	setup(async () => {
		root = fs.mkdtempSync(path.join(os.tmpdir(), 'hexcore-agent-server-'));
		queue = new FakeQueue();
		validationReport = { ok: true };
		server = new AgentBridgeServer({
			workspaceRoot: root,
			extensionVersion: 'test',
			queue,
			validateJob: async () => validationReport,
			listCapabilities: () => [{ command: 'hexcore.test' }],
			doctor: async () => ({ status: 'ready' }),
		});
		await server.start();
	});

	teardown(() => {
		server.dispose();
		fs.rmSync(root, { recursive: true, force: true });
	});

	test('submits through the existing queue and streams a hash-bound terminal result', async () => {
		const fixture = writeJobFixture(root);
		const submit = await requestAgentBridge(root, 'submit', { jobFile: fixture.jobPath }) as any;
		assert.strictEqual(submit.deduped, false);
		const duplicate = await requestAgentBridge(root, 'submit', { jobFile: fixture.jobPath }) as any;
		assert.strictEqual(duplicate.jobId, submit.jobId);
		assert.strictEqual(duplicate.deduped, true);

		const stream = streamAgentBridgeEvents(root, { jobId: submit.jobId }, () => undefined);
		queue.complete(submit.jobId, sampleRun(fixture, submit.jobId, submit.revision));
		const streamed = await stream;
		assert.strictEqual(streamed.terminalEvent?.event.eventType, 'terminal');

		const terminal = await requestAgentBridge(root, 'wait', { jobId: submit.jobId, timeoutMs: 1000 }) as any;
		assert.strictEqual(terminal.queueStatus, 'done');
		assert.strictEqual(terminal.pipeline.status, 'partial');
		assert.strictEqual(terminal.pipeline.executionId, 'execution-agent-test');
		assert.strictEqual(terminal.pipeline.target.sha256, 'b'.repeat(64));
		assert.ok(fs.existsSync(terminal.resultRecord.path));
		assert.strictEqual(typeof terminal.resultRecord.sha256, 'string');
	});

	test('validates a job without enqueueing it', async () => {
		const fixture = writeJobFixture(root);
		const result = await requestAgentBridge(root, 'validate', { jobFile: fixture.jobPath }) as any;
		assert.strictEqual(result.valid, true);
		assert.strictEqual(result.target, fixture.targetPath);
		assert.strictEqual(result.validation.ok, true);
		assert.deepStrictEqual(queue.getQueueStats(), { queued: 0, running: 0, done: 0, failed: 0, cancelled: 0 });
	});

	test('returns a bounded invalid contract without enqueueing', async () => {
		validationReport = { ok: false, issues: [{ level: 'error', code: 'FIXTURE', message: 'invalid fixture' }], steps: [] };
		const fixture = writeJobFixture(root);
		const result = await requestAgentBridge(root, 'validate', { jobFile: fixture.jobPath }) as any;
		assert.strictEqual(result.valid, false);
		assert.strictEqual(result.validation.issues[0].code, 'FIXTURE');
		assert.strictEqual(queue.getQueueStats().queued, 0);
	});

	test('rejects targets that escape the authenticated workspace', async () => {
		const outsideTarget = path.join(path.dirname(root), `${path.basename(root)}-outside.bin`);
		fs.writeFileSync(outsideTarget, Buffer.from([0xc3]));
		const outDir = path.join(root, 'reports');
		const jobPath = path.join(root, 'escape.hexcore_job.json');
		fs.writeFileSync(jobPath, JSON.stringify({ file: outsideTarget, outDir, steps: [{ cmd: 'hexcore.test' }] }));
		try {
			await assert.rejects(
				requestAgentBridge(root, 'submit', { jobFile: jobPath }),
				(error: unknown) => (error as any)?.code === 'containment-violation',
			);
		} finally {
			fs.unlinkSync(outsideTarget);
		}
	});

	test('exposes protocol schemas and doctor without exposing the token', async () => {
		const capabilities = await requestAgentBridge(root, 'capabilities') as any;
		assert.strictEqual(capabilities.protocolVersion, 1);
		assert.ok(capabilities.methods.submit);
		assert.strictEqual(JSON.stringify(capabilities).includes('token'), false);
		assert.deepStrictEqual(await requestAgentBridge(root, 'doctor'), { status: 'ready' });
	});

	test('orders submitted before a synchronous running transition', async () => {
		queue.startSynchronously = true;
		const fixture = writeJobFixture(root);
		const submit = await requestAgentBridge(root, 'submit', { jobFile: fixture.jobPath }) as any;
		const messages: any[] = [];
		const stream = streamAgentBridgeEvents(root, { jobId: submit.jobId }, message => messages.push(message));
		queue.complete(submit.jobId, sampleRun(fixture, submit.jobId, submit.revision));
		await stream;
		assert.deepStrictEqual(
			messages.filter(message => message.type === 'event').map(message => message.event.eventType),
			['submitted', 'running', 'terminal'],
		);
	});

	test('rejects an invalid workspace token', async () => {
		const discoveryPath = agentBridgeDiscoveryPath(root);
		const discovery = JSON.parse(fs.readFileSync(discoveryPath, 'utf8'));
		fs.writeFileSync(discoveryPath, JSON.stringify({ ...discovery, token: 'invalid-token' }));
		try {
			await assert.rejects(
				requestAgentBridge(root, 'doctor'),
				(error: unknown) => (error as any)?.code === 'unauthorized',
			);
		} finally {
			fs.writeFileSync(discoveryPath, JSON.stringify(discovery));
		}
	});

	test('bounds large validation reports before returning them', async () => {
		validationReport = {
			ok: true,
			totalSteps: 600,
			issues: Array.from({ length: 300 }, (_, index) => ({ level: 'warning', code: `W${index}`, message: 'x'.repeat(4096) })),
			steps: Array.from({ length: 600 }, (_, index) => ({ index, cmd: `hexcore.test.${index}`, registered: true })),
		};
		const fixture = writeJobFixture(root);
		const submit = await requestAgentBridge(root, 'submit', { jobFile: fixture.jobPath }) as any;
		assert.strictEqual(submit.validation.issues.length, 256);
		assert.strictEqual(submit.validation.steps.length, 512);
		assert.strictEqual(submit.validation.truncatedIssues, 44);
		assert.strictEqual(submit.validation.truncatedSteps, 88);
	});
});

class FakeQueue implements AgentBridgeQueue {
	private readonly reports = new Map<string, JobStatusReport>();
	private readonly listeners = new Set<(event: JobStatusChangeEvent) => unknown>();
	private counter = 0;
	public startSynchronously = false;

	queueJobIfAbsent(filePath: string, priority: JobPriority = 'normal', sessionId?: string, revision?: string): { jobId: string; deduped: boolean } {
		const active = [...this.reports.values()].find(report => report.filePath === filePath && (report.status === 'queued' || report.status === 'running'));
		if (active && active.revision === revision) {
			return { jobId: active.jobId, deduped: true };
		}
		const jobId = `job-${++this.counter}`;
		const report: JobStatusReport = {
			jobId,
			status: 'queued',
			priority,
			position: 1,
			submittedAt: Date.now(),
			filePath,
			...(revision ? { revision } : {}),
			...(sessionId ? { sessionId } : {}),
		};
		this.reports.set(jobId, report);
		if (this.startSynchronously) {
			report.startedAt = Date.now();
			this.transition(report, 'running');
		}
		return { jobId, deduped: false };
	}

	waitForJob(jobId: string): Promise<unknown> {
		const current = this.reports.get(jobId);
		if (current && terminal(current.status)) {
			return Promise.resolve(current.result);
		}
		return new Promise(resolve => {
			const listener = (event: JobStatusChangeEvent): void => {
				if (event.jobId === jobId && terminal(event.newStatus)) {
					this.listeners.delete(listener);
					resolve(event.result);
				}
			};
			this.listeners.add(listener);
		});
	}

	cancelJob(jobId: string): boolean {
		const report = this.reports.get(jobId);
		if (!report || terminal(report.status)) { return false; }
		this.transition(report, 'cancelled');
		return true;
	}

	getJobStatusReport(jobId: string): JobStatusReport | undefined {
		return this.reports.get(jobId);
	}

	getQueueStats(): QueueStats {
		const stats: QueueStats = { queued: 0, running: 0, done: 0, failed: 0, cancelled: 0 };
		for (const report of this.reports.values()) { stats[report.status]++; }
		return stats;
	}

	onJobStatusChanged(listener: (event: JobStatusChangeEvent) => unknown): { dispose(): void } {
		this.listeners.add(listener);
		return { dispose: () => this.listeners.delete(listener) };
	}

	complete(jobId: string, result: PipelineRunStatus): void {
		const report = this.reports.get(jobId);
		if (!report) { throw new Error(`Unknown fake job ${jobId}`); }
		report.result = result;
		this.transition(report, 'done');
	}

	private transition(report: JobStatusReport, status: JobStatus): void {
		const oldStatus = report.status;
		report.status = status;
		report.position = null;
		report.completedAt = Date.now();
		const event: JobStatusChangeEvent = { jobId: report.jobId, oldStatus, newStatus: status, result: report.result, error: report.error };
		for (const listener of [...this.listeners]) { listener(event); }
	}
}

function writeJobFixture(root: string): { jobPath: string; targetPath: string; outDir: string; outputPath: string; artifactPath: string } {
	const targetPath = path.join(root, 'target.bin');
	const outDir = path.join(root, 'reports');
	const outputPath = path.join(outDir, 'step.json');
	const artifactPath = path.join(outDir, 'step.provenance.json');
	fs.mkdirSync(outDir, { recursive: true });
	fs.writeFileSync(targetPath, Buffer.from([0x90, 0xc3]));
	fs.writeFileSync(outputPath, JSON.stringify({ status: 'UNKNOWN' }));
	fs.writeFileSync(artifactPath, JSON.stringify({ artifact: { path: outputPath, sha256: 'c'.repeat(64) } }));
	const jobPath = path.join(root, 'test.hexcore_job.json');
	fs.writeFileSync(jobPath, JSON.stringify({ file: targetPath, outDir, priority: 'high', steps: [{ cmd: 'hexcore.test' }] }));
	return { jobPath, targetPath, outDir, outputPath, artifactPath };
}

function sampleRun(fixture: ReturnType<typeof writeJobFixture>, jobId: string, revision: string): PipelineRunStatus {
	return {
		jobFile: fixture.jobPath,
		jobFileSha256: revision,
		file: fixture.targetPath,
		outDir: fixture.outDir,
		status: 'partial',
		startedAt: '2026-10-28T00:00:00.000Z',
		finishedAt: '2026-10-28T00:00:01.000Z',
		steps: [{
			cmd: 'hexcore.test', resolvedCmd: 'hexcore.test', status: 'partial',
			startedAt: '2026-10-28T00:00:00.000Z', finishedAt: '2026-10-28T00:00:01.000Z',
			durationMs: 1000, attemptCount: 1, outputPath: fixture.outputPath,
			outputBytes: fs.statSync(fixture.outputPath).size, artifactProvenancePath: fixture.artifactPath,
		}],
		provenance: {
			analysisContractVersion: 1, executionId: 'execution-agent-test', jobFileSha256: revision,
			jobId, contextGeneration: 1, binaryPath: fixture.targetPath, binarySha256: 'b'.repeat(64), binaryFormat: 'raw',
		},
	};
}

function terminal(status: JobStatus): boolean {
	return status === 'done' || status === 'failed' || status === 'cancelled';
}
