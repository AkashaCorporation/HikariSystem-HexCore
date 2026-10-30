/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as net from 'net';
import * as path from 'path';
import type { PipelineRunStatus } from './automationPipelineRunner';
import type { JobPriority, JobStatusChangeEvent, JobStatusReport, QueueStats } from './jobQueueManager';
import { persistAgentResultRecord, type AgentResultPointer } from './agentBridgeResult';
import {
	AGENT_BRIDGE_DEFAULT_WAIT_TIMEOUT_MS,
	AGENT_BRIDGE_MAX_REQUEST_BYTES,
	AGENT_BRIDGE_MAX_WAIT_TIMEOUT_MS,
	AGENT_BRIDGE_METHOD_SCHEMAS,
	AGENT_BRIDGE_PROTOCOL_VERSION,
	AgentBridgeProtocolError,
	agentBridgeDiscoveryPath,
	canonicalWorkspacePath,
	createAgentBridgeEndpoint,
	isRecord,
	makeAgentBridgeErrorResponse,
	makeAgentBridgeResponse,
	parseAgentBridgeRequest,
	serializeAgentBridgeMessage,
	timingSafeTokenEqual,
	workspaceSha256,
	type AgentBridgeDiscovery,
	type AgentBridgeEvent,
	type AgentBridgeRequest,
} from './agentBridgeProtocol';
import { jobRevisionSha256 } from './jobRevision';

const MAX_EVENT_HISTORY = 512;
const MAX_STATUS_STEPS = 512;
const MAX_VALIDATION_STEPS = 512;
const MAX_VALIDATION_ISSUES = 256;
const JOB_STATUS_FILENAME = 'hexcore-pipeline.status.json';

interface DisposableLike {
	dispose(): void;
}

export interface AgentBridgeQueue {
	queueJobIfAbsent(
		filePath: string,
		priority?: JobPriority,
		sessionId?: string,
		revision?: string,
	): { jobId: string; deduped: boolean; revisionUpdated?: boolean };
	waitForJob(jobId: string): Promise<unknown>;
	cancelJob(jobId: string): boolean;
	getJobStatusReport(jobId: string): JobStatusReport | undefined;
	getQueueStats(): QueueStats;
	onJobStatusChanged(listener: (event: JobStatusChangeEvent) => unknown): DisposableLike;
}

export interface AgentBridgeServerOptions {
	workspaceRoot: string;
	extensionVersion: string;
	queue: AgentBridgeQueue;
	validateJob: (jobFilePath: string) => Promise<{ ok: boolean }>;
	listCapabilities: () => unknown;
	doctor: () => Promise<unknown>;
	jobSchemaPath?: string;
}

interface EventSubscriber {
	socket: net.Socket;
	jobId: string;
}

interface JobDescriptor {
	file: string;
	outDir: string;
	priority: JobPriority;
}

export class AgentBridgeServer implements DisposableLike {
	private readonly workspaceRoot: string;
	private readonly workspaceIdentity: string;
	private readonly instanceId = crypto.randomUUID();
	private readonly token = crypto.randomBytes(32).toString('hex');
	private readonly endpoint: string;
	private readonly discoveryPath: string;
	private readonly server = net.createServer(socket => this.handleConnection(socket));
	private readonly sockets = new Set<net.Socket>();
	private readonly subscribers = new Set<EventSubscriber>();
	private readonly eventHistory: AgentBridgeEvent[] = [];
	private readonly resultPointers = new Map<string, AgentResultPointer>();
	private readonly terminalPromises = new Map<string, Promise<AgentResultPointer | undefined>>();
	private readonly terminalEvents = new Set<string>();
	private readonly submissionPathsInProgress = new Set<string>();
	private readonly deferredSubmissionTransitions = new Map<string, JobStatusChangeEvent[]>();
	private sequence = 0;
	private queueSubscription: DisposableLike | undefined;
	private started = false;
	private disposed = false;

	constructor(private readonly options: AgentBridgeServerOptions) {
		this.workspaceRoot = path.resolve(options.workspaceRoot);
		this.workspaceIdentity = canonicalWorkspacePath(this.workspaceRoot);
		this.endpoint = createAgentBridgeEndpoint(this.workspaceRoot, this.instanceId);
		this.discoveryPath = agentBridgeDiscoveryPath(this.workspaceRoot);
		this.server.on('error', error => {
			if (this.started && !this.disposed) {
				console.error(`[HexCore][AgentBridge] server error for ${this.workspaceRoot}:`, error);
			}
		});
	}

	public async start(): Promise<AgentBridgeDiscovery> {
		if (this.started || this.disposed) {
			throw new Error(this.disposed ? 'Agent Bridge is disposed.' : 'Agent Bridge is already started.');
		}
		this.queueSubscription = this.options.queue.onJobStatusChanged(event => {
			void this.handleQueueStatusChange(event);
		});
		try {
			await new Promise<void>((resolve, reject) => {
				const onError = (error: Error): void => {
					this.server.off('listening', onListening);
					reject(error);
				};
				const onListening = (): void => {
					this.server.off('error', onError);
					resolve();
				};
				this.server.once('error', onError);
				this.server.once('listening', onListening);
				this.server.listen(this.endpoint);
			});
			this.started = true;
			const discovery: AgentBridgeDiscovery = {
			schemaVersion: 1,
			protocolVersion: AGENT_BRIDGE_PROTOCOL_VERSION,
			instanceId: this.instanceId,
			workspace: this.workspaceRoot,
			workspaceSha256: workspaceSha256(this.workspaceRoot),
			endpoint: this.endpoint,
			token: this.token,
			pid: process.pid,
			createdAt: new Date().toISOString(),
			extensionVersion: this.options.extensionVersion,
			};
			writeJsonAtomic(this.discoveryPath, discovery);
			return discovery;
		} catch (error) {
			this.queueSubscription?.dispose();
			this.queueSubscription = undefined;
			try { this.server.close(); } catch { /* not listening */ }
			throw error;
		}
	}

	public dispose(): void {
		if (this.disposed) {
			return;
		}
		this.disposed = true;
		this.queueSubscription?.dispose();
		this.queueSubscription = undefined;
		for (const socket of this.sockets) {
			socket.destroy();
		}
		this.sockets.clear();
		this.subscribers.clear();
		if (this.started) {
			try { this.server.close(); } catch { /* already closed */ }
		}
		this.removeOwnedDiscoveryFile();
		if (process.platform !== 'win32') {
			try { fs.unlinkSync(this.endpoint); } catch { /* absent socket */ }
		}
	}

	private handleConnection(socket: net.Socket): void {
		this.sockets.add(socket);
		let buffer = '';
		let receivedBytes = 0;
		let handled = false;
		const cleanup = (): void => {
			this.sockets.delete(socket);
			for (const subscriber of [...this.subscribers]) {
				if (subscriber.socket === socket) {
					this.subscribers.delete(subscriber);
				}
			}
		};
		socket.on('close', cleanup);
		socket.on('error', cleanup);
		socket.on('data', chunk => {
			if (handled) {
				return;
			}
			receivedBytes += chunk.length;
			if (receivedBytes > AGENT_BRIDGE_MAX_REQUEST_BYTES) {
				handled = true;
				this.writeErrorAndEnd(socket, 'unknown', new AgentBridgeProtocolError('request-too-large', 'Request exceeded the byte limit.'));
				return;
			}
			buffer += chunk.toString('utf8');
			const newline = buffer.indexOf('\n');
			if (newline < 0) {
				return;
			}
			handled = true;
			const line = buffer.slice(0, newline).trim();
			void this.handleRequestLine(socket, line);
		});
	}

	private async handleRequestLine(socket: net.Socket, line: string): Promise<void> {
		let requestId = 'unknown';
		try {
			const request = parseAgentBridgeRequest(line);
			requestId = request.requestId;
			if (!timingSafeTokenEqual(request.token, this.token)) {
				throw new AgentBridgeProtocolError('unauthorized', 'Invalid workspace Agent Bridge token.');
			}
			if (request.method === 'events') {
				await this.openEventStream(socket, request);
				return;
			}
			const result = await this.dispatch(request);
			this.writeAndEnd(socket, makeAgentBridgeResponse(request.requestId, result));
		} catch (error) {
			this.writeErrorAndEnd(socket, requestId, error);
		}
	}

	private async dispatch(request: AgentBridgeRequest): Promise<unknown> {
		switch (request.method) {
			case 'validate': return this.validate(request.params ?? {});
			case 'submit': return this.submit(request.params ?? {});
			case 'status': return this.status(requiredParamString(request.params, 'jobId'));
			case 'wait': return this.wait(request.params ?? {});
			case 'cancel': return this.cancel(requiredParamString(request.params, 'jobId'));
			case 'capabilities': return this.capabilities();
			case 'doctor': return this.options.doctor();
			case 'events': throw new AgentBridgeProtocolError('internal-error', 'events must use streaming dispatch.');
	}
	}

	private async submit(params: Record<string, unknown>): Promise<unknown> {
		const jobFile = requiredParamString(params, 'jobFile');
		const jobPath = this.resolveContainedJobPath(jobFile);
		const rawContent = fs.readFileSync(jobPath, 'utf8');
		const descriptor = this.readContainedJobDescriptor(jobPath, rawContent);
		const validation = await this.options.validateJob(jobPath);
		if (!validation.ok) {
			throw new AgentBridgeProtocolError('job-validation-failed', 'The job failed HexCore preflight validation.', sanitizeValidationReport(validation));
		}
		const priority = parsePriority(params.priority, descriptor.priority);
		const sessionId = optionalSessionId(params.sessionId);
		const revision = jobRevisionSha256(rawContent);
		const submissionPathIdentity = canonicalWorkspacePath(jobPath);
		this.submissionPathsInProgress.add(submissionPathIdentity);
		let queued: { jobId: string; deduped: boolean; revisionUpdated?: boolean };
		try {
			queued = this.options.queue.queueJobIfAbsent(jobPath, priority, sessionId, revision);
		} finally {
			this.submissionPathsInProgress.delete(submissionPathIdentity);
		}
		const eventType = queued.deduped ? 'submission-deduped' : 'submitted';
		this.recordEvent(eventType, queued.jobId, {
			jobFile: jobPath,
			priority,
			revision,
			deduped: queued.deduped,
			...(queued.revisionUpdated ? { revisionUpdated: true } : {}),
			...(sessionId ? { sessionId } : {}),
		});
		const deferredTransitions = this.deferredSubmissionTransitions.get(queued.jobId) ?? [];
		this.deferredSubmissionTransitions.delete(queued.jobId);
		for (const transition of deferredTransitions) {
			void this.handleQueueStatusChange(transition);
		}
		return {
			jobId: queued.jobId,
			jobFile: jobPath,
			priority,
			revision,
			deduped: queued.deduped,
			...(queued.revisionUpdated ? { revisionUpdated: true } : {}),
			validation: sanitizeValidationReport(validation),
		};
	}

	private async status(jobId: string): Promise<unknown> {
		const report = this.requireJobReport(jobId);
		const pointer = isTerminalQueueStatus(report.status) ? await this.ensureTerminalResult(jobId) : undefined;
		return this.sanitizeJobReport(report, pointer);
	}

	private async wait(params: Record<string, unknown>): Promise<unknown> {
		const jobId = requiredParamString(params, 'jobId');
		this.requireJobReport(jobId);
		const timeoutMs = parseTimeout(params.timeoutMs);
		let timeoutHandle: NodeJS.Timeout | undefined;
		try {
			await Promise.race([
				this.options.queue.waitForJob(jobId).catch(() => undefined),
				new Promise<never>((_, reject) => {
					timeoutHandle = setTimeout(
						() => reject(new AgentBridgeProtocolError('wait-timeout', `Timed out waiting for job ${jobId}; the job was not cancelled.`, { timeoutMs })),
						timeoutMs,
					);
				}),
			]);
		} finally {
			if (timeoutHandle) {
				clearTimeout(timeoutHandle);
			}
		}
		const report = this.requireJobReport(jobId);
		const pointer = await this.ensureTerminalResult(jobId);
		return this.sanitizeJobReport(report, pointer);
	}

	private async cancel(jobId: string): Promise<unknown> {
		this.requireJobReport(jobId);
		const cancelled = this.options.queue.cancelJob(jobId);
		const status = await this.status(jobId) as Record<string, unknown>;
		return {
			jobId,
			cancelled,
			cancellationRequested: cancelled && status.queueStatus === 'running',
			status,
		};
	}

	private capabilities(): unknown {
		let jobSchema: unknown;
		if (this.options.jobSchemaPath) {
			try {
				jobSchema = JSON.parse(fs.readFileSync(this.options.jobSchemaPath, 'utf8')) as unknown;
			} catch (error) {
				jobSchema = { unavailable: true, reason: error instanceof Error ? error.message : String(error) };
			}
		}
		return {
			protocolVersion: AGENT_BRIDGE_PROTOCOL_VERSION,
			transport: process.platform === 'win32' ? 'windows-named-pipe' : 'unix-domain-socket',
			workspace: this.workspaceRoot,
			methods: AGENT_BRIDGE_METHOD_SCHEMAS,
			limits: {
				maxRequestBytes: AGENT_BRIDGE_MAX_REQUEST_BYTES,
				maxWaitTimeoutMs: AGENT_BRIDGE_MAX_WAIT_TIMEOUT_MS,
				maxEventHistory: MAX_EVENT_HISTORY,
			},
			pipelineCapabilities: this.options.listCapabilities(),
			...(jobSchema === undefined ? {} : { jobSchema }),
		};
	}

	private async openEventStream(socket: net.Socket, request: AgentBridgeRequest): Promise<void> {
		const jobId = requiredParamString(request.params, 'jobId');
		const report = this.requireJobReport(jobId);
		const sinceSequence = optionalNonNegativeInteger(request.params?.sinceSequence, 'sinceSequence') ?? 0;
		this.write(socket, makeAgentBridgeResponse(request.requestId, {
			subscribed: true,
			jobId,
			sinceSequence,
			latestSequence: this.sequence,
			snapshot: await this.status(jobId),
		}));

		if (isTerminalQueueStatus(report.status)) {
			await this.emitTerminalEventOnce(jobId);
			for (const event of this.eventHistory) {
				if (event.event.jobId === jobId && event.event.sequence > sinceSequence) {
					this.write(socket, event);
				}
			}
			socket.end();
			return;
		}

		for (const event of this.eventHistory) {
			if (event.event.jobId === jobId && event.event.sequence > sinceSequence) {
				this.write(socket, event);
			}
		}
		this.subscribers.add({ socket, jobId });
	}

	private async handleQueueStatusChange(event: JobStatusChangeEvent): Promise<void> {
		const report = this.options.queue.getJobStatusReport(event.jobId);
		if (report && this.submissionPathsInProgress.has(canonicalWorkspacePath(report.filePath))) {
			const deferred = this.deferredSubmissionTransitions.get(event.jobId) ?? [];
			deferred.push(event);
			this.deferredSubmissionTransitions.set(event.jobId, deferred);
			return;
		}
		if (event.newStatus === 'running') {
			this.recordEvent('running', event.jobId, report ? this.sanitizeJobReport(report) : { status: 'running' });
			return;
		}
		if (isTerminalQueueStatus(event.newStatus)) {
			await this.emitTerminalEventOnce(event.jobId);
		}
	}

	private async validate(params: Record<string, unknown>): Promise<unknown> {
		const jobFile = requiredParamString(params, 'jobFile');
		const jobPath = this.resolveContainedJobPath(jobFile);
		const rawContent = fs.readFileSync(jobPath, 'utf8');
		const revision = jobRevisionSha256(rawContent);
		try {
			const descriptor = this.readContainedJobDescriptor(jobPath, rawContent);
			const validation = await this.options.validateJob(jobPath);
			return {
				valid: validation.ok,
				jobFile: jobPath,
				revision,
				target: descriptor.file,
				outDir: descriptor.outDir,
				priority: descriptor.priority,
				validation: sanitizeValidationReport(validation),
			};
		} catch (error) {
			const code = error instanceof AgentBridgeProtocolError ? error.code : 'job-validation-failed';
			return {
				valid: false,
				jobFile: jobPath,
				revision,
				error: {
					code,
					message: error instanceof Error ? error.message : String(error),
				},
			};
		}
	}

	private async emitTerminalEventOnce(jobId: string): Promise<void> {
		if (this.terminalEvents.has(jobId)) {
			return;
		}
		this.terminalEvents.add(jobId);
		const report = this.options.queue.getJobStatusReport(jobId);
		if (!report) {
			return;
		}
		const pointer = await this.ensureTerminalResult(jobId);
		this.recordEvent('terminal', jobId, this.sanitizeJobReport(report, pointer));
	}

	private recordEvent(eventType: AgentBridgeEvent['event']['eventType'], jobId: string, payload: unknown): void {
		const event: AgentBridgeEvent = {
			protocolVersion: AGENT_BRIDGE_PROTOCOL_VERSION,
			type: 'event',
			event: {
				sequence: ++this.sequence,
				timestamp: new Date().toISOString(),
				eventType,
				jobId,
				payload,
			},
		};
		this.eventHistory.push(event);
		while (this.eventHistory.length > MAX_EVENT_HISTORY) {
			this.eventHistory.shift();
		}
		for (const subscriber of [...this.subscribers]) {
			if (subscriber.jobId !== jobId) {
				continue;
			}
			this.write(subscriber.socket, event);
			if (eventType === 'terminal') {
				this.subscribers.delete(subscriber);
				subscriber.socket.end();
			}
		}
	}

	private async ensureTerminalResult(jobId: string): Promise<AgentResultPointer | undefined> {
		const existing = this.resultPointers.get(jobId);
		if (existing) {
			return existing;
		}
		const pending = this.terminalPromises.get(jobId);
		if (pending) {
			return pending;
		}
		const promise = Promise.resolve().then(() => {
			const report = this.options.queue.getJobStatusReport(jobId);
			if (!report || !isTerminalQueueStatus(report.status)) {
				return undefined;
			}
			const run = asPipelineRunStatus(report.result) ?? this.readPipelineStatus(report);
			if (!run || run.status === 'running') {
				return undefined;
			}
			const pointer = persistAgentResultRecord({
				jobId,
				queueStatus: report.status,
				...(report.revision ? { revision: report.revision } : {}),
				run,
			});
			this.resultPointers.set(jobId, pointer);
			return pointer;
		}).finally(() => {
			this.terminalPromises.delete(jobId);
		});
		this.terminalPromises.set(jobId, promise);
		return promise;
	}

	private sanitizeJobReport(report: JobStatusReport, pointer?: AgentResultPointer): unknown {
		const run = asPipelineRunStatus(report.result) ?? this.readPipelineStatus(report);
		return {
			jobId: report.jobId,
			queueStatus: report.status,
			priority: report.priority,
			position: report.position,
			submittedAt: report.submittedAt,
			...(report.startedAt !== undefined ? { startedAt: report.startedAt } : {}),
			...(report.completedAt !== undefined ? { completedAt: report.completedAt } : {}),
			jobFile: report.filePath,
			...(report.revision ? { revision: report.revision } : {}),
			...(report.sessionId ? { sessionId: report.sessionId } : {}),
			...(report.workerId !== undefined ? { workerId: report.workerId } : {}),
			...(report.error ? { error: truncate(report.error, 4096) } : {}),
			...(run ? { pipeline: summarizePipelineStatus(run) } : {}),
			...(pointer ? { resultRecord: pointer } : {}),
			queue: this.options.queue.getQueueStats(),
		};
	}

	private readPipelineStatus(report: JobStatusReport): PipelineRunStatus | undefined {
		try {
			const rawJob = JSON.parse(fs.readFileSync(report.filePath, 'utf8')) as unknown;
			if (!isRecord(rawJob) || typeof rawJob.outDir !== 'string') {
				return undefined;
			}
			const outDir = path.isAbsolute(rawJob.outDir)
				? rawJob.outDir
				: path.resolve(path.dirname(report.filePath), rawJob.outDir);
			const parsed = JSON.parse(fs.readFileSync(path.join(outDir, JOB_STATUS_FILENAME), 'utf8')) as unknown;
			const run = asPipelineRunStatus(parsed);
			if (!run || run.provenance.jobId !== report.jobId) {
				return undefined;
			}
			if (report.revision && run.jobFileSha256 && report.revision !== run.jobFileSha256) {
				return undefined;
			}
			return run;
		} catch {
			return undefined;
		}
	}

	private resolveContainedJobPath(jobFile: string): string {
		const resolved = path.isAbsolute(jobFile) ? path.resolve(jobFile) : path.resolve(this.workspaceRoot, jobFile);
		if (!resolved.toLowerCase().endsWith('.hexcore_job.json')) {
			throw new AgentBridgeProtocolError('invalid-job-path', 'Agent Bridge only accepts *.hexcore_job.json files.');
		}
		if (!fs.existsSync(resolved) || !fs.statSync(resolved).isFile()) {
			throw new AgentBridgeProtocolError('job-not-found', `Job file not found: ${resolved}`);
		}
		this.assertContained(resolved, 'job file', true);
		return resolved;
	}

	private readContainedJobDescriptor(jobPath: string, rawContent: string): JobDescriptor {
		let parsed: unknown;
		try {
			parsed = JSON.parse(rawContent);
		} catch {
			throw new AgentBridgeProtocolError('invalid-job-json', `Job file is not valid JSON: ${jobPath}`);
		}
		if (!isRecord(parsed) || typeof parsed.file !== 'string' || typeof parsed.outDir !== 'string') {
			throw new AgentBridgeProtocolError('invalid-job', 'Job requires string file and outDir fields.');
		}
		const baseDir = path.dirname(jobPath);
		const target = path.isAbsolute(parsed.file) ? path.resolve(parsed.file) : path.resolve(baseDir, parsed.file);
		const outDir = path.isAbsolute(parsed.outDir) ? path.resolve(parsed.outDir) : path.resolve(baseDir, parsed.outDir);
		this.assertContained(target, 'analysis target', true);
		this.assertContained(outDir, 'output directory', false);
		return {
			file: target,
			outDir,
			priority: parsePriority(parsed.priority, 'normal'),
		};
	}

	private assertContained(candidate: string, label: string, mustExist: boolean): void {
		if (mustExist && !fs.existsSync(candidate)) {
			throw new AgentBridgeProtocolError('target-not-found', `${label} not found: ${candidate}`);
		}
		const physicalCandidate = resolvePhysicalPath(candidate);
		const physicalWorkspace = resolvePhysicalPath(this.workspaceRoot);
		if (!isPathWithin(physicalWorkspace, physicalCandidate)) {
			throw new AgentBridgeProtocolError(
				'containment-violation',
				`Agent Bridge ${label} resolves outside its authenticated workspace.`,
				{ workspace: this.workspaceRoot, candidate },
			);
		}
	}

	private requireJobReport(jobId: string): JobStatusReport {
		const report = this.options.queue.getJobStatusReport(jobId);
		if (!report) {
			throw new AgentBridgeProtocolError('job-not-found', `Unknown job: ${jobId}`);
		}
		if (!isPathWithin(this.workspaceIdentity, canonicalWorkspacePath(report.filePath))) {
			throw new AgentBridgeProtocolError('containment-violation', 'Job belongs to a different workspace bridge.');
		}
		return report;
	}

	private write(socket: net.Socket, message: ReturnType<typeof makeAgentBridgeResponse> | AgentBridgeEvent): void {
		try {
			socket.write(serializeAgentBridgeMessage(message));
		} catch (error) {
			if (!socket.destroyed) {
				socket.end(serializeAgentBridgeMessage(makeAgentBridgeErrorResponse('unknown', error)));
			}
		}
	}

	private writeAndEnd(socket: net.Socket, message: ReturnType<typeof makeAgentBridgeResponse>): void {
		try {
			socket.end(serializeAgentBridgeMessage(message));
		} catch (error) {
			socket.end(serializeAgentBridgeMessage(makeAgentBridgeErrorResponse(message.requestId, error)));
		}
	}

	private writeErrorAndEnd(socket: net.Socket, requestId: string, error: unknown): void {
		this.writeAndEnd(socket, makeAgentBridgeErrorResponse(requestId, error));
	}

	private removeOwnedDiscoveryFile(): void {
		try {
			const parsed = JSON.parse(fs.readFileSync(this.discoveryPath, 'utf8')) as unknown;
			if (isRecord(parsed) && parsed.instanceId === this.instanceId) {
				fs.unlinkSync(this.discoveryPath);
			}
		} catch {
			// A missing or replaced discovery file is not ours to repair during dispose.
		}
	}
}

function summarizePipelineStatus(run: PipelineRunStatus): unknown {
	return {
		status: run.status,
		executionId: run.provenance.executionId,
		jobFileSha256: run.jobFileSha256 ?? run.provenance.jobFileSha256,
		startedAt: run.startedAt,
		...(run.finishedAt ? { finishedAt: run.finishedAt } : {}),
		target: {
			path: run.provenance.binaryPath,
			sha256: run.provenance.binarySha256,
			format: run.provenance.binaryFormat,
			...(run.provenance.architecture ? { architecture: run.provenance.architecture } : {}),
			...(run.provenance.imageBase ? { imageBase: run.provenance.imageBase } : {}),
		},
		outDir: run.outDir,
		...(run.provenanceManifestPath ? { provenanceManifestPath: run.provenanceManifestPath } : {}),
		...(run.summary ? { summary: run.summary } : {}),
		steps: run.steps.slice(0, MAX_STATUS_STEPS).map(step => ({
			...(step.stepId ? { stepId: step.stepId } : {}),
			...(step.stepIndex !== undefined ? { stepIndex: step.stepIndex } : {}),
			cmd: step.cmd,
			resolvedCmd: step.resolvedCmd,
			status: step.status,
			durationMs: step.durationMs,
			attemptCount: step.attemptCount,
			...(step.outputPath ? { outputPath: step.outputPath } : {}),
			...(step.outputBytes !== undefined ? { outputBytes: step.outputBytes } : {}),
			...(step.artifactProvenancePath ? { artifactProvenancePath: step.artifactProvenancePath } : {}),
			...(step.error ? { error: truncate(step.error, 4096) } : {}),
		})),
		truncatedSteps: Math.max(0, run.steps.length - MAX_STATUS_STEPS),
	};
}

function sanitizeValidationReport(validation: unknown): unknown {
	if (!isRecord(validation)) {
		return { ok: false };
	}
	const issues = Array.isArray(validation.issues) ? validation.issues : [];
	const steps = Array.isArray(validation.steps) ? validation.steps : [];
	return {
		ok: validation.ok === true,
		...(typeof validation.jobFile === 'string' ? { jobFile: truncate(validation.jobFile, 4096) } : {}),
		...(typeof validation.file === 'string' ? { file: truncate(validation.file, 4096) } : {}),
		...(typeof validation.outDir === 'string' ? { outDir: truncate(validation.outDir, 4096) } : {}),
		...(typeof validation.generatedAt === 'string' ? { generatedAt: validation.generatedAt } : {}),
		...(typeof validation.totalSteps === 'number' ? { totalSteps: validation.totalSteps } : {}),
		issues: issues.slice(0, MAX_VALIDATION_ISSUES).map(issue => sanitizeValidationEntry(issue)),
		steps: steps.slice(0, MAX_VALIDATION_STEPS).map(step => sanitizeValidationEntry(step)),
		truncatedIssues: Math.max(0, issues.length - MAX_VALIDATION_ISSUES),
		truncatedSteps: Math.max(0, steps.length - MAX_VALIDATION_STEPS),
	};
}

function sanitizeValidationEntry(value: unknown): unknown {
	if (!isRecord(value)) {
		return String(value).slice(0, 1024);
	}
	const output: Record<string, unknown> = {};
	for (const key of Object.keys(value).sort().slice(0, 64)) {
		const field = value[key];
		if (typeof field === 'string') {
			output[key] = truncate(field, 2048);
		} else if (typeof field === 'number' || typeof field === 'boolean' || field === null) {
			output[key] = field;
		} else if (Array.isArray(field)) {
			output[key] = field.slice(0, 32).map(entry => isRecord(entry) ? sanitizeValidationEntry(entry) : entry);
		}
	}
	return output;
}

function asPipelineRunStatus(value: unknown): PipelineRunStatus | undefined {
	if (!isRecord(value) || !isRecord(value.provenance) || !Array.isArray(value.steps)) {
		return undefined;
	}
	if (typeof value.jobFile !== 'string' || typeof value.file !== 'string' || typeof value.outDir !== 'string') {
		return undefined;
	}
	if (typeof value.status !== 'string' || typeof value.startedAt !== 'string') {
		return undefined;
	}
	if (typeof value.provenance.executionId !== 'string' || typeof value.provenance.binarySha256 !== 'string') {
		return undefined;
	}
	return value as unknown as PipelineRunStatus;
}

function requiredParamString(params: Record<string, unknown> | undefined, key: string): string {
	const value = params?.[key];
	if (typeof value !== 'string' || value.trim().length === 0 || value.length > 4096) {
		throw new AgentBridgeProtocolError('invalid-params', `${key} must be a non-empty string.`);
	}
	return value.trim();
}

function optionalSessionId(value: unknown): string | undefined {
	if (value === undefined) {
		return undefined;
	}
	if (typeof value !== 'string' || value.trim().length === 0 || value.length > 128) {
		throw new AgentBridgeProtocolError('invalid-params', 'sessionId must be a non-empty string of at most 128 characters.');
	}
	return value.trim();
}

function parsePriority(value: unknown, fallback: JobPriority): JobPriority {
	if (value === undefined) {
		return fallback;
	}
	if (value === 'high' || value === 'normal' || value === 'low') {
		return value;
	}
	throw new AgentBridgeProtocolError('invalid-params', 'priority must be high, normal, or low.');
}

function parseTimeout(value: unknown): number {
	if (value === undefined) {
		return AGENT_BRIDGE_DEFAULT_WAIT_TIMEOUT_MS;
	}
	if (!Number.isInteger(value) || (value as number) < 1 || (value as number) > AGENT_BRIDGE_MAX_WAIT_TIMEOUT_MS) {
		throw new AgentBridgeProtocolError('invalid-params', `timeoutMs must be an integer from 1 to ${AGENT_BRIDGE_MAX_WAIT_TIMEOUT_MS}.`);
	}
	return value as number;
}

function optionalNonNegativeInteger(value: unknown, key: string): number | undefined {
	if (value === undefined) {
		return undefined;
	}
	if (!Number.isInteger(value) || (value as number) < 0) {
		throw new AgentBridgeProtocolError('invalid-params', `${key} must be a non-negative integer.`);
	}
	return value as number;
}

function isTerminalQueueStatus(status: string): boolean {
	return status === 'done' || status === 'failed' || status === 'cancelled';
}

function isPathWithin(root: string, candidate: string): boolean {
	const relative = path.relative(root, candidate);
	return relative === '' || (relative !== '..' && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative));
}

function resolvePhysicalPath(candidate: string): string {
	let current = path.resolve(candidate);
	const suffix: string[] = [];
	while (!fs.existsSync(current)) {
		const parent = path.dirname(current);
		if (parent === current) {
			break;
		}
		suffix.unshift(path.basename(current));
		current = parent;
	}
	let physical = current;
	try {
		physical = fs.realpathSync.native(current);
	} catch {
		physical = path.resolve(current);
	}
	return path.resolve(physical, ...suffix);
}

function writeJsonAtomic(filePath: string, value: unknown): void {
	fs.mkdirSync(path.dirname(filePath), { recursive: true });
	const serialized = `${JSON.stringify(value, null, 2)}\n`;
	const tempPath = `${filePath}.${process.pid}.${Date.now()}.tmp`;
	fs.writeFileSync(tempPath, serialized, { encoding: 'utf8', mode: 0o600 });
	fs.renameSync(tempPath, filePath);
}

function truncate(value: string, limit: number): string {
	return value.length <= limit ? value : `${value.slice(0, limit)}...[TRUNCATED]`;
}
