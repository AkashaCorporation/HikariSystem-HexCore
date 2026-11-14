/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Akasha Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as crypto from 'crypto';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import * as v8 from 'v8';
import * as zlib from 'zlib';
import { fork, type ChildProcess } from 'child_process';
import type { AnalysisEngineSnapshotV1, DisassemblerEngine } from './disassemblerEngine';
import type { QueryMaterializationPlan } from './queryMaterialization';
import { writeJsonAtomic } from './analyzeAllProcess';

export interface IsolatedQueryMaterializationRequest {
	filePath: string;
	inputSnapshotPath: string;
	inputSnapshotSha256: string;
	outputSnapshotPath: string;
	heartbeatPath: string;
	functions: Array<{ address: number; maxBytes: number }>;
	timeoutMs: number;
}

export interface StagedQueryMaterializationFunction {
	address: string;
	status: 'complete' | 'partial' | 'decode-empty' | 'unknown-function';
	spanBytes: number;
	instructionCount: number;
	bodySha256?: string;
}

export interface QueryMaterializationNativeExecution {
	isolation: 'child-process';
	outcome: 'completed' | 'timeout' | 'cancelled' | 'crashed' | 'error';
	workerPid?: number;
	durationMs: number;
	lastPhase: string;
	heartbeats: number;
	lastWorkerHeartbeatAt?: string;
	lastMemory?: { rss: number; heapUsed: number; heapTotal: number; external: number };
	peakHeapUsed: number;
	inputSnapshotSha256: string;
	outputSnapshotSha256?: string;
	artifactsRemoved: boolean;
}

export interface StagedQueryMaterializationResult {
	snapshot: AnalysisEngineSnapshotV1;
	functions: readonly StagedQueryMaterializationFunction[];
	nativeExecution: QueryMaterializationNativeExecution;
}

type WorkerMessage =
	| { type: 'phase' | 'heartbeat'; phase: string; at: string; pid: number; memory?: { rss: number; heapUsed: number; heapTotal: number; external: number } }
	| { type: 'result'; outputSnapshotPath: string; outputSnapshotSha256: string; outputSnapshotBytes: number; functions: StagedQueryMaterializationFunction[] }
	| { type: 'error'; error: string; phase: string };

export class QueryMaterializationProcessError extends Error {
	constructor(message: string, public readonly execution: QueryMaterializationNativeExecution) {
		super(message);
		this.name = 'QueryMaterializationProcessError';
	}
}

export type QueryMaterializationChildLauncher = () => ChildProcess;

function launchChild(): ChildProcess {
	return fork(path.join(__dirname, 'queryMaterializationProcessChild.js'), [], {
		env: { ...process.env, ELECTRON_RUN_AS_NODE: '1' }, execArgv: [], serialization: 'advanced',
		stdio: ['ignore', 'ignore', 'pipe', 'ipc'],
	});
}

export class QueryMaterializationProcessController {
	private active?: { child: ChildProcess; cancel: () => void };
	constructor(private readonly launch: QueryMaterializationChildLauncher = launchChild) {}

	isActive(): boolean { return this.active !== undefined; }
	cancelActive(): boolean { if (!this.active) return false; this.active.cancel(); return true; }

	async run(engine: DisassemblerEngine, plan: QueryMaterializationPlan, signal?: AbortSignal): Promise<StagedQueryMaterializationResult> {
		if (this.active) throw new Error('A query materialization process is already active.');
		if (signal?.aborted) {
			throw new QueryMaterializationProcessError('Query materialization cancelled before staging.', {
				isolation: 'child-process', outcome: 'cancelled', durationMs: 0, lastPhase: 'before-launch',
				heartbeats: 0, peakHeapUsed: 0, inputSnapshotSha256: sha256(Buffer.alloc(0)), artifactsRemoved: true,
			});
		}
		const filePath = engine.getFilePath();
		if (!filePath) throw new Error('Query materialization requires a loaded target.');
		const root = path.join(os.tmpdir(), 'hexcore-query-materialization', crypto.randomUUID());
		fs.mkdirSync(root, { recursive: true });
		const inputSnapshotPath = path.join(root, 'input.snapshot.gz');
		const outputSnapshotPath = path.join(root, 'output.snapshot.gz');
		const heartbeatPath = path.join(root, 'heartbeat.json');
		const inputCompressed = zlib.gzipSync(v8.serialize(engine.exportAnalysisSnapshot()), { level: 1 });
		fs.writeFileSync(inputSnapshotPath, inputCompressed);
		const inputSnapshotSha256 = sha256(inputCompressed);
		const request: IsolatedQueryMaterializationRequest = {
			filePath, inputSnapshotPath, inputSnapshotSha256, outputSnapshotPath, heartbeatPath,
			functions: plan.requested.map(entry => ({ address: entry.address, maxBytes: entry.spanBytes })),
			timeoutMs: plan.maxMilliseconds,
		};
		try {
			return await this.execute(request, root, signal);
		} catch (error) {
			safeCleanup(root);
			throw error;
		}
	}

	private execute(request: IsolatedQueryMaterializationRequest, root: string, signal?: AbortSignal): Promise<StagedQueryMaterializationResult> {
		return new Promise((resolve, reject) => {
			const startedAt = Date.now();
			const child = this.launch();
			let settled = false;
			let stderr = '';
			let lastPhase = 'launch';
			let heartbeats = 0;
			let lastWorkerHeartbeatAt: string | undefined;
			let lastMemory: QueryMaterializationNativeExecution['lastMemory'];
			let peakHeapUsed = 0;
			let outcome: QueryMaterializationNativeExecution['outcome'] = 'error';
			child.stderr?.on('data', chunk => { stderr = (stderr + String(chunk)).slice(-16_384); });
			const execution = (artifactsRemoved: boolean): QueryMaterializationNativeExecution => ({
				isolation: 'child-process', outcome, workerPid: child.pid, durationMs: Date.now() - startedAt,
				lastPhase, heartbeats, ...(lastWorkerHeartbeatAt ? { lastWorkerHeartbeatAt } : {}),
				...(lastMemory ? { lastMemory } : {}), peakHeapUsed,
				inputSnapshotSha256: request.inputSnapshotSha256, artifactsRemoved,
			});
			const heartbeat = () => writeJsonAtomic(request.heartbeatPath, {
				schemaVersion: 1, state: settled ? outcome : 'running', workerPid: child.pid,
				startedAt: new Date(startedAt).toISOString(), supervisorHeartbeatAt: new Date().toISOString(),
				lastWorkerHeartbeatAt, lastMemory, peakHeapUsed, lastPhase, target: request.filePath,
			});
			const supervisorTimer = setInterval(heartbeat, 1000);
			heartbeat();
			const finishError = (nextOutcome: QueryMaterializationNativeExecution['outcome'], message: string) => {
				if (settled) return;
				settled = true; outcome = nextOutcome;
				clearTimeout(timeout); clearInterval(supervisorTimer);
				signal?.removeEventListener('abort', abort);
				try { child.kill('SIGKILL'); } catch { /* already stopped */ }
				const artifactsRemoved = safeCleanup(root);
				this.active = undefined;
				reject(new QueryMaterializationProcessError(message, execution(artifactsRemoved)));
			};
			const abort = () => finishError('cancelled', `Query materialization cancelled (lastPhase=${lastPhase}).`);
			const timeout = setTimeout(() => finishError('timeout', `Query materialization timed out after ${request.timeoutMs}ms (lastPhase=${lastPhase}).`), request.timeoutMs);
			this.active = { child, cancel: abort };
			signal?.addEventListener('abort', abort, { once: true });
			child.on('message', (raw: WorkerMessage) => {
				if (!raw || typeof raw !== 'object') return;
				if (raw.type === 'phase' || raw.type === 'heartbeat') {
					lastPhase = raw.phase; lastWorkerHeartbeatAt = raw.at; heartbeats++;
					if (raw.memory) { lastMemory = raw.memory; peakHeapUsed = Math.max(peakHeapUsed, raw.memory.heapUsed); }
					heartbeat(); return;
				}
				if (raw.type === 'error') { lastPhase = raw.phase; finishError('error', `Query materialization failed: ${raw.error}`); return; }
				if (raw.type === 'result' && !settled) {
					try {
						const compressed = fs.readFileSync(raw.outputSnapshotPath);
						if (compressed.length !== raw.outputSnapshotBytes || sha256(compressed) !== raw.outputSnapshotSha256) throw new Error('staged snapshot digest/size mismatch');
						const snapshot = v8.deserialize(zlib.gunzipSync(compressed)) as AnalysisEngineSnapshotV1;
						if (snapshot.schemaVersion !== 1) throw new Error('staged snapshot schema mismatch');
						settled = true; outcome = 'completed'; lastPhase = 'completed';
						clearTimeout(timeout); clearInterval(supervisorTimer); signal?.removeEventListener('abort', abort);
						try { child.kill(); } catch { /* completed */ }
						const artifactsRemoved = safeCleanup(root); this.active = undefined;
						resolve({ snapshot, functions: raw.functions, nativeExecution: { ...execution(artifactsRemoved), outputSnapshotSha256: raw.outputSnapshotSha256 } });
					} catch (error) {
						finishError('error', error instanceof Error ? error.message : String(error));
					}
				}
			});
			child.on('error', error => finishError('crashed', `Query materialization launch error: ${error.message}`));
			child.on('exit', code => setImmediate(() => {
				if (!settled) finishError('crashed', `Query materialization exited before a result (code=${String(code)})${stderr.trim() ? `: ${stderr.trim()}` : ''}`);
			}));
			if (signal?.aborted) abort();
			else child.send(request);
		});
	}
}

function safeCleanup(root: string): boolean {
	const resolved = path.resolve(root);
	const parent = path.resolve(os.tmpdir(), 'hexcore-query-materialization');
	if (resolved === parent || !resolved.startsWith(`${parent}${path.sep}`)) throw new Error(`Refusing to clean unexpected query-materialization path: ${resolved}`);
	try {
		fs.rmSync(resolved, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
		return !fs.existsSync(resolved);
	} catch {
		return false;
	}
}

function sha256(value: Buffer): string { return crypto.createHash('sha256').update(value).digest('hex'); }

export const queryMaterializationProcessController = new QueryMaterializationProcessController();
