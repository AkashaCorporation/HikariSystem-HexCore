import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import { fork, type ChildProcess } from 'child_process';

export interface IsolatedAnalyzeAllRequest {
	filePath: string;
	raw?: { architecture?: string; baseAddress?: number };
	limits: { maxFunctions: number; maxFunctionSize: number };
	options: { filterJunk?: boolean; detectVM?: boolean; detectPRNG?: boolean; useCachedFunctions?: boolean };
	snapshotPath: string;
	heartbeatPath: string;
	timeoutMs: number;
}

export interface NativeAnalyzeExecution {
	isolation: 'child-process';
	outcome: 'completed' | 'timeout' | 'cancelled' | 'crashed' | 'error';
	workerPid?: number;
	durationMs: number;
	lastPhase: string;
	lastWorkerHeartbeatAt?: string;
	supervisorHeartbeatAt: string;
	heartbeatPath: string;
	snapshotSha256?: string;
	snapshotBytes?: number;
	snapshotUncompressedBytes?: number;
}

export interface IsolatedAnalyzeAllResult {
	snapshotPath: string;
	snapshotSha256: string;
	snapshotBytes: number;
	snapshotUncompressedBytes?: number;
	functionNetChange: number;
	nativeExecution: NativeAnalyzeExecution;
}

type WorkerMessage =
	| { type: 'phase' | 'heartbeat'; phase: string; at: string; pid: number }
	| { type: 'result'; functionNetChange: number; snapshotPath: string; snapshotSha256: string; snapshotBytes: number; snapshotUncompressedBytes?: number }
	| { type: 'error'; error: string; phase: string };

function writeJsonAtomic(filePath: string, value: unknown): void {
	fs.mkdirSync(path.dirname(filePath), { recursive: true });
	const temporary = `${filePath}.tmp-${process.pid}`;
	fs.writeFileSync(temporary, JSON.stringify(value, null, 2), 'utf8');
	fs.renameSync(temporary, filePath);
}

export type AnalyzeAllChildLauncher = () => ChildProcess;

function launchAnalyzeAllChild(): ChildProcess {
	return fork(path.join(__dirname, 'analyzeAllProcessChild.js'), [], {
		env: { ...process.env, ELECTRON_RUN_AS_NODE: '1' },
		execArgv: [],
		serialization: 'advanced',
		stdio: ['ignore', 'ignore', 'pipe', 'ipc'],
	});
}

export class AnalyzeAllProcessController {
	private active?: { child: ChildProcess; cancel: () => void };
	constructor(private readonly launchChild: AnalyzeAllChildLauncher = launchAnalyzeAllChild) {}

	isActive(): boolean { return this.active !== undefined; }

	cancelActive(): boolean {
		if (!this.active) { return false; }
		this.active.cancel();
		return true;
	}

	run(request: IsolatedAnalyzeAllRequest): Promise<IsolatedAnalyzeAllResult> {
		if (this.active) { return Promise.reject(new Error('An isolated analyzeAll process is already active')); }
		return new Promise<IsolatedAnalyzeAllResult>((resolve, reject) => {
			const startedAtMs = Date.now();
			const child = this.launchChild();
			let settled = false;
			let stderr = '';
			let lastPhase = 'launch';
			let lastWorkerHeartbeatAt: string | undefined;
			let outcome: NativeAnalyzeExecution['outcome'] = 'error';
			child.stderr?.on('data', chunk => { stderr = (stderr + String(chunk)).slice(-16_384); });

			const heartbeat = () => writeJsonAtomic(request.heartbeatPath, {
				schemaVersion: 1,
				state: settled ? outcome : 'running',
				workerPid: child.pid,
				startedAt: new Date(startedAtMs).toISOString(),
				supervisorHeartbeatAt: new Date().toISOString(),
				lastWorkerHeartbeatAt,
				lastPhase,
				target: request.filePath,
			});
			const supervisorTimer = setInterval(heartbeat, 1000);
			heartbeat();

			const execution = (): NativeAnalyzeExecution => ({
				isolation: 'child-process', outcome, workerPid: child.pid,
				durationMs: Date.now() - startedAtMs,
				lastPhase, ...(lastWorkerHeartbeatAt ? { lastWorkerHeartbeatAt } : {}),
				supervisorHeartbeatAt: new Date().toISOString(), heartbeatPath: request.heartbeatPath,
			});
			const settleError = (nextOutcome: NativeAnalyzeExecution['outcome'], message: string) => {
				if (settled) { return; }
				settled = true;
				outcome = nextOutcome;
				clearTimeout(timeout);
				clearInterval(supervisorTimer);
				try { child.kill('SIGKILL'); } catch { /* already dead */ }
				heartbeat();
				this.active = undefined;
				reject(new Error(`${message}; nativeExecution=${JSON.stringify(execution())}`));
			};
			const timeout = setTimeout(() => {
				settleError('timeout', `Isolated analyzeAll timed out after ${request.timeoutMs}ms (lastPhase=${lastPhase})`);
			}, request.timeoutMs);
			this.active = { child, cancel: () => settleError('cancelled', `Isolated analyzeAll cancelled (lastPhase=${lastPhase})`) };

			child.on('message', (raw: WorkerMessage) => {
				if (!raw || typeof raw !== 'object') { return; }
				if (raw.type === 'phase' || raw.type === 'heartbeat') {
					lastPhase = raw.phase;
					lastWorkerHeartbeatAt = raw.at;
					heartbeat();
					return;
				}
				if (raw.type === 'error') {
					lastPhase = raw.phase;
					settleError('error', `Isolated analyzeAll failed: ${raw.error}`);
					return;
				}
				if (raw.type === 'result' && !settled) {
					try {
						const bytes = fs.readFileSync(raw.snapshotPath);
						const digest = crypto.createHash('sha256').update(bytes).digest('hex');
						if (digest !== raw.snapshotSha256 || bytes.length !== raw.snapshotBytes) {
							throw new Error('snapshot digest/size mismatch');
						}
						settled = true;
						outcome = 'completed';
						lastPhase = 'completed';
						clearTimeout(timeout);
						clearInterval(supervisorTimer);
						this.active = undefined;
						const nativeExecution = {
							...execution(), snapshotSha256: raw.snapshotSha256, snapshotBytes: raw.snapshotBytes,
							...(raw.snapshotUncompressedBytes !== undefined ? { snapshotUncompressedBytes: raw.snapshotUncompressedBytes } : {}),
						};
						heartbeat();
						resolve({
							snapshotPath: raw.snapshotPath, snapshotSha256: raw.snapshotSha256,
							snapshotBytes: raw.snapshotBytes, functionNetChange: raw.functionNetChange,
							...(raw.snapshotUncompressedBytes !== undefined ? { snapshotUncompressedBytes: raw.snapshotUncompressedBytes } : {}),
							nativeExecution,
						});
						try { child.kill(); } catch { /* completed */ }
					} catch (error: unknown) {
						settleError('error', error instanceof Error ? error.message : String(error));
					}
				}
			});
			child.on('error', error => settleError('crashed', `Isolated analyzeAll launch error: ${error.message}`));
			child.on('exit', code => {
				if (!settled) {
					const detail = stderr.trim() ? `: ${stderr.trim()}` : '';
					settleError('crashed', `Isolated analyzeAll exited before a result (code=${String(code)})${detail}`);
				}
			});
			child.send(request);
		});
	}
}

export const analyzeAllProcessController = new AnalyzeAllProcessController();
