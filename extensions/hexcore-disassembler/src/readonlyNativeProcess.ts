/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import { fork, type ChildProcess, type ForkOptions } from 'child_process';
import * as path from 'path';
import { nativeBytesSha256, nativeError, nativeRequestSha256, validateReadonlyNativeRequest, type ReadonlyNativeRequest, type ReadonlyNativeResult } from './readonlyNativeProtocol';

export interface ReadonlyNativeHeartbeat { pid?: number; phase: ReadonlyNativeResult['phase']; elapsedMs: number; terminating: boolean }
export interface ReadonlyNativeExecution extends ReadonlyNativeResult {
	execution: { isolation: 'child-process'; pid?: number; exited: true; elapsedMs: number; exitCode: number | null; signal: NodeJS.Signals | null };
}

function launchNativeProducer(): ChildProcess {
	const options: ForkOptions & { windowsHide: boolean } = {
		env: { ...process.env, ELECTRON_RUN_AS_NODE: '1' }, execArgv: ['--max-old-space-size=512'],
		serialization: 'advanced', windowsHide: true, stdio: ['ignore', 'ignore', 'pipe', 'ipc'],
	};
	return fork(path.join(__dirname, 'readonlyNativeChild.js'), [], options);
}

/** Owns native initialization, lifting and decompilation under one external deadline. */
export class ReadonlyNativeProcess {
	constructor(private readonly launch: () => ChildProcess = launchNativeProducer) {}
	async run(input: ReadonlyNativeRequest, options: { timeoutMs?: number; signal?: AbortSignal; onHeartbeat?: (event: ReadonlyNativeHeartbeat) => void } = {}): Promise<ReadonlyNativeExecution> {
		validateReadonlyNativeRequest(input);
		const timeoutMs = options.timeoutMs ?? 300000;
		if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 600000) { throw new Error('native-query: invalid timeout'); }
		const request: ReadonlyNativeRequest = JSON.parse(JSON.stringify(input));
		const requestSha256 = nativeRequestSha256(request);
		if (options.signal?.aborted) { return { ...nativeError(request, requestSha256, 'native-query: cancelled'), execution: { isolation: 'child-process', exited: true, elapsedMs: 0, exitCode: null, signal: null } }; }
		const started = Date.now();
		return new Promise(resolve => {
			let child: ChildProcess;
			try { child = this.launch(); }
			catch (error) { resolve({ ...nativeError(request, requestSha256, `native-query: launch failed: ${String(error)}`), execution: { isolation: 'child-process', exited: true, elapsedMs: Date.now() - started, exitCode: null, signal: null } }); return; }
			let phase: ReadonlyNativeResult['phase'] = 'initializing';
			let terminal: ReadonlyNativeResult | undefined;
			let closed = false;
			let stderr = '';
			let escalation: NodeJS.Timeout | undefined;
			const stop = (result: ReadonlyNativeResult) => {
				if (closed || terminal) { return; }
				terminal = result;
				child.kill();
				escalation = setTimeout(() => { if (!closed) { child.kill('SIGKILL'); } }, 1000);
			};
			const cancel = () => stop(nativeError(request, requestSha256, 'native-query: cancelled'));
			const deadline = setTimeout(() => stop(nativeError(request, requestSha256, `native-query: timeout during ${phase}`)), Math.max(1, timeoutMs - (Date.now() - started)));
			const heartbeat = setInterval(() => {
				try { options.onHeartbeat?.({ pid: child.pid, phase, elapsedMs: Date.now() - started, terminating: !!terminal }); } catch { /* A telemetry listener must not orphan native work. */ }
			}, 50);
			child.stderr?.on('data', chunk => { stderr = (stderr + String(chunk)).slice(-8192); });
			child.on('message', (message: any) => {
				if (terminal || closed) { return; }
				if (message?.requestSha256 !== requestSha256) { stop(nativeError(request, requestSha256, 'native-query: response identity mismatch')); return; }
				if (message.phase && !message.result) {
					if (!['initializing', 'lifting', 'decompiling'].includes(message.phase)) { stop(nativeError(request, requestSha256, 'native-query: invalid phase')); return; }
					phase = message.phase; return;
				}
				const result: ReadonlyNativeResult = message.result;
				try {
					if (!result || result.requestSha256 !== requestSha256 || result.contextSha256 !== request.context.contextSha256 || result.architecture !== request.architecture || result.phase !== 'terminal' || !['ok', 'partial', 'error'].includes(result.status) || typeof result.success !== 'boolean' || typeof result.semanticEligible !== 'boolean' || !Array.isArray(result.qualityIssues) || typeof result.source !== 'string' || typeof result.hastBase64 !== 'string') { throw new Error('invalid result contract'); }
					if (result.status === 'error' && (result.success || result.semanticEligible) || result.status !== 'error' && !result.success || result.semanticEligible && (result.status !== 'ok' || result.qualityIssues.length)) { throw new Error('contradictory result quality'); }
					if (Buffer.byteLength(JSON.stringify(result)) > request.maxOutputBytes) { throw new Error('result budget exceeded'); }
					if (result.qualityIssues.some(issue => typeof issue !== 'string')) { throw new Error('invalid quality reasons'); }
					if (result.success && (!result.hastBase64 || Buffer.from(result.hastBase64, 'base64').toString('base64') !== result.hastBase64 || nativeBytesSha256(Buffer.from(result.hastBase64, 'base64')) !== result.hastSha256)) { throw new Error('HAST digest mismatch'); }
					phase = 'terminal'; stop(result);
				} catch (error) { stop(nativeError(request, requestSha256, `native-query: ${String(error)}`)); }
			});
			child.on('error', error => stop(nativeError(request, requestSha256, `native-query: process error: ${error.message}`)));
			child.once('close', (exitCode, signal) => {
				closed = true;
				clearTimeout(deadline); clearInterval(heartbeat); if (escalation) { clearTimeout(escalation); }
				options.signal?.removeEventListener('abort', cancel);
				resolve({ ...(terminal ?? nativeError(request, requestSha256, `native-query: exited without result (${exitCode}) ${stderr}`)), execution: { isolation: 'child-process', pid: child.pid, exited: true, elapsedMs: Date.now() - started, exitCode, signal } });
			});
			options.signal?.addEventListener('abort', cancel, { once: true });
			if (options.signal?.aborted) { cancel(); }
			if (!terminal) { child.send({ request, requestSha256 }, error => { if (error) { stop(nativeError(request, requestSha256, `native-query: IPC error: ${error.message}`)); } }); }
		});
	}
}
