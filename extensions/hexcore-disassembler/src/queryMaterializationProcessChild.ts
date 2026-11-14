/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Akasha Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import * as v8 from 'v8';
import * as zlib from 'zlib';
import type { AnalysisEngineSnapshotV1 } from './disassemblerEngine';
import type { IsolatedQueryMaterializationRequest, StagedQueryMaterializationFunction } from './queryMaterializationProcess';

function installVscodeShim(): void {
	const Module = require('module');
	const originalLoad = Module._load;
	Module._load = function (request: string, parent: unknown, isMain: boolean) {
		if (request === 'vscode') return { workspace: { getConfiguration: () => ({ get: (_key: string, fallback: unknown) => fallback }) } };
		return originalLoad.call(this, request, parent, isMain);
	};
}

let phase = 'waiting-request';
const memory = () => { const value = process.memoryUsage(); return { rss: value.rss, heapUsed: value.heapUsed, heapTotal: value.heapTotal, external: value.external }; };
const send = (message: unknown) => { try { process.send?.(message, () => undefined); } catch { /* parent exited */ } };
const sendTerminal = (message: unknown): Promise<boolean> => new Promise(resolve => {
	try { if (!process.connected || !process.send) { resolve(false); return; } process.send(message, (error: Error | null) => resolve(!error)); }
	catch { resolve(false); }
});
const holdTerminal = async (message: unknown) => {
	const hold = setTimeout(() => process.exit(process.exitCode ?? 0), 10_000);
	if (!await sendTerminal(message)) { clearTimeout(hold); process.exitCode = 1; }
};
const setPhase = (next: string) => { phase = next; send({ type: 'phase', phase, at: new Date().toISOString(), pid: process.pid, memory: memory() }); };
const heartbeat = setInterval(() => send({ type: 'heartbeat', phase, at: new Date().toISOString(), pid: process.pid, memory: memory() }), 1000);

process.once('message', async (request: IsolatedQueryMaterializationRequest) => {
	let engine: import('./disassemblerEngine').DisassemblerEngine | undefined;
	try {
		installVscodeShim();
		if (!request || !Array.isArray(request.functions) || request.functions.length === 0 || request.functions.length > 4096) throw new Error('Invalid staged function request.');
		const compressed = fs.readFileSync(request.inputSnapshotPath);
		if (sha256(compressed) !== request.inputSnapshotSha256) throw new Error('Input analysis snapshot digest mismatch.');
		const snapshot = v8.deserialize(zlib.gunzipSync(compressed)) as AnalysisEngineSnapshotV1;
		const { DisassemblerEngine } = require('./disassemblerEngine') as typeof import('./disassemblerEngine');
		engine = new DisassemblerEngine();
		setPhase('load-target');
		const loaded = await engine.loadFile(request.filePath, {
			architecture: snapshot.architecture, baseAddress: snapshot.baseAddress,
			analysisLimits: snapshot.limits, persistence: false,
		});
		if (!loaded) throw new Error(`Failed to load target: ${request.filePath}`);
		setPhase('import-snapshot');
		engine.importAnalysisSnapshot(snapshot, { adopt: true });
		const functions: StagedQueryMaterializationFunction[] = [];
		const seen = new Set<number>();
		for (const entry of request.functions) {
			if (!Number.isSafeInteger(entry.address) || entry.address <= 0 || !Number.isSafeInteger(entry.maxBytes) || entry.maxBytes < 1) throw new Error('Invalid staged function address/budget.');
			if (seen.has(entry.address)) throw new Error(`Duplicate staged function address: 0x${entry.address.toString(16)}`);
			seen.add(entry.address);
			setPhase(`materialize:0x${entry.address.toString(16)}`);
			const fn = await engine.materializeFunction(entry.address, { maxBytes: entry.maxBytes });
			const completeness = engine.peekFunctionBodyCompleteness(entry.address);
			const status: StagedQueryMaterializationFunction['status'] = !fn ? 'unknown-function'
				: completeness?.state === 'complete' && completeness.boundaryReached === true ? 'complete'
					: completeness?.state === 'partial' ? 'partial' : 'decode-empty';
			functions.push({
				address: `0x${entry.address.toString(16)}`,
				status,
				spanBytes: fn ? fn.endAddress - fn.address : 0,
				instructionCount: fn?.instructions.length ?? 0,
				...(status === 'complete' ? { bodySha256: engine.getFunctionBodySha256(entry.address) } : {}),
			});
		}
		setPhase('refresh-indexes');
		engine.refreshStagedMaterializationIndexes();
		setPhase('serialize-snapshot');
		const output = zlib.gzipSync(v8.serialize(engine.exportAnalysisSnapshot()), { level: 1 });
		fs.mkdirSync(path.dirname(request.outputSnapshotPath), { recursive: true });
		const temporary = `${request.outputSnapshotPath}.tmp-${process.pid}`;
		fs.writeFileSync(temporary, output);
		fs.renameSync(temporary, request.outputSnapshotPath);
		const outputSnapshotSha256 = sha256(output);
		try { engine.dispose(); } catch { /* process exit closes native state */ }
		engine = undefined;
		setPhase('reply');
		clearInterval(heartbeat);
		await holdTerminal({ type: 'result', outputSnapshotPath: request.outputSnapshotPath, outputSnapshotSha256, outputSnapshotBytes: output.length, functions });
	} catch (error) {
		clearInterval(heartbeat);
		try { engine?.dispose(); } catch { /* best effort */ }
		await holdTerminal({ type: 'error', phase, error: error instanceof Error ? `${error.message}\n${error.stack ?? ''}` : String(error) });
		process.exitCode = 1;
	}
});

function sha256(value: Buffer): string { return crypto.createHash('sha256').update(value).digest('hex'); }
