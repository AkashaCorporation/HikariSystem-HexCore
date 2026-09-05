import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import * as v8 from 'v8';
import * as zlib from 'zlib';
import type { IsolatedAnalyzeAllRequest } from './analyzeAllProcess';

function installVscodeShim(): void {
	const Module = require('module');
	const originalLoad = Module._load;
	Module._load = function (request: string, parent: unknown, isMain: boolean) {
		if (request === 'vscode') {
			return { workspace: { getConfiguration: () => ({ get: (_key: string, fallback: unknown) => fallback }) } };
		}
		return originalLoad.call(this, request, parent, isMain);
	};
}

let phase = 'waiting-request';
const send = (message: unknown) => { try { process.send?.(message); } catch { /* parent exited */ } };
const setPhase = (next: string) => {
	phase = next;
	send({ type: 'phase', phase, at: new Date().toISOString(), pid: process.pid });
};
const heartbeat = setInterval(() => send({ type: 'heartbeat', phase, at: new Date().toISOString(), pid: process.pid }), 1000);

process.once('message', async (request: IsolatedAnalyzeAllRequest) => {
	let engine: any;
	try {
		installVscodeShim();
		const { DisassemblerEngine } = require('./disassemblerEngine');
		engine = new DisassemblerEngine();
		setPhase('load-file');
		const loaded = await engine.loadFile(request.filePath, {
			architecture: request.raw?.architecture,
			baseAddress: request.raw?.baseAddress,
		});
		if (!loaded) { throw new Error(`Failed to load target: ${request.filePath}`); }
		// loadFile reloads configuration defaults; apply the request afterwards so
		// the isolated lane honors the same per-job limits as the in-process lane.
		engine.setAnalysisLimits(request.limits.maxFunctions, request.limits.maxFunctionSize);
		setPhase('analyze-all');
		const functionNetChange = await engine.analyzeAll({
			...request.options,
			onPhase: (next: string) => setPhase(next),
		});
		setPhase('serialize-snapshot');
		const serialized = v8.serialize(engine.exportAnalysisSnapshot({
			includeExecScan: request.options.detectVM === true || request.options.detectPRNG === true,
		}));
		const compressed = zlib.gzipSync(serialized, { level: 1 });
		fs.mkdirSync(path.dirname(request.snapshotPath), { recursive: true });
		const temporary = `${request.snapshotPath}.tmp-${process.pid}`;
		fs.writeFileSync(temporary, compressed);
		fs.renameSync(temporary, request.snapshotPath);
		const snapshotSha256 = crypto.createHash('sha256').update(compressed).digest('hex');
		// Release the session DB/native engines before announcing completion so
		// the parent can immediately bind/import without racing an open handle.
		try { engine.dispose(); } catch { /* process exit is the final boundary */ }
		engine = undefined;
		setPhase('reply');
		send({
			type: 'result', functionNetChange, snapshotPath: request.snapshotPath,
			snapshotSha256, snapshotBytes: compressed.length, snapshotUncompressedBytes: serialized.length,
		});
		clearInterval(heartbeat);
		setTimeout(() => process.exit(0), 10);
	} catch (error: unknown) {
		clearInterval(heartbeat);
		try { engine?.dispose(); } catch { /* process exit closes native state */ }
		send({
			type: 'error', phase,
			error: error instanceof Error ? `${error.message}\n${error.stack ?? ''}` : String(error),
		});
		setTimeout(() => process.exit(1), 10);
	}
});
