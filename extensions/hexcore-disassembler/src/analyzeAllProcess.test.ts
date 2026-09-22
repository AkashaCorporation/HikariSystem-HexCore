import * as assert from 'assert';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import * as v8 from 'v8';
import * as zlib from 'zlib';
import { EventEmitter } from 'events';
import { PassThrough } from 'stream';
import type { ChildProcess } from 'child_process';
import { AnalyzeAllProcessController, writeJsonAtomic, type IsolatedAnalyzeAllRequest } from './analyzeAllProcess';

class FakeChild extends EventEmitter {
	pid = 4242;
	stderr = new PassThrough();
	killed = false;
	onSend?: (request: IsolatedAnalyzeAllRequest) => void;
	send(request: IsolatedAnalyzeAllRequest): boolean {
		this.onSend?.(request);
		return true;
	}
	kill(): boolean {
		this.killed = true;
		return true;
	}
}

suite('isolated analyzeAll process controller', () => {
	let tempDir = '';
	let request: IsolatedAnalyzeAllRequest;

	setup(() => {
		tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'hexcore-analyze-process-'));
		request = {
			filePath: path.join(tempDir, 'target.bin'),
			limits: { maxFunctions: 100, maxFunctionSize: 4096 },
			options: {},
			snapshotPath: path.join(tempDir, 'snapshot.bin'),
			heartbeatPath: path.join(tempDir, 'heartbeat.json'),
			timeoutMs: 1000,
		};
		fs.writeFileSync(request.filePath, Buffer.from([0xc3]));
	});

	teardown(() => fs.rmSync(tempDir, { recursive: true, force: true }));

	test('repeated atomic heartbeat writes use unique temporaries and leave valid JSON', () => {
		const heartbeat = path.join(tempDir, 'atomic-heartbeat.json');
		for (let index = 0; index < 100; index++) {
			assert.strictEqual(writeJsonAtomic(heartbeat, { index }), true);
		}
		assert.deepStrictEqual(JSON.parse(fs.readFileSync(heartbeat, 'utf8')), { index: 99 });
		assert.deepStrictEqual(
			fs.readdirSync(tempDir).filter(name => name.startsWith('atomic-heartbeat.json.tmp-')),
			[],
		);
	});

	test('accepts a digest-verified snapshot and records terminal heartbeat', async () => {
		const child = new FakeChild();
		child.onSend = sent => setImmediate(() => {
			const bytes = Buffer.from('snapshot');
			fs.writeFileSync(sent.snapshotPath, bytes);
			child.emit('message', { type: 'phase', phase: 'serialize-snapshot', at: new Date().toISOString(), pid: child.pid });
			child.emit('message', {
				type: 'result', functionNetChange: 3, snapshotPath: sent.snapshotPath,
				snapshotSha256: crypto.createHash('sha256').update(bytes).digest('hex'), snapshotBytes: bytes.length,
			});
		});
		const controller = new AnalyzeAllProcessController(() => child as unknown as ChildProcess);
		const result = await controller.run(request);
		assert.strictEqual(result.functionNetChange, 3);
		assert.strictEqual(result.nativeExecution.outcome, 'completed');
		assert.strictEqual(result.nativeExecution.lastPhase, 'completed');
		assert.strictEqual(JSON.parse(fs.readFileSync(request.heartbeatPath, 'utf8')).state, 'completed');
	});

	test('kills a worker at the external deadline', async () => {
		const child = new FakeChild();
		request.timeoutMs = 20;
		const controller = new AnalyzeAllProcessController(() => child as unknown as ChildProcess);
		await assert.rejects(controller.run(request), /timed out after 20ms/);
		assert.strictEqual(child.killed, true);
		assert.strictEqual(JSON.parse(fs.readFileSync(request.heartbeatPath, 'utf8')).state, 'timeout');
	});

	test('supports explicit cancellation', async () => {
		const child = new FakeChild();
		const controller = new AnalyzeAllProcessController(() => child as unknown as ChildProcess);
		const running = controller.run(request);
		assert.strictEqual(controller.cancelActive(), true);
		await assert.rejects(running, /cancelled/);
		assert.strictEqual(child.killed, true);
	});

	test('turns a child crash into a terminal error', async () => {
		const child = new FakeChild();
		child.onSend = () => setImmediate(() => child.emit('exit', 0xc0000005));
		const controller = new AnalyzeAllProcessController(() => child as unknown as ChildProcess);
		await assert.rejects(controller.run(request), /exited before a result/);
		assert.strictEqual(JSON.parse(fs.readFileSync(request.heartbeatPath, 'utf8')).state, 'crashed');
	});

	test('runs the real child and returns a target-bound engine snapshot', async function () {
		this.timeout(30_000);
		request.raw = { architecture: 'x64', baseAddress: 0x401000 };
		request.timeoutMs = 20_000;
		const controller = new AnalyzeAllProcessController();
		const result = await controller.run(request);
		const snapshot = v8.deserialize(zlib.gunzipSync(fs.readFileSync(result.snapshotPath)));
		assert.strictEqual(snapshot.schemaVersion, 1);
		assert.strictEqual(snapshot.target.fileSize, 1);
		assert.deepStrictEqual(snapshot.limits, request.limits);
		assert.strictEqual(result.nativeExecution.outcome, 'completed');
		assert.strictEqual(JSON.parse(fs.readFileSync(request.heartbeatPath, 'utf8')).state, 'completed');
	});

	test('flushes every real result while repeatedly restoring the same persisted session', async function () {
		this.timeout(30_000);
		request.raw = { architecture: 'x64', baseAddress: 0x401000 };
		request.timeoutMs = 20_000;
		const controller = new AnalyzeAllProcessController();
		const hashes: string[] = [];
		for (let index = 0; index < 32; index++) {
			request.snapshotPath = path.join(tempDir, `snapshot-${index}.bin`);
			request.heartbeatPath = path.join(tempDir, `heartbeat-${index}.json`);
			const result = await controller.run(request);
			hashes.push(result.snapshotSha256);
			assert.strictEqual(result.nativeExecution.outcome, 'completed');
			assert.strictEqual(result.nativeExecution.lastPhase, 'completed');
			assert.strictEqual(JSON.parse(fs.readFileSync(request.heartbeatPath, 'utf8')).state, 'completed');
		}
		assert.strictEqual(new Set(hashes).size, 1, 'restoring unchanged state must serialize deterministically');
	});
});
