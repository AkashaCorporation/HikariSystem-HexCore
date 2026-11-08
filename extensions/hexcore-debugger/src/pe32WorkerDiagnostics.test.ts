/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as assert from 'assert';
import { EventEmitter } from 'events';
import { PassThrough } from 'stream';
import { Pe32WorkerClient } from './pe32WorkerClient';

function createWorker(pid: number, emitExitOnKill = true): { worker: any; killed: () => boolean } {
	const worker = new EventEmitter() as any;
	const stdout = new PassThrough();
	const stderr = new PassThrough();
	let wasKilled = false;
	worker.pid = pid;
	worker.stdout = stdout;
	worker.stderr = stderr;
	worker.send = () => true;
	worker.kill = () => {
		wasKilled = true;
		if (emitExitOnKill) {
			setImmediate(() => worker.emit('exit', null, 'SIGTERM'));
		}
		return true;
	};
	return { worker, killed: () => wasKilled };
}

suite('PE32 worker bootstrap diagnostics', () => {
	test('timeout reports bounded bootstrap evidence and terminates the child', async () => {
		const fake = createWorker(4242);
		const client = new Pe32WorkerClient({
			startTimeoutMs: 20,
			findSystemNode: () => null,
			fork: (() => fake.worker) as any,
		});
		setImmediate(() => fake.worker.stderr.write('worker did not reach ready'));

		await assert.rejects(client.start(), (error: Error) => {
			assert.match(error.message, /failed to become ready within 20ms/);
			assert.match(error.message, /runtime=electron-fallback/);
			assert.match(error.message, /pid=4242/);
			assert.match(error.message, /addon=not-attempted/);
			assert.match(error.message, /worker did not reach ready/);
			return true;
		});
		assert.strictEqual(fake.killed(), true);
		assert.strictEqual(client.isAlive(), false);
	});

	test('ready payload records the actual child runtime', async () => {
		const fake = createWorker(4343);
		const client = new Pe32WorkerClient({
			startTimeoutMs: 100,
			findSystemNode: () => null,
			fork: (() => fake.worker) as any,
		});
		setImmediate(() => fake.worker.emit('message', {
			type: 'ready',
			diagnostics: {
				execPath: 'C:\\HexCore\\HexCore.exe',
				nodeVersion: 'v22.0.0',
				pid: 4343,
				workerPath: 'C:\\HexCore\\pe32Worker.js',
				addonResolution: 'not-attempted',
			},
		}));

		await client.start();
		assert.deepStrictEqual(client.getDiagnostics(), {
			runtime: 'electron-fallback',
			execPath: 'C:\\HexCore\\HexCore.exe',
			nodeVersion: 'v22.0.0',
			workerPath: 'C:\\HexCore\\pe32Worker.js',
			pid: 4343,
			addonResolution: 'not-attempted',
			stdoutTail: '',
			stderrTail: '',
			exitCode: null,
			signal: null,
		});
		client.dispose();
	});

	test('late exit from a timed-out child cannot invalidate a replacement', async () => {
		const first = createWorker(4441, false);
		const second = createWorker(4442, false);
		let forkCount = 0;
		const client = new Pe32WorkerClient({
			startTimeoutMs: 10,
			findSystemNode: () => null,
			fork: (() => forkCount++ === 0 ? first.worker : second.worker) as any,
		});

		await assert.rejects(client.start(), /failed to become ready/);
		const replacementStart = client.start();
		setImmediate(() => second.worker.emit('message', { type: 'ready' }));
		await replacementStart;
		first.worker.emit('exit', null, 'SIGTERM');

		assert.strictEqual(client.isAlive(), true);
		client.dispose();
	});
});
