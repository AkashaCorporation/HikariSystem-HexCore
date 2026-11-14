/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Akasha Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as assert from 'assert';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { EventEmitter } from 'events';
import { PassThrough } from 'stream';
import type { ChildProcess } from 'child_process';
import type { DisassemblerEngine } from './disassemblerEngine';
import type { QueryMaterializationPlan } from './queryMaterialization';
import {
	QueryMaterializationProcessController,
	QueryMaterializationProcessError,
	type IsolatedQueryMaterializationRequest,
} from './queryMaterializationProcess';

const Module = require('module');
const originalResolveFilename = Module._resolveFilename;
Module._resolveFilename = function (request: string, parent: unknown, isMain: boolean, options: unknown) {
	if (request === 'vscode') return '__vscode_mock_query_materialization_process__';
	return originalResolveFilename.call(this, request, parent, isMain, options);
};
require.cache.__vscode_mock_query_materialization_process__ = {
	id: '__vscode_mock_query_materialization_process__', filename: '__vscode_mock_query_materialization_process__', loaded: true,
	exports: { workspace: { getConfiguration: () => ({ get: (_key: string, fallback: unknown) => fallback }), onDidChangeConfiguration: () => ({ dispose() {} }) } },
} as NodeModule;

class FakeChild extends EventEmitter {
	pid = 42420;
	stderr = new PassThrough();
	killed = false;
	onSend?: (request: IsolatedQueryMaterializationRequest) => void;
	send(request: IsolatedQueryMaterializationRequest): boolean {
		setImmediate(() => this.onSend?.(request));
		return true;
	}
	kill(): boolean { this.killed = true; return true; }
}

function engine(): DisassemblerEngine {
	return {
		getFilePath: () => path.join(os.tmpdir(), 'query-materialization-target.bin'),
		exportAnalysisSnapshot: () => ({ schemaVersion: 1, target: { fileSha256: 'a'.repeat(64), fileSize: 1 } }),
	} as unknown as DisassemblerEngine;
}

function plan(maxMilliseconds = 1000): QueryMaterializationPlan {
	return {
		schemaVersion: 1, mode: 'bounded', targetIdentity: 'target:test', initialGeneration: 1,
		initialUniverseSha256: 'b'.repeat(64), maxFunctions: 2, maxBytes: 128,
		maxMilliseconds, maxDepth: 2, bodyRequired: true, semanticDependenciesRequired: true,
		requested: [{ address: 0x1000, addressHex: '0x1000', functionIdentity: 'function:0x1000', name: 'root', depth: 0, spanBytes: 16, currentState: 'lazy', reason: 'explicit' }],
		visitedFunctions: ['function:0x1000'], estimatedBytes: 16, budgetExhausted: false,
		unknownReasons: [], planSha256: 'c'.repeat(64),
	};
}

function roots(): string[] {
	const parent = path.join(os.tmpdir(), 'hexcore-query-materialization');
	return fs.existsSync(parent) ? fs.readdirSync(parent).sort() : [];
}

suite('G06 isolated query materialization process', () => {
	test('validates and imports a staged snapshot then removes every artifact', async () => {
		const before = roots();
		const child = new FakeChild();
		child.onSend = request => {
			child.emit('message', { type: 'phase', phase: 'materialize:0x1000', at: new Date().toISOString(), pid: child.pid });
			fs.copyFileSync(request.inputSnapshotPath, request.outputSnapshotPath);
			const bytes = fs.readFileSync(request.outputSnapshotPath);
			child.emit('message', {
				type: 'result', outputSnapshotPath: request.outputSnapshotPath,
				outputSnapshotSha256: crypto.createHash('sha256').update(bytes).digest('hex'), outputSnapshotBytes: bytes.length,
				functions: [{ address: '0x1000', status: 'complete', spanBytes: 16, instructionCount: 3, bodySha256: 'd'.repeat(64) }],
			});
		};
		const controller = new QueryMaterializationProcessController(() => child as unknown as ChildProcess);
		const result = await controller.run(engine(), plan());
		assert.strictEqual(result.snapshot.schemaVersion, 1);
		assert.strictEqual(result.functions[0].status, 'complete');
		assert.strictEqual(result.nativeExecution.outcome, 'completed');
		assert.strictEqual(result.nativeExecution.artifactsRemoved, true);
		assert.strictEqual(controller.isActive(), false);
		assert.deepStrictEqual(roots(), before);
	});

	test('timeout and cancellation preserve the parent and remove snapshots', async () => {
		const before = roots();
		const timeoutChild = new FakeChild();
		const timeoutController = new QueryMaterializationProcessController(() => timeoutChild as unknown as ChildProcess);
		await assert.rejects(timeoutController.run(engine(), plan(20)), (error: unknown) => {
			assert.ok(error instanceof QueryMaterializationProcessError);
			assert.strictEqual(error.execution.outcome, 'timeout');
			return true;
		});
		assert.strictEqual(timeoutChild.killed, true);
		const cancelChild = new FakeChild();
		const cancelController = new QueryMaterializationProcessController(() => cancelChild as unknown as ChildProcess);
		const abort = new AbortController();
		const pending = cancelController.run(engine(), plan(1000), abort.signal);
		setTimeout(() => abort.abort(), 10);
		await assert.rejects(pending, (error: unknown) => {
			assert.ok(error instanceof QueryMaterializationProcessError);
			assert.strictEqual(error.execution.outcome, 'cancelled');
			return true;
		});
		assert.strictEqual(cancelChild.killed, true);
		assert.deepStrictEqual(roots(), before);
	});

	test('an already-cancelled request never launches a child', async () => {
		let launches = 0;
		const controller = new QueryMaterializationProcessController(() => { launches++; return new FakeChild() as unknown as ChildProcess; });
		const abort = new AbortController(); abort.abort();
		await assert.rejects(controller.run(engine(), plan(), abort.signal), (error: unknown) => {
			assert.ok(error instanceof QueryMaterializationProcessError);
			assert.strictEqual(error.execution.outcome, 'cancelled');
			return true;
		});
		assert.strictEqual(launches, 0);
	});

	test('rejects a corrupted worker snapshot', async () => {
		const child = new FakeChild();
		child.onSend = request => {
			fs.writeFileSync(request.outputSnapshotPath, Buffer.from('corrupt'));
			child.emit('message', { type: 'result', outputSnapshotPath: request.outputSnapshotPath, outputSnapshotSha256: '0'.repeat(64), outputSnapshotBytes: 7, functions: [] });
		};
		const controller = new QueryMaterializationProcessController(() => child as unknown as ChildProcess);
		await assert.rejects(controller.run(engine(), plan()), /digest\/size mismatch/);
		assert.strictEqual(controller.isActive(), false);
	});

	test('real child stages a body without mutating the lazy parent before commit', async function () {
		this.timeout(60_000);
		const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'hexcore-query-materialization-real-'));
		const file = path.join(directory, 'fixture.bin');
		fs.writeFileSync(file, Buffer.from([0xb8, 7, 0, 0, 0, 0xc3]));
		const { DisassemblerEngine } = require('./disassemblerEngine') as typeof import('./disassemblerEngine');
		const live = new DisassemblerEngine();
		try {
			assert.strictEqual(await live.loadFile(file, { architecture: 'x64', baseAddress: 0x1000 }), true);
			await live.analyzeAll();
			const fn = live.getFunctionAt(0x1000)!;
			fn.instructions = [];
			fn.bodyCompleteness = undefined;
			(live as unknown as { unmaterializedStubs: Set<number> }).unmaterializedStubs.add(0x1000);
			const session = live.getSessionStore()!;
			const initialGeneration = session.getAnalysisSession()!.generation;
			const initialUniverse = session.getAnalysisUniverseManifest()!.universeSha256;
			const requestPlan: QueryMaterializationPlan = {
				...plan(20_000), targetIdentity: session.getAnalysisTarget()!.id,
				initialGeneration, initialUniverseSha256: initialUniverse,
			};
			const controller = new QueryMaterializationProcessController();
			const staged = await controller.run(live, requestPlan);
			assert.strictEqual(staged.functions[0].status, 'complete');
			assert.strictEqual(live.peekFunctionBodyCompleteness(0x1000)?.state, 'lazy');
			assert.strictEqual(session.getAnalysisSession()!.generation, initialGeneration);
			assert.strictEqual(session.getAnalysisUniverseManifest()!.universeSha256, initialUniverse);
			live.importAnalysisSnapshot(staged.snapshot, { adopt: true });
			assert.strictEqual(live.getFunctionBodySha256(0x1000), staged.functions[0].bodySha256);
			const committed = live.commitStagedFunctionMaterializations([0x1000]);
			assert.strictEqual(committed.persistence.session.generation, initialGeneration + 1);
			assert.notStrictEqual(committed.persistence.manifest.universeSha256, initialUniverse);
			const acceptedHash = live.getFunctionBodySha256(0x1000);
			live.dispose();
			const reopened = new DisassemblerEngine();
			try {
				assert.strictEqual(await reopened.loadFile(file, { architecture: 'x64', baseAddress: 0x1000 }), true);
				await reopened.analyzeAll();
				assert.strictEqual(reopened.getSessionStore()!.getAnalysisSession()!.generation, committed.persistence.session.generation);
				assert.strictEqual(reopened.getSessionStore()!.getAnalysisUniverseManifest()!.universeSha256, committed.persistence.manifest.universeSha256);
				assert.strictEqual(reopened.getFunctionBodySha256(0x1000), acceptedHash);
				assert.strictEqual(reopened.getAnalysisClosureRestoration().restored, 1);
			} finally { reopened.dispose(); }
		} finally {
			live.dispose();
			fs.rmSync(directory, { recursive: true, force: true });
		}
	});
});
