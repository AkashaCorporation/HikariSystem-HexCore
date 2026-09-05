/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Akasha Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as assert from 'assert';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

const Module = require('module');
const originalResolveFilename = Module._resolveFilename;
Module._resolveFilename = function (request: string, parent: unknown, isMain: boolean, options: unknown) {
	if (request === 'vscode') { return '__vscode_mock_propagation_runtime__'; }
	return originalResolveFilename.call(this, request, parent, isMain, options);
};
require.cache.__vscode_mock_propagation_runtime__ = {
	id: '__vscode_mock_propagation_runtime__', filename: '__vscode_mock_propagation_runtime__', loaded: true,
	exports: {
		workspace: {
			getConfiguration: () => ({ get: (_key: string, fallback: unknown) => fallback }),
			onDidChangeConfiguration: () => ({ dispose() { /* noop */ } }),
			workspaceFolders: undefined,
		},
		commands: { executeCommand: async () => undefined, getCommands: async () => [] },
		extensions: { getExtension: () => undefined },
		Uri: { file: (file: string) => ({ fsPath: file, scheme: 'file' }) },
		window: {},
	},
} as NodeModule;

const { DisassemblerEngine } = require('./disassemblerEngine') as typeof import('./disassemblerEngine');
const { syncWholeProgramPropagation } = require('./wholeProgramPropagationProducer') as typeof import('./wholeProgramPropagationProducer');
const { runPropagationExport, runPropagationStatus } = require('./wholeProgramPropagationCommands') as typeof import('./wholeProgramPropagationCommands');

suite('R34 whole-program real-binary runtime gate', function () {
	this.timeout(180_000);

	test('persists and deterministically reopens accepted summaries for a pinned corpus PE', async () => {
		const hqlRoot = path.resolve(__dirname, '..', '..', 'hexcore-hql');
		const manifest = JSON.parse(fs.readFileSync(path.join(hqlRoot, 'benchmarks', 'corpus', 'build', 'build-manifest.json'), 'utf8').replace(/^\uFEFF/, '')) as {
			entries: Array<{ id: string; binaryPath: string; binarySha256: string }>;
		};
		const entry = manifest.entries.find(item => item.id === 'msvc-x64-O2-stripped');
		assert.ok(entry && fs.existsSync(entry.binaryPath), 'Pinned Function Atlas corpus binary is required');
		const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'hexcore-r34-runtime-'));
		const target = path.join(directory, 'semantic-benchmark.exe');
		fs.copyFileSync(entry.binaryPath, target);

		const first = new DisassemblerEngine();
		let firstOutputHash: string;
		let firstSummaryCount: number;
		let firstCollectionHash: string;
		let firstReferenceGraphHash: string;
		try {
			assert.strictEqual(await first.loadFile(target), true);
			await first.analyzeAll();
			const result = syncWholeProgramPropagation(first);
			assert.strictEqual(result.references.status, 'ok');
			assert.strictEqual(result.collection.status, 'ok');
			assert.strictEqual(result.run.status, 'committed');
			assert.ok(result.run.summaries.length > 0);
			firstOutputHash = result.run.outputHash!;
			firstSummaryCount = result.run.summaries.length;
			firstCollectionHash = result.collection.collectionHash;
			firstReferenceGraphHash = result.references.graphHash;
			const status = runPropagationStatus(first);
			assert.strictEqual(status.latestAcceptedGeneration, result.collection.analysisGeneration);
			assert.strictEqual(status.summaryCount, firstSummaryCount);
			assert.strictEqual(status.dirty.length, 0);
			const exported = runPropagationExport(first);
			assert.strictEqual(exported.payload.propagation.summaries.length, firstSummaryCount);
			assert.match(exported.contentHash, /^[0-9a-f]{64}$/);
		} finally {
			first.dispose();
		}

		const reopened = new DisassemblerEngine();
		try {
			assert.strictEqual(await reopened.loadFile(target), true);
			const persisted = reopened.getSessionStore()!.getSemanticStore().getWholeProgramPropagationStore().listSummaries();
			assert.strictEqual(persisted.length, firstSummaryCount);
			assert.strictEqual(persisted.map(item => item.outputHash).sort().length, firstSummaryCount);
			await reopened.analyzeAll();
			const repeated = syncWholeProgramPropagation(reopened);
			assert.strictEqual(repeated.run.status, 'committed');
			assert.strictEqual(repeated.collection.collectionHash, firstCollectionHash);
			assert.strictEqual(repeated.references.graphHash, firstReferenceGraphHash);
			assert.strictEqual(repeated.run.outputHash, firstOutputHash);
			assert.strictEqual(repeated.run.summaries.length, firstSummaryCount);
		} finally {
			reopened.dispose();
			fs.rmSync(directory, { recursive: true, force: true });
		}
	});
});
