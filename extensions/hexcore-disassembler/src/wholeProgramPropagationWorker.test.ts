import * as assert from 'assert';
import * as path from 'path';
import { SemanticStore, type SemanticSqliteFactory } from './semanticStore';
import {
	WholeProgramPropagationEngine,
	type FunctionSummaryInput,
} from './wholeProgramPropagation';
import { runPropagationInWorker } from './wholeProgramPropagationWorkerClient';

function sqlite(): SemanticSqliteFactory {
	// eslint-disable-next-line @typescript-eslint/no-var-requires
	return require(path.join(__dirname, '..', '..', 'hexcore-better-sqlite3')) as SemanticSqliteFactory;
}

const targetIdentity = `target:sha256:${'7'.repeat(64)}`;

function input(index: number): FunctionSummaryInput {
	const functionIdentity = `function:0x${(0x140001000 + index * 0x10).toString(16)}`;
	return {
		analysisTargetIdentity: targetIdentity,
		functionIdentity,
		functionBodySha256: index.toString(16).padStart(64, '0'),
		generation: 1,
		materialized: true,
		constraints: [],
	};
}

suite('Perseus propagation worker', () => {
	test('matches the synchronous solver and commits only in the parent', async () => {
		const directStore = new SemanticStore(sqlite().openDatabase(':memory:'), targetIdentity);
		const workerStore = new SemanticStore(sqlite().openDatabase(':memory:'), targetIdentity);
		try {
			const inputs = [input(1), input(2)];
			const direct = new WholeProgramPropagationEngine(directStore).solve(inputs, { generation: 1 });
			const isolated = await runPropagationInWorker(workerStore, inputs, { generation: 1, maxMilliseconds: 30_000 });
			assert.strictEqual(isolated.run.status, 'committed');
			assert.strictEqual(isolated.run.outputHash, direct.outputHash);
			assert.strictEqual(isolated.run.inputHash, direct.inputHash);
			assert.strictEqual(isolated.run.runHash, direct.runHash);
			assert.deepStrictEqual(isolated.run.summaries, direct.summaries);
			assert.strictEqual(workerStore.getWholeProgramPropagationStore().listSummaries().length, 2);
			assert.strictEqual(isolated.diagnostics.transport, 'perseus-sab-v1');
			assert.ok(isolated.diagnostics.heartbeats >= 3);
			assert.strictEqual(isolated.diagnostics.hardTerminated, false);
		} finally {
			directStore.dispose();
			workerStore.dispose();
		}
	});

	test('hard-terminates without committing a partial generation', async () => {
		const store = new SemanticStore(sqlite().openDatabase(':memory:'), targetIdentity);
		try {
			const inputs = Array.from({ length: 2_000 }, (_, index) => input(index + 10));
			const before = store.exportHash();
			const startedAt = Date.now();
			const isolated = await runPropagationInWorker(store, inputs, {
				generation: 1,
				maxMilliseconds: 300_000,
				hardTimeoutMs: 10,
			});
			assert.ok(Date.now() - startedAt < 1_000, 'terminal timeout must not await worker teardown');
			assert.strictEqual(isolated.run.status, 'timeout');
			assert.strictEqual(isolated.run.committed, false);
			assert.strictEqual(isolated.diagnostics.hardTerminated, true);
			await new Promise(resolve => setTimeout(resolve, 100));
			assert.strictEqual(store.exportHash(), before);
			assert.strictEqual(store.getWholeProgramPropagationStore().listSummaries().length, 0);
		} finally {
			store.dispose();
		}
	});
});
