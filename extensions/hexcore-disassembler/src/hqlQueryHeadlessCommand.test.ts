/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import * as assert from 'assert';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
const Module = require('module');
const originalResolveFilename = Module._resolveFilename;
Module._resolveFilename = function (request: string, parent: unknown, isMain: boolean, options: unknown) {
	if (request === 'vscode') { return '__vscode_mock_hql_query_command__'; }
	return originalResolveFilename.call(this, request, parent, isMain, options);
};
require.cache['__vscode_mock_hql_query_command__'] = { id: '__vscode_mock_hql_query_command__', filename: '__vscode_mock_hql_query_command__', loaded: true,
	exports: { workspace: { getConfiguration: () => ({ get: (_key: string, fallback: unknown) => fallback }), onDidChangeConfiguration: () => ({ dispose() {} }) }, commands: { executeCommand: async () => undefined }, extensions: { getExtension: () => undefined }, Uri: { file: (file: string) => ({ fsPath: file }) } } } as NodeModule;
const { DisassemblerEngine } = require('./disassemblerEngine') as typeof import('./disassemblerEngine');
const { runHqlQueryHeadlessCommand } = require('./hqlQueryHeadlessCommand') as typeof import('./hqlQueryHeadlessCommand');
const { canonicalizeSemanticType } = require('./semanticModel') as typeof import('./semanticModel');
const { QueryMaterializationProcessError } = require('./queryMaterializationProcess') as typeof import('./queryMaterializationProcess');

suite('HQL ad-hoc headless command core', () => {
	let directory: string;
	let file: string;
	let engine: InstanceType<typeof DisassemblerEngine>;
	setup(async () => {
		directory = fs.mkdtempSync(path.join(os.tmpdir(), 'hexcore-hql-query-command-'));
		file = path.join(directory, 'fixture.bin'); fs.writeFileSync(file, Buffer.from([0xb8, 7, 0, 0, 0, 0xc3]));
		engine = new DisassemblerEngine(); assert.strictEqual(await engine.loadFile(file, { architecture: 'x64', baseAddress: 0x1000 }), true); await engine.analyzeAll();
		const evidence = { strength: 'debug' as const, source: 'debug-info' as const, producer: 'fixture', generation: 0 };
		const store = engine.getSessionStore()!.getSemanticStore();
		const type = canonicalizeSemanticType({ kind: 'integer', sizeBits: 32, signed: true }, evidence); store.putType(type);
		store.putPrototype({ targetIdentity: store.targetIdentity, functionIdentity: 'function:0x1000', functionAddress: '0x1000', callingConventionId: 'win64', returnTypeId: type.typeId, parameters: [], evidence });
	});
	teardown(() => { engine.dispose(); fs.rmSync(directory, { recursive: true, force: true }); });
	const prototype = { fact: { fact: 'function-prototype' } };
	const closedPrototype = { all: [prototype, { not: { fact: { fact: 'summary-barrier' } } }] };
	test('semantic positive uses the pinned view without starting a native producer', async () => {
		const revision = engine.getSessionStore()!.getSemanticReadRevision();
		const report: any = await runHqlQueryHeadlessCommand(engine, { condition: prototype, addresses: ['0x1000'] }, () => { throw new Error('must not create native producer'); });
		assert.strictEqual(report.status, 'partial'); assert.strictEqual(report.rows.length, 1);
		assert.strictEqual(report.rows[0].address, '0x1000'); assert.strictEqual(report.nativeProducers.length, 0);
		assert.strictEqual(report.materialization, 'never'); assert.strictEqual(report.targetIdentity, report.identity.targetIdentity);
		assert.strictEqual(engine.getSessionStore()!.getSemanticReadRevision(), revision);
	});
	test('semantic absence remains unknown and partial ancestor blocks positive evidence', async () => {
		const negative: any = await runHqlQueryHeadlessCommand(engine, { condition: { not: { fact: { fact: 'summary-barrier' } } }, addresses: ['0x1000'] });
		assert.strictEqual(negative.rows.length, 0); assert.strictEqual(negative.coverage.unknownFunctions, 1);
		const inherited: any = await runHqlQueryHeadlessCommand(engine, { condition: prototype, addresses: ['0x1000'], pipelineInputQuality: { status: 'partial', reasons: ['fixture ancestor'] } });
		assert.strictEqual(inherited.rows.length, 0); assert.strictEqual(inherited.coverage.unknownFunctions, 1);
	});
	test('target switches, unsupported policy and malformed queries return error contracts', async () => {
		for (const args of [{ file: path.join(directory, 'other.bin'), condition: prototype }, { materialization: 'needed', condition: prototype }, { query: { condition: prototype }, addresses: ['0x1000'] }, { condition: { fact: { fact: 'typo' } } }, { condition: prototype, maxRows: 0 },
			{ condition: { query: { target: 'CReturnStmt' } }, addresses: ['0x1000'], irText: 'define void @f() { ret void }' },
			{ condition: { query: { target: 'CReturnStmt' } }, addresses: ['0x1000'], irPath: file, pipelineArtifactBindings: [{ path: file }] }]) {
			const report: any = await runHqlQueryHeadlessCommand(engine, args);
			assert.strictEqual(report.status, 'error'); assert.strictEqual(report.success, false);
		}
		assert.strictEqual(engine.getFilePath(), file);
	});
	test('bounded materialization commits one generation and an exact rerun does no work', async () => {
		const completeSnapshot = engine.exportAnalysisSnapshot();
		const bodySha256 = engine.getFunctionBodySha256(0x1000)!;
		const fn = engine.getFunctionAt(0x1000)!;
		fn.instructions = [];
		fn.bodyCompleteness = undefined;
		(engine as any).unmaterializedStubs.add(0x1000);
		const initialGeneration = engine.getSessionStore()!.getAnalysisSession()!.generation;
		const initialUniverse = engine.getSessionStore()!.getAnalysisUniverseManifest()!.universeSha256;
		let stagedRuns = 0;
		const controller = { run: async () => {
			stagedRuns++;
			return {
				snapshot: completeSnapshot,
				functions: [{ address: '0x1000', status: 'complete' as const, spanBytes: 6, instructionCount: 2, bodySha256 }],
				nativeExecution: { isolation: 'child-process' as const, outcome: 'completed' as const, durationMs: 1, lastPhase: 'completed', heartbeats: 1, peakHeapUsed: 1, inputSnapshotSha256: 'a'.repeat(64), outputSnapshotSha256: 'b'.repeat(64), artifactsRemoved: true },
			};
		} };
		const report: any = await runHqlQueryHeadlessCommand(engine, {
			condition: closedPrototype, addresses: ['0x1000'],
			materialization: { mode: 'bounded', maxFunctions: 4, maxBytes: 4096, maxMilliseconds: 5000, maxDepth: 2 },
		}, undefined, { materializationController: controller });
		assert.strictEqual(stagedRuns, 1);
		assert.strictEqual(report.materialization.status, 'committed');
		assert.strictEqual(report.materialization.materializedFunctions, 1);
		assert.strictEqual(report.initialGeneration, initialGeneration);
		assert.strictEqual(report.finalGeneration, initialGeneration + 1);
		assert.notStrictEqual(report.finalUniverseSha256, initialUniverse);
		assert.strictEqual(report.rows.length, 1);
		assert.strictEqual(report.evaluations[0].state, 'matched');
		assert.strictEqual(report.evaluations[0].status, 'ok');
		const rerunGeneration = report.finalGeneration;
		const rerun: any = await runHqlQueryHeadlessCommand(engine, {
			condition: closedPrototype, addresses: ['0x1000'], materialization: { mode: 'bounded', maxFunctions: 4, maxBytes: 4096, maxMilliseconds: 5000, maxDepth: 2 },
		}, undefined, { materializationController: { run: async () => { throw new Error('unchanged body was restaged'); } } });
		assert.strictEqual(rerun.initialGeneration, rerunGeneration);
		assert.strictEqual(rerun.finalGeneration, rerunGeneration);
		assert.strictEqual(rerun.materialization.requestedFunctions, 0);
	});
	test('default child process stages and commits a real needed query body', async function () {
		this.timeout(60_000);
		const fn = engine.getFunctionAt(0x1000)!;
		fn.instructions = [];
		fn.bodyCompleteness = undefined;
		(engine as any).unmaterializedStubs.add(0x1000);
		const before = engine.getSessionStore()!.getAnalysisSession()!.generation;
		const report: any = await runHqlQueryHeadlessCommand(engine, {
			condition: closedPrototype, addresses: ['0x1000'], materialization: { mode: 'needed', maxMilliseconds: 20_000 },
		});
		assert.strictEqual(report.materialization.nativeExecution.outcome, 'completed');
		assert.strictEqual(report.materialization.status, 'committed');
		assert.strictEqual(report.materialization.nativeExecution.artifactsRemoved, true);
		assert.strictEqual(report.materialization.materializedFunctions, 1);
		assert.strictEqual(report.finalGeneration, before + 1);
		assert.strictEqual(engine.peekFunctionBodyCompleteness(0x1000)?.state, 'complete');
	});
	test('real structural lane materializes and decompiles but preserves an upstream ABI barrier', async function () {
		this.timeout(180_000);
		const fn = engine.getFunctionAt(0x1000)!;
		fn.instructions = [];
		fn.bodyCompleteness = undefined;
		(engine as any).unmaterializedStubs.add(0x1000);
		const report: any = await runHqlQueryHeadlessCommand(engine, {
			condition: { query: { target: 'CReturnStmt' } },
			addresses: ['0x1000'],
			materialization: { mode: 'needed', maxMilliseconds: 30_000 },
			timeoutMs: 120_000,
		});
		assert.strictEqual(report.materialization.materializedFunctions, 1);
		assert.strictEqual(report.materialization.nativeExecution.outcome, 'completed');
		assert.strictEqual(report.nativeProducers.length, 1);
		assert.strictEqual(report.nativeProducers[0].success, true, JSON.stringify(report.nativeProducers[0]));
		assert.ok(report.nativeProducers[0].hastSha256);
		assert.strictEqual(report.rows.length, 0);
		assert.strictEqual(report.evaluations[0].state, 'unknown');
		assert.ok(report.evaluations[0].partialReasons.includes('raw target ABI not assessed'));
	});
	test('qualified PE structural lane materializes and reevaluates HAST end to end', async function () {
		this.timeout(180_000);
		const hqlRoot = path.resolve(__dirname, '..', '..', 'hexcore-hql');
		const manifest = JSON.parse(fs.readFileSync(path.join(hqlRoot, 'benchmarks', 'corpus', 'build', 'build-manifest.json'), 'utf8').replace(/^\uFEFF/, '')) as {
			entries: Array<{ id: string; binaryPath: string }>;
		};
		const binary = manifest.entries.find(entry => entry.id === 'msvc-x64-O2-debug')!.binaryPath;
		const peDirectory = fs.mkdtempSync(path.join(os.tmpdir(), 'hexcore-g06-pe-'));
		const target = path.join(peDirectory, path.basename(binary));
		fs.copyFileSync(binary, target);
		const pe = new DisassemblerEngine();
		try {
			assert.strictEqual(await pe.loadFile(target), true);
			await pe.analyzeAll();
			const exported = pe.getExports().find(item => item.name === 'bench_plain_copy')!;
			const bodyAddress = pe.getFunctionAt(exported.address)?.instructions.find(
				instruction => instruction.isJump && !instruction.isConditional && instruction.targetAddress !== undefined,
			)?.targetAddress ?? exported.address;
			const body = pe.getFunctionAt(bodyAddress)!;
			body.instructions = [];
			body.bodyCompleteness = undefined;
			(pe as any).unmaterializedStubs.add(bodyAddress);
			const report: any = await runHqlQueryHeadlessCommand(pe, {
				condition: { query: { target: 'CReturnStmt' } }, addresses: [`0x${bodyAddress.toString(16)}`],
				materialization: { mode: 'needed', maxMilliseconds: 30_000 }, timeoutMs: 120_000,
			});
			assert.strictEqual(report.materialization.materializedFunctions, 1, JSON.stringify(report.materialization));
			assert.strictEqual(report.nativeProducers[0].success, true, JSON.stringify(report.nativeProducers[0]));
			assert.strictEqual(report.nativeProducers[0].status, 'ok', JSON.stringify(report.nativeProducers[0]));
			assert.strictEqual(report.rows.length, 1, JSON.stringify(report));
			assert.strictEqual(report.evaluations[0].state, 'matched');
		} finally {
			pe.dispose();
			fs.rmSync(peDirectory, { recursive: true, force: true });
		}
	});
	test('materialization cancellation preserves the accepted generation and universe', async () => {
		const fn = engine.getFunctionAt(0x1000)!;
		fn.instructions = [];
		fn.bodyCompleteness = undefined;
		(engine as any).unmaterializedStubs.add(0x1000);
		const beforeGeneration = engine.getSessionStore()!.getAnalysisSession()!.generation;
		const beforeUniverse = engine.getSessionStore()!.getAnalysisUniverseManifest()!.universeSha256;
		const execution = { isolation: 'child-process' as const, outcome: 'cancelled' as const, durationMs: 1, lastPhase: 'materialize', heartbeats: 1, peakHeapUsed: 1, inputSnapshotSha256: 'a'.repeat(64), artifactsRemoved: true };
		const report: any = await runHqlQueryHeadlessCommand(engine, {
			condition: closedPrototype, addresses: ['0x1000'], materialization: { mode: 'needed' },
		}, undefined, { materializationController: { run: async () => { throw new QueryMaterializationProcessError('cancelled fixture', execution); } } });
		assert.strictEqual(report.status, 'partial');
		assert.strictEqual(report.materialization.status, 'cancelled');
		assert.strictEqual(report.finalGeneration, beforeGeneration);
		assert.strictEqual(report.finalUniverseSha256, beforeUniverse);
		assert.ok(report.partialReasons.some((reason: string) => reason.includes('materialization-cancelled')));
	});
	test('materialization timeout preserves the accepted generation and universe', async () => {
		const fn = engine.getFunctionAt(0x1000)!;
		fn.instructions = [];
		fn.bodyCompleteness = undefined;
		(engine as any).unmaterializedStubs.add(0x1000);
		const beforeGeneration = engine.getSessionStore()!.getAnalysisSession()!.generation;
		const beforeUniverse = engine.getSessionStore()!.getAnalysisUniverseManifest()!.universeSha256;
		const execution = { isolation: 'child-process' as const, outcome: 'timeout' as const, durationMs: 30, lastPhase: 'materialize', heartbeats: 1, peakHeapUsed: 1, inputSnapshotSha256: 'a'.repeat(64), artifactsRemoved: true };
		const report: any = await runHqlQueryHeadlessCommand(engine, {
			condition: closedPrototype, addresses: ['0x1000'], materialization: { mode: 'needed' },
		}, undefined, { materializationController: { run: async () => { throw new QueryMaterializationProcessError('timeout fixture', execution); } } });
		assert.strictEqual(report.status, 'partial');
		assert.strictEqual(report.materialization.status, 'timeout');
		assert.strictEqual(report.finalGeneration, beforeGeneration);
		assert.strictEqual(report.finalUniverseSha256, beforeUniverse);
		assert.ok(report.partialReasons.some((reason: string) => reason.includes('materialization-timeout')));
	});
	test('materialization byte exhaustion is explicit and never launches a worker', async () => {
		const fn = engine.getFunctionAt(0x1000)!;
		fn.instructions = [];
		fn.bodyCompleteness = undefined;
		(engine as any).unmaterializedStubs.add(0x1000);
		let runs = 0;
		const report: any = await runHqlQueryHeadlessCommand(engine, {
			condition: closedPrototype, addresses: ['0x1000'], materialization: { mode: 'bounded', maxFunctions: 1, maxBytes: 1, maxMilliseconds: 5000, maxDepth: 1 },
		}, undefined, { materializationController: { run: async () => { runs++; throw new Error('budgeted body launched'); } } });
		assert.strictEqual(runs, 0);
		assert.strictEqual(report.materialization.budgetExhausted, true);
		assert.strictEqual(report.materialization.reason, 'maxBytes');
		assert.strictEqual(report.finalGeneration, report.initialGeneration);
		assert.ok(report.partialReasons.some((reason: string) => reason.includes('maxBytes')));
	});
	test('a staged snapshot for another target is rejected before generation commit', async () => {
		const fn = engine.getFunctionAt(0x1000)!;
		const bodySha256 = engine.getFunctionBodySha256(0x1000)!;
		const foreign = engine.exportAnalysisSnapshot();
		foreign.target.fileSha256 = '0'.repeat(64);
		fn.instructions = [];
		fn.bodyCompleteness = undefined;
		(engine as any).unmaterializedStubs.add(0x1000);
		const beforeGeneration = engine.getSessionStore()!.getAnalysisSession()!.generation;
		const beforeUniverse = engine.getSessionStore()!.getAnalysisUniverseManifest()!.universeSha256;
		const report: any = await runHqlQueryHeadlessCommand(engine, {
			condition: closedPrototype, addresses: ['0x1000'], materialization: { mode: 'needed' },
		}, undefined, { materializationController: { run: async () => ({
			snapshot: foreign,
			functions: [{ address: '0x1000', status: 'complete' as const, spanBytes: 6, instructionCount: 2, bodySha256 }],
			nativeExecution: { isolation: 'child-process' as const, outcome: 'completed' as const, durationMs: 1, lastPhase: 'completed', heartbeats: 1, peakHeapUsed: 1, inputSnapshotSha256: 'a'.repeat(64), artifactsRemoved: true },
		}) } });
		assert.strictEqual(report.status, 'error');
		assert.match(report.error, /target identity/);
		assert.strictEqual(engine.getSessionStore()!.getAnalysisSession()!.generation, beforeGeneration);
		assert.strictEqual(engine.getSessionStore()!.getAnalysisUniverseManifest()!.universeSha256, beforeUniverse);
	});
	test('partial staged bodies remain outside the universe and retryable', async () => {
		const fn = engine.getFunctionAt(0x1000)!;
		fn.instructions = [];
		fn.bodyCompleteness = undefined;
		(engine as any).unmaterializedStubs.add(0x1000);
		const lazySnapshot = engine.exportAnalysisSnapshot();
		const beforeGeneration = engine.getSessionStore()!.getAnalysisSession()!.generation;
		let runs = 0;
		const controller = { run: async () => {
			runs++;
			return {
				snapshot: structuredClone(lazySnapshot),
				functions: [{ address: '0x1000', status: 'partial' as const, spanBytes: 6, instructionCount: 1 }],
				nativeExecution: { isolation: 'child-process' as const, outcome: 'completed' as const, durationMs: 1, lastPhase: 'completed', heartbeats: 1, peakHeapUsed: 1, inputSnapshotSha256: 'a'.repeat(64), artifactsRemoved: true },
			};
		} };
		for (let iteration = 0; iteration < 2; iteration++) {
			const report: any = await runHqlQueryHeadlessCommand(engine, {
				condition: closedPrototype, addresses: ['0x1000'], materialization: { mode: 'needed' },
			}, undefined, { materializationController: controller });
			assert.strictEqual(report.materialization.partialFunctions, 1);
			assert.strictEqual(report.materialization.materializedFunctions, 0);
			assert.strictEqual(report.finalGeneration, beforeGeneration);
			assert.ok(report.partialReasons.some((reason: string) => reason.includes('dependency-body-unavailable')));
		}
		assert.strictEqual(runs, 2);
	});
	test('missing selectors and selection limits retain unevaluated coverage', async () => {
		const missing: any = await runHqlQueryHeadlessCommand(engine, { condition: prototype, functions: ['missing'] });
		assert.strictEqual(missing.status, 'partial'); assert.strictEqual(missing.coverage.requestedFunctions, 1); assert.strictEqual(missing.coverage.unevaluatedFunctions, 1);
		assert.ok(missing.partialReasons.some((reason: string) => reason.includes('not indexed')));
		const address: any = await runHqlQueryHeadlessCommand(engine, { condition: prototype, addresses: ['0x2000'] });
		assert.strictEqual(address.coverage.unknownFunctions, 1); assert.strictEqual(address.rows.length, 0);
	});
	test('large implicit scope is retained as counts, not unbounded selection objects', async () => {
		for (let index = 1; index < 300; index++) (engine as any).functions.set(0x1000 + index, { address: 0x1000 + index, endAddress: 0x1001 + index, size: 1, name: `fn_${index}`, instructions: [], callers: [], callees: [] });
		const report: any = await runHqlQueryHeadlessCommand(engine, { condition: prototype, maxFunctions: 2 });
		assert.strictEqual(report.coverage.requestedFunctions, 300); assert.strictEqual(report.evaluations.length, 2);
		assert.strictEqual(report.coverage.unevaluatedFunctions, 298); assert.ok(report.partialReasons.some((reason: string) => reason.includes('298')));
	});
	test('implicit structural scope prioritizes an accepted body over earlier lazy stubs', async () => {
		(engine as any).functions.set(0x500, { address: 0x500, endAddress: 0x501, size: 1, name: 'early_lazy', instructions: [], callers: [], callees: [] });
		(engine as any).unmaterializedStubs.add(0x500);
		let requestedAddress = -1;
		const report: any = await runHqlQueryHeadlessCommand(engine, { condition: { query: { target: 'CReturnStmt' } }, maxFunctions: 1 }, () => ({ run: async (request: any) => {
			requestedAddress = request.input.address;
			return { status: 'error', success: false, requestSha256: 'a'.repeat(64), contextSha256: request.context.contextSha256, phase: 'terminal', architecture: 'x64', source: '', hastBase64: '', qualityIssues: [], semanticEligible: false, error: 'fixture', execution: { isolation: 'child-process', exited: true, elapsedMs: 1, exitCode: 1, signal: null } };
		} } as any));
		assert.strictEqual(requestedAddress, 0x1000); assert.strictEqual(report.coverage.requestedFunctions, 2); assert.strictEqual(report.coverage.unevaluatedFunctions, 1);
	});
	test('structural query never materializes a lazy function', async () => {
		const fn = engine.getFunctionAt(0x1000)!; fn.instructions = []; fn.bodyCompleteness = undefined;
		(engine as any).unmaterializedStubs.add(0x1000);
		engine.materializeFunction = async () => { throw new Error('implicit materialization'); };
		engine.getFunctionInstructions = async () => { throw new Error('implicit instruction read'); };
		let runs = 0;
		const report: any = await runHqlQueryHeadlessCommand(engine, { condition: { query: { target: 'CReturnStmt' } }, addresses: ['0x1000'] }, () => ({ run: async () => { runs++; throw new Error('must not run'); } } as any));
		assert.strictEqual(runs, 0); assert.strictEqual(report.status, 'partial'); assert.strictEqual(report.coverage.unknownFunctions, 1);
		assert.ok(report.evaluations[0].partialReasons.some((reason: string) => reason.includes('lazy')));
	});
	test('native producer failure is recorded and cannot become a negative', async () => {
		let runs = 0;
		const report: any = await runHqlQueryHeadlessCommand(engine, { condition: { query: { target: 'CReturnStmt' } }, addresses: ['0x1000'] }, () => ({ run: async (request: any) => {
			runs++;
			return { status: 'error', success: false, requestSha256: 'a'.repeat(64), contextSha256: request.context.contextSha256, phase: 'terminal', architecture: 'x64', source: '', hastBase64: '', qualityIssues: ['fixture'], semanticEligible: false, error: 'fixture failure', execution: { isolation: 'child-process', exited: true, elapsedMs: 1, exitCode: 1, signal: null } };
		} } as any));
		assert.strictEqual(runs, 1); assert.strictEqual(report.status, 'partial'); assert.strictEqual(report.rows.length, 0);
		assert.strictEqual(report.coverage.unknownFunctions, 1); assert.strictEqual(report.nativeProducers[0].error, 'fixture failure');
	});
	test('runner cancellation reaches query execution without becoming a negative', async () => {
		const abort = new AbortController(); abort.abort();
		const report: any = await runHqlQueryHeadlessCommand(engine, { condition: prototype, addresses: ['0x1000'] }, undefined, { signal: abort.signal });
		assert.strictEqual(report.status, 'partial'); assert.strictEqual(report.rows.length, 0);
		assert.ok(report.partialReasons.includes('query-cancelled'));
		assert.strictEqual(report.coverage.evaluatedFunctions, 0);
	});
	test('native deadline reserves cleanup time before the outer step timeout', async () => {
		let observed = 0;
		const report: any = await runHqlQueryHeadlessCommand(engine, { condition: { query: { target: 'CReturnStmt' } }, addresses: ['0x1000'], timeoutMs: 5000 }, () => ({ run: async (_request: any, options: any) => {
			observed = options.timeoutMs;
			return { status: 'error', success: false, requestSha256: 'a'.repeat(64), contextSha256: 'b'.repeat(64), phase: 'terminal', architecture: 'x64', source: '', hastBase64: '', qualityIssues: [], semanticEligible: false, error: 'deadline fixture', execution: { isolation: 'child-process', exited: true, elapsedMs: 1, exitCode: 1, signal: null } };
		} } as any), { stepTimeoutMs: 1000 });
		assert.ok(observed >= 700 && observed <= 750, `reserved timeout was ${observed}ms`); assert.strictEqual(report.status, 'partial');
	});
});
