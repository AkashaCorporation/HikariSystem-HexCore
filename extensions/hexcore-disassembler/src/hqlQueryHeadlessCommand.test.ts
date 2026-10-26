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
		assert.strictEqual(observed, 750); assert.strictEqual(report.status, 'partial');
	});
});
