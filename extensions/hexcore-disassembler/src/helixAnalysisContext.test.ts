/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Akasha Corporation. All rights reserved.
 *--------------------------------------------------------------------------------------------*/

import * as assert from 'assert';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

const Module = require('module');
const originalResolveFilename = Module._resolveFilename;
Module._resolveFilename = function (request: string, parent: unknown, isMain: boolean, options: unknown) {
	if (request === 'vscode') { return '__vscode_mock_helix_context__'; }
	return originalResolveFilename.call(this, request, parent, isMain, options);
};
require.cache['__vscode_mock_helix_context__'] = {
	id: '__vscode_mock_helix_context__',
	filename: '__vscode_mock_helix_context__',
	loaded: true,
	exports: {
		workspace: {
			getConfiguration: () => ({ get: (_key: string, fallback: unknown) => fallback }),
			onDidChangeConfiguration: () => ({ dispose() { /* noop */ } }),
		},
		commands: { executeCommand: async () => undefined },
		extensions: { getExtension: () => undefined },
		Uri: { file: (file: string) => ({ fsPath: file, scheme: 'file' }) },
	},
} as unknown as NodeModule;

const { DisassemblerEngine } = require('./disassemblerEngine');
const { createHelixAnalysisContext, createHelixDebugTypeEnvelope } = require('./helixAnalysisContext');
const { openSemanticQueryView } = require('./semanticQueryView');
const { captureReadOnlyHelixInput, ReadOnlyHelixCapture } = require('./readOnlyHelixCapture');
const { TypeManager } = require('./typeManager') as typeof import('./typeManager');
const { SemanticCommandService } = require('./semanticCommandService') as typeof import('./semanticCommandService');

suite('Immutable Disassembler to Helix analysis context', () => {
	test('read-only capture never materializes or caches body assessments', async () => {
		const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hexcore-read-only-context-'));
		const file = path.join(dir, 'sample.bin'); fs.writeFileSync(file, Buffer.from([0x31, 0xc0, 0xc3]));
		const engine = new DisassemblerEngine();
		try {
			await engine.loadFile(file, { architecture: 'x86', baseAddress: 0x1000 }); await engine.analyzeAll();
			const selected = engine.getFunctionAt(0x1000); assert.ok(selected);
			delete selected.bodyCompleteness;
			const session = engine.getSessionStore();
			const view = openSemanticQueryView(session, { engineGeneration: engine.getAnalysisGeneration() });
			const revision = session.getSemanticReadRevision();
			engine.getFunctionInstructions = async () => { throw new Error('unexpected materialization'); };
			engine.getFunctionBodyCompleteness = () => { throw new Error('unexpected caching'); };
			const before = JSON.stringify(selected);
			const capture = captureReadOnlyHelixInput(engine, view, 0x1000);
			assert.strictEqual(JSON.stringify(selected), before);
			assert.strictEqual(selected.bodyCompleteness, undefined);
			assert.strictEqual(session.getSemanticReadRevision(), revision);
			assert.strictEqual(capture.context.queryIdentity.snapshotSha256, view.identity.snapshotSha256);
			capture.assertCurrent(engine);
			const copied = capture.copyBytes(); copied[0] ^= 0xff;
			assert.deepStrictEqual(engine.getBytes(0x1000, 3), Buffer.from([0x31, 0xc0, 0xc3]));
			assert.throws(() => new ReadOnlyHelixCapture(engine, view, 0x1000, Symbol('forged')), /captureReadOnly/);
			assert.throws(() => captureReadOnlyHelixInput(engine, view, 0x1001), /exact function/);
			session.renameFunction('0x1000', 'changed');
			assert.throws(() => capture.assertCurrent(engine), /no longer current/);
			assert.throws(() => captureReadOnlyHelixInput(engine, view, 0x1000), /identity-mismatch/);
		} finally { engine.dispose(); fs.rmSync(dir, { recursive: true, force: true }); }
	});
	test('read-only capture rejects lazy/partial bodies, coverage gaps and stale bytes', async () => {
		const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hexcore-read-only-reject-'));
		const file = path.join(dir, 'sample.bin'); fs.writeFileSync(file, Buffer.from([0x31, 0xc0, 0xc3]));
		const engine = new DisassemblerEngine();
		try {
			await engine.loadFile(file, { architecture: 'x86', baseAddress: 0x1000 }); await engine.analyzeAll();
			const view = openSemanticQueryView(engine.getSessionStore(), { engineGeneration: engine.getAnalysisGeneration() });
			const fn = engine.getFunctionAt(0x1000); const instructions = [...fn.instructions];
			const capture = captureReadOnlyHelixInput(engine, view, 0x1000);
			fn.instructions = [];
			assert.throws(() => capture.assertCurrent(engine), /instruction model changed/);
			fn.bodyCompleteness = undefined;
			(engine as any).unmaterializedStubs.add(0x1000);
			assert.throws(() => captureReadOnlyHelixInput(engine, view, 0x1000), /lazy/);
			(engine as any).unmaterializedStubs.delete(0x1000);
			fn.instructions = [instructions[0]];
			assert.throws(() => captureReadOnlyHelixInput(engine, view, 0x1000), /partial/);
			fn.instructions = [instructions[1]];
			assert.throws(() => captureReadOnlyHelixInput(engine, view, 0x1000), /coverage/);
			fn.instructions = instructions;
			capture.assertCurrent(engine);
			const bytes = engine.getBytes(0x1000, 3); bytes[0] ^= 0xff;
			assert.throws(() => capture.assertCurrent(engine), /image changed/);
			assert.throws(() => captureReadOnlyHelixInput(engine, view, 0x1000), /image differs/);
		} finally { engine.dispose(); fs.rmSync(dir, { recursive: true, force: true }); }
	});
	test('captures owned blocks and becomes authoritative only after analyzeAll', async () => {
		const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hexcore-helix-context-'));
		const file = path.join(dir, 'sample.bin');
		fs.writeFileSync(file, Buffer.from([
			0x85, 0xc0,       // test eax, eax
			0x74, 0x03,       // je 0x1007
			0xc3,
			0xcc, 0xcc,
			0x31, 0xc0,
			0xc3,
		]));
		const engine = new DisassemblerEngine();
		try {
			assert.strictEqual(await engine.loadFile(file, { architecture: 'x86', baseAddress: 0x1000 }), true);
			const before = await createHelixAnalysisContext(engine, 0x1000);
			assert.strictEqual(before.analysis.functionStartsAuthoritative, false);

			await engine.analyzeAll();
			const context = await createHelixAnalysisContext(engine, 0x1000);
			assert.strictEqual(context.analysis.functionStartsAuthoritative, true);
			assert.strictEqual(context.function.start, '0x1000');
			assert.strictEqual(context.function.end, '0x100a');
			assert.ok(context.blocks.some((block: { start: string }) => block.start === '0x1007'));
			assert.ok(context.edges.some((edge: { to: string }) => edge.to === '0x1007'));
			assert.strictEqual(Object.isFrozen(context), true);
			assert.strictEqual(Object.isFrozen(context.blocks), true);

			const originalName = context.function.name;
			engine.renameFunction(0x1000, 'renamed_after_snapshot');
			assert.strictEqual(context.function.name, originalName);
			const afterRename = await createHelixAnalysisContext(engine, 0x1000);
			assert.notStrictEqual(afterRename.contextSha256, context.contextSha256);

			const envelope = createHelixDebugTypeEnvelope(context, {
				structs: {},
				functions: { imported_api: { returnType: 'int', parameters: [] } },
			});
			assert.strictEqual(envelope.hexcoreContext.contextSha256, context.contextSha256);
			assert.ok(envelope.functions.imported_api);

			const session = engine.getSessionStore()!;
			const manager = new TypeManager(session.getSemanticStore());
			const integer = manager.create({ kind: 'integer', name: 'uint32_t', sizeBits: 32, alignBits: 32, signed: false }, 1);
			const record = manager.create({ kind: 'struct', name: 'RuntimeContext', sizeBits: 32, alignBits: 32, members: [{ name: 'value', typeId: integer.typeId, bitOffset: 0, bitSize: 32 }] }, 2);
			const pointer = manager.create({ kind: 'pointer', targetTypeId: record.typeId, sizeBits: 32, alignBits: 32 }, 3);
			new SemanticCommandService(session).applyPrototype({
				functionIdentity: 'function:0x1000', functionAddress: '0x1000', returnType: { typeId: integer.typeId }, callingConventionId: 'cdecl',
				parameters: [{ ordinal: 0, name: 'context', type: { typeId: pointer.typeId }, location: { kind: 'stack', base: 'entry-sp', offsetBytes: 4, sizeBytes: 4 } }],
				evidence: { strength: 'definitive', source: 'analyst', producer: 'fixture', generation: 4, userDefined: true },
			});
			const semanticContext = await createHelixAnalysisContext(engine, 0x1000);
			assert.notStrictEqual(semanticContext.contextSha256, context.contextSha256);
			assert.ok(semanticContext.semantic.types.length >= 3);
			const semanticEnvelope = createHelixDebugTypeEnvelope(semanticContext);
			assert.strictEqual(semanticEnvelope.functions[semanticContext.function.name].returnType, 'uint32_t');
			assert.strictEqual(semanticEnvelope.functions[semanticContext.function.name].params[0].type, 'struct RuntimeContext *');
			assert.strictEqual(semanticEnvelope.structs.RuntimeContext.fields[0].name, 'value');
		} finally {
			engine.dispose();
			fs.rmSync(dir, { recursive: true, force: true });
		}
	});
});
