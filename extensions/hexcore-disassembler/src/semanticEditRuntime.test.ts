import * as assert from 'assert';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

const Module = require('module');
const originalResolveFilename = Module._resolveFilename;
Module._resolveFilename = function (request: string, parent: unknown, isMain: boolean, options: unknown) {
	if (request === 'vscode') return '__vscode_mock_semantic_edit_runtime__';
	return originalResolveFilename.call(this, request, parent, isMain, options);
};
require.cache.__vscode_mock_semantic_edit_runtime__ = { id: '__vscode_mock_semantic_edit_runtime__', filename: '__vscode_mock_semantic_edit_runtime__', loaded: true, exports: { workspace: { getConfiguration: () => ({ get: (_key: string, fallback: unknown) => fallback }), onDidChangeConfiguration: () => ({ dispose() {} }), workspaceFolders: undefined }, commands: { executeCommand: async () => undefined, getCommands: async () => [] }, extensions: { getExtension: () => undefined }, Uri: { file: (file: string) => ({ fsPath: file, scheme: 'file' }) }, window: {} } } as NodeModule;

const { DisassemblerEngine } = require('./disassemblerEngine') as typeof import('./disassemblerEngine');
const { SemanticCommandService } = require('./semanticCommandService') as typeof import('./semanticCommandService');
const { semanticCommandCallbacks } = require('./semanticCommandIntegration') as typeof import('./semanticCommandIntegration');
const { createHelixAnalysisContext, createHelixDebugTypeEnvelope } = require('./helixAnalysisContext') as typeof import('./helixAnalysisContext');

suite('R37 semantic edit live closure', function () {
	this.timeout(180_000);
	test('advances the live generation, recomputes R33/R34 and changes the Helix/HQL context', async () => {
		const hqlRoot = path.resolve(__dirname, '..', '..', 'hexcore-hql');
		const manifest = JSON.parse(fs.readFileSync(path.join(hqlRoot, 'benchmarks', 'corpus', 'build', 'build-manifest.json'), 'utf8').replace(/^\uFEFF/, '')) as { entries: Array<{ id: string; binaryPath: string; exports: Array<{ name: string; rva: string }> }> };
		const entry = manifest.entries.find(item => item.id === 'msvc-x64-O2-stripped')!;
		const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'hexcore-r37-edit-'));
		const target = path.join(directory, 'fixture.dll'); fs.copyFileSync(entry.binaryPath, target);
		const engine = new DisassemblerEngine();
		try {
			assert.strictEqual(await engine.loadFile(target), true);
			await engine.analyzeAll();
			const exportEntry = entry.exports.find(item => item.name === 'bench_plain_add')!;
			const address = engine.getBaseAddress() + Number.parseInt(exportEntry.rva.slice(2), 16);
			const functionIdentity = `function:0x${address.toString(16)}`;
			const before = await createHelixAnalysisContext(engine, address);
			const generationBefore = engine.getAnalysisGeneration();
			const session = engine.getSessionStore()!;
			const service = new SemanticCommandService(session, { callbacks: semanticCommandCallbacks(session, engine) });
			const result = service.applyPrototype({
				functionIdentity, functionAddress: `0x${address.toString(16)}`, returnType: 'int32_t', callingConventionId: 'win64',
				parameters: [{ ordinal: 0, name: 'left', type: 'int32_t' }, { ordinal: 1, name: 'right', type: 'int32_t' }],
			});
			assert.strictEqual(result.propagationComplete, true, JSON.stringify(result.callbackFailures));
			assert.strictEqual(engine.getAnalysisGeneration(), generationBefore + 1);
			const summary = session.getSemanticStore().getWholeProgramPropagationStore().getSummary(functionIdentity);
			assert.ok(summary);
			assert.strictEqual(summary?.generation, engine.getAnalysisGeneration());
			const after = await createHelixAnalysisContext(engine, address);
			assert.notStrictEqual(after.contextSha256, before.contextSha256);
			const envelope = createHelixDebugTypeEnvelope(after);
			assert.strictEqual(envelope.functions[after.function.name].params.length, 2);
			const sqlite = require(path.resolve(__dirname, '..', '..', 'hexcore-better-sqlite3'));
			const { SessionDbReader } = require(path.resolve(hqlRoot, 'dist', 'index.js')) as { SessionDbReader: new (dbPath: string, sqliteModule: unknown) => { getSemanticFacts(address: string): Array<{ kind: string; attributes: Record<string, unknown> }>; dispose(): void } };
			const reader = new SessionDbReader(session.getDbPath(), sqlite);
			try {
				const facts = reader.getSemanticFacts(`0x${address.toString(16)}`);
				assert.ok(facts.some(fact => fact.kind === 'function-prototype' && fact.attributes.callingConventionId === 'win64'));
			} finally { reader.dispose(); }
		} finally { engine.dispose(); fs.rmSync(directory, { recursive: true, force: true }); }
	});
});
