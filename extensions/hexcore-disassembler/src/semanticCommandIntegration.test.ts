/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Akasha Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as assert from 'assert';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import {
	decorateSemanticCommandResult,
	prepareSemanticCommandService,
	readSemanticImportInput,
	resolveSemanticOutputPath,
	semanticCommandCallbacks,
	type SemanticCommandHost,
} from './semanticCommandIntegration';
import { SessionStore } from './sessionStore';

suite('R32 semantic command extension integration', () => {
	test('declares every public semantic command and activation event in the extension manifest', () => {
		const manifest = JSON.parse(fs.readFileSync(path.resolve(__dirname, '..', 'package.json'), 'utf8')) as {
			activationEvents?: string[];
			contributes?: { commands?: Array<{ command?: string }> };
		};
		const commandIds = [
			'hexcore.types.applyPrototype',
			'hexcore.types.setCallingConvention',
			'hexcore.types.setParameter',
			'hexcore.types.clearOverride',
			'hexcore.types.explainPrototype',
			'hexcore.types.export',
			'hexcore.types.import',
		];
		const declared = new Set((manifest.contributes?.commands ?? []).map(command => command.command));
		const activation = new Set(manifest.activationEvents ?? []);
		for (const command of commandIds) {
			assert.ok(declared.has(command), `package.json does not contribute ${command}`);
			assert.ok(activation.has(`onCommand:${command}`), `package.json does not activate for ${command}`);
		}
	});

	test('marks changed prototypes partial until typed caller propagation exists', () => {
		const decorated = decorateSemanticCommandResult({
			ok: true,
			changed: true,
			propagationComplete: false,
			status: 'accepted',
		});
		assert.strictEqual(decorated.status, 'accepted');
		assert.strictEqual(decorated.semanticStatus, 'partial');
		assert.match(decorated.semanticWarning ?? '', /R33 Reference Graph/);

		const unchanged = decorateSemanticCommandResult({
			ok: true,
			changed: false,
			propagationComplete: false,
		});
		assert.strictEqual(unchanged.semanticStatus, 'ok');

		const imported = decorateSemanticCommandResult({
			ok: true,
			changedPrototypeCount: 2,
			propagationComplete: false,
		});
		assert.strictEqual(imported.semanticStatus, 'partial');
	});

	test('requires an explicit or active target and never reuses a different session', async () => {
		let loaded = false;
		let activePath: string | undefined;
		const loadedPaths: string[] = [];
		const host: SemanticCommandHost = {
			isFileLoaded: () => loaded,
			getFilePath: () => activePath,
			loadFile: async filePath => {
				loadedPaths.push(filePath);
				loaded = true;
				activePath = filePath;
			},
			getSessionStore: () => undefined,
		};

		await assert.rejects(() => prepareSemanticCommandService(host, undefined), /Load a binary/);
		await assert.rejects(
			() => prepareSemanticCommandService(host, 'C:\\targets\\first.exe'),
			/HXDB semantic persistence is unavailable/,
		);
		assert.deepStrictEqual(loadedPaths, ['C:\\targets\\first.exe']);

		await assert.rejects(
			() => prepareSemanticCommandService(host, 'C:\\targets\\second.exe'),
			/HXDB semantic persistence is unavailable/,
		);
		assert.deepStrictEqual(loadedPaths, ['C:\\targets\\first.exe', 'C:\\targets\\second.exe']);
	});

	test('persists through HXDB, advances the bound generation and invalidates the edited function', async () => {
		const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'hexcore-semantic-command-e2e-'));
		const binaryPath = path.join(directory, 'target.bin');
		fs.writeFileSync(binaryPath, Buffer.from([0x90, 0xc3]));
		const session = new SessionStore(binaryPath);
		try {
			session.bindAnalysisTarget({
				filePath: binaryPath,
				fileSize: 2,
				format: 'raw',
				architecture: 'x64',
				imageBase: '0x140000000',
			});
			session.cacheFunction('0x140001000', 'fixture', 2, 0x140001002);
			const host: SemanticCommandHost = {
				isFileLoaded: () => true,
				getFilePath: () => binaryPath,
				loadFile: async () => true,
				getSessionStore: () => session,
			};
			const prepared = await prepareSemanticCommandService(host, binaryPath, bound => ({
				callbacks: semanticCommandCallbacks(bound),
			}));
			const mutation = prepared.service.applyPrototype({
				functionIdentity: '0x140001000',
				returnType: 'bool',
				callingConventionId: 'win64',
				parameters: [{ ordinal: 0, name: 'context', type: 'void *' }],
			});
			assert.strictEqual(mutation.changed, true);
			assert.strictEqual(mutation.propagationComplete, false);
			assert.strictEqual(decorateSemanticCommandResult({ ...mutation }).semanticStatus, 'partial');
			assert.strictEqual(session.getAnalysisSession()?.generation, 1);
			assert.strictEqual(session.getCachedFunctions().length, 0);
			assert.strictEqual(
				session.getSemanticStore().getPrototype('0x140001000')?.parameters.length,
				1,
			);
		} finally {
			session.dispose();
			fs.rmSync(directory, { recursive: true, force: true });
		}
	});

	test('keeps inline import JSON distinct from inputPath and normalizes output paths', () => {
		const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'hexcore-semantic-integration-'));
		try {
			const inputPath = path.join(directory, 'semantic.json');
			fs.writeFileSync(inputPath, '{"format":"fixture"}', 'utf8');
			assert.strictEqual(readSemanticImportInput({ inputPath }), '{"format":"fixture"}');
			assert.strictEqual(readSemanticImportInput({ input: '{"inline":true}' }), '{"inline":true}');
			assert.deepStrictEqual(readSemanticImportInput({ input: { inline: true } }), { inline: true });
			assert.throws(() => readSemanticImportInput({}), /requires input or inputPath/);
			assert.strictEqual(resolveSemanticOutputPath(' result.json '), 'result.json');
			assert.strictEqual(resolveSemanticOutputPath({ path: ' export.json ' }), 'export.json');
			assert.strictEqual(resolveSemanticOutputPath({}), undefined);
		} finally {
			fs.rmSync(directory, { recursive: true, force: true });
		}
	});
});
