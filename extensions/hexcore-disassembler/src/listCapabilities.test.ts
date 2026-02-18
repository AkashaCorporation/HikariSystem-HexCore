/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as assert from 'assert';
import * as path from 'path';

/**
 * Minimal vscode mock — automationPipelineRunner.ts imports 'vscode' at the
 * top level but listCapabilities() only reads static Maps.
 */
function installVscodeMock(): void {
	const Module = require('module');
	const originalResolveFilename = Module._resolveFilename;
	Module._resolveFilename = function (request: string, parent: unknown, isMain: boolean, options: unknown) {
		if (request === 'vscode') {
			return '__vscode_mock__';
		}
		return originalResolveFilename.call(this, request, parent, isMain, options);
	};

	require.cache['__vscode_mock__'] = {
		id: '__vscode_mock__',
		filename: '__vscode_mock__',
		loaded: true,
		exports: {
			commands: {
				getCommands: async () => [],
				executeCommand: async () => undefined,
				registerCommand: () => ({ dispose() { /* noop */ } })
			},
			workspace: { workspaceFolders: undefined },
			extensions: { getExtension: () => undefined },
			Uri: { file: (f: string) => ({ fsPath: f, scheme: 'file' }) }
		}
	} as unknown as NodeModule;
}

interface PipelineCapabilityEntry {
	command: string;
	aliases: string[];
	headless: boolean;
	defaultTimeoutMs: number;
	validateOutput: boolean;
	reason?: string;
	requiredExtension: string[];
}

suite('Unit tests: listCapabilities', () => {

	let allEntries: PipelineCapabilityEntry[];

	suiteSetup(() => {
		installVscodeMock();
		const modulePath = path.resolve(__dirname, 'automationPipelineRunner');
		const runner = require(modulePath);
		allEntries = runner.listCapabilities();
	});

	// -----------------------------------------------------------------------
	// v3.5.2 headless commands that MUST appear in the capability list
	// -----------------------------------------------------------------------
	const V352_HEADLESS_COMMANDS = [
		'hexcore.debug.snapshotHeadless',
		'hexcore.debug.restoreSnapshotHeadless',
		'hexcore.debug.exportTraceHeadless',
		'hexcore.elfanalyzer.analyze',
		'hexcore.base64.decodeHeadless',
		'hexcore.hexview.dumpHeadless',
		'hexcore.hexview.searchHeadless',
		'hexcore.pipeline.composeReport'
	];

	/**
	 * **Validates: Requirements 8.1**
	 * All v3.5.2 headless commands appear in the capability list.
	 */
	test('all v3.5.2 headless commands are present', () => {
		const commandSet = new Set(allEntries.map(e => e.command));
		for (const cmd of V352_HEADLESS_COMMANDS) {
			assert.ok(commandSet.has(cmd), `missing capability entry for ${cmd}`);
		}
	});

	/**
	 * **Validates: Requirements 8.1**
	 * Each v3.5.2 headless command has headless: true.
	 */
	test('each v3.5.2 headless command has headless: true', () => {
		for (const cmd of V352_HEADLESS_COMMANDS) {
			const entry = allEntries.find(e => e.command === cmd);
			assert.ok(entry, `entry not found for ${cmd}`);
			assert.strictEqual(entry!.headless, true, `${cmd} should be headless`);
		}
	});

	/**
	 * **Validates: Requirements 8.1**
	 * Each v3.5.2 headless command has a non-empty requiredExtension.
	 */
	test('each v3.5.2 headless command has a non-empty requiredExtension', () => {
		for (const cmd of V352_HEADLESS_COMMANDS) {
			const entry = allEntries.find(e => e.command === cmd);
			assert.ok(entry, `entry not found for ${cmd}`);
			assert.ok(
				Array.isArray(entry!.requiredExtension) && entry!.requiredExtension.length > 0,
				`${cmd} must have at least one requiredExtension`
			);
		}
	});

	/**
	 * **Validates: Requirements 8.1**
	 * The interactive command elfanalyzer.analyzeActive is also present
	 * but with headless: false.
	 */
	test('elfanalyzer.analyzeActive is present with headless: false', () => {
		const entry = allEntries.find(e => e.command === 'hexcore.elfanalyzer.analyzeActive');
		assert.ok(entry, 'missing capability entry for hexcore.elfanalyzer.analyzeActive');
		assert.strictEqual(entry!.headless, false, 'analyzeActive should not be headless');
	});

	/**
	 * Total capabilities count is reasonable (> 30 entries).
	 */
	test('total capabilities count exceeds 30', () => {
		assert.ok(
			allEntries.length > 30,
			`expected more than 30 capability entries, got ${allEntries.length}`
		);
	});

	/**
	 * No duplicate commands in the list.
	 */
	test('no duplicate commands in the list', () => {
		const seen = new Set<string>();
		for (const entry of allEntries) {
			assert.ok(
				!seen.has(entry.command),
				`duplicate capability entry for ${entry.command}`
			);
			seen.add(entry.command);
		}
	});
});
