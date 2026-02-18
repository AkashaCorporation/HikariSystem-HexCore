/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

// Feature: v3.5.2-pipeline-maturity, Property 19: Capability entry completeness

import * as assert from 'assert';
import * as fc from 'fast-check';
import * as path from 'path';

/**
 * We need a minimal vscode mock because automationPipelineRunner.ts imports
 * 'vscode' at the top level. The listCapabilities() function itself only
 * reads static Maps and does not call any vscode API.
 */
function installVscodeMock(): void {
	const Module = require('module');
	const originalResolveFilename = Module._resolveFilename;
	Module._resolveFilename = function (request: string, parent: unknown, isMain: boolean, options: unknown) {
		if (request === 'vscode') {
			// Return a path that will resolve to our inline mock below.
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

suite('Property 19: Capability entry completeness', () => {

	let headlessEntries: PipelineCapabilityEntry[];

	suiteSetup(() => {
		installVscodeMock();
		// Dynamic require after mock is installed
		const modulePath = path.resolve(__dirname, 'automationPipelineRunner');
		const runner = require(modulePath);
		const allEntries: PipelineCapabilityEntry[] = runner.listCapabilities();
		headlessEntries = allEntries.filter((e: PipelineCapabilityEntry) => e.headless === true);
	});

	/**
	 * **Validates: Requirements 8.2**
	 *
	 * For any entry returned by listCapabilities with headless: true,
	 * the entry MUST contain non-empty command, headless === true,
	 * defaultTimeoutMs > 0, requiredExtension with at least one entry,
	 * aliases as an array, and validateOutput as a boolean.
	 */
	test('every headless capability entry contains all required fields', () => {
		assert.ok(headlessEntries.length > 0, 'there must be at least one headless entry');

		fc.assert(
			fc.property(
				fc.integer({ min: 0, max: headlessEntries.length - 1 }),
				(index: number) => {
					const entry = headlessEntries[index];

					// command is a non-empty string
					assert.strictEqual(typeof entry.command, 'string',
						`command must be a string, got ${typeof entry.command}`);
					assert.ok(entry.command.length > 0,
						`command must be non-empty for entry at index ${index}`);

					// headless is true
					assert.strictEqual(entry.headless, true,
						`headless must be true for ${entry.command}`);

					// defaultTimeoutMs is a positive number
					assert.strictEqual(typeof entry.defaultTimeoutMs, 'number',
						`defaultTimeoutMs must be a number for ${entry.command}`);
					assert.ok(entry.defaultTimeoutMs > 0,
						`defaultTimeoutMs must be positive for ${entry.command}, got ${entry.defaultTimeoutMs}`);

					// requiredExtension is a non-empty array
					assert.ok(Array.isArray(entry.requiredExtension),
						`requiredExtension must be an array for ${entry.command}`);
					assert.ok(entry.requiredExtension.length > 0,
						`requiredExtension must have at least one entry for ${entry.command}`);

					// aliases is an array (can be empty)
					assert.ok(Array.isArray(entry.aliases),
						`aliases must be an array for ${entry.command}`);

					// validateOutput is a boolean
					assert.strictEqual(typeof entry.validateOutput, 'boolean',
						`validateOutput must be a boolean for ${entry.command}`);
				}
			),
			{ numRuns: 100 }
		);
	});
});
