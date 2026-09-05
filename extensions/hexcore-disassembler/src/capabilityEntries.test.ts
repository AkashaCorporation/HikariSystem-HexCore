/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

// Feature: v3.5.2-pipeline-maturity, Property 19: Capability entry completeness

import * as assert from 'assert';
import * as fc from 'fast-check';
import * as path from 'path';
import * as fs from 'fs';
import * as os from 'os';

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
	cancelCommand?: string;
	reason?: string;
	requiredExtension: string[];
	supportedTargets?: string[];
}

suite('Property 19: Capability entry completeness', () => {

	let headlessEntries: PipelineCapabilityEntry[];
	let checkBinaryArchGate: (command: string, targetPath: string) => { skip: boolean; reason?: string };

	suiteSetup(() => {
		installVscodeMock();
		// Dynamic require after mock is installed
		const modulePath = path.resolve(__dirname, 'automationPipelineRunner');
		const runner = require(modulePath);
		const allEntries: PipelineCapabilityEntry[] = runner.listCapabilities();
		headlessEntries = allEntries.filter((e: PipelineCapabilityEntry) => e.headless === true);
		checkBinaryArchGate = runner.checkBinaryArchGate;
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

	test('Elixir capabilities and ELF gate expose the PE32+ boundary', () => {
		const elixir = headlessEntries.find(entry => entry.command === 'hexcore.elixir.emulateHeadless');
		assert.deepStrictEqual(elixir?.supportedTargets, ['PE32+ x86_64']);

		const fixture = path.join(os.tmpdir(), `hexcore-elixir-gate-${process.pid}.elf`);
		try {
			const header = Buffer.alloc(0x80);
			header.set([0x7f, 0x45, 0x4c, 0x46]);
			fs.writeFileSync(fixture, header);
			const gate = checkBinaryArchGate('hexcore.elixir.emulateHeadless', fixture);
			assert.strictEqual(gate.skip, true);
			assert.match(gate.reason ?? '', /PE32\+ x86_64 only/);
		} finally {
			fs.rmSync(fixture, { force: true });
		}
	});

	test('live-memory commands declare the cross-extension ownership boundary', () => {
		const disassemble = headlessEntries.find(entry => entry.command === 'hexcore.debug.disassembleMemoryHeadless');
		const decompile = headlessEntries.find(entry => entry.command === 'hexcore.debug.decompileMemoryHeadless');
		const lift = headlessEntries.find(entry => entry.command === 'hexcore.disasm.liftMemoryHeadless');
		const bufferDisasm = headlessEntries.find(entry => entry.command === 'hexcore.disasm.disassembleBufferHeadless');
		assert.deepStrictEqual(disassemble?.requiredExtension, [
			'hikarisystem.hexcore-debugger',
			'hikarisystem.hexcore-disassembler',
		]);
		assert.deepStrictEqual(decompile?.requiredExtension, [
			'hikarisystem.hexcore-debugger',
			'hikarisystem.hexcore-disassembler',
		]);
		assert.deepStrictEqual(lift?.requiredExtension, ['hikarisystem.hexcore-disassembler']);
		assert.deepStrictEqual(bufferDisasm?.requiredExtension, ['hikarisystem.hexcore-disassembler']);
		assert.strictEqual(decompile?.validateOutput, true);
		assert.strictEqual(decompile?.cancelCommand, 'hexcore.helix.cancelActiveLiveDecompile');
	});
});
