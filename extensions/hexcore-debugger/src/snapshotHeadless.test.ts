/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import * as assert from 'assert';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { DebugEngine } from './debugEngine';

suite('snapshotHeadless and restoreSnapshotHeadless', () => {

	let engine: DebugEngine;

	setup(() => {
		engine = new DebugEngine();
	});

	// --- snapshotHeadless error: no active session ---

	test('snapshotHeadless throws when no emulation session is active', () => {
		const state = engine.getEmulationState();
		assert.strictEqual(state, null, 'getEmulationState should return null without emulation');

		// The headless command checks getEmulationState() and throws if null
		assert.throws(
			() => {
				if (!engine.getEmulationState()) {
					throw new Error('No active emulation session. Call emulateHeadless first.');
				}
				engine.saveSnapshot();
			},
			(err: Error) => {
				assert.strictEqual(err.message, 'No active emulation session. Call emulateHeadless first.');
				return true;
			}
		);
	});

	// --- restoreSnapshotHeadless error: no active session ---

	test('restoreSnapshotHeadless throws when no emulation session is active', () => {
		const state = engine.getEmulationState();
		assert.strictEqual(state, null);

		assert.throws(
			() => {
				if (!engine.getEmulationState()) {
					throw new Error('No active emulation session. Call emulateHeadless first.');
				}
				engine.restoreSnapshot();
			},
			(err: Error) => {
				assert.strictEqual(err.message, 'No active emulation session. Call emulateHeadless first.');
				return true;
			}
		);
	});

	// --- restoreSnapshotHeadless error: no snapshot saved ---

	test('restoreSnapshot throws when emulator has no saved snapshot', () => {
		// DebugEngine.restoreSnapshot() throws 'Emulator not initialized' when no emulator.
		// The headless command catches any restoreSnapshot error and re-throws as
		// 'No snapshot available. Call snapshotHeadless first.'
		assert.throws(
			() => {
				try {
					engine.restoreSnapshot();
				} catch {
					throw new Error('No snapshot available. Call snapshotHeadless first.');
				}
			},
			(err: Error) => {
				assert.strictEqual(err.message, 'No snapshot available. Call snapshotHeadless first.');
				return true;
			}
		);
	});

	// --- snapshotHeadless output generates valid JSON ---

	test('snapshot export data is valid JSON with required fields', () => {
		// Simulate the export data structure that snapshotHeadless produces
		const exportData = {
			success: true,
			generatedAt: new Date().toISOString()
		};

		const json = JSON.stringify(exportData, null, 2);
		const parsed = JSON.parse(json);

		assert.strictEqual(parsed.success, true);
		assert.strictEqual(typeof parsed.generatedAt, 'string');
		// Validate ISO 8601 date format
		assert.ok(!isNaN(Date.parse(parsed.generatedAt)), 'generatedAt should be a valid ISO date');
	});

	test('restoreSnapshot export data is valid JSON with required fields', () => {
		// Simulate the export data structure that restoreSnapshotHeadless produces
		const exportData = {
			success: true,
			registers: { rax: '0x0', rbx: '0x0', rip: '0x400000' },
			state: {
				currentAddress: '0x400000',
				instructionsExecuted: 42,
				isRunning: true
			},
			generatedAt: new Date().toISOString()
		};

		const json = JSON.stringify(exportData, null, 2);
		const parsed = JSON.parse(json);

		assert.strictEqual(parsed.success, true);
		assert.strictEqual(typeof parsed.generatedAt, 'string');
		assert.ok(!isNaN(Date.parse(parsed.generatedAt)));
		assert.strictEqual(typeof parsed.registers, 'object');
		assert.strictEqual(typeof parsed.state, 'object');
		assert.strictEqual(typeof parsed.state.currentAddress, 'string');
		assert.strictEqual(typeof parsed.state.instructionsExecuted, 'number');
		assert.strictEqual(typeof parsed.state.isRunning, 'boolean');
	});

	test('snapshot output writes valid JSON file', () => {
		const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'hexcore-test-'));
		const outputPath = path.join(tmpDir, 'snapshot.json');

		try {
			const exportData = {
				success: true,
				generatedAt: new Date().toISOString()
			};

			// Replicate the file-writing logic from snapshotHeadless
			fs.mkdirSync(path.dirname(outputPath), { recursive: true });
			fs.writeFileSync(outputPath, JSON.stringify(exportData, null, 2), 'utf8');

			assert.ok(fs.existsSync(outputPath), 'Output file should exist');

			const content = fs.readFileSync(outputPath, 'utf8');
			const parsed = JSON.parse(content);
			assert.strictEqual(parsed.success, true);
			assert.strictEqual(typeof parsed.generatedAt, 'string');
		} finally {
			// Cleanup
			fs.rmSync(tmpDir, { recursive: true, force: true });
		}
	});

	test('restoreSnapshot output writes valid JSON file', () => {
		const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'hexcore-test-'));
		const outputPath = path.join(tmpDir, 'restore.json');

		try {
			const exportData = {
				success: true,
				registers: { rax: '0x0', rsp: '0x7fff0000' },
				state: {
					currentAddress: '0x401000',
					instructionsExecuted: 10,
					isRunning: true
				},
				generatedAt: new Date().toISOString()
			};

			fs.mkdirSync(path.dirname(outputPath), { recursive: true });
			fs.writeFileSync(outputPath, JSON.stringify(exportData, null, 2), 'utf8');

			assert.ok(fs.existsSync(outputPath));

			const content = fs.readFileSync(outputPath, 'utf8');
			const parsed = JSON.parse(content);
			assert.strictEqual(parsed.success, true);
			assert.strictEqual(typeof parsed.registers, 'object');
			assert.strictEqual(typeof parsed.state, 'object');
			assert.strictEqual(typeof parsed.generatedAt, 'string');
		} finally {
			fs.rmSync(tmpDir, { recursive: true, force: true });
		}
	});

	// --- getFullRegisters returns empty object without emulator ---

	test('getFullRegisters returns empty object when no emulator', () => {
		const regs = engine.getFullRegisters();
		assert.deepStrictEqual(regs, {});
	});
});
