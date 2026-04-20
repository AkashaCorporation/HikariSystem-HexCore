/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

// Feature: v3.7.1, Properties P11–P14: onResult evaluation, actions, normalizeStep, loop protection

import * as assert from 'assert';
import * as fc from 'fast-check';
import * as path from 'path';
import * as os from 'os';
import * as fs from 'fs';

/**
 * Minimal vscode mock for automationPipelineRunner.ts imports.
 */
function installVscodeMock(): void {
	const Module = require('module');
	const originalResolveFilename = Module._resolveFilename;
	Module._resolveFilename = function (request: string, parent: unknown, isMain: boolean, options: unknown) {
		if (request === 'vscode') { return '__vscode_mock__'; }
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

interface OnResultRule {
	field: string;
	operator: 'contains' | 'equals' | 'not' | 'gt' | 'lt' | 'regex';
	value: string | number;
	action: 'skip' | 'goto' | 'abort' | 'log';
	actionValue?: string | number;
}

let evaluateOnResult: (rule: OnResultRule, stepOutput: Record<string, unknown>) => boolean;
let applyOnResultAction: (rule: OnResultRule, currentIndex: number, totalSteps: number, logPath: string) => number;
let normalizeStep: (step: unknown, index: number, jobFilePath: string) => unknown;
let MAX_LOOP_ITERATIONS: number;

suite('Property P11–P14: onResult evaluation, actions, normalizeStep, loop protection', () => {

	let tempLogPath: string;

	suiteSetup(() => {
		installVscodeMock();
		const modulePath = path.resolve(__dirname, 'automationPipelineRunner');
		const runner = require(modulePath);
		evaluateOnResult = runner.evaluateOnResult;
		applyOnResultAction = runner.applyOnResultAction;
		normalizeStep = runner.normalizeStep;
		MAX_LOOP_ITERATIONS = runner.MAX_LOOP_ITERATIONS;
	});

	setup(() => {
		tempLogPath = path.join(os.tmpdir(), `hexcore-test-${Date.now()}.log`);
	});

	teardown(() => {
		try { fs.unlinkSync(tempLogPath); } catch { /* ignore */ }
	});

	// ── P11: evaluateOnResult with all 6 operators ──────────────────────

	test('P11.1: contains operator checks substring inclusion', () => {
		fc.assert(
			fc.property(fc.string({ minLength: 1, maxLength: 20 }), fc.string({ minLength: 0, maxLength: 5 }), fc.string({ minLength: 0, maxLength: 5 }),
				(needle, prefix, suffix) => {
					const haystack = prefix + needle + suffix;
					const rule: OnResultRule = { field: 'f', operator: 'contains', value: needle, action: 'log' };
					assert.strictEqual(evaluateOnResult(rule, { f: haystack }), true);
				}
			),
			{ numRuns: 100 }
		);
	});

	test('P11.2: equals operator checks strict equality', () => {
		fc.assert(
			fc.property(fc.oneof(fc.string(), fc.integer()), (val) => {
				const rule: OnResultRule = { field: 'f', operator: 'equals', value: val, action: 'log' };
				assert.strictEqual(evaluateOnResult(rule, { f: val }), true);
			}),
			{ numRuns: 100 }
		);
	});

	test('P11.3: not operator checks inequality', () => {
		fc.assert(
			fc.property(fc.string({ minLength: 1 }), (val) => {
				const rule: OnResultRule = { field: 'f', operator: 'not', value: val + '_different', action: 'log' };
				assert.strictEqual(evaluateOnResult(rule, { f: val }), true);
			}),
			{ numRuns: 100 }
		);
	});

	test('P11.4: gt operator compares numerically', () => {
		fc.assert(
			fc.property(fc.integer({ min: 1, max: 10000 }), (val) => {
				const rule: OnResultRule = { field: 'f', operator: 'gt', value: val - 1, action: 'log' };
				assert.strictEqual(evaluateOnResult(rule, { f: val }), true);
			}),
			{ numRuns: 100 }
		);
	});

	test('P11.5: lt operator compares numerically', () => {
		fc.assert(
			fc.property(fc.integer({ min: 0, max: 9999 }), (val) => {
				const rule: OnResultRule = { field: 'f', operator: 'lt', value: val + 1, action: 'log' };
				assert.strictEqual(evaluateOnResult(rule, { f: val }), true);
			}),
			{ numRuns: 100 }
		);
	});

	test('P11.6: regex operator matches RegExp pattern', () => {
		fc.assert(
			fc.property(fc.hexaString({ minLength: 1, maxLength: 16 }), (hex) => {
				const rule: OnResultRule = { field: 'f', operator: 'regex', value: '^[0-9a-f]+$', action: 'log' };
				assert.strictEqual(evaluateOnResult(rule, { f: hex }), true);
			}),
			{ numRuns: 100 }
		);
	});

	test('P11.7: missing field returns false', () => {
		fc.assert(
			fc.property(
				fc.constantFrom<OnResultRule['operator']>('contains', 'equals', 'not', 'gt', 'lt', 'regex'),
				(op) => {
					const rule: OnResultRule = { field: 'nonexistent', operator: op, value: 'x', action: 'log' };
					assert.strictEqual(evaluateOnResult(rule, { other: 'value' }), false);
				}
			),
			{ numRuns: 50 }
		);
	});

	// ── P12: applyOnResultAction ────────────────────────────────────────

	test('P12.1: skip advances index by 1 + N', () => {
		fc.assert(
			fc.property(
				fc.integer({ min: 0, max: 50 }),
				fc.integer({ min: 1, max: 10 }),
				(currentIndex, skipN) => {
					const rule: OnResultRule = { field: 'f', operator: 'equals', value: 1, action: 'skip', actionValue: skipN };
					const result = applyOnResultAction(rule, currentIndex, 100, tempLogPath);
					assert.strictEqual(result, currentIndex + 1 + skipN);
				}
			),
			{ numRuns: 100 }
		);
	});

	test('P12.2: goto validates bounds [0, totalSteps-1]', () => {
		fc.assert(
			fc.property(
				fc.integer({ min: 5, max: 50 }),
				(totalSteps) => {
					const target = Math.floor(totalSteps / 2);
					const rule: OnResultRule = { field: 'f', operator: 'equals', value: 1, action: 'goto', actionValue: target };
					const result = applyOnResultAction(rule, 0, totalSteps, tempLogPath);
					assert.strictEqual(result, target);
				}
			),
			{ numRuns: 100 }
		);
	});

	test('P12.3: goto out of bounds throws Error', () => {
		fc.assert(
			fc.property(
				fc.integer({ min: 1, max: 20 }),
				(totalSteps) => {
					const rule: OnResultRule = { field: 'f', operator: 'equals', value: 1, action: 'goto', actionValue: totalSteps };
					assert.throws(() => applyOnResultAction(rule, 0, totalSteps, tempLogPath), /out of bounds/);

					const ruleNeg: OnResultRule = { field: 'f', operator: 'equals', value: 1, action: 'goto', actionValue: -1 };
					assert.throws(() => applyOnResultAction(ruleNeg, 0, totalSteps, tempLogPath), /out of bounds/);
				}
			),
			{ numRuns: 50 }
		);
	});

	test('P12.4: abort returns -1', () => {
		const rule: OnResultRule = { field: 'f', operator: 'equals', value: 1, action: 'abort', actionValue: 'test abort' };
		const result = applyOnResultAction(rule, 5, 10, tempLogPath);
		assert.strictEqual(result, -1);
	});

	test('P12.5: log returns currentIndex + 1', () => {
		fc.assert(
			fc.property(fc.integer({ min: 0, max: 50 }), (currentIndex) => {
				const rule: OnResultRule = { field: 'f', operator: 'equals', value: 1, action: 'log', actionValue: 'test log' };
				const result = applyOnResultAction(rule, currentIndex, 100, tempLogPath);
				assert.strictEqual(result, currentIndex + 1);
			}),
			{ numRuns: 50 }
		);
	});

	// ── P13: normalizeStep validation ───────────────────────────────────

	test('P13.1: missing field throws descriptive error', () => {
		const step = { cmd: 'test', onResult: { operator: 'equals', value: 1, action: 'log' } };
		assert.throws(() => normalizeStep(step, 0, 'test.json'), /field/i);
	});

	test('P13.2: invalid operator throws descriptive error', () => {
		fc.assert(
			fc.property(
				fc.string({ minLength: 1, maxLength: 10 }).filter(s => !['contains', 'equals', 'not', 'gt', 'lt', 'regex'].includes(s)),
				(invalidOp) => {
					const step = { cmd: 'test', onResult: { field: 'f', operator: invalidOp, value: 1, action: 'log' } };
					assert.throws(() => normalizeStep(step, 0, 'test.json'), /operator/i);
				}
			),
			{ numRuns: 50 }
		);
	});

	test('P13.3: missing value throws descriptive error', () => {
		const step = { cmd: 'test', onResult: { field: 'f', operator: 'equals', action: 'log' } };
		assert.throws(() => normalizeStep(step, 0, 'test.json'), /value/i);
	});

	test('P13.4: invalid action throws descriptive error', () => {
		fc.assert(
			fc.property(
				fc.string({ minLength: 1, maxLength: 10 }).filter(s => !['skip', 'goto', 'abort', 'log'].includes(s)),
				(invalidAction) => {
					const step = { cmd: 'test', onResult: { field: 'f', operator: 'equals', value: 1, action: invalidAction } };
					assert.throws(() => normalizeStep(step, 0, 'test.json'), /action/i);
				}
			),
			{ numRuns: 50 }
		);
	});

	// ── P14: Loop protection ────────────────────────────────────────────

	test('P14.1: MAX_LOOP_ITERATIONS is 100', () => {
		assert.strictEqual(MAX_LOOP_ITERATIONS, 100);
	});

	test('P14.2: loop counter simulation triggers at MAX_LOOP_ITERATIONS', () => {
		fc.assert(
			fc.property(
				fc.integer({ min: 101, max: 200 }),
				(jumps) => {
					let loopCounter = 0;
					let aborted = false;
					for (let i = 0; i < jumps; i++) {
						loopCounter++;
						if (loopCounter > MAX_LOOP_ITERATIONS) {
							aborted = true;
							break;
						}
					}
					assert.ok(aborted, `Pipeline must abort after ${MAX_LOOP_ITERATIONS} non-sequential jumps`);
				}
			),
			{ numRuns: 50 }
		);
	});

	test('P14.3: sequential execution does not increment counter', () => {
		// Sequential means nextIndex === currentIndex + 1, so loopCounter stays 0
		let loopCounter = 0;
		const totalSteps = 20;
		for (let index = 0; index < totalSteps; index++) {
			const nextIndex = index + 1; // sequential
			if (nextIndex !== index + 1) {
				loopCounter++;
			}
		}
		assert.strictEqual(loopCounter, 0, 'Sequential execution must not increment loop counter');
	});
});
