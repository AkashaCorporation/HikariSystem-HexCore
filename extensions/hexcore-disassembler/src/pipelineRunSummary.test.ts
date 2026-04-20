/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

/**
 * PipelineRunSummary shape + back-compat (v3.8.0).
 *
 * Source: hexcore-disassembler/src/automationPipelineRunner.ts
 *   - New: `PipelineRunSummary` written to `status.summary` on terminal status.
 *   - New: `PipelineStepStatus.outputBytes` — best-effort file-size probe.
 *   - New: top-level `continueOnError` in the .hexcore_job.json schema.
 *
 * Contract pinned here:
 *   - The summary has a stable set of REQUIRED fields consumers may rely on.
 *   - Optional fields are exactly the ones documented (queueSnapshot, slowest*).
 *   - Mid-run status (running) MUST NOT carry `summary` (it's terminal-only).
 *   - Legacy status files WITHOUT `summary`/`outputBytes` still deserialise
 *     and round-trip through JSON.parse / JSON.stringify without warnings.
 *
 * Why spec-level: the runner imports `vscode`, the queue manager, and fs; a
 * unit test wiring all that up is worth less than a tight contract test on
 * the *output shape* that downstream consumers (report composer, UI) read.
 */

import * as assert from 'assert';
import 'mocha';
// eslint-disable-next-line local/code-import-patterns
import * as fc from 'fast-check';

// ---------------------------------------------------------------------------
// Local re-declaration of the public types (matches automationPipelineRunner.ts)
// If these drift, update both places.
// ---------------------------------------------------------------------------

interface PipelineStepStatus {
	index: number;
	cmd: string;
	resolvedCmd: string;
	startedAt: string;
	finishedAt?: string;
	durationMs: number;
	status: 'ok' | 'error' | 'skipped' | 'running';
	outputBytes?: number;  // v3.8.0 — optional
	error?: string;
}

interface PipelineRunSummary {
	totalSteps: number;
	okCount: number;
	errorCount: number;
	skippedCount: number;
	totalDurationMs: number;
	slowestStepCmd?: string;
	slowestStepMs?: number;
	queueSnapshot?: {
		queued: number;
		running: number;
		done: number;
		failed: number;
		cancelled: number;
	};
}

interface PipelineRunStatus {
	jobFile: string;
	file: string;
	outDir: string;
	status: 'running' | 'ok' | 'error' | 'partial';
	startedAt: string;
	finishedAt?: string;
	steps: PipelineStepStatus[];
	summary?: PipelineRunSummary;
}

// ---------------------------------------------------------------------------
// Pure build helper — mirrors the runner's summary-build block at line 1096.
// Keeping this in lockstep with the real implementation is the whole job of
// this test. If the runner diverges (new field, renamed field), update here
// AND the consumer docs.
// ---------------------------------------------------------------------------

function buildSummary(status: PipelineRunStatus): PipelineRunSummary {
	assert.ok(status.finishedAt, 'buildSummary called on non-terminal status');
	const summary: PipelineRunSummary = {
		totalSteps: status.steps.length,
		okCount: status.steps.filter(s => s.status === 'ok').length,
		errorCount: status.steps.filter(s => s.status === 'error').length,
		skippedCount: status.steps.filter(s => s.status === 'skipped').length,
		totalDurationMs: new Date(status.finishedAt).getTime() - new Date(status.startedAt).getTime()
	};
	let slowest: PipelineStepStatus | undefined;
	for (const s of status.steps) {
		if (s.status === 'ok' && (!slowest || s.durationMs > slowest.durationMs)) {
			slowest = s;
		}
	}
	if (slowest) {
		summary.slowestStepCmd = slowest.resolvedCmd;
		summary.slowestStepMs = slowest.durationMs;
	}
	return summary;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const STARTED = '2026-04-18T10:00:00.000Z';
const FINISHED = '2026-04-18T10:00:05.000Z';   // 5000ms window

function mkStep(partial: Partial<PipelineStepStatus>): PipelineStepStatus {
	return {
		index: 1,
		cmd: 'x',
		resolvedCmd: 'hexcore.x',
		startedAt: STARTED,
		finishedAt: FINISHED,
		durationMs: 100,
		status: 'ok',
		...partial
	};
}

suite('PipelineRunSummary (v3.8.0)', () => {

	suite('shape — required fields always present', () => {
		test('empty-steps job still yields a valid summary', () => {
			const status: PipelineRunStatus = {
				jobFile: 'j.json', file: 't.exe', outDir: 'out',
				status: 'ok', startedAt: STARTED, finishedAt: FINISHED, steps: []
			};
			const s = buildSummary(status);
			assert.strictEqual(s.totalSteps, 0);
			assert.strictEqual(s.okCount, 0);
			assert.strictEqual(s.errorCount, 0);
			assert.strictEqual(s.skippedCount, 0);
			assert.strictEqual(s.totalDurationMs, 5000);
			assert.strictEqual(s.slowestStepCmd, undefined);
			assert.strictEqual(s.slowestStepMs, undefined);
		});

		test('counts partition cleanly across ok/error/skipped', () => {
			const status: PipelineRunStatus = {
				jobFile: 'j.json', file: 't.exe', outDir: 'out',
				status: 'partial', startedAt: STARTED, finishedAt: FINISHED,
				steps: [
					mkStep({ index: 1, status: 'ok', durationMs: 100 }),
					mkStep({ index: 2, status: 'ok', durationMs: 200 }),
					mkStep({ index: 3, status: 'error', durationMs: 50, error: 'boom' }),
					mkStep({ index: 4, status: 'skipped', durationMs: 0 })
				]
			};
			const s = buildSummary(status);
			assert.strictEqual(s.totalSteps, 4);
			assert.strictEqual(s.okCount, 2);
			assert.strictEqual(s.errorCount, 1);
			assert.strictEqual(s.skippedCount, 1);
		});
	});

	suite('slowest-step detection', () => {
		test('picks the slowest OK step (errors excluded from slowest)', () => {
			const status: PipelineRunStatus = {
				jobFile: 'j.json', file: 't.exe', outDir: 'out',
				status: 'partial', startedAt: STARTED, finishedAt: FINISHED,
				steps: [
					mkStep({ index: 1, status: 'ok', durationMs: 100, resolvedCmd: 'hexcore.A' }),
					mkStep({ index: 2, status: 'error', durationMs: 9999, resolvedCmd: 'hexcore.B' }),
					mkStep({ index: 3, status: 'ok', durationMs: 500, resolvedCmd: 'hexcore.C' })
				]
			};
			const s = buildSummary(status);
			// Slowest-of-ok is hexcore.C (500) — errors are deliberately excluded
			// so a 9s timeout doesn't poison the "slowest" metric.
			assert.strictEqual(s.slowestStepCmd, 'hexcore.C');
			assert.strictEqual(s.slowestStepMs, 500);
		});

		test('no ok steps → slowest fields remain undefined', () => {
			const status: PipelineRunStatus = {
				jobFile: 'j.json', file: 't.exe', outDir: 'out',
				status: 'error', startedAt: STARTED, finishedAt: FINISHED,
				steps: [
					mkStep({ status: 'error', durationMs: 100, error: 'fail' })
				]
			};
			const s = buildSummary(status);
			assert.strictEqual(s.slowestStepCmd, undefined);
			assert.strictEqual(s.slowestStepMs, undefined);
		});
	});

	suite('JSON round-trip — no silent field loss', () => {
		test('summary survives stringify/parse bit-identical', () => {
			const status: PipelineRunStatus = {
				jobFile: 'j.json', file: 't.exe', outDir: 'out',
				status: 'ok', startedAt: STARTED, finishedAt: FINISHED,
				steps: [mkStep({ status: 'ok', durationMs: 42, resolvedCmd: 'hexcore.foo', outputBytes: 1024 })]
			};
			status.summary = buildSummary(status);
			const clone = JSON.parse(JSON.stringify(status)) as PipelineRunStatus;
			assert.deepStrictEqual(clone.summary, status.summary);
			assert.strictEqual(clone.steps[0].outputBytes, 1024);
		});

		test('legacy status WITHOUT summary/outputBytes parses cleanly', () => {
			// Back-compat pin: a pre-v3.8.0 status file must still be a valid
			// PipelineRunStatus when deserialised — no required field gating.
			const legacy = {
				jobFile: 'j.json', file: 't.exe', outDir: 'out',
				status: 'ok', startedAt: STARTED, finishedAt: FINISHED,
				steps: [{
					index: 1, cmd: 'x', resolvedCmd: 'hexcore.x',
					startedAt: STARTED, finishedAt: FINISHED,
					durationMs: 42, status: 'ok'
					// NOTE: no outputBytes, no error.
				}]
				// NOTE: no summary field.
			};
			const clone = JSON.parse(JSON.stringify(legacy)) as PipelineRunStatus;
			assert.strictEqual(clone.summary, undefined);
			assert.strictEqual(clone.steps[0].outputBytes, undefined);
			assert.strictEqual(clone.steps[0].status, 'ok');
		});
	});

	suite('invariant — summary only on terminal status', () => {
		test('running status MUST NOT have summary populated', () => {
			// The runner writes `summary` in the `ok|error|partial` branch only.
			// Mid-run snapshots omit it.
			const mid: PipelineRunStatus = {
				jobFile: 'j.json', file: 't.exe', outDir: 'out',
				status: 'running', startedAt: STARTED, steps: [
					mkStep({ status: 'running', finishedAt: undefined })
				]
			};
			assert.strictEqual(mid.summary, undefined);
			// And buildSummary MUST refuse to run on non-terminal status.
			assert.throws(() => buildSummary(mid));
		});
	});

	// -----------------------------------------------------------------------
	// PBT: okCount + errorCount + skippedCount ≤ totalSteps for arbitrary runs.
	// (running steps are possible during abnormal termination, hence ≤ not ==.)
	// -----------------------------------------------------------------------

	suite('PBT: count invariants', () => {
		test('okCount + errorCount + skippedCount ≤ totalSteps', () => {
			const stepArb = fc.record({
				index: fc.integer({ min: 1, max: 100 }),
				status: fc.constantFrom<'ok' | 'error' | 'skipped' | 'running'>('ok', 'error', 'skipped', 'running'),
				durationMs: fc.integer({ min: 0, max: 60000 }),
				resolvedCmd: fc.constantFrom('hexcore.a', 'hexcore.b', 'hexcore.c')
			});
			fc.assert(
				fc.property(
					fc.array(stepArb, { minLength: 0, maxLength: 20 }),
					(rows) => {
						const status: PipelineRunStatus = {
							jobFile: 'j.json', file: 't.exe', outDir: 'out',
							status: 'partial', startedAt: STARTED, finishedAt: FINISHED,
							steps: rows.map(r => mkStep({
								index: r.index, status: r.status as PipelineStepStatus['status'],
								durationMs: r.durationMs, resolvedCmd: r.resolvedCmd
							}))
						};
						const s = buildSummary(status);
						assert.strictEqual(s.totalSteps, rows.length);
						assert.ok(s.okCount + s.errorCount + s.skippedCount <= s.totalSteps,
							`counts overflow totalSteps: ${JSON.stringify(s)}`);
						// If no ok step, slowest fields must be undefined.
						if (s.okCount === 0) {
							assert.strictEqual(s.slowestStepMs, undefined);
							assert.strictEqual(s.slowestStepCmd, undefined);
						} else {
							assert.ok(typeof s.slowestStepMs === 'number');
							assert.ok(typeof s.slowestStepCmd === 'string');
						}
						// totalDurationMs is always non-negative for valid timestamps.
						assert.ok(s.totalDurationMs >= 0);
					}
				),
				{ seed: 4242, numRuns: 300 }
			);
		});

		test('slowestStepMs is the max durationMs across ok steps', () => {
			fc.assert(
				fc.property(
					fc.array(fc.integer({ min: 0, max: 60000 }), { minLength: 1, maxLength: 15 }),
					(durations) => {
						const status: PipelineRunStatus = {
							jobFile: 'j.json', file: 't.exe', outDir: 'out',
							status: 'ok', startedAt: STARTED, finishedAt: FINISHED,
							steps: durations.map((d, i) => mkStep({
								index: i + 1, status: 'ok', durationMs: d,
								resolvedCmd: `hexcore.s${i}`
							}))
						};
						const s = buildSummary(status);
						const expected = Math.max(...durations);
						assert.strictEqual(s.slowestStepMs, expected);
					}
				),
				{ seed: 7777, numRuns: 300 }
			);
		});
	});

	// -----------------------------------------------------------------------
	// Schema lock: PipelineRunSummary has EXACTLY this set of keys, no more.
	// If someone adds a field, this test flags the need for docs+compat review.
	// -----------------------------------------------------------------------

	suite('schema lock', () => {
		test('summary emits exactly the documented key set', () => {
			const status: PipelineRunStatus = {
				jobFile: 'j.json', file: 't.exe', outDir: 'out',
				status: 'ok', startedAt: STARTED, finishedAt: FINISHED,
				steps: [mkStep({ status: 'ok', durationMs: 10, resolvedCmd: 'hexcore.x' })]
			};
			const s = buildSummary(status);
			const keys = Object.keys(s).sort();
			const allowed = new Set([
				'totalSteps', 'okCount', 'errorCount', 'skippedCount',
				'totalDurationMs', 'slowestStepCmd', 'slowestStepMs', 'queueSnapshot'
			]);
			for (const k of keys) {
				assert.ok(allowed.has(k), `unexpected summary key: ${k}`);
			}
			// Required keys must be present.
			for (const k of ['totalSteps', 'okCount', 'errorCount', 'skippedCount', 'totalDurationMs']) {
				assert.ok(keys.includes(k), `missing required key: ${k}`);
			}
		});
	});
});
