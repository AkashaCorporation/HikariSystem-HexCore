/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Akasha Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as assert from 'assert';
import {
	decorateOkResult,
	decoratePipelineRunStatus,
	decorateValidationReport,
	toAnalysisStatus,
} from './commandResult';
import type { PipelineRunStatus } from './automationPipelineRunner';

function makeRunStatus(overrides: Partial<PipelineRunStatus>): PipelineRunStatus {
	return {
		jobFile: 'job.hexcore_job.json',
		file: 'sample.exe',
		outDir: 'out',
		status: 'ok',
		startedAt: '2026-08-06T00:00:00.000Z',
		steps: [],
		provenance: {
			analysisContractVersion: 1,
			executionId: 'exec-1',
			contextGeneration: 1,
			binaryPath: 'sample.exe',
			binarySha256: 'a'.repeat(64),
			binaryFormat: 'pe',
		},
		...overrides,
	} as PipelineRunStatus;
}

suite('commandResult contract decoration (3.8.4 C4)', () => {
	test('maps the runner status vocabulary to the contract one', () => {
		assert.strictEqual(toAnalysisStatus('ok'), 'ok');
		assert.strictEqual(toAnalysisStatus('partial'), 'partial');
		assert.strictEqual(toAnalysisStatus('error'), 'failed');
		assert.strictEqual(toAnalysisStatus('running'), 'partial');
	});

	test('ok run decorates with empty diagnostics and preserves legacy fields', () => {
		const decorated = decoratePipelineRunStatus(makeRunStatus({ status: 'ok' }));
		assert.strictEqual(decorated.contractVersion, 1);
		assert.strictEqual(decorated.status, 'ok');
		assert.deepStrictEqual(decorated.diagnostics, []);
		assert.strictEqual(decorated.jobFile, 'job.hexcore_job.json');
	});

	test('error steps become failed with typed codes; timeout maps to timeout', () => {
		const decorated = decoratePipelineRunStatus(makeRunStatus({
			status: 'error',
			steps: [
				{
					cmd: 'hexcore.disasm.liftToIR', resolvedCmd: 'hexcore.disasm.liftToIR',
					status: 'error', startedAt: '', finishedAt: '', durationMs: 1, attemptCount: 1,
					error: 'remill exploded',
				},
				{
					cmd: 'hexcore.helix.decompileIR', resolvedCmd: 'hexcore.helix.decompileIR',
					status: 'error', startedAt: '', finishedAt: '', durationMs: 1, attemptCount: 1,
					error: 'Command timed out after 120000ms',
				},
			],
		}));
		assert.strictEqual(decorated.status, 'failed');
		assert.strictEqual(decorated.diagnostics[0].code, 'engine-fault');
		assert.strictEqual(decorated.diagnostics[1].code, 'timeout');
		assert.strictEqual(decorated.diagnostics[1].retryable, true);
	});

	test('partial steps become warning diagnostics and skipped gates are classified', () => {
		const decorated = decoratePipelineRunStatus(makeRunStatus({
			status: 'partial',
			steps: [
				{
					cmd: 'hexcore.helix.decompileIR', resolvedCmd: 'hexcore.helix.decompileIR',
					status: 'partial', startedAt: '', finishedAt: '', durationMs: 1, attemptCount: 1,
					error: 'command reported semantic status partial',
					artifactProvenancePath: 'out/.hexcore-meta/provenance.json',
				},
				{
					cmd: 'hexcore.disasm.peAnalysisHeadless', resolvedCmd: 'x',
					status: 'skipped', startedAt: '', finishedAt: '', durationMs: 0, attemptCount: 0,
					error: 'binary header gate: not a PE file',
				},
			],
		}));
		assert.strictEqual(decorated.status, 'partial');
		assert.strictEqual(decorated.diagnostics[0].severity, 'warning');
		assert.strictEqual(decorated.diagnostics[0].code, 'partial-result');
		assert.strictEqual(decorated.diagnostics[0].details?.artifactProvenancePath, 'out/.hexcore-meta/provenance.json');
		assert.strictEqual(decorated.diagnostics[1].severity, 'info');
		assert.strictEqual(decorated.diagnostics[1].code, 'parse-failed');
	});

	test('validation reports map issues to typed diagnostics and honor registry codes', () => {
		const report = {
			ok: false,
			jobFile: 'job', totalSteps: 2,
			issues: [
				{ level: 'error' as const, code: 'E_OUTDIR', message: 'outDir resolves outside the workspace' },
				{ level: 'warning' as const, code: 'stale-generation', message: 'session is stale' },
				{ level: 'error' as const, code: 'E_STEPS', message: 'job file not found somewhere' },
			],
			steps: [],
		};
		const decorated = decorateValidationReport(report as never);
		assert.strictEqual(decorated.status, 'failed');
		assert.strictEqual(decorated.diagnostics[0].code, 'output-unsafe');
		assert.strictEqual(decorated.diagnostics[1].code, 'stale-generation');
		assert.strictEqual(decorated.diagnostics[1].severity, 'warning');
		assert.strictEqual(decorated.diagnostics[2].code, 'not-found');
		assert.strictEqual(decorated.diagnostics[0].details?.issueCode, 'E_OUTDIR');

		const okReport = decorateValidationReport({ ok: true, issues: [], totalSteps: 1, steps: [], jobFile: 'j' } as never);
		assert.strictEqual(okReport.status, 'ok');
		assert.deepStrictEqual(okReport.diagnostics, []);
	});

	test('decorateOkResult preserves payload and adds ok status', () => {
		const decorated = decorateOkResult({ jobId: 'abc', priority: 'normal' });
		assert.strictEqual(decorated.status, 'ok');
		assert.strictEqual(decorated.jobId, 'abc');
		assert.strictEqual(decorated.contractVersion, 1);
	});
});
