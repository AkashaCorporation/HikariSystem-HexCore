/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import * as assert from 'assert';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import type { PipelineRunStatus } from './automationPipelineRunner';
import { buildAgentResultRecord, persistAgentResultRecord, verifyAgentResultRecord } from './agentBridgeResult';

suite('Agent Bridge result records', () => {
	let root: string;

	setup(() => {
		root = fs.mkdtempSync(path.join(os.tmpdir(), 'hexcore-agent-result-'));
	});

	teardown(() => {
		fs.rmSync(root, { recursive: true, force: true });
	});

	test('persists bounded hash-bound step evidence without leaking secrets', () => {
		const outputPath = path.join(root, 'step.json');
		const output = { proofStatus: 'UNKNOWN', status: 'partial', token: 'must-not-leak', nested: { value: 7 } };
		fs.writeFileSync(outputPath, JSON.stringify(output));
		const outputSha256 = crypto.createHash('sha256').update(fs.readFileSync(outputPath)).digest('hex');
		const artifactProvenancePath = path.join(root, 'step.provenance.json');
		fs.writeFileSync(artifactProvenancePath, JSON.stringify({
			artifacts: [{ artifact: { path: outputPath, sha256: outputSha256 } }],
		}));
		const run = sampleRun(root, outputPath, artifactProvenancePath);
		const record = buildAgentResultRecord({ jobId: 'job-1', queueStatus: 'done', revision: run.jobFileSha256, run });

		assert.strictEqual(record.pipeline.status, 'partial');
		assert.strictEqual(record.pipeline.target.sha256, 'b'.repeat(64));
		assert.strictEqual(record.steps[0].output?.sha256, outputSha256);
		assert.strictEqual(record.steps[0].output?.hashAuthority, 'artifact-provenance');
		assert.strictEqual((record.steps[0].resultPreview as any).proofStatus, 'UNKNOWN');
		assert.strictEqual((record.steps[0].resultPreview as any).token, '[REDACTED]');
		assert.strictEqual(record.steps[0].resultPreviewStatus, 'redacted-or-truncated');
		assert.strictEqual(verifyAgentResultRecord(record), true);

		const pointer = persistAgentResultRecord({ jobId: 'job-1', queueStatus: 'done', revision: run.jobFileSha256, run });
		assert.strictEqual(pointer.sha256, JSON.parse(fs.readFileSync(pointer.path, 'utf8')).recordSha256);
		assert.ok(pointer.path.includes(path.join('.hexcore-meta', 'agent-results')));
	});

	test('keeps an adversarial multi-step record below the hard byte limit', () => {
		const outputPath = path.join(root, 'step.json');
		const artifactProvenancePath = path.join(root, 'step.provenance.json');
		fs.writeFileSync(outputPath, JSON.stringify({ status: 'UNKNOWN' }));
		fs.writeFileSync(artifactProvenancePath, JSON.stringify({ artifact: { path: outputPath, sha256: 'c'.repeat(64) } }));
		const run = sampleRun(root, outputPath, artifactProvenancePath);
		const template = run.steps[0];
		run.steps = Array.from({ length: 3000 }, (_, stepIndex) => ({
			...template,
			stepIndex,
			stepId: `step-${stepIndex}`,
			error: 'x'.repeat(4096),
		}));
		const record = buildAgentResultRecord({ jobId: 'job-large', queueStatus: 'done', run });
		assert.ok(Buffer.byteLength(JSON.stringify(record), 'utf8') <= 2 * 1024 * 1024);
		assert.ok(record.truncation.omittedSteps > 0);
		assert.strictEqual(verifyAgentResultRecord(record), true);
	});
});

function sampleRun(root: string, outputPath: string, artifactProvenancePath: string): PipelineRunStatus {
	const jobFile = path.join(root, 'test.hexcore_job.json');
	return {
		jobFile,
		jobFileSha256: 'a'.repeat(64),
		file: path.join(root, 'target.bin'),
		outDir: root,
		status: 'partial',
		startedAt: '2026-10-28T00:00:00.000Z',
		finishedAt: '2026-10-28T00:00:01.000Z',
		steps: [{
			stepId: 'inspect',
			stepIndex: 0,
			cmd: 'hexcore.test.inspect',
			resolvedCmd: 'hexcore.test.inspect',
			status: 'partial',
			startedAt: '2026-10-28T00:00:00.000Z',
			finishedAt: '2026-10-28T00:00:01.000Z',
			durationMs: 1000,
			attemptCount: 1,
			outputPath,
			outputBytes: fs.statSync(outputPath).size,
			artifactProvenancePath,
		}],
		provenance: {
			analysisContractVersion: 1,
			executionId: 'execution-1',
			jobFileSha256: 'a'.repeat(64),
			jobId: 'job-1',
			contextGeneration: 1,
			binaryPath: path.join(root, 'target.bin'),
			binarySha256: 'b'.repeat(64),
			binaryFormat: 'raw',
		},
		summary: {
			totalSteps: 1,
			okCount: 0,
			partialCount: 1,
			errorCount: 0,
			skippedCount: 0,
			totalDurationMs: 1000,
		},
	};
}
