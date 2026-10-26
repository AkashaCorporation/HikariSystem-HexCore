/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import * as assert from 'assert';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

suite('named steps through the pipeline runner', () => {
	let root: string;
	let Runner: any;
	let handler: (options: any) => any;
	let calls: string[];
	suiteSetup(() => {
		const Module = require('module'); const resolve = Module._resolveFilename;
		Module._resolveFilename = function (request: string, ...args: unknown[]) { return request === 'vscode' ? '__named_steps__' : resolve.call(this, request, ...args); };
		require.cache.__named_steps__ = { id: '__named_steps__', filename: '__named_steps__', loaded: true, exports: {
			workspace: { get workspaceFolders() { return [{ uri: { fsPath: root } }]; }, getConfiguration: () => ({ get: (_key: string, fallback: unknown) => fallback }) },
			extensions: { getExtension: (id: string) => ({ id, isActive: true, packageJSON: { version: 'test' }, activate: async () => undefined }) },
			commands: { getCommands: async () => ['hexcore.hashcalc.calculate'], executeCommand: async (_command: string, options: any) => {
				calls.push(options.pipelineStepIdentity?.stepId ?? 'legacy');
				const result = await handler(options);
				if (options.output) { fs.writeFileSync(options.output.path, JSON.stringify(result)); }
				return result;
			} }, Uri: { file: (file: string) => ({ fsPath: file, scheme: 'file' }) },
		} } as NodeModule;
		Runner = require('./automationPipelineRunner').AutomationPipelineRunner;
	});
	setup(() => {
		root = fs.mkdtempSync(path.join(os.tmpdir(), 'hexcore-named-steps-'));
		fs.writeFileSync(path.join(root, 'target.bin'), Buffer.from([0xc3]));
		calls = []; handler = () => ({ success: true });
	});
	teardown(() => { fs.rmSync(root, { recursive: true, force: true }); });
	const step = (id?: string, extra: Record<string, unknown> = {}) => ({ ...(id ? { id } : {}), cmd: 'hexcore.hashcalc.calculate', ...extra });
	function job(steps: unknown[], extra: Record<string, unknown> = {}): string {
		const file = path.join(root, 'case.draft.json');
		fs.writeFileSync(file, JSON.stringify({ file: 'target.bin', outDir: 'out', quiet: true, steps, ...extra }));
		return file;
	}
	function manifest(): any { return JSON.parse(fs.readFileSync(path.join(root, 'out/.hexcore-meta/provenance.json'), 'utf8')); }

	test('inserting an earlier step does not change named references', async () => {
		for (const inserted of [false, true]) {
			const steps = [step('produce', { output: { path: 'produce.json' } }), step('consume', { args: { value: '$step[produce].result.value', input: '$step[produce].output' } })];
			if (inserted) { steps.unshift(step('setup')); }
			handler = options => {
				if (options.pipelineStepIdentity.stepId === 'consume') {
					assert.strictEqual(options.value, 42);
					assert.strictEqual(JSON.parse(fs.readFileSync(options.input, 'utf8')).value, 42);
					return { success: true, consumed: 42 };
				}
				return { success: true, value: 42 };
			};
			const status = await new Runner().runJobFile(job(steps), true);
			assert.strictEqual(status.status, 'ok');
			assert.strictEqual(status.steps.at(-1).stepId, 'consume');
			assert.strictEqual(status.steps.at(-1).stepIndex, inserted ? 2 : 1);
		}
	});

	test('resolves nested result paths completely and rejects object string coercion', async () => {
		handler = options => {
			if (options.pipelineStepIdentity.stepId === 'produce') { return { success: true, prototype: { prototypeId: 'prototype:exact' } }; }
			assert.strictEqual(options.identity, 'prototype:exact'); return { success: true };
		};
		assert.strictEqual((await new Runner().runJobFile(job([step('produce'), step('consume', { args: { identity: '$step[produce].result.prototype.prototypeId' } })]), true)).status, 'ok');
		calls = [];
		const object = await new Runner().runJobFile(job([step('produce'), step('consume', { args: { identity: 'prefix-$step[produce].result.prototype' } })]), true);
		assert.strictEqual(object.status, 'error'); assert.match(object.steps.at(-1).error, /requires a scalar/);
		calls = [];
		const missing = await new Runner().runJobFile(job([step('produce'), step('consume', { args: { identity: '$step[produce].result.prototype.missing' } })]), true);
		assert.strictEqual(missing.status, 'error'); assert.match(missing.steps.at(-1).error, /field path is unavailable/);
	});

	test('nested result dependency preserves the producer artifact in provenance', async () => {
		handler = options => options.pipelineStepIdentity.stepId === 'produce'
			? { success: true, prototype: { prototypeId: 'prototype:exact' } }
			: (assert.strictEqual(options.identity, 'prototype:exact'), { success: true });
		const status = await new Runner().runJobFile(job([
			step('produce', { output: { path: 'prototype.json' } }),
			step('consume', { args: { identity: '$step[produce].result.prototype.prototypeId' }, output: { path: 'explanation.json' } }),
		]), true);
		assert.strictEqual(status.status, 'ok');
		const entries = manifest().artifacts;
		const producer = entries.find((entry: any) => entry.step.stepId === 'produce');
		const consumer = entries.find((entry: any) => entry.step.stepId === 'consume');
		assert.ok(consumer.analysisContract.inputs.some((input: any) => input.id === producer.analysisContract.artifact.id));
		assert.ok(!consumer.analysisContract.inputs.some((input: any) => input.id === consumer.analysisContract.artifact.id));
	});

	test('validation rejects invalid/duplicate IDs and unknown branch targets before dispatch', async () => {
		for (const steps of [[step('same'), step('same')], [{ ...step(), id: 1 }], [step('prev')], [step('start', { onResult: { field: 'x', operator: 'equals', value: 1, action: 'goto', actionValue: 'missing' } })]]) {
			const file = job(steps);
			assert.strictEqual((await new Runner().validateJobFile(file)).ok, false);
			assert.strictEqual((await new Runner().runJobFile(file, true)).status, 'error');
		}
		assert.strictEqual(calls.length, 0);
	});

	test('named goto can execute a producer declared after its consumer', async () => {
		const jump = (to: string) => ({ field: 'jump', operator: 'equals', value: 1, action: 'goto', actionValue: to });
		handler = options => options.pipelineStepIdentity.stepId === 'consume'
			? (assert.strictEqual(options.value, 7), { success: true, jump: 1, value: 7, consumed: true })
			: { success: true, jump: 1, value: 7 };
		const file = job([step('route', { onResult: jump('produce') }), step('consume', { args: { value: '$step[produce].result.value' }, onResult: jump('end') }), step('produce', { onResult: jump('consume') }), step('end')]);
		const validation = await new Runner().validateJobFile(file);
		assert.ok(validation.issues.some((issue: any) => issue.code === 'STEP_REF_REQUIRES_PRIOR_EXECUTION' && issue.level === 'warning'));
		const status = await new Runner().runJobFile(file, true);
		assert.strictEqual(status.status, 'ok', JSON.stringify(status));
		assert.deepStrictEqual(calls, ['route', 'produce', 'consume', 'end']);
	});

	test('a named reference that has never executed fails without dispatch', async () => {
		const status = await new Runner().runJobFile(job([step('consume', { args: { value: '$step[produce].result.value' } }), step('produce')]), true);
		assert.strictEqual(status.status, 'error');
		assert.strictEqual(calls.length, 0);
	});

	test('skip validation resolves dependency names', async () => {
		const file = job([step('route', { onResult: { field: 'x', operator: 'equals', value: 1, action: 'skip', actionValue: 1 } }), step('produce'), step('consume', { args: { value: '$step[produce].result.value' } })]);
		const validation = await new Runner().validateJobFile(file);
		assert.ok(validation.issues.some((issue: any) => issue.code === 'STEP_REF_MAY_BE_SKIPPED'));
	});

	test('backward goto reads the latest occurrence and retains history', async () => {
		let iteration = 0; const seen: number[] = [];
		handler = options => {
			if (options.pipelineStepIdentity.stepId === 'produce') { return { success: true, value: ++iteration }; }
			seen.push(options.value); return { success: true, again: options.value < 2 };
		};
		const status = await new Runner().runJobFile(job([step('produce'), step('consume', { args: { value: '$step[produce].result.value' }, onResult: { field: 'again', operator: 'equals', value: true, action: 'goto', actionValue: 'produce' } })]), true);
		assert.strictEqual(status.status, 'ok'); assert.deepStrictEqual(seen, [1, 2]);
		assert.deepStrictEqual(status.steps.map((entry: any) => [entry.stepId, entry.occurrence]), [['produce', 1], ['consume', 1], ['produce', 2], ['consume', 2]]);
		assert.ok(manifest().history.some((entry: any) => entry.step.stepId === 'produce' && entry.step.occurrence === 1));
		assert.ok(manifest().artifacts.every((entry: any) => entry.step.occurrence === 2));
	});

	test('retry history keeps failure and success as separate attempts', async () => {
		let attempt = 0; handler = () => ++attempt === 1 ? { success: false, error: 'transient' } : { success: true, value: 5 };
		const status = await new Runner().runJobFile(job([step('retry', { retryCount: 1, retryDelayMs: 0 })]), true);
		assert.strictEqual(status.status, 'ok', JSON.stringify(status));
		assert.deepStrictEqual(status.steps[0].attempts.map((entry: any) => [entry.attempt, entry.status]), [[1, 'error'], [2, 'ok']]);
	});

	test('a failed rerun cannot resurrect its earlier success', async () => {
		let iteration = 0;
		handler = options => options.pipelineStepIdentity.stepId === 'produce'
			? (++iteration === 1 ? { success: true, value: 7 } : { success: false, error: 'second run failed' })
			: { success: true, again: true };
		const status = await new Runner().runJobFile(job([step('produce'), step('consume', { args: { value: '$step[produce].result.value' }, onResult: { field: 'again', operator: 'equals', value: true, action: 'goto', actionValue: 'produce' } })], { continueOnError: true }), true);
		assert.deepStrictEqual(calls, ['produce', 'consume', 'produce']);
		assert.strictEqual(status.steps.at(-1).status, 'error');
		const current = manifest().artifacts.find((entry: any) => entry.step.stepId === 'consume');
		assert.strictEqual(current.step.occurrence, 2);
		assert.strictEqual(current.step.semanticStatus, 'error');
	});

	test('a replaced output is not silently read as an earlier named artifact', async () => {
		handler = options => ({ success: true, value: options.pipelineStepIdentity.stepId });
		const status = await new Runner().runJobFile(job([step('first', { output: { path: 'shared.json' } }), step('second', { output: { path: 'shared.json' } }), step('consume', { args: { input: '$step[first].output' } })]), true);
		assert.deepStrictEqual(calls, ['first', 'second']);
		assert.match(status.steps.at(-1).error, /hash-mismatch/);
	});

	test('legacy steps do not gain named-step metadata', async () => {
		handler = options => options.value === 2 ? { success: true, value: 2, consumed: true } : { success: true, value: 2 };
		const status = await new Runner().runJobFile(job([step(), step(undefined, { args: { value: '$step[0].result.value' } })]), true);
		assert.strictEqual(status.status, 'ok', JSON.stringify(status));
		assert.ok(status.steps.every((entry: any) => !('stepId' in entry) && !('occurrence' in entry) && !('attempts' in entry)));
		assert.ok(!('history' in manifest()));
	});

	test('named result-field references retain partial status, not only output paths', async () => {
		handler = options => {
			if (options.pipelineStepIdentity.stepId === 'produce') { return { success: true, status: 'partial', value: 7 }; }
			assert.strictEqual(options.pipelineInputQuality.status, 'partial');
			return { success: true, consumed: options.value };
		};
		const status = await new Runner().runJobFile(job([step('produce', { allowPartial: true }), step('consume', { allowPartial: true, args: { value: '$step[produce].result.value' } })]), true);
		assert.strictEqual(status.status, 'partial');
		assert.strictEqual(status.steps[1].status, 'partial');
		assert.strictEqual(manifest().artifacts.find((entry: any) => entry.step.stepId === 'consume').step.semanticStatus, 'partial');
	});
});
