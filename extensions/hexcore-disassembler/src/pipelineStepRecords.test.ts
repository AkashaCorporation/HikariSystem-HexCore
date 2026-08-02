import * as assert from 'assert';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

type PipelineStep = any;
let findStepThatMaySkip: (steps: PipelineStep[], targetIndex: number) => number | undefined;
let readStepOutputForCapture: (outputPath: string, kind: 'json' | 'text') => Record<string, unknown> | undefined;
let resolveStepReferences: (args: Record<string, unknown>, records: any[], currentIndex: number) => Record<string, unknown>;

function installVscodeMock(): void {
	const Module = require('module');
	const originalResolveFilename = Module._resolveFilename;
	Module._resolveFilename = function (request: string, parent: unknown, isMain: boolean, options: unknown) {
		if (request === 'vscode') { return '__vscode_mock_step_records__'; }
		return originalResolveFilename.call(this, request, parent, isMain, options);
	};
	require.cache['__vscode_mock_step_records__'] = {
		id: '__vscode_mock_step_records__', filename: '__vscode_mock_step_records__', loaded: true,
		exports: {
			commands: { getCommands: async () => [], executeCommand: async () => undefined },
			workspace: { workspaceFolders: undefined, getConfiguration: () => ({ get: (_k: string, d: unknown) => d }) },
			extensions: { getExtension: () => undefined },
			Uri: { file: (f: string) => ({ fsPath: f, scheme: 'file' }) },
		},
	} as unknown as NodeModule;
}

suite('pipeline step records (#44/#59)', () => {
	suiteSetup(() => {
		installVscodeMock();
		const runner = require(path.resolve(__dirname, 'automationPipelineRunner'));
		findStepThatMaySkip = runner.findStepThatMaySkip;
		readStepOutputForCapture = runner.readStepOutputForCapture;
		resolveStepReferences = runner.resolveStepReferences;
	});

	test('$step[N] uses declared index and rejects a skipped hole', () => {
		const records: any[] = [
			{ outputPath: 'zero.json', result: { value: 0 } },
			undefined,
			{ outputPath: 'two.json', result: { value: 2 } },
		];
		assert.throws(
			() => resolveStepReferences({ x: '$step[1].result.value' }, records, 3),
			/referenced step did not run/,
		);
		assert.deepStrictEqual(
			resolveStepReferences({ x: '$step[2].result.value' }, records, 3),
			{ x: 2 },
		);
	});

	test('a rerun overwrites the stale result at its declared index', () => {
		const records: any[] = [{ outputPath: 'a.json', result: { run: 1 } }];
		records[0] = { outputPath: 'a.json', result: { run: 2 } };
		assert.deepStrictEqual(
			resolveStepReferences({ run: '$step[0].result.run' }, records, 1),
			{ run: 2 },
		);
	});

	test('validator helper identifies a conditional jump over a referenced step', () => {
		const steps: PipelineStep[] = [
			{ cmd: 'a', onResult: { field: 'x', operator: 'equals', value: 1, action: 'skip', actionValue: 2 } },
			{ cmd: 'b' },
			{ cmd: 'c' },
			{ cmd: 'd', args: { x: '$step[1].output' } },
		];
		assert.strictEqual(findStepThatMaySkip(steps, 1), 0);
	});

	test('text artifacts are captured as metadata without JSON parsing', () => {
		const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hexcore-step-'));
		const file = path.join(dir, 'report.md');
		try {
			fs.writeFileSync(file, '# report\nnot json\n', 'utf8');
			const result = readStepOutputForCapture(file, 'text');
			assert.strictEqual(result?.kind, 'text');
			assert.strictEqual(result?.path, file);
			assert.strictEqual(result?.bytes, Buffer.byteLength('# report\nnot json\n'));
		} finally {
			fs.rmSync(dir, { recursive: true, force: true });
		}
	});

	test('JSON artifacts remain available to onResult and $step fields', () => {
		const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hexcore-step-'));
		const file = path.join(dir, 'result.json');
		try {
			fs.writeFileSync(file, '{"score":7}', 'utf8');
			assert.deepStrictEqual(readStepOutputForCapture(file, 'json'), { score: 7 });
		} finally {
			fs.rmSync(dir, { recursive: true, force: true });
		}
	});
});
