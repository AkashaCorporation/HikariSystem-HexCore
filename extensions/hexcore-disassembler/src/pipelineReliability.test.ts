import * as assert from 'assert';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

type ExecuteCommand = (command: string, options: Record<string, unknown>) => Promise<unknown>;

let executeCommand: ExecuteCommand = async () => undefined;
let AutomationPipelineRunner: new () => {
	runJobFile(jobFilePath: string, quietOverride?: boolean, abortSignal?: AbortSignal, runContext?: Record<string, unknown>): Promise<any>;
};
let inspectSemanticResult: (value: unknown) => { status: 'ok' | 'partial' | 'failed'; reason?: string };
let jobRequiresExclusiveEngine: (steps: Array<{ cmd: string }>) => boolean;
let inspectBinaryIdentity: (filePath: string) => { format: string; architecture?: string; imageBase?: string };
let checkBinaryFormatGate: (command: string, filePath: string) => { skip: boolean; reason?: string };
let JobQueueManager: new (poolSize: number) => any;

function installVscodeMock(): void {
	class MockEventEmitter<T> {
		private readonly listeners = new Set<(event: T) => void>();
		readonly event = (listener: (event: T) => void) => {
			this.listeners.add(listener);
			return { dispose: () => this.listeners.delete(listener) };
		};
		fire(event: T): void { for (const listener of this.listeners) { listener(event); } }
		dispose(): void { this.listeners.clear(); }
	}
	const Module = require('module');
	const originalResolveFilename = Module._resolveFilename;
	Module._resolveFilename = function (request: string, parent: unknown, isMain: boolean, options: unknown) {
		if (request === 'vscode') { return '__vscode_mock_pipeline_reliability__'; }
		return originalResolveFilename.call(this, request, parent, isMain, options);
	};
	require.cache['__vscode_mock_pipeline_reliability__'] = {
		id: '__vscode_mock_pipeline_reliability__',
		filename: '__vscode_mock_pipeline_reliability__',
		loaded: true,
		exports: {
			commands: {
				getCommands: async () => [
					'hexcore.disasm.analyzeAll',
					'hexcore.hashcalc.calculate',
					'hexcore.hql.scanHeadless',
				],
				executeCommand: async (command: string, options: Record<string, unknown>) => executeCommand(command, options),
			},
			workspace: {
				workspaceFolders: undefined,
				getConfiguration: () => ({ get: (_key: string, defaultValue: unknown) => defaultValue }),
			},
			extensions: {
				getExtension: (id: string) => ({ id, isActive: true, packageJSON: { version: 'test-version' }, activate: async () => undefined }),
			},
			Uri: { file: (filePath: string) => ({ fsPath: filePath, scheme: 'file' }) },
			EventEmitter: MockEventEmitter,
		},
	} as unknown as NodeModule;
}

function writeJob(
	dir: string,
	name: string,
	target: string,
	step: Record<string, unknown>,
): string {
	const jobDir = path.join(dir, name);
	fs.mkdirSync(jobDir, { recursive: true });
	const jobPath = path.join(jobDir, `${name}.hexcore_job.json`);
	fs.writeFileSync(jobPath, JSON.stringify({
		file: target,
		outDir: 'out',
		quiet: true,
		steps: [step],
	}), 'utf8');
	return jobPath;
}

suite('pipeline reliability gates (3.8.3 RC)', () => {
	let tempDir: string;

	suiteSetup(() => {
		installVscodeMock();
		const runnerPath = path.resolve(__dirname, 'automationPipelineRunner');
		delete require.cache[require.resolve(runnerPath)];
		const runner = require(runnerPath);
		AutomationPipelineRunner = runner.AutomationPipelineRunner;
		inspectSemanticResult = runner.inspectSemanticResult;
		jobRequiresExclusiveEngine = runner.jobRequiresExclusiveEngine;
		inspectBinaryIdentity = runner.inspectBinaryIdentity;
		checkBinaryFormatGate = runner.checkBinaryFormatGate;
		JobQueueManager = runner.JobQueueManager;
	});

	setup(() => {
		tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'hexcore-pipeline-reliability-'));
		executeCommand = async () => undefined;
	});

	teardown(() => {
		fs.rmSync(tempDir, { recursive: true, force: true });
	});

	test('semantic classifier rejects hidden HQL and debugger failures', () => {
		assert.deepStrictEqual(
			inspectSemanticResult({ success: true, results: [{ error: 'decompile failed' }] }).status,
			'failed',
		);
		assert.deepStrictEqual(
			inspectSemanticResult({ success: true, results: [{ success: true }, { error: 'decompile failed' }] }).status,
			'partial',
		);
		assert.deepStrictEqual(
			inspectSemanticResult({ terminatedWithError: true, error: 'UC_ERR_WRITE_UNMAPPED' }).status,
			'failed',
		);
		assert.deepStrictEqual(inspectSemanticResult({ success: true }).status, 'ok');
	});

	test('stateful aliases require whole-job isolation while byte tools remain parallel', () => {
		assert.strictEqual(jobRequiresExclusiveEngine([{ cmd: 'hexcore.disasm.analyzeAll' }]), true);
		assert.strictEqual(jobRequiresExclusiveEngine([{ cmd: 'hexcore.decompile' }]), true);
		assert.strictEqual(jobRequiresExclusiveEngine([
			{ cmd: 'hexcore.filetype.detect' },
			{ cmd: 'hexcore.hash.file' },
		]), false);
	});

	test('binary header gate skips incompatible parsers before dispatch', () => {
		const pe = Buffer.alloc(512);
		pe.write('MZ', 0, 'ascii');
		pe.writeUInt32LE(0x80, 0x3c);
		pe.write('PE\0\0', 0x80, 'ascii');
		pe.writeUInt16LE(0x8664, 0x84);
		pe.writeUInt16LE(0x20b, 0x98);
		pe.writeBigUInt64LE(0x140000000n, 0xb0);
		const pePath = path.join(tempDir, 'sample.exe');
		fs.writeFileSync(pePath, pe);

		const elf = Buffer.alloc(64);
		elf.set([0x7f, 0x45, 0x4c, 0x46, 2, 1]);
		elf.writeUInt16LE(183, 18);
		const elfPath = path.join(tempDir, 'sample.ko');
		fs.writeFileSync(elfPath, elf);

		assert.deepStrictEqual(inspectBinaryIdentity(pePath), {
			format: 'pe', architecture: 'x86_64', imageBase: '0x140000000',
		});
		assert.deepStrictEqual(inspectBinaryIdentity(elfPath), { format: 'elf', architecture: 'aarch64' });
		assert.strictEqual(checkBinaryFormatGate('hexcore.elfanalyzer.analyze', pePath).skip, true);
		assert.strictEqual(checkBinaryFormatGate('hexcore.peanalyzer.analyze', elfPath).skip, true);
		assert.strictEqual(checkBinaryFormatGate('hexcore.disasm.analyzeAll', elfPath).skip, false);
	});

	test('preflight rejects an escaping output before executing any command', async () => {
		const target = path.join(tempDir, 'target.bin');
		fs.writeFileSync(target, 'target', 'utf8');
		const jobPath = writeJob(tempDir, 'escape', target, {
			cmd: 'hexcore.disasm.analyzeAll',
			output: { path: '../escape.json', format: 'json' },
		});
		let executions = 0;
		executeCommand = async () => { executions++; return { success: true }; };

		const status = await new AutomationPipelineRunner().runJobFile(jobPath);
		assert.strictEqual(status.status, 'error');
		assert.strictEqual(status.steps.length, 0);
		assert.strictEqual(executions, 0);
		assert.ok(status.summary.errorCount > 0);
		const validationPath = path.join(path.dirname(jobPath), 'out', 'hexcore-pipeline.validation.json');
		assert.ok(fs.existsSync(validationPath));
		const validation = JSON.parse(fs.readFileSync(validationPath, 'utf8'));
		assert.ok(validation.issues.some((issue: any) => issue.code === 'OUTPUT_PATH_INVALID'));
	});

	test('stateful jobs cannot exchange active binaries under concurrent stress', async () => {
		const pairs = 100;
		const jobs: Array<{ target: string; output: string; jobPath: string; sentinel: string; imageBase: string; architecture: string; sessionId: string }> = [];
		for (let i = 0; i < pairs * 2; i++) {
			const target = path.join(tempDir, `binary-${i}.bin`);
			fs.writeFileSync(target, `binary-${i}`, 'utf8');
			const name = `job-${i}`;
			const sentinel = `sentinel-string-${i}`;
			const imageBase = `0x${(0x400000 + i * 0x10000).toString(16)}`;
			const architecture = i % 2 === 0 ? 'x86_64' : 'aarch64';
			const sessionId = `session-${i}`;
			const jobPath = writeJob(tempDir, name, target, {
				cmd: 'hexcore.disasm.analyzeAll',
				output: { path: 'analysis.json', format: 'json' },
			});
			jobs.push({ target, jobPath, sentinel, imageBase, architecture, sessionId, output: path.join(path.dirname(jobPath), 'out', 'analysis.json') });
		}

		let activeBinary = '';
		executeCommand = async (_command, options) => {
			activeBinary = String(options.file);
			await new Promise(resolve => setTimeout(resolve, 2));
			const observed = activeBinary;
			const activeIndex = Number(path.basename(observed).match(/\d+/)?.[0]);
			const output = options.output as { path: string };
			fs.mkdirSync(path.dirname(output.path), { recursive: true });
			const result = {
				success: true,
				filePath: observed,
				imageBase: `0x${(0x400000 + activeIndex * 0x10000).toString(16)}`,
				architecture: activeIndex % 2 === 0 ? 'x86_64' : 'aarch64',
				strings: [`sentinel-string-${activeIndex}`],
			};
			fs.writeFileSync(output.path, JSON.stringify(result), 'utf8');
			return result;
		};

		const runner = new AutomationPipelineRunner();
		const statuses = await Promise.all(jobs.map((job, index) => runner.runJobFile(
			job.jobPath,
			undefined,
			undefined,
			{ jobId: `queue-job-${index}`, workerId: index % 2, sessionId: job.sessionId },
		)));
		assert.ok(statuses.every(status => status.status === 'ok'));
		assert.strictEqual(new Set(statuses.map(status => status.provenance.contextGeneration)).size, jobs.length);
		for (let index = 0; index < jobs.length; index++) {
			const job = jobs[index];
			const result = JSON.parse(fs.readFileSync(job.output, 'utf8'));
			assert.strictEqual(result.filePath, job.target);
			assert.strictEqual(result.imageBase, job.imageBase);
			assert.strictEqual(result.architecture, job.architecture);
			assert.deepStrictEqual(result.strings, [job.sentinel]);
			const provenancePath = `${job.output}.provenance.json`;
			assert.ok(fs.existsSync(provenancePath));
			const provenance = JSON.parse(fs.readFileSync(provenancePath, 'utf8'));
			assert.strictEqual(provenance.execution.binaryPath, job.target);
			assert.strictEqual(provenance.execution.jobId, `queue-job-${index}`);
			assert.strictEqual(provenance.execution.workerId, index % 2);
			assert.strictEqual(provenance.execution.sessionId, job.sessionId);
			assert.match(provenance.execution.binarySha256, /^[a-f0-9]{64}$/);
			assert.match(provenance.artifact.sha256, /^[a-f0-9]{64}$/);
			assert.strictEqual(provenance.step.resolvedCmd, 'hexcore.disasm.analyzeAll');
			assert.deepStrictEqual(provenance.ownerExtensions, [
				{ id: 'hikarisystem.hexcore-disassembler', version: 'test-version' },
			]);
		}
	});

	test('partial child results require an explicit allowPartial opt-in', async () => {
		const target = path.join(tempDir, 'hql.bin');
		fs.writeFileSync(target, 'hql', 'utf8');
		executeCommand = async (_command, options) => {
			const report = { success: true, results: [{ success: true }, { error: 'decompile failed' }] };
			const output = options.output as { path: string };
			fs.mkdirSync(path.dirname(output.path), { recursive: true });
			fs.writeFileSync(output.path, JSON.stringify(report), 'utf8');
			return report;
		};

		const strictJob = writeJob(tempDir, 'hql-strict', target, {
			cmd: 'hexcore.hql.scanHeadless',
			output: { path: 'hql.json', format: 'json' },
		});
		const partialJob = writeJob(tempDir, 'hql-partial', target, {
			cmd: 'hexcore.hql.scanHeadless',
			allowPartial: true,
			output: { path: 'hql.json', format: 'json' },
		});

		const runner = new AutomationPipelineRunner();
		const strictStatus = await runner.runJobFile(strictJob);
		const partialStatus = await runner.runJobFile(partialJob);
		assert.strictEqual(strictStatus.status, 'error');
		assert.strictEqual(strictStatus.steps[0].status, 'error');
		assert.strictEqual(partialStatus.status, 'partial');
		assert.strictEqual(partialStatus.steps[0].status, 'partial');
		assert.strictEqual(partialStatus.summary.partialCount, 1);
	});

	test('terminal pipeline errors propagate into the queue failed state', async () => {
		const queue = new JobQueueManager(1);
		queue.setJobExecutor(async () => ({ status: 'error', summary: { errorCount: 1 } }));
		queue.start();
		const jobId = queue.queueJob(path.join(tempDir, 'semantic-failure.hexcore_job.json'));
		for (let i = 0; i < 100 && queue.getJobStatus(jobId)?.status !== 'failed'; i++) {
			await new Promise(resolve => setTimeout(resolve, 5));
		}
		assert.strictEqual(queue.getJobStatus(jobId)?.status, 'failed');
		assert.strictEqual(queue.getQueueStats().failed, 1);
		await queue.stop();
		queue.dispose();
	});

	test('a provenance write failure terminates cleanly instead of freezing running status', async () => {
		const target = path.join(tempDir, 'provenance.bin');
		fs.writeFileSync(target, 'target', 'utf8');
		const jobPath = writeJob(tempDir, 'provenance-failure', target, {
			cmd: 'hexcore.disasm.analyzeAll',
			output: { path: 'analysis.json', format: 'json' },
		});
		executeCommand = async (_command, options) => {
			const output = options.output as { path: string };
			fs.mkdirSync(path.dirname(output.path), { recursive: true });
			fs.writeFileSync(output.path, JSON.stringify({ success: true }), 'utf8');
			fs.mkdirSync(`${output.path}.provenance.json`);
			return { success: true };
		};

		const status = await new AutomationPipelineRunner().runJobFile(jobPath);
		assert.strictEqual(status.status, 'error');
		assert.strictEqual(status.steps[0].status, 'error');
		assert.match(status.steps[0].error, /artifact provenance unavailable/i);
		const persisted = JSON.parse(fs.readFileSync(
			path.join(path.dirname(jobPath), 'out', 'hexcore-pipeline.status.json'),
			'utf8',
		));
		assert.strictEqual(persisted.status, 'error');
	});
});
