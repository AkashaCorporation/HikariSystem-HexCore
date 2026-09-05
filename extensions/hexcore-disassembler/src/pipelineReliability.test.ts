import * as assert from 'assert';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import * as crypto from 'crypto';
import { createInvestigationJob } from './investigationJob';

type ExecuteCommand = (command: string, options: Record<string, unknown>) => Promise<unknown>;

let executeCommand: ExecuteCommand = async () => undefined;
let mockWorkspaceRoot: string | undefined;
let AutomationPipelineRunner: new () => {
	runJobFile(jobFilePath: string, quietOverride?: boolean, abortSignal?: AbortSignal, runContext?: Record<string, unknown>): Promise<any>;
	validateJobFile(jobFilePath: string, quietOverride?: boolean): Promise<{ ok: boolean; issues: Array<{ level: string; code: string }> }>;
};
let inspectSemanticResult: (value: unknown) => { status: 'ok' | 'partial' | 'failed'; reason?: string };
let jobRequiresExclusiveEngine: (steps: Array<{ cmd: string }>) => boolean;
let inspectBinaryIdentity: (filePath: string) => { format: string; architecture?: string; imageBase?: string };
let checkBinaryFormatGate: (command: string, filePath: string) => { skip: boolean; reason?: string };
let resolveArtifactMediaType: (outputPath: string, format?: 'json' | 'md') => string;
let formatAnalysisContextLog: (context: Record<string, unknown>) => string;
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
					'hexcore.disasm.disassembleAtHeadless',
					'hexcore.disasm.windowsFilesystemAuditHeadless',
					'hexcore.disasm.searchStringHeadless',
					'hexcore.disasm.liftToIR',
					'hexcore.helix.decompileIR',
					'hexcore.hashcalc.calculate',
					'hexcore.entropy.analyze',
					'hexcore.hql.scanHeadless',
					'hexcore.pipeline.composeReport',
					'hexcore.audit.refcountScan',
					'hexcore.pipeline.jobStatus',
				],
				executeCommand: async (command: string, options: Record<string, unknown>) => executeCommand(command, options),
			},
			workspace: {
				get workspaceFolders() {
					return mockWorkspaceRoot ? [{ uri: { fsPath: mockWorkspaceRoot } }] : undefined;
				},
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
		resolveArtifactMediaType = runner.resolveArtifactMediaType;
		formatAnalysisContextLog = runner.formatAnalysisContextLog;
		JobQueueManager = runner.JobQueueManager;
	});

	setup(() => {
		tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'hexcore-pipeline-reliability-'));
		mockWorkspaceRoot = tempDir;
		executeCommand = async () => undefined;
	});

	teardown(() => {
		mockWorkspaceRoot = undefined;
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
		assert.deepStrictEqual(
			inspectSemanticResult({ success: true, status: 'partial', confidence: 50 }).status,
			'partial',
		);
		assert.strictEqual(
			inspectSemanticResult({ success: true, status: 'partial', semanticWarning: 'coverage 11.54%' }).reason,
			'coverage 11.54%',
		);
		const solverTimeout = inspectSemanticResult({
			status: 'unknown',
			semanticStatus: 'error',
			timeout: true,
			error: 'Z3 timed out',
		});
		assert.strictEqual(solverTimeout.status, 'failed');
		assert.strictEqual(solverTimeout.reason, 'Z3 timed out');
		const toleratedSolverTimeout = inspectSemanticResult({
			status: 'unknown',
			semanticStatus: 'partial',
			timeout: true,
			semanticWarning: 'Z3 timed out',
		});
		assert.strictEqual(toleratedSolverTimeout.status, 'partial');
		assert.strictEqual(toleratedSolverTimeout.reason, 'Z3 timed out');
	});

	test('external refcount input and consumed ancestry are lineage inputs, not empty or re-hashed later', async () => {
		const target = path.join(tempDir, 'target.bin'); fs.writeFileSync(target, 'test');
		const input = path.join(tempDir, 'old-job.c'); fs.writeFileSync(input, 'int f(void) { return 1; }');
		const inputDigest = crypto.createHash('sha256').update(fs.readFileSync(input)).digest('hex');
		const snapshot = path.join(tempDir, 'snapshot.json'); fs.writeFileSync(snapshot, '{"artifacts":[]}');
		const snapshotDigest = crypto.createHash('sha256').update(fs.readFileSync(snapshot)).digest('hex');
		const job = writeJob(tempDir, 'cross-run-refcount', target, {
			cmd: 'hexcore.audit.refcountScan', args: { input }, output: { path: 'audit.json' }, allowPartial: true,
		});
		executeCommand = async (_command, options) => {
			fs.writeFileSync(input, 'changed after scan');
			const result = { status: 'partial', inputFile: input, inputQuality: {
				inputSha256: inputDigest, provenanceSnapshot: { path: snapshot, sha256: snapshotDigest },
			}, findings: [], negativeEvidenceUsable: false };
			fs.writeFileSync((options.output as { path: string }).path, JSON.stringify(result));
			return result;
		};
		const terminal = await new AutomationPipelineRunner().runJobFile(job, true);
		assert.strictEqual(terminal.status, 'partial', JSON.stringify(terminal.steps));
		const manifest = JSON.parse(fs.readFileSync(path.join(terminal.outDir, '.hexcore-meta', 'provenance.json'), 'utf8'));
		const references = manifest.artifacts[0].inputs;
		assert.strictEqual(references.length, 2);
		assert.strictEqual(references.find((ref: any) => ref.path === input).sha256, inputDigest);
		assert.strictEqual(references.find((ref: any) => ref.path === snapshot).sha256, snapshotDigest);
		assert.deepStrictEqual(manifest.artifacts[0].analysisContract.inputs, references);
		assert.ok(references.every((ref: any) => ref.path !== terminal.steps[0].outputPath));
	});

	test('status step receives actual observer identity instead of user-supplied context', async () => {
		const target = path.join(tempDir, 'target.bin'); fs.writeFileSync(target, 'test');
		const job = writeJob(tempDir, 'queue-observer', target, {
			cmd: 'hexcore.pipeline.jobStatus', args: { pipelineQueryContext: { jobId: 'wrong' } }, output: { path: 'queue.json' },
		});
		let received: any;
		executeCommand = async (_command, options) => {
			received = options.pipelineQueryContext;
			fs.writeFileSync((options.output as { path: string }).path, JSON.stringify({ status: 'ok' }));
			return { status: 'ok' };
		};
		const terminal = await new AutomationPipelineRunner().runJobFile(job, true, undefined, { jobId: 'observer' });
		assert.strictEqual(terminal.status, 'ok', JSON.stringify(terminal.steps));
		assert.strictEqual(received.jobId, 'observer');
		assert.strictEqual(received.executionId, terminal.provenance.executionId);
	});

	test('formats audit bindings without Helix ownership false-negatives', () => {
		assert.strictEqual(formatAnalysisContextLog({
			sessionId: 'session:abc', sessionGeneration: 6, universeSha256: 'def', materializedFunctions: 10, lazyFunctions: 2,
		}), 'binding=persisted-session session=session:abc generation=6 universe=def materialized=10 lazy=2');
		assert.strictEqual(formatAnalysisContextLog({
			ownership: 'matched', activeEngineEvidenceUsed: true, sourceTargetFile: 'a.exe', activeTargetFile: 'a.exe',
		}), 'ownership=matched activeEngineEvidenceUsed=true source=a.exe active=a.exe');
	});

	test('report step is recomposed after terminal status persistence', async () => {
		const target = path.join(tempDir, 'target.bin');
		fs.writeFileSync(target, Buffer.from([0x90, 0xc3]));
		const jobPath = writeJob(tempDir, 'terminal-report', target, {
			cmd: 'hexcore.pipeline.composeReport',
			output: { path: 'FINAL_REPORT.md', format: 'md' },
		});
		let executions = 0;
		executeCommand = async (_command, options) => {
			executions++;
			const output = options.output as { path: string };
			const statusPath = path.join(path.dirname(output.path), 'hexcore-pipeline.status.json');
			const snapshot = JSON.parse(fs.readFileSync(statusPath, 'utf8')) as { status: string; steps: unknown[] };
			fs.writeFileSync(output.path, `status=${snapshot.status};steps=${snapshot.steps.length}`, 'utf8');
			return { success: true, sources: [{ filePath: statusPath }] };
		};

		const status = await new AutomationPipelineRunner().runJobFile(jobPath);
		const reportPath = path.join(path.dirname(jobPath), 'out', 'FINAL_REPORT.md');
		assert.strictEqual(status.status, 'ok');
		assert.strictEqual(executions, 2, 'ordinary step plus one terminal recomposition');
		assert.strictEqual(fs.readFileSync(reportPath, 'utf8'), 'status=ok;steps=1');
		assert.strictEqual(status.summary.totalSteps, 1);
		assert.strictEqual(status.summary.okCount, 1);
		const manifest = JSON.parse(fs.readFileSync(
			path.join(path.dirname(reportPath), '.hexcore-meta', 'provenance.json'),
			'utf8',
		));
		const reportEntry = manifest.artifacts.find((entry: any) => entry.artifact.path === reportPath);
		assert.deepStrictEqual(reportEntry.inputs.map((input: any) => input.path), [
			path.join(path.dirname(reportPath), 'hexcore-pipeline.status.json'),
		]);
		assert.ok(reportEntry.inputs.every((input: any) => input.path !== reportPath));
	});

	test('filesystem audit provenance inherits analyzeAll and committed materialization artifacts', async () => {
		const target = path.join(tempDir, 'target.exe');
		const pe = Buffer.alloc(512);
		pe.write('MZ', 0, 'ascii');
		pe.writeUInt32LE(0x80, 0x3c);
		pe.write('PE\0\0', 0x80, 'ascii');
		pe.writeUInt16LE(0x8664, 0x84);
		pe.writeUInt16LE(0x20b, 0x98);
		pe.writeBigUInt64LE(0x140000000n, 0xb0);
		fs.writeFileSync(target, pe);
		const jobDir = path.join(tempDir, 'audit-lineage');
		fs.mkdirSync(jobDir, { recursive: true });
		const jobPath = path.join(jobDir, '.hexcore_job.json');
		fs.writeFileSync(jobPath, JSON.stringify({
			file: target,
			outDir: 'out',
			quiet: true,
			steps: [
				{ cmd: 'hexcore.disasm.analyzeAll', output: { path: '00-analysis.json' } },
				{
					cmd: 'hexcore.disasm.disassembleAtHeadless',
					args: { address: '0x140001000', endExclusive: '0x140001020' },
					output: { path: '01-materialized.disassembly.json' },
				},
				{
					cmd: 'hexcore.disasm.windowsFilesystemAuditHeadless',
					output: { path: '02-audit.json' },
					allowPartial: true,
				},
			],
		}), 'utf8');
		executeCommand = async (command, options) => {
			const output = options.output as { path: string };
			if (command === 'hexcore.disasm.analyzeAll') {
				fs.writeFileSync(output.path, JSON.stringify({ status: 'ok', materializedFunctionRatio: 0.5 }), 'utf8');
				return { status: 'ok' };
			}
			if (command === 'hexcore.disasm.disassembleAtHeadless') {
				const result = {
					status: 'ok',
					analysisClosure: { status: 'committed', changed: true, auditUniverseChanged: true },
				};
				fs.writeFileSync(output.path, JSON.stringify(result), 'utf8');
				return result;
			}
			fs.writeFileSync(output.path, JSON.stringify({ status: 'partial', verdict: 'incomplete' }), 'utf8');
			return { status: 'partial', semanticWarning: 'writer edge blocked' };
		};

		const status = await new AutomationPipelineRunner().runJobFile(jobPath);
		assert.strictEqual(status.status, 'partial', JSON.stringify(status.steps));
		const outDir = path.join(jobDir, 'out');
		const manifest = JSON.parse(fs.readFileSync(path.join(outDir, '.hexcore-meta', 'provenance.json'), 'utf8'));
		const auditPath = path.join(outDir, '02-audit.json');
		const auditEntry = manifest.artifacts.find((entry: any) => entry.artifact.path === auditPath);
		assert.deepStrictEqual(auditEntry.inputs.map((input: any) => input.path).sort(), [
			path.join(outDir, '00-analysis.json'),
			path.join(outDir, '01-materialized.disassembly.json'),
		].sort());
		assert.ok(auditEntry.step.configurationSha256.match(/^[a-f0-9]{64}$/));
		assert.ok(auditEntry.inputs.every((input: any) => input.path !== auditPath));
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

	test('preflight accepts the investigation job emitted by the Analysis Center', async () => {
		const targetPath = path.join(tempDir, 'sample.exe');
		const pe = Buffer.alloc(512);
		pe.write('MZ', 0, 'ascii');
		pe.writeUInt32LE(0x80, 0x3c);
		pe.write('PE\0\0', 0x80, 'ascii');
		pe.writeUInt16LE(0x8664, 0x84);
		pe.writeUInt16LE(0x20b, 0x98);
		pe.writeBigUInt64LE(0x140000000n, 0xb0);
		fs.writeFileSync(targetPath, pe);

		const jobDirectory = path.join(tempDir, 'hexcore-jobs');
		const definition = createInvestigationJob({
			targetPath: path.relative(jobDirectory, targetPath),
			outputDirectory: path.join('..', 'hexcore-reports', 'investigations', 'health-points'),
			name: 'Health Points',
			query: 'health_percent',
			functionAddress: '0x140001000',
		});
		fs.mkdirSync(jobDirectory, { recursive: true });
		const jobPath = path.join(jobDirectory, definition.fileName);
		fs.writeFileSync(jobPath, JSON.stringify(definition.job), 'utf8');

		const report = await new AutomationPipelineRunner().validateJobFile(jobPath, true);
		assert.strictEqual(report.ok, true, JSON.stringify(report.issues));
		assert.deepStrictEqual(report.issues.filter(issue => issue.level === 'error'), []);
	});

	test('artifact media types describe retained IR and C instead of JSON', () => {
		assert.strictEqual(resolveArtifactMediaType('function.ll'), 'text/x-llvm');
		assert.strictEqual(resolveArtifactMediaType('function.helix.c'), 'text/x-c');
		assert.strictEqual(resolveArtifactMediaType('references.json'), 'application/json');
	});

	test('decompile provenance binds the retained IR input artifact', async () => {
		const targetPath = path.join(tempDir, 'sample.exe');
		const pe = Buffer.alloc(512);
		pe.write('MZ', 0, 'ascii');
		pe.writeUInt32LE(0x80, 0x3c);
		pe.write('PE\0\0', 0x80, 'ascii');
		pe.writeUInt16LE(0x8664, 0x84);
		pe.writeUInt16LE(0x20b, 0x98);
		pe.writeBigUInt64LE(0x140000000n, 0xb0);
		fs.writeFileSync(targetPath, pe);

		const jobPath = path.join(tempDir, 'provenance.hexcore_job.json');
		const outDir = path.join(tempDir, 'out');
		fs.writeFileSync(jobPath, JSON.stringify({
			file: targetPath,
			outDir,
			quiet: true,
			steps: [
				{
					cmd: 'hexcore.disasm.liftToIR',
					args: { address: '0x140001000', count: 150 },
					output: { path: 'function.ll' },
				},
				{
					cmd: 'hexcore.helix.decompileIR',
					args: { irPath: '$step[0].output' },
					output: { path: 'function.helix.c' },
				},
			],
		}), 'utf8');

		executeCommand = async (_command, options) => {
			const output = options.output as { path?: string } | undefined;
			if (output?.path) {
				fs.mkdirSync(path.dirname(output.path), { recursive: true });
				fs.writeFileSync(output.path, output.path.endsWith('.ll') ? 'define i64 @sample() { ret i64 0 }\n' : 'int64_t sample(void) { return 0; }\n');
			}
			return { success: true, status: 'ok' };
		};

		const status = await new AutomationPipelineRunner().runJobFile(jobPath, true);
		assert.strictEqual(status.status, 'ok');
		const manifestPath = path.join(outDir, '.hexcore-meta', 'provenance.json');
		const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
		const liftEntry = manifest.artifacts.find((entry: any) => entry.artifact.path === path.join(outDir, 'function.ll'));
		const cEntry = manifest.artifacts.find((entry: any) => entry.artifact.path === path.join(outDir, 'function.helix.c'));
		assert.strictEqual(status.provenanceManifestPath, manifestPath);
		assert.strictEqual(manifest.status, 'ok');
		assert.strictEqual(cEntry.analysisContract.artifact.mediaType, 'text/x-c');
		assert.strictEqual(liftEntry.analysisContract.artifact.mediaType, 'text/x-llvm');
		assert.strictEqual(cEntry.analysisContract.inputs.length, 1);
		assert.strictEqual(cEntry.analysisContract.inputs[0].sha256, liftEntry.analysisContract.artifact.sha256);
		assert.strictEqual(cEntry.analysisContract.inputs[0].path, path.join(outDir, 'function.ll'));
		assert.ok(!fs.existsSync(`${path.join(outDir, 'function.ll')}.provenance.json`));
	});

	test('stateful jobs cannot exchange active binaries under concurrent stress', async function () {
		this.timeout(30_000);
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
			const provenancePath = path.join(path.dirname(job.output), '.hexcore-meta', 'provenance.json');
			assert.ok(fs.existsSync(provenancePath));
			const manifest = JSON.parse(fs.readFileSync(provenancePath, 'utf8'));
			const provenance = manifest.artifacts[0];
			assert.strictEqual(manifest.status, 'ok');
			assert.strictEqual(manifest.execution.binaryPath, job.target);
			assert.strictEqual(manifest.execution.jobId, `queue-job-${index}`);
			assert.strictEqual(manifest.execution.workerId, index % 2);
			assert.strictEqual(manifest.execution.sessionId, job.sessionId);
			assert.strictEqual(manifest.schemaVersion, 1);
			assert.strictEqual(manifest.execution.analysisContractVersion, 1);
			assert.match(manifest.execution.binarySha256, /^[a-f0-9]{64}$/);
			assert.match(provenance.artifact.sha256, /^[a-f0-9]{64}$/);
			assert.strictEqual(
				manifest.execution.analysisTarget.id,
				`target:sha256:${manifest.execution.binarySha256}`,
			);
			assert.strictEqual(
				manifest.execution.analysisSession.generation,
				manifest.execution.contextGeneration,
			);
			assert.strictEqual(provenance.analysisContract.contractVersion, 1);
			assert.strictEqual(
				provenance.analysisContract.target.id,
				manifest.execution.analysisTarget.id,
			);
			assert.strictEqual(
				provenance.analysisContract.session.id,
				job.sessionId,
			);
			assert.strictEqual(provenance.analysisContract.status, 'ok');
			assert.strictEqual(
				provenance.analysisContract.artifact.sha256,
				provenance.artifact.sha256,
			);
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

	test('a reused output directory cannot rebind a stale failed artifact', async () => {
		const target = path.join(tempDir, 'stale-output.bin');
		fs.writeFileSync(target, 'target', 'utf8');
		const jobPath = writeJob(tempDir, 'stale-output', target, {
			cmd: 'hexcore.entropy.analyze',
			output: { path: 'entropy.json', format: 'json' },
		});
		let failure = 'first failure';
		executeCommand = async () => {
			throw new Error(failure);
		};

		const runner = new AutomationPipelineRunner();
		await runner.runJobFile(jobPath);
		failure = 'second failure';
		const second = await runner.runJobFile(jobPath);

		const artifactPath = path.join(path.dirname(jobPath), 'out', 'entropy.json');
		const artifact = JSON.parse(fs.readFileSync(artifactPath, 'utf8'));
		const manifestPath = path.join(path.dirname(artifactPath), '.hexcore-meta', 'provenance.json');
		const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
		const provenance = manifest.artifacts[0];
		assert.strictEqual(second.status, 'error');
		assert.match(artifact.error, /second failure/);
		assert.doesNotMatch(artifact.error, /first failure/);
		assert.strictEqual(manifest.status, 'error');
		assert.strictEqual(provenance.analysisContract.status, 'failed');
		assert.strictEqual(provenance.artifact.sha256, provenance.analysisContract.artifact.sha256);
		assert.ok(!fs.existsSync(`${artifactPath}.provenance.json`));
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
			const manifestPath = path.join(path.dirname(output.path), '.hexcore-meta', 'provenance.json');
			fs.unlinkSync(manifestPath);
			fs.mkdirSync(manifestPath);
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
