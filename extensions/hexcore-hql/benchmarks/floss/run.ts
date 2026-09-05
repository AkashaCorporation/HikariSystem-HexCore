import { spawnSync } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import { importFlossEvidence } from '../../../hexcore-disassembler/src/flossEvidence.js';
import { canonicalJson, sha256Hex } from '../../src/atlas/canonical.js';
import {
	assertGitIdentity,
	assertSafeEntryId,
	executeWithWatchdog,
	lockedExecutable,
	policySha256,
	readJson,
	readLockedTool,
	sha256File,
	writeExecutionArtifact,
	writeJson,
} from '../lib/contract.js';

interface BuildEntry {
	id: string;
	binaryPath: string;
	binarySha256: string;
}

interface BuildManifest {
	schemaVersion: number;
	entries: BuildEntry[];
}

interface FlossNormalizationPolicy {
	schemaVersion: number;
	id: string;
	tool: string;
	volatileRawPointers: string[];
	identityPointers: string[];
	nonEvidencePointers: string[];
	reason: string;
}

class BenchmarkError extends Error {
	constructor(readonly code: string, message: string) {
		super(message);
	}
}

const RUNNER_VERSION = '2.0.0';
const WATCHDOG_MS = 180_000;
const packageRoot = path.resolve(__dirname, '..', '..');
const toolsRoot = process.env.HEXCORE_TOOLS_ROOT ?? path.join(process.env.USERPROFILE ?? '', '.hexcore-tools');
const entryId = assertSafeEntryId(process.argv[2] ?? 'msvc-x64-O2-stripped');
const runDir = path.join(packageRoot, 'benchmarks', 'floss', 'runs', entryId);
const statusFile = path.join(runDir, 'floss.status.json');
fs.mkdirSync(runDir, { recursive: true });

try {
	runBenchmark();
} catch (error) {
	const code = error instanceof BenchmarkError ? error.code : 'CONTRACT_ERROR';
	const message = error instanceof Error ? error.message : String(error);
	writeJson(path.join(runDir, 'floss.failure.json'), { schemaVersion: 1, runner: 'floss', entryId, code, message });
	writeJson(statusFile, { schemaVersion: 1, runner: 'floss', runnerVersion: RUNNER_VERSION, entryId, status: 'error', code });
	console.error(`FLOSS benchmark failed [${code}]: ${message}`);
	process.exitCode = 1;
}

function runBenchmark(): void {
	const manifest = readJson<BuildManifest>(path.join(packageRoot, 'benchmarks', 'corpus', 'build', 'build-manifest.json'));
	if (manifest.schemaVersion !== 2 || !Array.isArray(manifest.entries)) {
		throw new BenchmarkError('CORPUS_CONTRACT', 'Invalid corpus build manifest');
	}
	const entry = manifest.entries.find(candidate => candidate.id === entryId);
	if (!entry) {
		throw new BenchmarkError('CORPUS_CONTRACT', `Unknown corpus entry ${entryId}`);
	}
	const binaryPath = path.resolve(entry.binaryPath);
	if (sha256File(binaryPath) !== entry.binarySha256) {
		throw new BenchmarkError('INPUT_IDENTITY', 'FLOSS input binary hash drift');
	}

	const lockPath = path.join(packageRoot, 'benchmarks', 'third_party.lock.json');
	const runtimeLockPath = path.join(packageRoot, 'benchmarks', 'runtime.lock.json');
	const tool = readLockedTool(lockPath, 'mandiant.flare-floss');
	const sourceRoot = path.join(toolsRoot, 'src', 'flare-floss');
	assertGitIdentity(sourceRoot, tool);
	const executable = lockedExecutable(runtimeLockPath, toolsRoot, tool.id);
	assertVersion(executable.path, `floss ${tool.version}`);

	const policyPath = path.join(packageRoot, 'benchmarks', 'floss', 'normalization-policy.json');
	const policy = readJson<FlossNormalizationPolicy>(policyPath);
	validatePolicy(policy);
	const normalizationPolicySha256 = policySha256(policyPath);
	const logicalArguments = ['-j', `sha256:${entry.binarySha256}`];
	const configurationSha256 = sha256Hex(canonicalJson({
		runnerVersion: RUNNER_VERSION,
		tool: { version: tool.version, commit: tool.commit, executableSha256: executable.sha256 },
		logicalArguments,
		normalizationPolicySha256,
	}));
	const outcome = executeWithWatchdog(executable.path, ['-j', binaryPath], WATCHDOG_MS);
	fs.writeFileSync(path.join(runDir, 'floss.raw.json'), outcome.stdout, 'utf8');
	fs.writeFileSync(path.join(runDir, 'floss.stderr.txt'), outcome.stderr, 'utf8');
	writeExecutionArtifact(path.join(runDir, 'floss.execution.json'), 'floss', entryId, WATCHDOG_MS, outcome);
	if (outcome.status !== 'ok') {
		throw new BenchmarkError(outcome.code, `FLOSS process failed: exit=${outcome.exitCode} signal=${outcome.signal ?? 'none'}`);
	}

	const report = importFlossEvidence(outcome.stdout, {
		binarySha256: entry.binarySha256,
		toolVersion: tool.version,
		toolSha256: executable.sha256,
		configurationSha256,
		normalizationPolicyId: policy.id,
		normalizationPolicySha256,
	});
	const canonicalEvidence = Object.fromEntries(Object.entries(report).filter(([key]) => key !== 'sourceJsonSha256'));
	const evidenceSha256 = sha256Hex(canonicalJson(canonicalEvidence));
	writeJson(path.join(runDir, 'floss.facts.json'), canonicalEvidence);
	writeJson(statusFile, {
		schemaVersion: 1,
		runner: 'floss',
		runnerVersion: RUNNER_VERSION,
		entryId,
		status: 'ok',
		code: 'OK',
		identity: {
			targetSha256: entry.binarySha256,
			toolCommit: tool.commit,
			toolExecutableSha256: executable.sha256,
			configurationSha256,
			normalizationPolicySha256,
			normalizedSha256: report.normalizedSha256,
			evidenceSha256,
		},
	});
	fs.rmSync(path.join(runDir, 'floss.failure.json'), { force: true });
	console.log(`FLOSS evidence: ${entryId}, facts=${report.facts.length}, runtime=${outcome.runtimeMs.toFixed(1)}ms, normalized=${report.normalizedSha256}`);
}

function assertVersion(executable: string, expected: string): void {
	const version = spawnSync(executable, ['--version'], { encoding: 'utf8', timeout: 30_000 });
	if (version.error || version.status !== 0 || version.signal || version.stdout.trim() !== expected) {
		throw new BenchmarkError('TOOL_IDENTITY', `Unexpected tool version: ${version.stdout}${version.stderr}`);
	}
}

function validatePolicy(policy: FlossNormalizationPolicy): void {
	if (canonicalJson(Object.keys(policy).sort()) !== canonicalJson(['id', 'identityPointers', 'nonEvidencePointers', 'reason', 'schemaVersion', 'tool', 'volatileRawPointers'])) {
		throw new BenchmarkError('NORMALIZATION_POLICY', 'FLOSS normalization policy contains missing or unknown fields');
	}
	if (policy.schemaVersion !== 1 || policy.id !== 'hexcore.floss-evidence-projection.v1' || policy.tool !== 'mandiant.flare-floss' || !policy.reason) {
		throw new BenchmarkError('NORMALIZATION_POLICY', 'Invalid FLOSS normalization policy header');
	}
	const expectedVolatile = ['/metadata/file_path', '/metadata/runtime'];
	const expectedIdentity = [
		'/metadata/version', '/metadata/imagebase', '/metadata/min_length',
		'/strings/static_strings', '/strings/language_strings', '/strings/language_strings_missed',
		'/strings/stack_strings', '/strings/tight_strings', '/strings/decoded_strings',
	];
	const expectedNonEvidence = ['/analysis', '/metadata/language', '/metadata/language_selected', '/metadata/language_version'];
	for (const [actual, expected, label] of [
		[policy.volatileRawPointers, expectedVolatile, 'volatile'],
		[policy.identityPointers, expectedIdentity, 'identity'],
		[policy.nonEvidencePointers, expectedNonEvidence, 'non-evidence'],
	] as const) {
		if (!Array.isArray(actual) || new Set(actual).size !== actual.length || canonicalJson([...actual].sort()) !== canonicalJson([...expected].sort())) {
			throw new BenchmarkError('NORMALIZATION_POLICY', `FLOSS ${label} pointer policy differs from the audited importer projection`);
		}
	}
}
