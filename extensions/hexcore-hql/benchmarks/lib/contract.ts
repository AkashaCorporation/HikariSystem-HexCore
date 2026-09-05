import { spawnSync } from 'child_process';
import { createHash } from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import { canonicalJson, sha256Hex } from '../../src/atlas/canonical.js';
import { validateAtlasRecord } from '../../src/atlas/source.js';
import type { AtlasBenchmarkRecord } from '../../src/atlas/types.js';

const SHA256 = /^[a-f0-9]{64}$/;
const GIT_OBJECT = /^[a-f0-9]{40}$/;
const SAFE_ID = /^[A-Za-z0-9._-]+$/;

export interface LockedTool {
	id: string;
	version: string;
	ref: string;
	commit: string;
	repository: string;
	license: string;
}

export interface SpawnOutcome {
	status: 'ok' | 'error' | 'timeout';
	code: 'OK' | 'PROCESS_ERROR' | 'WATCHDOG_TIMEOUT';
	exitCode: number | null;
	signal: NodeJS.Signals | null;
	runtimeMs: number;
	stdout: string;
	stderr: string;
	errorMessage?: string;
}

export interface ConfusionMatrix {
	truePositive: number;
	falsePositive: number;
	trueNegative: number;
	falseNegative: number;
	precision: number;
	recall: number;
}

export function assertSafeEntryId(value: string): string {
	if (!SAFE_ID.test(value)) {
		throw new Error(`Unsafe benchmark entry id ${JSON.stringify(value)}`);
	}
	return value;
}

export function readJson<T>(file: string): T {
	return JSON.parse(fs.readFileSync(file, 'utf8').replace(/^\uFEFF/, '')) as T;
}

export function sha256File(file: string): string {
	return createHash('sha256').update(fs.readFileSync(file)).digest('hex');
}

export function writeJson(file: string, value: unknown): void {
	fs.mkdirSync(path.dirname(file), { recursive: true });
	fs.writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`, 'utf8');
}

export function readLockedTool(lockFile: string, toolId: string): LockedTool {
	const document = readJson<Record<string, unknown>>(lockFile);
	assertExactKeys(document, ['schemaVersion', 'generatedAt', 'tools'], 'third-party lock');
	if (document.schemaVersion !== 1 || typeof document.generatedAt !== 'string' || !Array.isArray(document.tools)) {
		throw new Error('Invalid third-party lock header');
	}
	const ids = new Set<string>();
	let selected: LockedTool | undefined;
	for (const [index, value] of document.tools.entries()) {
		if (!isRecord(value)) {
			throw new Error(`third-party lock tool ${index} must be an object`);
		}
		assertExactKeys(value, ['id', 'version', 'ref', 'commit', 'repository', 'license'], `third-party lock tool ${index}`);
		for (const field of ['id', 'version', 'ref', 'commit', 'repository', 'license']) {
			if (typeof value[field] !== 'string' || value[field].length === 0) {
				throw new Error(`third-party lock tool ${index}.${field} must be non-empty`);
			}
		}
		if (!GIT_OBJECT.test(String(value.commit))) {
			throw new Error(`third-party lock tool ${index}.commit must be a full lowercase Git object id`);
		}
		if (!String(value.repository).startsWith('https://github.com/')) {
			throw new Error(`third-party lock tool ${index}.repository must be an HTTPS GitHub URL`);
		}
		if (ids.has(String(value.id))) {
			throw new Error(`Duplicate third-party tool ${String(value.id)}`);
		}
		ids.add(String(value.id));
		if (value.id === toolId) {
			selected = value as unknown as LockedTool;
		}
	}
	if (!selected) {
		throw new Error(`Third-party lock entry ${toolId} is missing`);
	}
	return selected;
}

export function assertGitIdentity(root: string, tool: LockedTool): void {
	const head = runGit(root, ['rev-parse', 'HEAD']);
	if (head !== tool.commit) {
		throw new Error(`${tool.id}: expected commit ${tool.commit}, got ${head}`);
	}
	const refCommit = runGit(root, ['rev-parse', `${tool.ref}^{commit}`]);
	if (refCommit !== tool.commit) {
		throw new Error(`${tool.id}: ref ${tool.ref} resolves to ${refCommit}, not ${tool.commit}`);
	}
	const status = spawnSync('git', ['-C', root, 'status', '--porcelain', '--untracked-files=all'], {
		encoding: 'utf8', timeout: 30_000,
	});
	if (status.error || status.status !== 0 || status.signal) {
		throw new Error(`${tool.id}: cannot inspect checkout cleanliness`);
	}
	if (status.stdout.trim().length !== 0) {
		throw new Error(`${tool.id}: checkout is dirty; benchmark identity is not pinned`);
	}
}

export function lockedExecutable(runtimeLockFile: string, toolsRoot: string, toolId: string): { path: string; sha256: string } {
	const document = readJson<Record<string, unknown>>(runtimeLockFile);
	assertExactKeys(document, ['schemaVersion', 'platform', 'executables'], 'runtime lock');
	if (document.schemaVersion !== 1 || document.platform !== 'win32-x64' || !Array.isArray(document.executables)) {
		throw new Error('Invalid benchmark runtime lock header');
	}
	if (`${process.platform}-${process.arch}` !== document.platform) {
		throw new Error(`Runtime lock is for ${String(document.platform)}, current runtime is ${process.platform}-${process.arch}`);
	}
	const matches = document.executables.filter(value => isRecord(value) && value.toolId === toolId);
	if (matches.length !== 1) {
		throw new Error(`Runtime lock must contain exactly one executable for ${toolId}`);
	}
	const entry = matches[0];
	assertExactKeys(entry, ['toolId', 'relativePath', 'sha256'], `${toolId} runtime lock`);
	if (typeof entry.relativePath !== 'string' || path.isAbsolute(entry.relativePath) || entry.relativePath.split(/[\\/]/).includes('..')) {
		throw new Error(`${toolId}: runtime path must be safe and relative`);
	}
	if (typeof entry.sha256 !== 'string' || !SHA256.test(entry.sha256)) {
		throw new Error(`${toolId}: runtime SHA-256 is invalid`);
	}
	const executable = path.resolve(toolsRoot, ...entry.relativePath.split('/'));
	const relative = path.relative(path.resolve(toolsRoot), executable);
	if (relative.startsWith('..') || path.isAbsolute(relative) || !fs.existsSync(executable)) {
		throw new Error(`${toolId}: locked executable is missing or escapes tools root`);
	}
	const actual = sha256File(executable);
	if (actual !== entry.sha256) {
		throw new Error(`${toolId}: executable SHA-256 drift (expected ${entry.sha256}, got ${actual})`);
	}
	return { path: executable, sha256: actual };
}

export function executeWithWatchdog(command: string, args: string[], timeoutMs: number): SpawnOutcome {
	if (!Number.isSafeInteger(timeoutMs) || timeoutMs <= 0) {
		throw new Error('Watchdog timeout must be a positive safe integer');
	}
	const started = process.hrtime.bigint();
	const result = spawnSync(command, args, {
		encoding: 'utf8', timeout: timeoutMs, maxBuffer: 32 * 1024 * 1024,
	});
	const runtimeMs = Number(process.hrtime.bigint() - started) / 1_000_000;
	const timedOut = (result.error as NodeJS.ErrnoException | undefined)?.code === 'ETIMEDOUT';
	const status = timedOut ? 'timeout' : result.error || result.status !== 0 || result.signal ? 'error' : 'ok';
	return {
		status,
		code: timedOut ? 'WATCHDOG_TIMEOUT' : status === 'ok' ? 'OK' : 'PROCESS_ERROR',
		exitCode: result.status,
		signal: result.signal,
		runtimeMs,
		stdout: result.stdout ?? '',
		stderr: result.stderr ?? '',
		...(result.error ? { errorMessage: result.error.message } : {}),
	};
}

export function writeExecutionArtifact(file: string, runner: string, entryId: string, timeoutMs: number, outcome: SpawnOutcome): void {
	writeJson(file, {
		schemaVersion: 1,
		runner,
		entryId,
		timeoutMs,
		status: outcome.status,
		code: outcome.code,
		exitCode: outcome.exitCode,
		signal: outcome.signal,
		runtimeMs: outcome.runtimeMs,
		stdoutSha256: sha256Hex(outcome.stdout),
		stderrSha256: sha256Hex(outcome.stderr),
		...(outcome.errorMessage ? { errorMessage: outcome.errorMessage } : {}),
	});
}

export function confusionMatrix(universe: string[], expectedValues: Iterable<string>, detectedValues: Iterable<string>): ConfusionMatrix {
	const uniqueUniverse = new Set(universe);
	if (uniqueUniverse.size !== universe.length) {
		throw new Error('Metric universe contains duplicate identities');
	}
	const expected = new Set(expectedValues);
	const detected = new Set(detectedValues);
	for (const value of [...expected, ...detected]) {
		if (!uniqueUniverse.has(value)) {
			throw new Error(`Metric identity ${value} is outside the declared universe`);
		}
	}
	let truePositive = 0;
	let falsePositive = 0;
	let trueNegative = 0;
	let falseNegative = 0;
	for (const value of universe) {
		const truth = expected.has(value);
		const actual = detected.has(value);
		if (truth && actual) {
			truePositive++;
		} else if (actual) {
			falsePositive++;
		} else if (truth) {
			falseNegative++;
		} else {
			trueNegative++;
		}
	}
	return {
		truePositive,
		falsePositive,
		trueNegative,
		falseNegative,
		precision: truePositive + falsePositive === 0 ? 0 : truePositive / (truePositive + falsePositive),
		recall: truePositive + falseNegative === 0 ? 0 : truePositive / (truePositive + falseNegative),
	};
}

export function assertAtlasBenchmarkRecords(records: AtlasBenchmarkRecord[], universeSize: number): void {
	const ids = new Set<string>();
	for (const [index, record] of records.entries()) {
		const validated = validateAtlasRecord(record, `benchmark[${index}]`);
		if (validated.recordType !== 'benchmark') {
			throw new Error(`benchmark[${index}] is not a benchmark record`);
		}
		if (ids.has(record.id)) {
			throw new Error(`Duplicate benchmark record ${record.id}`);
		}
		ids.add(record.id);
		if (record.truePositive + record.falsePositive + record.trueNegative + record.falseNegative !== universeSize) {
			throw new Error(`${record.id}: confusion matrix does not cover the corpus universe`);
		}
		const serialized = canonicalJson(record);
		for (const forbidden of ['expectedFunctions', 'detectedFunctions', 'binaryPath', 'targetSha256', 'address']) {
			if (serialized.includes(`\"${forbidden}\"`)) {
				throw new Error(`${record.id}: target-specific field ${forbidden} is forbidden in Atlas benchmark records`);
			}
		}
	}
}

/** Keep the first measured runtime for a byte-stable Atlas baseline when all semantic fields are unchanged. */
export function preserveBaselineRuntime(next: AtlasBenchmarkRecord[], existingFile: string): AtlasBenchmarkRecord[] {
	if (!fs.existsSync(existingFile)) {
		return next;
	}
	let existing: AtlasBenchmarkRecord[];
	try {
		existing = readJson<AtlasBenchmarkRecord[]>(existingFile);
	} catch {
		return next;
	}
	const prior = new Map(existing.map(record => [record.id, record]));
	return next.map(record => {
		const candidate = prior.get(record.id);
		if (!candidate || !Number.isFinite(candidate.runtimeMs) || candidate.runtimeMs < 0) {
			return record;
		}
		const withoutRuntime = ({ runtimeMs: _runtimeMs, ...value }: AtlasBenchmarkRecord) => value;
		return canonicalJson(withoutRuntime(candidate)) === canonicalJson(withoutRuntime(record))
			? { ...record, runtimeMs: candidate.runtimeMs }
			: record;
	});
}

export function policySha256(file: string): string {
	return sha256Hex(canonicalJson(readJson<unknown>(file)));
}

function runGit(root: string, args: string[]): string {
	const result = spawnSync('git', ['-C', root, ...args], { encoding: 'utf8', timeout: 30_000 });
	if (result.error || result.status !== 0 || result.signal) {
		throw new Error(`${root}: git ${args.join(' ')} failed`);
	}
	return result.stdout.trim();
}

function isRecord(value: unknown): value is Record<string, unknown> {
	return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function assertExactKeys(value: Record<string, unknown>, keys: string[], label: string): void {
	const expected = new Set(keys);
	for (const key of Object.keys(value)) {
		if (!expected.has(key)) {
			throw new Error(`${label} contains unknown field ${key}`);
		}
	}
}
