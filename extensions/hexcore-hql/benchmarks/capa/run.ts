import { spawnSync } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import { canonicalJson, sha256Hex } from '../../src/atlas/canonical.js';
import { getDefaultSignatures } from '../../src/signatures/loader.js';
import { signatureSetSha256 } from '../../src/scan.js';
import type { AtlasBenchmarkRecord } from '../../src/atlas/types.js';
import {
	assertAtlasBenchmarkRecords,
	assertGitIdentity,
	assertSafeEntryId,
	confusionMatrix,
	executeWithWatchdog,
	lockedExecutable,
	policySha256,
	preserveBaselineRuntime,
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
	sourceSha256: string;
	groundTruthSha256: string;
	configurationSha256: string;
	exports: Array<{ name: string; rva: string }>;
}

interface BuildManifest {
	schemaVersion: number;
	corpusId: string;
	entries: BuildEntry[];
}

interface GroundTruth {
	schemaVersion: number;
	corpusId: string;
	source: string;
	functions: Record<string, string[]>;
}

interface Mapping {
	hqlRuleId: string;
	relationship: string;
	aggregation: 'any' | 'all';
	capaRules: string[];
	limitations: string;
}

interface MappingDocument {
	schemaVersion: number;
	capaVersion: string;
	rulesVersion: string;
	mappings: Mapping[];
}

interface CapaNormalizationOperation {
	operation: 'remove' | 'replace';
	pointer: string;
	value?: unknown;
	reason: string;
}

interface CapaNormalizationPolicy {
	schemaVersion: number;
	id: string;
	tool: string;
	operations: CapaNormalizationOperation[];
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
const runDir = path.join(packageRoot, 'benchmarks', 'capa', 'runs', entryId);
const statusFile = path.join(runDir, 'capa.status.json');
fs.mkdirSync(runDir, { recursive: true });

try {
	runBenchmark();
} catch (error) {
	const code = error instanceof BenchmarkError ? error.code : 'CONTRACT_ERROR';
	const message = error instanceof Error ? error.message : String(error);
	writeJson(path.join(runDir, 'capa.failure.json'), { schemaVersion: 1, runner: 'capa', entryId, code, message });
	writeJson(statusFile, { schemaVersion: 1, runner: 'capa', runnerVersion: RUNNER_VERSION, entryId, status: 'error', code });
	console.error(`capa benchmark failed [${code}]: ${message}`);
	process.exitCode = 1;
}

function runBenchmark(): void {
	const manifestPath = path.join(packageRoot, 'benchmarks', 'corpus', 'build', 'build-manifest.json');
	const manifest = readJson<BuildManifest>(manifestPath);
	if (manifest.schemaVersion !== 2 || !Array.isArray(manifest.entries)) {
		throw new BenchmarkError('CORPUS_CONTRACT', 'Invalid corpus build manifest');
	}
	const entry = manifest.entries.find(candidate => candidate.id === entryId);
	if (!entry) {
		throw new BenchmarkError('CORPUS_CONTRACT', `Unknown corpus entry ${entryId}`);
	}
	const binaryPath = path.resolve(entry.binaryPath);
	if (sha256File(binaryPath) !== entry.binarySha256) {
		throw new BenchmarkError('INPUT_IDENTITY', `${entryId}: binary hash drift`);
	}

	const lockPath = path.join(packageRoot, 'benchmarks', 'third_party.lock.json');
	const runtimeLockPath = path.join(packageRoot, 'benchmarks', 'runtime.lock.json');
	const capaLock = readLockedTool(lockPath, 'mandiant.capa');
	const rulesLock = readLockedTool(lockPath, 'mandiant.capa-rules');
	if (capaLock.version.split('.')[0] !== rulesLock.version.split('.')[0]) {
		throw new BenchmarkError('TOOL_IDENTITY', 'capa and capa-rules major versions must match');
	}
	const capaSource = path.join(toolsRoot, 'src', 'capa');
	const rulesSource = path.join(toolsRoot, 'src', 'capa-rules');
	assertGitIdentity(capaSource, capaLock);
	assertGitIdentity(rulesSource, rulesLock);
	const capaExecutable = lockedExecutable(runtimeLockPath, toolsRoot, capaLock.id);
	assertVersion(capaExecutable.path, `capa ${capaLock.version}`);

	const policyPath = path.join(packageRoot, 'benchmarks', 'capa', 'normalization-policy.json');
	const policy = readJson<CapaNormalizationPolicy>(policyPath);
	validatePolicy(policy);
	const normalizationPolicySha256 = policySha256(policyPath);
	const args = ['-j', '-r', rulesSource, binaryPath];
	const configurationSha256 = sha256Hex(canonicalJson({
		runnerVersion: RUNNER_VERSION,
		tool: { version: capaLock.version, commit: capaLock.commit, executableSha256: capaExecutable.sha256 },
		rules: { version: rulesLock.version, commit: rulesLock.commit },
		logicalArgs: ['-j', '-r', `capa-rules@${rulesLock.commit}`, `sha256:${entry.binarySha256}`],
		normalizationPolicySha256,
	}));

	const outcome = executeWithWatchdog(capaExecutable.path, args, WATCHDOG_MS);
	fs.writeFileSync(path.join(runDir, 'capa.raw.json'), outcome.stdout, 'utf8');
	fs.writeFileSync(path.join(runDir, 'capa.stderr.txt'), outcome.stderr, 'utf8');
	writeExecutionArtifact(path.join(runDir, 'capa.execution.json'), 'capa', entryId, WATCHDOG_MS, outcome);
	if (outcome.status !== 'ok') {
		throw new BenchmarkError(outcome.code, `capa process failed: exit=${outcome.exitCode} signal=${outcome.signal ?? 'none'}`);
	}

	let raw: any;
	try {
		raw = JSON.parse(outcome.stdout);
	} catch (error) {
		throw new BenchmarkError('RESULT_CONTRACT', `Malformed capa ResultDocument: ${error instanceof Error ? error.message : String(error)}`);
	}
	if (raw.meta?.version !== capaLock.version || raw.meta?.sample?.sha256 !== entry.binarySha256) {
		throw new BenchmarkError('RESULT_IDENTITY', 'capa ResultDocument identity mismatch');
	}
	const normalized = applyNormalizationPolicy(raw, policy, {
		'<RULES_COMMIT>': rulesLock.commit,
		'<TARGET_SHA256>': entry.binarySha256,
		'<TARGET_BASENAME>': path.basename(binaryPath),
	});
	const normalizedJson = canonicalJson(normalized);
	const normalizedSha256 = sha256Hex(normalizedJson);
	fs.writeFileSync(path.join(runDir, 'capa.normalized.json'), `${normalizedJson}\n`, 'utf8');

	const groundTruthPath = path.join(packageRoot, 'benchmarks', 'corpus', 'ground_truth.json');
	const groundTruth = readJson<GroundTruth>(groundTruthPath);
	const sourcePath = path.join(packageRoot, 'benchmarks', 'corpus', groundTruth.source);
	if (groundTruth.schemaVersion !== 1 || groundTruth.corpusId !== manifest.corpusId || sha256File(groundTruthPath) !== entry.groundTruthSha256 || sha256File(sourcePath) !== entry.sourceSha256) {
		throw new BenchmarkError('CORPUS_IDENTITY', 'Corpus source or ground-truth identity drift');
	}
	const mappingPath = path.join(packageRoot, 'benchmarks', 'capa', 'mapping.json');
	const mappingDocument = readJson<MappingDocument>(mappingPath);
	validateMappings(mappingDocument, capaLock.version, rulesLock.version);
	const baseAddress = exactBigInt(raw.meta?.analysis?.base_address?.value, 'capa base address');
	const exports = entry.exports
		.map(item => ({ name: item.name, address: baseAddress + exactBigInt(item.rva, `${item.name} RVA`) }))
		.sort((left, right) => left.address < right.address ? -1 : left.address > right.address ? 1 : left.name.localeCompare(right.name));
	const functionNames = Object.keys(groundTruth.functions).sort();
	const exportedNames = exports.map(item => item.name).sort();
	if (canonicalJson(exportedNames) !== canonicalJson(functionNames)) {
		throw new BenchmarkError('CORPUS_CONTRACT', 'Ground-truth functions and exported corpus functions differ');
	}
	const functionForAddress = (address: bigint): string | undefined => {
		for (let index = 0; index < exports.length; index++) {
			const next = exports[index + 1]?.address ?? (exports[index].address + 0x10000n);
			if (address >= exports[index].address && address < next) {
				return exports[index].name;
			}
		}
		return undefined;
	};
	const capaFunctionsByRule = new Map<string, Set<string>>();
	const unattributedCapaRules = new Set<string>();
	for (const [ruleName, rule] of Object.entries<any>(raw.rules ?? {})) {
		const functions = new Set<string>();
		let matchedWithoutOwner = false;
		for (const match of rule.matches ?? []) {
			const value = match?.[0]?.value;
			if (typeof value !== 'number' && typeof value !== 'string') {
				matchedWithoutOwner = true;
				continue;
			}
			const owner = functionForAddress(exactBigInt(value, `${ruleName} match address`));
			if (owner) {
				functions.add(owner);
			} else {
				matchedWithoutOwner = true;
			}
		}
		capaFunctionsByRule.set(ruleName, functions);
		if (matchedWithoutOwner) {
			unattributedCapaRules.add(ruleName);
		}
	}

	const activeRules = new Map(getDefaultSignatures().map(rule => [rule.id, rule]));
	const signatureHash = signatureSetSha256([...activeRules.values()]);
	const corpusSha256 = sha256Hex(canonicalJson({
		corpusId: groundTruth.corpusId,
		binarySha256: entry.binarySha256,
		groundTruthSha256: entry.groundTruthSha256,
		configurationSha256: entry.configurationSha256,
		mapping: mappingDocument,
		capaCommit: capaLock.commit,
		rulesCommit: rulesLock.commit,
		runnerVersion: RUNNER_VERSION,
		normalizationPolicySha256,
	}));
	let benchmarks: AtlasBenchmarkRecord[] = [];
	const comparisonDetails: Array<Record<string, unknown>> = [];
	for (const mapping of mappingDocument.mappings) {
		const rule = activeRules.get(mapping.hqlRuleId);
		if (!rule?.version) {
			throw new BenchmarkError('MAPPING_CONTRACT', `Mapping references unknown or unversioned rule ${mapping.hqlRuleId}`);
		}
		const detected = new Set(functionNames.filter(functionName => {
			const branchMatches = mapping.capaRules.map(capaRule => capaFunctionsByRule.get(capaRule)?.has(functionName) === true);
			return mapping.aggregation === 'all' ? branchMatches.every(Boolean) : branchMatches.some(Boolean);
		}));
		const expected = new Set(functionNames.filter(functionName => groundTruth.functions[functionName].includes(mapping.hqlRuleId)));
		const metrics = confusionMatrix(functionNames, expected, detected);
		const record: AtlasBenchmarkRecord = {
			recordType: 'benchmark',
			id: `capa-${capaLock.version}.${entryId}.${mapping.hqlRuleId}`.toLowerCase(),
			ruleId: mapping.hqlRuleId,
			ruleVersion: rule.version,
			corpus: `${groundTruth.corpusId}/capa/${entryId}`,
			corpusSha256,
			...metrics,
			runtimeMs: outcome.runtimeMs,
			engineVersion: `capa-${capaLock.version}`,
			signatureSetSha256: signatureHash,
			notes: `${mapping.relationship}: ${mapping.limitations}`,
		};
		benchmarks.push(record);
		comparisonDetails.push({
			ruleId: mapping.hqlRuleId,
			expectedFunctions: [...expected].sort(),
			detectedFunctions: [...detected].sort(),
			capaRules: mapping.capaRules,
			metrics,
		});
	}

	const resultDir = path.join(packageRoot, 'benchmarks', 'results');
	const resultFile = path.join(resultDir, `capa-${entryId}.json`);
	benchmarks = preserveBaselineRuntime(benchmarks, resultFile);
	assertAtlasBenchmarkRecords(benchmarks, functionNames.length);
	writeJson(resultFile, benchmarks);
	const benchmarkRecordsSha256 = sha256Hex(canonicalJson(benchmarks));
	writeJson(path.join(runDir, 'comparison.json'), {
		schemaVersion: 2,
		runnerVersion: RUNNER_VERSION,
		tool: { version: capaLock.version, commit: capaLock.commit, executableSha256: capaExecutable.sha256 },
		rules: { version: rulesLock.version, commit: rulesLock.commit },
		input: { id: entryId, path: path.basename(binaryPath), sha256: entry.binarySha256 },
		configurationSha256,
		normalization: { policyId: policy.id, policySha256: normalizationPolicySha256, normalizedSha256 },
		corpusSha256,
		unattributedCapaRules: [...unattributedCapaRules].sort(),
		comparisons: comparisonDetails,
		benchmarkRecordsSha256,
	});
	writeJson(statusFile, {
		schemaVersion: 1,
		runner: 'capa',
		runnerVersion: RUNNER_VERSION,
		entryId,
		status: 'ok',
		code: 'OK',
		identity: {
			targetSha256: entry.binarySha256,
			toolCommit: capaLock.commit,
			toolExecutableSha256: capaExecutable.sha256,
			rulesCommit: rulesLock.commit,
			configurationSha256,
			normalizationPolicySha256,
			normalizedSha256,
			benchmarkRecordsSha256,
		},
	});
	fs.rmSync(path.join(runDir, 'capa.failure.json'), { force: true });
	console.log(`capa benchmark: ${entryId}, ${benchmarks.length} mappings, runtime=${outcome.runtimeMs.toFixed(1)}ms, normalized=${normalizedSha256}`);
}

function assertVersion(executable: string, expected: string): void {
	const version = spawnSync(executable, ['--version'], { encoding: 'utf8', timeout: 30_000 });
	if (version.error || version.status !== 0 || version.signal || version.stdout.trim() !== expected) {
		throw new BenchmarkError('TOOL_IDENTITY', `Unexpected tool version: ${version.stdout}${version.stderr}`);
	}
}

function validateMappings(document: MappingDocument, capaVersion: string, rulesVersion: string): void {
	if (document.schemaVersion !== 1 || document.capaVersion !== capaVersion || document.rulesVersion !== rulesVersion || !Array.isArray(document.mappings) || document.mappings.length === 0) {
		throw new BenchmarkError('MAPPING_CONTRACT', 'Invalid or version-mismatched capa mapping document');
	}
	const ids = new Set<string>();
	for (const mapping of document.mappings) {
		if (!mapping.hqlRuleId || !mapping.relationship || !mapping.limitations || !['any', 'all'].includes(mapping.aggregation) || !Array.isArray(mapping.capaRules) || mapping.capaRules.length === 0) {
			throw new BenchmarkError('MAPPING_CONTRACT', `Invalid mapping for ${mapping.hqlRuleId ?? '<unknown>'}`);
		}
		if (ids.has(mapping.hqlRuleId) || new Set(mapping.capaRules).size !== mapping.capaRules.length) {
			throw new BenchmarkError('MAPPING_CONTRACT', `Duplicate mapping or capa rule for ${mapping.hqlRuleId}`);
		}
		ids.add(mapping.hqlRuleId);
	}
}

function validatePolicy(policy: CapaNormalizationPolicy): void {
	if (canonicalJson(Object.keys(policy).sort()) !== canonicalJson(['id', 'operations', 'schemaVersion', 'tool'])) {
		throw new BenchmarkError('NORMALIZATION_POLICY', 'capa normalization policy contains missing or unknown fields');
	}
	if (policy.schemaVersion !== 1 || policy.id !== 'hexcore.capa-result-document.v1' || policy.tool !== 'mandiant.capa' || !Array.isArray(policy.operations)) {
		throw new BenchmarkError('NORMALIZATION_POLICY', 'Invalid capa normalization policy header');
	}
	const expectedPointers = ['/meta/timestamp', '/meta/argv', '/meta/sample/path', '/meta/analysis/rules'];
	const pointers = policy.operations.map(operation => operation.pointer).sort();
	if (canonicalJson(pointers) !== canonicalJson(expectedPointers.sort()) || new Set(pointers).size !== pointers.length) {
		throw new BenchmarkError('NORMALIZATION_POLICY', 'capa normalization policy must declare exactly the audited volatile path fields');
	}
	for (const operation of policy.operations) {
		const expectedKeys = operation.operation === 'remove' ? ['operation', 'pointer', 'reason'] : ['operation', 'pointer', 'reason', 'value'];
		if (canonicalJson(Object.keys(operation).sort()) !== canonicalJson(expectedKeys.sort())) {
			throw new BenchmarkError('NORMALIZATION_POLICY', `Normalization operation ${operation.pointer} contains missing or unknown fields`);
		}
		if (!operation.reason || !['remove', 'replace'].includes(operation.operation) || (operation.operation === 'replace' && operation.value === undefined)) {
			throw new BenchmarkError('NORMALIZATION_POLICY', `Invalid normalization operation ${operation.pointer}`);
		}
	}
}

function applyNormalizationPolicy(value: unknown, policy: CapaNormalizationPolicy, replacements: Record<string, string>): unknown {
	const normalized = JSON.parse(JSON.stringify(value)) as Record<string, unknown>;
	for (const operation of policy.operations) {
		const parts = operation.pointer.split('/').slice(1).map(unescapePointer);
		let owner: any = normalized;
		for (const part of parts.slice(0, -1)) {
			if (!owner || typeof owner !== 'object' || !(part in owner)) {
				throw new BenchmarkError('NORMALIZATION_POLICY', `Declared pointer ${operation.pointer} is absent`);
			}
			owner = owner[part];
		}
		const key = parts.at(-1)!;
		if (!owner || typeof owner !== 'object' || !(key in owner)) {
			throw new BenchmarkError('NORMALIZATION_POLICY', `Declared pointer ${operation.pointer} is absent`);
		}
		if (operation.operation === 'remove') {
			delete owner[key];
		} else {
			owner[key] = expandPolicyValue(operation.value, replacements);
		}
	}
	return normalized;
}

function expandPolicyValue(value: unknown, replacements: Record<string, string>): unknown {
	if (typeof value === 'string') {
		return Object.entries(replacements).reduce((current, [token, replacement]) => current.split(token).join(replacement), value);
	}
	if (Array.isArray(value)) {
		return value.map(entry => expandPolicyValue(entry, replacements));
	}
	if (value && typeof value === 'object') {
		return Object.fromEntries(Object.entries(value).map(([key, entry]) => [key, expandPolicyValue(entry, replacements)]));
	}
	return value;
}

function unescapePointer(value: string): string {
	return value.replace(/~1/g, '/').replace(/~0/g, '~');
}

function exactBigInt(value: unknown, label: string): bigint {
	if (typeof value === 'number') {
		if (!Number.isSafeInteger(value)) {
			throw new BenchmarkError('RESULT_CONTRACT', `${label} must be an exact integer`);
		}
		return BigInt(value);
	}
	if (typeof value === 'string' && /^(?:0x[0-9a-f]+|[0-9]+)$/i.test(value)) {
		return BigInt(value);
	}
	throw new BenchmarkError('RESULT_CONTRACT', `${label} must be an integer`);
}
