import * as fs from 'fs';
import * as path from 'path';
import { hydrateHAST } from '../../src/adapter/flatbuf.js';
import {
	buildFunctionAtlasBenchmarkArtifact,
	buildFunctionAtlasRecord,
	InMemoryFunctionAtlasIndex,
	type FunctionAtlasRecord,
} from '../../src/atlas/functionAtlas.js';
import { canonicalJson, sha256Hex } from '../../src/atlas/canonical.js';
import { evaluateSimilarityBenchmark } from '../bsim/evaluate.js';
import { readJson, sha256File, writeJson } from '../lib/contract.js';

interface CorpusEntry {
	id: string;
	compiler: string;
	compilerBanner: string;
	compilerArguments: string[];
	linkerArguments: string[];
	architecture: 'x86' | 'x64';
	optimization: string;
	configurationSha256: string;
	sourceSha256: string;
	groundTruthSha256: string;
	binaryPath: string;
	binarySha256: string;
	exports: Array<{ name: string; rva: string }>;
}

interface CorpusManifest {
	schemaVersion: number;
	corpusId: string;
	entries: CorpusEntry[];
}

interface EngineLock {
	schemaVersion: number;
	helix: { version: string; nodeSha256: string; hastSchema: number };
	remill: { version: string; upstreamVersion: string; upstreamCommit: string; nodeSha256: string };
}

interface PeSection {
	name: string;
	virtualAddress: number;
	virtualSize: number;
	rawOffset: number;
	rawSize: number;
}

interface PeImage {
	imageBase: bigint;
	format: 'pe32' | 'pe64';
	sections: PeSection[];
	functionEnds: Map<number, number>;
}

interface NativeHelix {
	HelixEngine: new (architecture: number) => {
		setUseCastLayer(value: boolean): void;
		setFunctionStarts(values: number[]): void;
		version(): string;
		decompileIr(ir: string): { astBuffer?: Buffer; pipeline: string };
		dispose(): void;
	};
}

interface NativeRemill {
	version: string;
	upstreamVersion: string;
	upstreamCommit: string;
	ARCH: { X86: string; AMD64: string };
	OS: { WINDOWS: string };
	RemillLifter: new (architecture: string, os: string) => {
		liftBytes(code: Buffer, address: bigint, options: Record<string, unknown>): {
			success: boolean;
			error: string;
			ir: string;
			bytesConsumed: number;
			decodedInstructions: number;
			liftedInstructions: number;
			unsupportedInstructions: number;
			decodeFailureInstructions: number;
			semanticCoverage: number;
			truncated?: boolean;
			unsupportedOpcodes: Record<string, number>;
		};
		close(): void;
	};
}

const RUNNER_VERSION = 'hast-remill-v1';
const packageRoot = path.resolve(__dirname, '..', '..');
const benchmarkRoot = path.join(packageRoot, 'benchmarks', 'function-atlas');
const runRoot = path.join(benchmarkRoot, 'runs');
const queryRoot = path.join(runRoot, 'queries');
const statusFile = path.join(runRoot, 'status.json');
fs.mkdirSync(queryRoot, { recursive: true });

function canonicalArtifactPaths(): string[] {
	return [
		path.join(benchmarkRoot, 'function-atlas-vs-bsim.json'),
		path.join(runRoot, 'hast-evidence.json'),
		statusFile,
		...fs.readdirSync(queryRoot).filter(name => name.endsWith('.json')).sort(compareAscii).map(name => path.join(queryRoot, name)),
	];
}

function captureArtifactHashes(): Map<string, string> {
	return new Map(canonicalArtifactPaths()
		.filter(file => fs.existsSync(file))
		.map(file => [path.relative(packageRoot, file).replace(/\\/g, '/'), sha256File(file)]));
}

function compareAscii(left: string, right: string): number {
	return left < right ? -1 : left > right ? 1 : 0;
}

try {
	run();
} catch (error) {
	const message = error instanceof Error ? error.message : String(error);
	writeJson(path.join(runRoot, 'failure.json'), { schemaVersion: 1, runner: 'function-atlas', code: 'GATE_FAILED', message });
	writeJson(statusFile, { schemaVersion: 1, runner: 'function-atlas', runnerVersion: RUNNER_VERSION, status: 'error', code: 'GATE_FAILED' });
	console.error(`Function Atlas benchmark failed: ${message}`);
	process.exitCode = 1;
}

function run(): void {
	const previousArtifactHashes = captureArtifactHashes();
	const manifestPath = path.join(packageRoot, 'benchmarks', 'corpus', 'build', 'build-manifest.json');
	const groundTruthPath = path.join(packageRoot, 'benchmarks', 'corpus', 'ground_truth.json');
	const sourcePath = path.join(packageRoot, 'benchmarks', 'corpus', 'semantic_benchmark.c');
	const manifest = readJson<CorpusManifest>(manifestPath);
	const groundTruth = readJson<{ schemaVersion: number; corpusId: string; functions: Record<string, string[]> }>(groundTruthPath);
	if (manifest.schemaVersion !== 2 || groundTruth.schemaVersion !== 1 || manifest.corpusId !== groundTruth.corpusId || manifest.entries.length !== 16) {
		throw new Error('Function Atlas requires the complete schema-2 16-binary corpus');
	}
	const sourceSha256 = sha256File(sourcePath);
	const groundTruthSha256 = sha256File(groundTruthPath);
	const functionNames = Object.keys(groundTruth.functions).sort();
	if (functionNames.length !== 14) {
		throw new Error('Function Atlas ground truth must contain 14 functions');
	}
	const ids = new Set<string>();
	for (const entry of manifest.entries) {
		if (ids.has(entry.id) || !Array.isArray(entry.compilerArguments) || !Array.isArray(entry.linkerArguments)) {
			throw new Error(`Invalid or duplicate corpus entry ${entry.id}`);
		}
		ids.add(entry.id);
		if (entry.sourceSha256 !== sourceSha256 || entry.groundTruthSha256 !== groundTruthSha256 || sha256File(entry.binaryPath) !== entry.binarySha256) {
			throw new Error(`${entry.id}: source, ground truth, or binary identity drift`);
		}
		if (canonicalJson(entry.exports.map(item => item.name).sort()) !== canonicalJson(functionNames)) {
			throw new Error(`${entry.id}: exported function universe drift`);
		}
	}

	const engineLock = readJson<EngineLock>(path.join(benchmarkRoot, 'engine.lock.json'));
	if (engineLock.schemaVersion !== 1) {
		throw new Error('Unsupported Function Atlas engine lock');
	}
	const helixNode = resolveHelixNode(engineLock.helix.nodeSha256);
	const remillRoot = path.resolve(packageRoot, '..', 'hexcore-remill');
	const remillNode = resolveRemillNode(remillRoot, engineLock.remill.nodeSha256);
	const helix = require(helixNode) as NativeHelix;
	const remill = require(remillRoot) as NativeRemill;
	if (remill.version !== engineLock.remill.version || remill.upstreamVersion !== engineLock.remill.upstreamVersion || remill.upstreamCommit !== engineLock.remill.upstreamCommit) {
		throw new Error('Remill runtime identity differs from the Function Atlas engine lock');
	}

	const allRecords: FunctionAtlasRecord[] = [];
	const evidence: Array<Record<string, unknown>> = [];
	const failures: Array<{ program: string; function: string; error: string }> = [];
	let smallestX86Regression: { program: string; function: string; binarySha256: string; configurationSha256: string; ir: string; error: string } | undefined;
	for (const entry of [...manifest.entries].sort((left, right) => compareAscii(left.id, right.id))) {
		const binary = fs.readFileSync(entry.binaryPath);
		const image = parsePe(binary);
		if ((entry.architecture === 'x64') !== (image.format === 'pe64')) {
			throw new Error(`${entry.id}: manifest and PE architecture differ`);
		}
		const text = image.sections.find(section => section.name === '.text');
		if (!text) {
			throw new Error(`${entry.id}: PE has no .text section`);
		}
		const exports = entry.exports.map(item => {
			const exportRva = exactRva(item.rva);
			return { name: item.name, exportRva, bodyRva: resolveDirectJumpTarget(binary, text, exportRva) };
		}).sort((left, right) => left.bodyRva - right.bodyRva || compareAscii(left.name, right.name));
		if (new Set(exports.map(item => item.bodyRva)).size !== exports.length) {
			throw new Error(`${entry.id}: exported functions resolve to duplicate bodies`);
		}
		const starts = exports.map(item => Number(image.imageBase + BigInt(item.bodyRva)));
		const lifter = new remill.RemillLifter(entry.architecture === 'x64' ? remill.ARCH.AMD64 : remill.ARCH.X86, remill.OS.WINDOWS);
		const engine = new helix.HelixEngine(entry.architecture === 'x64' ? 1 : 0);
		try {
			engine.setUseCastLayer(true);
			engine.setFunctionStarts(starts);
			if (engine.version() !== engineLock.helix.version) {
				throw new Error(`Helix version drift: ${engine.version()}`);
			}
			for (const [index, exported] of exports.entries()) {
				let diagnosticIr: string | undefined;
				try {
				const nextRva = exports[index + 1]?.bodyRva;
				const sectionEnd = text.virtualAddress + text.rawSize;
				const endRva = image.functionEnds.get(exported.bodyRva) ?? nextRva ?? Math.min(sectionEnd, exported.bodyRva + 4096);
				if (endRva <= exported.bodyRva || exported.bodyRva < text.virtualAddress || endRva > sectionEnd) {
					throw new Error(`${entry.id}/${exported.name}: invalid function byte range`);
				}
				const rawStart = text.rawOffset + exported.bodyRva - text.virtualAddress;
				const rawEnd = text.rawOffset + endRva - text.virtualAddress;
				const code = binary.subarray(rawStart, rawEnd);
				const address = image.imageBase + BigInt(exported.bodyRva);
				const exportAddress = image.imageBase + BigInt(exported.exportRva);
				const endAddress = image.imageBase + BigInt(endRva);
				const lift = lifter.liftBytes(code, address, {
					maxBytes: code.length,
					maxInstructions: 4096,
					maxBasicBlocks: 1024,
					splitAtCalls: true,
					optimizeIR: false,
					entryAddress: address,
					reachableOnly: true,
					liftMode: entry.architecture === 'x64' ? 'pe64' : 'generic',
					knownFunctionEnds: [Number(endAddress)],
				});
				if (!lift.success || lift.truncated || lift.semanticCoverage !== 1 || lift.unsupportedInstructions !== 0 || lift.decodeFailureInstructions !== 0) {
					throw new Error(`${entry.id}/${exported.name}: incomplete Remill lift ${JSON.stringify({
						success: lift.success,
						error: lift.error,
						truncated: lift.truncated ?? false,
						semanticCoverage: lift.semanticCoverage,
						decodedInstructions: lift.decodedInstructions,
						liftedInstructions: lift.liftedInstructions,
						unsupportedInstructions: lift.unsupportedInstructions,
						decodeFailureInstructions: lift.decodeFailureInstructions,
						unsupportedOpcodes: lift.unsupportedOpcodes,
					})}`);
				}
				diagnosticIr = lift.ir;
				const decompiled = engine.decompileIr(lift.ir);
				if (decompiled.pipeline !== 'mlir' || !decompiled.astBuffer?.length) {
					throw new Error(`${entry.id}/${exported.name}: Helix did not produce MLIR HAST`);
				}
				const functions = hydrateHAST(decompiled.astBuffer);
				const expectedAddress = `0x${address.toString(16)}`;
				const sourceAddress = `0x${exportAddress.toString(16)}`;
				const fn = functions.find(candidate => candidate.address?.toLowerCase() === expectedAddress) ?? (functions.length === 1 ? functions[0] : undefined);
				if (!fn || fn.hast?.schemaMajor !== engineLock.helix.hastSchema || !fn.hast.semanticEligible || fn.adapterCoverage?.coverage !== 1) {
					throw new Error(`${entry.id}/${exported.name}: HAST v1 semantic eligibility gate failed ${JSON.stringify({
						expectedAddress,
						functionCount: functions.length,
						functions: functions.map(candidate => ({ address: candidate.address, hast: candidate.hast, adapterCoverage: candidate.adapterCoverage })),
					})}`);
				}
				const record = buildFunctionAtlasRecord({
					function: fn,
					sourceFunctionName: exported.name,
					sourceAddress,
					provenance: {
						corpusId: manifest.corpusId,
						corpusVersion: '1',
						sampleId: entry.id,
						sourceSha256,
						groundTruthSha256,
						binarySha256: entry.binarySha256,
						architecture: entry.architecture === 'x64' ? 'x86_64' : 'x86',
						format: image.format,
						compiler: {
							name: entry.compiler,
							version: compilerVersion(entry),
							targetTriple: entry.architecture === 'x64' ? 'x86_64-pc-windows-msvc' : 'i686-pc-windows-msvc',
							optimization: entry.optimization,
							flags: [...entry.compilerArguments, ...entry.linkerArguments],
						},
						producer: { name: 'hexcore-helix', version: engine.version(), hastSchema: engineLock.helix.hastSchema },
					},
				});
				allRecords.push(record);
				evidence.push({
					program: entry.id,
					function: exported.name,
					address: sourceAddress,
					bodyAddress: expectedAddress,
					binarySha256: entry.binarySha256,
					codeSha256: sha256Hex(code),
					irSha256: sha256Hex(lift.ir),
					hastSha256: sha256Hex(decompiled.astBuffer),
					contentId: record.contentId,
					instanceId: record.instanceId,
					bytesConsumed: lift.bytesConsumed,
					instructionCount: lift.decodedInstructions,
					semanticCoverage: lift.semanticCoverage,
					adapterCoverage: fn.adapterCoverage.coverage,
				});
				} catch (error) {
					const message = error instanceof Error ? error.message : String(error);
					failures.push({
						program: entry.id,
						function: exported.name,
						error: message,
					});
					if (entry.architecture === 'x86'
						&& diagnosticIr
						&& message.includes('MLIR verification failed')
						&& (!smallestX86Regression || diagnosticIr.length < smallestX86Regression.ir.length)) {
						smallestX86Regression = {
							program: entry.id,
							function: exported.name,
							binarySha256: entry.binarySha256,
							configurationSha256: entry.configurationSha256,
							ir: diagnosticIr,
							error: message,
						};
					}
				}
			}
		} finally {
			lifter.close();
			engine.dispose();
		}
	}
	if (failures.length > 0 || allRecords.length !== 224 || evidence.length !== 224) {
		const regressionRoot = path.join(benchmarkRoot, 'regressions');
		fs.mkdirSync(regressionRoot, { recursive: true });
		if (smallestX86Regression) {
			const irPath = path.join(regressionRoot, 'x86-current-verifier-failure.ll');
			fs.writeFileSync(irPath, smallestX86Regression.ir, 'utf8');
			writeJson(path.join(regressionRoot, 'x86-current-verifier-failure.json'), {
				schemaVersion: 1,
				producer: { remill: engineLock.remill, helix: engineLock.helix },
				program: smallestX86Regression.program,
				function: smallestX86Regression.function,
				binarySha256: smallestX86Regression.binarySha256,
				configurationSha256: smallestX86Regression.configurationSha256,
				irSha256: sha256Hex(smallestX86Regression.ir),
				irBytes: Buffer.byteLength(smallestX86Regression.ir, 'utf8'),
				error: smallestX86Regression.error,
				reproduction: 'HelixEngine(Architecture.X86).setUseCastLayer(true); decompileIr(irText)',
			});
		}
		writeJson(path.join(regressionRoot, 'adapter-losses.current.json'), {
			schemaVersion: 1,
			producer: { remill: engineLock.remill, helix: engineLock.helix },
			failures: failures.filter(failure => failure.error.includes('HAST v1 semantic eligibility gate failed')),
		});
		writeJson(path.join(runRoot, 'acceptance-failures.json'), {
			schemaVersion: 1,
			runnerVersion: RUNNER_VERSION,
			expectedFunctions: 224,
			acceptedFunctions: allRecords.length,
			failures: failures.sort((left, right) => compareAscii(left.program, right.program) || compareAscii(left.function, right.function)),
		});
		throw new Error(`Function Atlas accepted ${allRecords.length}/224 real HAST functions; ${failures.length} failed semantic gates`);
	}
	fs.rmSync(path.join(runRoot, 'acceptance-failures.json'), { force: true });

	const index = new InMemoryFunctionAtlasIndex();
	for (const record of allRecords) {
		index.add(record);
	}
	const artifactSummaries: Array<Record<string, unknown>> = [];
	for (const entry of [...manifest.entries].sort((left, right) => compareAscii(left.id, right.id))) {
		const records = allRecords.filter(record => record.provenance.sampleId === entry.id);
		const artifact = buildFunctionAtlasBenchmarkArtifact(records.map(record => ({
			record,
			result: index.query(record, { topK: 32, excludeSameBinary: true }),
		})));
		writeJson(path.join(queryRoot, `${entry.id}.json`), artifact);
		artifactSummaries.push({ program: entry.id, binarySha256: entry.binarySha256, queryCount: artifact.queries.length, artifactSha256: artifact.artifactSha256 });
	}
	const queryFiles = fs.readdirSync(queryRoot).filter(name => name.endsWith('.json')).sort();
	if (queryFiles.length !== 16) {
		throw new Error(`Function Atlas query directory contains ${queryFiles.length} files, expected 16`);
	}
	assertBsimCorpus(path.join(packageRoot, 'benchmarks', 'bsim', 'work', 'queries'), manifest, functionNames);
	const comparison = evaluateSimilarityBenchmark({
		bsimPath: path.join(packageRoot, 'benchmarks', 'bsim', 'work', 'queries'),
		functionAtlasPath: queryRoot,
		groundTruthPath,
	});
	const evidenceDocument = {
		schemaVersion: 1,
		runnerVersion: RUNNER_VERSION,
		engines: {
			helix: { version: engineLock.helix.version, nodeSha256: sha256File(helixNode) },
			remill: { version: remill.version, upstreamVersion: remill.upstreamVersion, upstreamCommit: remill.upstreamCommit, nodeSha256: sha256File(remillNode) },
		},
		functions: evidence.sort((left, right) => compareAscii(canonicalJson(left), canonicalJson(right))),
	};
	writeJson(path.join(runRoot, 'hast-evidence.json'), evidenceDocument);
	const logicalBaseline = {
		schemaVersion: 1,
		runnerVersion: RUNNER_VERSION,
		corpus: {
			id: manifest.corpusId,
			sourceSha256,
			groundTruthSha256,
			binaryCount: manifest.entries.length,
			functionCount: allRecords.length,
			corpusIdentitySha256: sha256Hex(canonicalJson(manifest.entries.map(entry => ({ id: entry.id, binarySha256: entry.binarySha256, configurationSha256: entry.configurationSha256 })) )),
		},
		engines: evidenceDocument.engines,
		artifacts: artifactSummaries,
		evidenceSha256: sha256Hex(canonicalJson(evidenceDocument)),
		comparison,
	};
	const baseline = { ...logicalBaseline, artifactSha256: sha256Hex(canonicalJson(logicalBaseline)) };
	writeJson(path.join(benchmarkRoot, 'function-atlas-vs-bsim.json'), baseline);
	const regressionRoot = path.join(benchmarkRoot, 'regressions');
	for (const stale of [
		'x86-current-verifier-failure.ll',
		'x86-current-verifier-failure.json',
		'adapter-losses.current.json',
	]) {
		fs.rmSync(path.join(regressionRoot, stale), { force: true });
	}
	writeJson(path.join(regressionRoot, 'adapter-losses.resolved.json'), {
		schemaVersion: 1,
		status: 'resolved',
		producer: {
			helixNodeSha256: engineLock.helix.nodeSha256,
			hqlAdapterContract: 'hast-v1-unary-compound-v1',
		},
		failures: [],
		acceptedFunctions: allRecords.length,
		expectedFunctions: 224,
		functionAtlasArtifactSha256: baseline.artifactSha256,
	});
	const resolvedRegressionPath = path.join(regressionRoot, 'x86-width-and-unary-regression.json');
	if (fs.existsSync(resolvedRegressionPath)) {
		const resolvedRegression = readJson<Record<string, unknown>>(resolvedRegressionPath);
		writeJson(resolvedRegressionPath, {
			...resolvedRegression,
			producer: { remill: engineLock.remill, helix: engineLock.helix },
			acceptedBy: {
				functionAtlasArtifactSha256: baseline.artifactSha256,
				functionCount: allRecords.length,
				binaryCount: manifest.entries.length,
			},
		});
	}
	writeJson(statusFile, {
		schemaVersion: 1,
		runner: 'function-atlas',
		runnerVersion: RUNNER_VERSION,
		status: 'ok',
		code: 'OK',
		identity: { artifactSha256: baseline.artifactSha256, evidenceSha256: logicalBaseline.evidenceSha256 },
	});
	const rerunArtifacts = canonicalArtifactPaths().map(file => {
		const relativePath = path.relative(packageRoot, file).replace(/\\/g, '/');
		const currentSha256 = sha256File(file);
		const previousSha256 = previousArtifactHashes.get(relativePath);
		return {
			path: relativePath,
			previousSha256: previousSha256 ?? null,
			currentSha256,
			identical: previousSha256 === currentSha256,
		};
	});
	writeJson(path.join(runRoot, 'rerun-verification.json'), {
		schemaVersion: 1,
		runner: 'function-atlas',
		runnerVersion: RUNNER_VERSION,
		verificationComplete: previousArtifactHashes.size === rerunArtifacts.length,
		allCanonicalArtifactsIdentical: previousArtifactHashes.size === rerunArtifacts.length
			&& rerunArtifacts.every(artifact => artifact.identical),
		artifacts: rerunArtifacts,
	});
	fs.rmSync(path.join(runRoot, 'failure.json'), { force: true });
	console.log(`Function Atlas: 16 binaries, 224 HAST functions, top1=${comparison.functionAtlas?.metrics.top1Accuracy}, recall=${comparison.functionAtlas?.metrics.recall}, artifact=${baseline.artifactSha256}`);
}

function resolveHelixNode(expectedSha256: string): string {
	const candidates = [
		process.env.HEXCORE_HELIX_HAST_NODE,
		path.resolve(packageRoot, '..', 'hexcore-helix', 'hexcore-helix.win32-x64-msvc.node'),
		path.resolve(packageRoot, '..', '..', '..', 'HexCore-Helix-v2', 'target', 'release', 'hexcore-helix.hast1-r30.node'),
	].filter((value): value is string => Boolean(value));
	const match = candidates.find(candidate => fs.existsSync(candidate) && sha256File(candidate) === expectedSha256);
	if (!match) {
		throw new Error(`No Helix HAST v1 node matches pinned SHA-256 ${expectedSha256}; set HEXCORE_HELIX_HAST_NODE`);
	}
	return match;
}

function resolveRemillNode(root: string, expectedSha256: string): string {
	const candidates = [
		path.join(root, 'build', 'Release', 'hexcore_remill.node'),
		path.join(root, 'prebuilds', `${process.platform}-${process.arch}`, 'hexcore-remill.node'),
	];
	const match = candidates.find(candidate => fs.existsSync(candidate) && sha256File(candidate) === expectedSha256);
	if (!match) {
		throw new Error(`No Remill node matches pinned SHA-256 ${expectedSha256}`);
	}
	return match;
}

function compilerVersion(entry: CorpusEntry): string {
	const pattern = entry.compiler === 'clangcl' ? /clang version ([^\r\n]+)/i : /cl\.exe:.*?(\d+\.\d+(?:\.\d+)*)/i;
	const match = pattern.exec(entry.compilerBanner);
	if (!match) {
		throw new Error(`${entry.id}: compiler version is absent from the verified banner`);
	}
	return match[1].trim();
}

function parsePe(buffer: Buffer): PeImage {
	if (buffer.length < 0x100 || buffer.readUInt16LE(0) !== 0x5a4d) {
		throw new Error('Invalid PE DOS header');
	}
	const pe = buffer.readUInt32LE(0x3c);
	if (pe + 24 > buffer.length || buffer.readUInt32LE(pe) !== 0x4550) {
		throw new Error('Invalid PE signature');
	}
	const sectionCount = buffer.readUInt16LE(pe + 6);
	const optionalSize = buffer.readUInt16LE(pe + 20);
	const optional = pe + 24;
	const magic = buffer.readUInt16LE(optional);
	const format = magic === 0x20b ? 'pe64' : magic === 0x10b ? 'pe32' : undefined;
	if (!format) {
		throw new Error(`Unsupported PE optional-header magic 0x${magic.toString(16)}`);
	}
	const imageBase = format === 'pe64' ? buffer.readBigUInt64LE(optional + 24) : BigInt(buffer.readUInt32LE(optional + 28));
	const sectionTable = optional + optionalSize;
	const sections: PeSection[] = [];
	for (let index = 0; index < sectionCount; index++) {
		const offset = sectionTable + index * 40;
		if (offset + 40 > buffer.length) {
			throw new Error('PE section table exceeds file');
		}
		sections.push({
			name: buffer.subarray(offset, offset + 8).toString('ascii').replace(/\0.*$/, ''),
			virtualSize: buffer.readUInt32LE(offset + 8),
			virtualAddress: buffer.readUInt32LE(offset + 12),
			rawSize: buffer.readUInt32LE(offset + 16),
			rawOffset: buffer.readUInt32LE(offset + 20),
		});
	}
	const functionEnds = new Map<number, number>();
	if (format === 'pe64') {
		const directory = optional + 112 + 3 * 8;
		const exceptionRva = buffer.readUInt32LE(directory);
		const exceptionSize = buffer.readUInt32LE(directory + 4);
		const exceptionOffset = rvaToOffset(exceptionRva, sections);
		if (exceptionRva && exceptionSize && exceptionOffset !== undefined && exceptionOffset + exceptionSize <= buffer.length) {
			for (let offset = exceptionOffset; offset + 12 <= exceptionOffset + exceptionSize; offset += 12) {
				functionEnds.set(buffer.readUInt32LE(offset), buffer.readUInt32LE(offset + 4));
			}
		}
	}
	return { imageBase, format, sections, functionEnds };
}

function rvaToOffset(rva: number, sections: PeSection[]): number | undefined {
	const section = sections.find(candidate => rva >= candidate.virtualAddress && rva < candidate.virtualAddress + Math.max(candidate.virtualSize, candidate.rawSize));
	return section ? section.rawOffset + rva - section.virtualAddress : undefined;
}

function resolveDirectJumpTarget(binary: Buffer, text: PeSection, exportRva: number): number {
	let current = exportRva;
	const visited = new Set<number>();
	for (let depth = 0; depth < 4; depth++) {
		if (visited.has(current) || current < text.virtualAddress || current >= text.virtualAddress + text.rawSize) {
			throw new Error(`Invalid or cyclic export thunk at RVA 0x${exportRva.toString(16)}`);
		}
		visited.add(current);
		const offset = text.rawOffset + current - text.virtualAddress;
		const opcode = binary[offset];
		let target: number | undefined;
		if (opcode === 0xe9 && offset + 5 <= binary.length) {
			target = current + 5 + binary.readInt32LE(offset + 1);
		} else if (opcode === 0xeb && offset + 2 <= binary.length) {
			target = current + 2 + binary.readInt8(offset + 1);
		}
		if (target === undefined || target < text.virtualAddress || target >= text.virtualAddress + text.rawSize) {
			return current;
		}
		current = target;
	}
	throw new Error(`Export thunk depth exceeded at RVA 0x${exportRva.toString(16)}`);
}

function exactRva(value: string): number {
	if (!/^0x[0-9a-f]+$/i.test(value)) {
		throw new Error(`Invalid corpus RVA ${value}`);
	}
	const result = Number(BigInt(value));
	if (!Number.isSafeInteger(result)) {
		throw new Error(`Unsafe corpus RVA ${value}`);
	}
	return result;
}

function assertBsimCorpus(root: string, manifest: CorpusManifest, functionNames: string[]): void {
	const files = fs.readdirSync(root).filter(name => name.endsWith('.json')).sort();
	if (files.length !== manifest.entries.length) {
		throw new Error(`BSim baseline has ${files.length} programs, expected ${manifest.entries.length}`);
	}
	const entries = new Map(manifest.entries.map(entry => [entry.id.toLowerCase(), entry]));
	for (const file of files) {
		const document = readJson<{ program: string; executableSha256: string; queries: Array<{ function: string }> }>(path.join(root, file));
		const id = path.basename(document.program, '.dll').toLowerCase();
		const entry = entries.get(id);
		if (!entry || document.executableSha256 !== entry.binarySha256 || document.queries.length !== functionNames.length || canonicalJson(document.queries.map(query => query.function).sort()) !== canonicalJson(functionNames)) {
			throw new Error(`${file}: BSim query evidence does not match the current corpus`);
		}
	}
}
