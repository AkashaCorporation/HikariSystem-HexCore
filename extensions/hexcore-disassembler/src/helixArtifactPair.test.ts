import * as assert from 'assert';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import {
	createHelixArtifactPairEnvelope,
	extractCFunctionSurfaces,
	persistHelixArtifactPair,
	verifyHelixArtifactPair,
	type HastContractSummary,
	type HelixArtifactPairInput,
} from './helixArtifactPair';

suite('Helix C/HAST artifact pairing', () => {
	let tempDir: string;
	let hastBuffer: Buffer;
	let hastContract: HastContractSummary;
	let inspectHASTContract: (buffer: Uint8Array) => HastContractSummary;

	setup(() => {
		tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'hexcore-helix-pair-'));
		// eslint-disable-next-line @typescript-eslint/no-var-requires
		const hql = require('../../hexcore-hql/dist/index.js') as {
			inspectHASTContract(buffer: Uint8Array): HastContractSummary;
		};
		inspectHASTContract = buffer => hql.inspectHASTContract(buffer);
		hastBuffer = fs.readFileSync(path.resolve(
			__dirname, '..', '..', 'hexcore-hql', 'test', 'fixtures', 'semantic-quality-v1_1.fb'));
		hastContract = inspectHASTContract(hastBuffer);
	});

	teardown(() => fs.rmSync(tempDir, { recursive: true, force: true }));

	function input(cSource = 'uint64_t semantic_quality_fixture(struct QualityRecord* record)\n{\n    return 0;\n}\n'): HelixArtifactPairInput {
		return {
			paths: {
				cPath: path.join(tempDir, 'function.c'),
				hastPath: path.join(tempDir, 'function.hast.fb'),
				pairingPath: path.join(tempDir, 'function.pairing.json'),
			},
			cSource,
			hastBuffer,
			hastContract,
			runtimeIdentity: {
				component: 'hexcore-helix', wrapperVersion: '0.9.4-rc.2', nativeVersion: '0.9.4-rc.2',
				platform: 'win32', arch: 'x64', binaryPath: path.join(tempDir, 'helix.node'),
				binarySha256: 'a'.repeat(64), binaryBytes: 1234, artifactKind: 'native-node',
			},
			input: { sha256: 'b'.repeat(64), mediaType: 'text/x-llvm' },
			architecture: 'arm64',
			helixInvocation: { mode: 'decompileIR', useCastLayer: true },
			nativeFunction: {
				name: 'semantic_quality_fixture', address: '0xfedcba9876543210', instructionCount: 1,
			},
			qualityIssues: [],
			cfgBuffer: null,
		};
	}

	test('extracts the declaration surface used for pairing', () => {
		assert.deepStrictEqual(extractCFunctionSurfaces(input().cSource), [{
			name: 'semantic_quality_fixture', returnType: 'uint64_t',
			params: [{ name: 'record', type: 'struct QualityRecord*' }], isVariadic: false,
		}]);
	});

	test('persists and independently verifies one C/HAST invocation pair', () => {
		const persisted = persistHelixArtifactPair(input());
		assert.strictEqual(persisted.sideArtifacts.length, 2);
		assert.strictEqual(persisted.envelope.equivalence.status, 'verified');
		assert.strictEqual(persisted.envelope.artifacts.cfg.status, 'not-emitted');
		assert.strictEqual(persisted.envelope.hast.schemaMajor, 1);
		assert.strictEqual(persisted.envelope.hast.functionCount, 1);
		assert.strictEqual(
			verifyHelixArtifactPair(input().paths.pairingPath, inspectHASTContract).pairingId,
			persisted.envelope.pairingId,
		);
	});

	test('rejects declaration mismatch before publishing artifacts', () => {
		assert.throws(() => createHelixArtifactPairEnvelope(input(
			'int64_t semantic_quality_fixture(int64_t record)\n{\n    return 0;\n}\n')),
		/C\/HAST pairing mismatch/);
	});

	test('rejects a HAST artifact changed after pairing', () => {
		const value = input();
		persistHelixArtifactPair(value);
		const corrupted = Buffer.from(hastBuffer);
		corrupted[corrupted.length - 1] ^= 0xff;
		fs.writeFileSync(value.paths.hastPath, corrupted);
		assert.throws(() => verifyHelixArtifactPair(value.paths.pairingPath, inspectHASTContract),
			/Paired HAST artifact identity mismatch/);
	});
});
