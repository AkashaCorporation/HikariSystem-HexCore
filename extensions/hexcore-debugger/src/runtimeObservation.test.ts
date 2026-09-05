import * as assert from 'assert';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { buildRuntimeObservationArtifact } from './runtimeObservation';

suite('R37 runtime observation contract', () => {
	test('binds corroboration to binary, input and trace configuration deterministically', () => {
		const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'hexcore-runtime-observation-'));
		const binaryPath = path.join(directory, 'fixture.bin'); fs.writeFileSync(binaryPath, Buffer.from('fixture'));
		try {
			const input = {
				binaryPath, architecture: 'x64', executionBackend: 'unicorn', inputConfiguration: { stdinSha256: 'a'.repeat(64), prngSeed: 7 },
				trace: { entries: [{ functionName: 'CreateFileW', library: 'KERNEL32.dll', arguments: ['0x1000'], returnValue: '0x44', pcAddress: '0x140001000', timestamp: 123 }], totalEntries: 1, totalCalls: 1, retainedEntries: 1, aggregatedCalls: 0, sampledOut: 0, dropped: 0, configuration: { maxEntries: 10, sampleEvery: 1, groupRepeated: true }, generatedAt: 'ignored' },
				sideChannels: { basicBlockCounts: [], memoryAccesses: [{ address: '0x2000', size: 8, type: 'write' as const, pc: '0x140001010' }], branchStats: [], totalInstructions: 3 },
			};
			const first = buildRuntimeObservationArtifact(input);
			const repeat = buildRuntimeObservationArtifact({ ...input, trace: { ...input.trace, generatedAt: 'different' } });
			assert.strictEqual(first.normalizedIdentitySha256, repeat.normalizedIdentitySha256);
			assert.strictEqual(first.observations.length, 4);
			assert.ok(first.observations.every(item => item.evidenceLevel === 'runtime-corroboration'));
			const changed = buildRuntimeObservationArtifact({ ...input, inputConfiguration: { ...input.inputConfiguration, prngSeed: 8 } });
			assert.notStrictEqual(changed.normalizedIdentitySha256, first.normalizedIdentitySha256);
		} finally { fs.rmSync(directory, { recursive: true, force: true }); }
	});
});
