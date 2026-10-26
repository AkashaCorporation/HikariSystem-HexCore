import * as assert from 'assert';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { canReuseAnalyzeAll, createAnalyzeAllReuseKey, sha256AnalyzeAllFile, type AnalyzeAllReuseIdentity } from './analyzeAllReuse';

suite('analyzeAll exact reuse', () => {
	const identity: AnalyzeAllReuseIdentity = {
		targetPath: 'C:\\fixtures\\target.exe',
		fileSha256: 'a'.repeat(64),
		architecture: 'x64',
		maxFunctions: 10_000,
		maxFunctionSize: 1_000_000,
		filterJunk: false,
		detectVM: false,
		detectPRNG: false,
	};

	test('reuses only the exact accepted target and configuration', () => {
		const key = createAnalyzeAllReuseKey(identity);
		assert.deepStrictEqual(canReuseAnalyzeAll({
			forceReload: false,
			lastAcceptedKey: key,
			requestedKey: key,
			analysisComplete: true,
			loadedPath: identity.targetPath,
			requestedPath: identity.targetPath,
			loadedImageSha256: identity.fileSha256,
			requestedFileSha256: identity.fileSha256,
		}), {
			reusable: true,
			reason: 'exact target and analysis configuration already accepted',
		});
	});

	test('configuration changes produce a distinct key', () => {
		assert.notStrictEqual(
			createAnalyzeAllReuseKey(identity),
			createAnalyzeAllReuseKey({ ...identity, detectVM: true }),
		);
	});

	test('force reload and changed image bytes fail closed', () => {
		const key = createAnalyzeAllReuseKey(identity);
		assert.strictEqual(canReuseAnalyzeAll({
			forceReload: true, lastAcceptedKey: key, requestedKey: key, analysisComplete: true,
			loadedPath: identity.targetPath, requestedPath: identity.targetPath,
			loadedImageSha256: identity.fileSha256, requestedFileSha256: identity.fileSha256,
		}).reusable, false);
		assert.strictEqual(canReuseAnalyzeAll({
			forceReload: false, lastAcceptedKey: key, requestedKey: key, analysisComplete: true,
			loadedPath: identity.targetPath, requestedPath: identity.targetPath,
			loadedImageSha256: 'b'.repeat(64), requestedFileSha256: identity.fileSha256,
		}).reusable, false);
	});

	test('hashes target bytes through a non-blocking stream', async () => {
		const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'hexcore-analyze-reuse-'));
		const file = path.join(directory, 'target.bin');
		fs.writeFileSync(file, 'abc', 'utf8');
		try {
			assert.strictEqual(
				await sha256AnalyzeAllFile(file),
				'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
			);
		} finally {
			fs.rmSync(directory, { recursive: true, force: true });
		}
	});
});
