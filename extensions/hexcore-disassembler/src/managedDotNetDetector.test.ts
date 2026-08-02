/*---------------------------------------------------------------------------------------------
 *  Managed .NET target detection regression tests.
 *--------------------------------------------------------------------------------------------*/

import * as assert from 'assert';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { detectSingleFileBundle, isSingleFileBundle } from './managedDotNetDetector';

const SIGNATURE = Buffer.from('8b1202b96a612038727b930214d7a03213f5b9e6efae3318ee3b2dce24b36aae', 'hex');

suite('managedDotNetDetector', () => {
	let tempDir: string;

	setup(() => {
		tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'hexcore-dotnet-detector-'));
	});

	teardown(() => {
		fs.rmSync(tempDir, { recursive: true, force: true });
	});

	test('accepts a valid bundle offset and rejects zero or out-of-range offsets', () => {
		const fixture = Buffer.alloc(256);
		fixture.writeBigInt64LE(64n, 192);
		SIGNATURE.copy(fixture, 200);
		assert.strictEqual(detectSingleFileBundle(fixture), true);

		fixture.writeBigInt64LE(0n, 192);
		assert.strictEqual(detectSingleFileBundle(fixture), false);
		fixture.writeBigInt64LE(256n, 192);
		assert.strictEqual(detectSingleFileBundle(fixture), false);
	});

	test('detects a marker split across the one MiB read boundary', () => {
		const fixture = Buffer.alloc(1024 * 1024 + 64);
		const markerAt = 1024 * 1024 - 16;
		fixture.writeBigInt64LE(128n, markerAt - 8);
		SIGNATURE.copy(fixture, markerAt);
		const filePath = path.join(tempDir, 'bundle.exe');
		fs.writeFileSync(filePath, fixture);

		assert.strictEqual(isSingleFileBundle(filePath), true);
	});

	test('rejects native, truncated, and missing files without throwing', () => {
		const nativePath = path.join(tempDir, 'native.exe');
		fs.writeFileSync(nativePath, Buffer.alloc(4096, 0x90));
		assert.strictEqual(isSingleFileBundle(nativePath), false);
		assert.strictEqual(isSingleFileBundle(path.join(tempDir, 'missing.exe')), false);
	});
});
