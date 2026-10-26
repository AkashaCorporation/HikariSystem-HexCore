/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as assert from 'assert';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { canonicalHelixJson, loadCanonicalHelixRequest, writeCanonicalHelixRequest } from './helixCanonicalRequest';

suite('canonical Helix request', () => {
	test('sorts object keys recursively and rejects semantic numbers', () => {
		assert.strictEqual(canonicalHelixJson({ z: 'last', a: { y: false, b: ['x', null] } }),
			'{"a":{"b":["x",null],"y":false},"z":"last"}');
		assert.throws(() => canonicalHelixJson({ invalid: 1 } as any), /may contain only/);
	});

	test('round-trips hash-bound artifacts and rejects IR tampering', () => {
		const root = fs.mkdtempSync(path.join(os.tmpdir(), 'hexcore-canonical-helix-'));
		try {
			const target = path.join(root, 'target.exe');
			const request = path.join(root, 'request.json');
			const ir = [
				'; RequestedByteRange: [0x401000, 0x401004) domain=byte-range sourceSha256=' + 'a'.repeat(64) + ' reason=fixture',
				'; ModuleID = \'fixture\'',
				'target triple = "x86_64-unknown-windows-msvc"',
			].join('\n');
			fs.writeFileSync(target, Buffer.from([0x4d, 0x5a, 0, 0]));
			const envelope = writeCanonicalHelixRequest({
				requestPath: request,
				irText: ir,
				targetPath: target,
				architecture: 'x64',
				imageBase: 0x400000,
				functionStarts: [0x402000, 0x401000, 0x402000],
				dataSections: [{ vaStart: 0x500000n, bytes: Buffer.from([1, 2, 3]), name: '.rdata' }],
				useCastLayer: true,
				skipOptimization: false,
			});
			assert.match(envelope.requestHash, /^sha256:[a-f0-9]{64}$/);
			const repeated = writeCanonicalHelixRequest({
				requestPath: path.join(root, 'transport-only-path-change.json'),
				irText: ir,
				targetPath: target,
				architecture: 'x64',
				imageBase: 0x400000,
				functionStarts: [0x402000, 0x401000, 0x402000],
				dataSections: [{ vaStart: 0x500000n, bytes: Buffer.from([1, 2, 3]), name: '.rdata' }],
				useCastLayer: true,
				skipOptimization: false,
			});
			assert.strictEqual(repeated.requestHash, envelope.requestHash);
			const loaded = loadCanonicalHelixRequest(request);
			assert.deepStrictEqual(loaded.functionStarts, [0x401000, 0x402000]);
			assert.strictEqual(loaded.dataSections[0].vaStart, 0x500000n);
			assert.deepStrictEqual(loaded.dataSections[0].bytes, Buffer.from([1, 2, 3]));
			assert.strictEqual(loaded.exactRange.endExclusive, 0x401004);

			const parsed = JSON.parse(fs.readFileSync(request, 'utf8'));
			const irPath = path.resolve(root, parsed.artifacts.ir.path);
			fs.appendFileSync(irPath, '\n; tampered');
			assert.throws(() => loadCanonicalHelixRequest(request), /IR artifact hash mismatch/);
		} finally {
			fs.rmSync(root, { recursive: true, force: true });
		}
	});
});
