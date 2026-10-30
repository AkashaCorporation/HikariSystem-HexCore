/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as assert from 'assert';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { inspectPEOverlay } from './peOverlay';

const root = fs.mkdtempSync(path.join(os.tmpdir(), 'hexcore-pe-overlay-'));
try {
	const file = path.join(root, 'fixture.exe');
	const image = Buffer.alloc(0x400);
	image.writeUInt16LE(0x5a4d, 0);
	image.writeUInt32LE(0x80, 0x3c);
	image.write('PE\0\0', 0x80, 'ascii');
	image.writeUInt16LE(0x8664, 0x84);
	image.writeUInt16LE(1, 0x86);
	image.writeUInt16LE(0xf0, 0x94);
	const optional = 0x98;
	image.writeUInt16LE(0x20b, optional);
	image.writeUInt32LE(0x200, optional + 60);
	const section = optional + 0xf0;
	image.write('.text', section, 'ascii');
	image.writeUInt32LE(0x100, section + 16);
	image.writeUInt32LE(0x200, section + 20);
	Buffer.from('efbeadde4e756c6c736f6674496e7374', 'hex').copy(image, 0x304);
	image.writeUInt32LE(0x40, 0x314);
	image.writeUInt32LE(0xfc, 0x318);
	fs.writeFileSync(file, image);
	const result = inspectPEOverlay(file);
	assert.ok(result);
	assert.strictEqual(result.offset, 0x300);
	assert.strictEqual(result.size, 0x100);
	assert.strictEqual(result.container, 'nsis');
	assert.strictEqual(result.nsis?.signatureOffset, 0x304);
	assert.strictEqual(result.nsis?.headerLength, 0x40);

	fs.writeFileSync(file, image.subarray(0, 0x300));
	assert.strictEqual(inspectPEOverlay(file), undefined);
	console.log('PE overlay inspection tests passed.');
} finally {
	fs.rmSync(root, { recursive: true, force: true });
}
