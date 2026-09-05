/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as assert from 'assert';
import 'mocha';
import { resolvePeRvaMapping, PeSectionMappingShape } from './peAddressMapping';

const baseAddress = 0x400000;
const textSection: PeSectionMappingShape = {
	name: '.text',
	virtualAddress: 0x401000,
	virtualSize: 0x78f0,
	rawAddress: 0x400,
	rawSize: 0x7a00,
};

suite('PE VA/RVA/raw mapping regression', () => {
	test('maps a raw-backed section tail beyond VirtualSize', () => {
		const mapping = resolvePeRvaMapping(0x8904, baseAddress, [textSection], 0x9000);

		assert.strictEqual(mapping.valid, true);
		assert.strictEqual(mapping.source, 'file-section');
		assert.strictEqual(mapping.section, '.text');
		assert.strictEqual(mapping.fileOffset, 0x7d04);
		assert.strictEqual(mapping.availableBytes, 0xfc);
	});

	test('rejects virtual zero-fill beyond SizeOfRawData', () => {
		const section = { ...textSection, virtualSize: 0x7c00 };
		const mapping = resolvePeRvaMapping(0x8b00, baseAddress, [section], 0x9000);

		assert.strictEqual(mapping.valid, false);
		assert.strictEqual(mapping.source, 'virtual-zero-fill');
		assert.strictEqual(mapping.fileOffset, undefined);
	});

	test('maps PE headers but rejects unrelated file offsets as virtual addresses', () => {
		assert.strictEqual(resolvePeRvaMapping(0x200, baseAddress, [textSection], 0x9000).fileOffset, 0x200);
		assert.strictEqual(resolvePeRvaMapping(0x9000, baseAddress, [textSection], 0xa000).valid, false);
	});
});
