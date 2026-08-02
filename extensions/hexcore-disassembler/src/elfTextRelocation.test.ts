/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as assert from 'assert';
import 'mocha';
import {
	encodeX86PcRelativeDataDisplacement,
	isX86PcRelativeDataRelocation,
	x86PcRelativeDataSectionOffset,
} from './elfTextRelocation';

suite('ELF text relocations', () => {
	test('classifies PC32 STT_OBJECT in .rodata as data and preserves its effective address', () => {
		assert.strictEqual(isX86PcRelativeDataRelocation({
			relocationType: 2,
			symbolType: 1,
			symbolValue: 0x7700,
			addend: -4,
			targetSectionFlags: 0x2,
		}), true);

		const sectionOffset = x86PcRelativeDataSectionOffset(0x7700, -4);
		assert.strictEqual(sectionOffset, 0x7700);

		const relocationAddress = 0x7737f;
		const fakeTarget = 0x7f000000 + sectionOffset;
		const displacement = encodeX86PcRelativeDataDisplacement(fakeTarget, relocationAddress);
		assert.strictEqual(
			(relocationAddress + 4 + displacement) >>> 0,
			fakeTarget >>> 0,
		);
	});

	test('keeps PC32 STT_FUNC in executable .text on the control-flow path', () => {
		assert.strictEqual(isX86PcRelativeDataRelocation({
			relocationType: 2,
			symbolType: 2,
			symbolValue: 0x120,
			addend: -4,
			targetSectionFlags: 0x6,
		}), false);
	});

	test('does not reinterpret an undefined external PC32 symbol as data', () => {
		assert.strictEqual(isX86PcRelativeDataRelocation({
			relocationType: 2,
			symbolType: 0,
			symbolValue: 0,
			addend: -4,
		}), false);
	});
});
