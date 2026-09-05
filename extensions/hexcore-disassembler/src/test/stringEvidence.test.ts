/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as assert from 'assert';
import 'mocha';
import { assessStringEvidence, findCrc32LookupRanges } from '../stringEvidence';

function crc32Table(): Buffer {
	const table = Buffer.alloc(1024);
	for (let index = 0; index < 256; index++) {
		let value = index;
		for (let bit = 0; bit < 8; bit++) {
			value = (value & 1) !== 0 ? 0xedb88320 ^ (value >>> 1) : value >>> 1;
		}
		table.writeUInt32LE(value >>> 0, index * 4);
	}
	return table;
}

suite('string evidence classification', () => {
	test('demotes printable fragments inside a standard CRC32 table', () => {
		const data = Buffer.concat([Buffer.alloc(17, 0xcc), crc32Table(), Buffer.alloc(5)]);
		const ranges = findCrc32LookupRanges(data);
		assert.deepStrictEqual(ranges, [{ start: 17, end: 1041 }]);
		const assessment = assessStringEvidence(17 + 321, false, 0, ranges);
		assert.strictEqual(assessment.evidenceClass, 'lookup-table-sequence');
		assert.strictEqual(assessment.literalConfidence, 0.1);
	});

	test('promotes referenced strings over termination-only evidence', () => {
		assert.strictEqual(assessStringEvidence(0, false, 2, []).literalConfidence, 0.95);
		assert.strictEqual(assessStringEvidence(0, true, 0, []).literalConfidence, 0.75);
		assert.strictEqual(assessStringEvidence(0, false, 0, []).literalConfidence, 0.3);
	});
});
