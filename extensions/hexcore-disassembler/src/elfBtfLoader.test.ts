/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

// Feature: v3.8.0 BTF debug-info loader
// Target: elfBtfLoader.ts parseBtfSection -- parser-bounds hardening (clamp the
// type/string region to the real buffer length) + ENUM64 64-bit value combine.

import * as assert from 'assert';
import 'mocha';
import { parseBtfSection, resolveTypeSize } from './elfBtfLoader';

function btfHeader(typeOff: number, typeLen: number, strOff: number, strLen: number): Buffer {
	const h = Buffer.alloc(24);
	h.writeUInt16LE(0xEB9F, 0); // magic
	h.writeUInt8(1, 2);         // version
	h.writeUInt8(0, 3);         // flags
	h.writeUInt32LE(24, 4);     // hdrLen
	h.writeUInt32LE(typeOff, 8);
	h.writeUInt32LE(typeLen, 12);
	h.writeUInt32LE(strOff, 16);
	h.writeUInt32LE(strLen, 20);
	return h;
}

suite('elfBtfLoader.parseBtfSection', () => {

	test('does not crash on an inflated typeLen -- parses the valid prefix (region clamped to buffer length)', () => {
		// Header claims 1000 bytes of types but the buffer holds only one 16-byte INT type.
		const h = btfHeader(0, 1000, 16, 0);
		const t = Buffer.alloc(16);
		t.writeUInt32LE(0, 0);               // nameOff
		t.writeUInt32LE((1 << 24) >>> 0, 4); // info: kind=1 (INT), vlen=0
		t.writeUInt32LE(4, 8);               // sizeOrType
		t.writeUInt32LE(0x01000020, 12);     // INT encoding word
		const buf = Buffer.concat([h, t]);   // 40 bytes total

		// Before the clamp this threw RangeError (read past the 40-byte buffer).
		const data = parseBtfSection(buf);
		assert.strictEqual(data.typeCount, 1);
		assert.strictEqual(data.types.get(1)?.kindName, 'int');
	});

	test('combines a 64-bit ENUM64 value without dropping the high dword', () => {
		// One ENUM64 type, one value entry valLo=1, valHi=2 -> 0x2_00000001.
		const h = btfHeader(0, 24, 24, 1);
		const t = Buffer.alloc(24);
		t.writeUInt32LE(0, 0);                      // nameOff
		t.writeUInt32LE(((19 << 24) | 1) >>> 0, 4); // info: kind=19 (ENUM64), vlen=1
		t.writeUInt32LE(8, 8);                      // sizeOrType
		t.writeUInt32LE(0, 12);                     // value entry nameOff
		t.writeUInt32LE(1, 16);                     // valLo
		t.writeUInt32LE(2, 20);                     // valHi
		const s = Buffer.alloc(1);                  // empty string at offset 0
		const buf = Buffer.concat([h, t, s]);

		const data = parseBtfSection(buf);
		const value = data.types.get(1)?.enumValues?.[0].value;
		// Before the fix `valLo | (valHi << 32)` collapsed to `1 | 2` === 3.
		assert.strictEqual(value, 8589934593); // 0x2_00000001
	});

	test('does not crash on an inflated strLen (string region clamped to buffer length)', () => {
		// Header claims a 64 KB string table but the buffer ends right after the header.
		const h = btfHeader(0, 0, 0, 0x10000);
		// Before the clamp the string loop read past the buffer -> RangeError.
		const data = parseBtfSection(h);
		assert.ok(Array.isArray(data.strings));
	});

	test('extracts INT encoding/bits per the BTF spec (#47)', () => {
		// A signed int32 has btf_int VAL=0x01000020: encoding=SIGNED(1), nr_bits=32.
		const h = btfHeader(0, 16, 16, 1);
		const t = Buffer.alloc(16);
		t.writeUInt32LE(0, 0);
		t.writeUInt32LE((1 << 24) >>> 0, 4); // info: kind=1 (INT)
		t.writeUInt32LE(4, 8);               // sizeOrType
		t.writeUInt32LE(0x01000020, 12);     // btf_int VAL
		const data = parseBtfSection(Buffer.concat([h, t, Buffer.alloc(1)]));
		const ty = data.types.get(1);
		assert.strictEqual(ty?.encoding, 1); // was 0x20 (32) -- the low byte (nr_bits)
		assert.strictEqual(ty?.bits, 32);    // was 0x100 (256)
	});

	test('clamps an oversized ARRAY size to a sane ceiling (#47)', () => {
		// type 1 = INT (4 bytes); type 2 = ARRAY of type 1 with nelems=0xFFFFFFFF.
		const h = btfHeader(0, 16 + 24, 16 + 24, 1);
		const t1 = Buffer.alloc(16);
		t1.writeUInt32LE(0, 0); t1.writeUInt32LE((1 << 24) >>> 0, 4); t1.writeUInt32LE(4, 8); t1.writeUInt32LE(0x01000020, 12);
		const t2 = Buffer.alloc(24);
		t2.writeUInt32LE(0, 0); t2.writeUInt32LE((3 << 24) >>> 0, 4); t2.writeUInt32LE(0, 8); // info: kind=3 (ARRAY)
		t2.writeUInt32LE(1, 12); t2.writeUInt32LE(0, 16); t2.writeUInt32LE(0xFFFFFFFF, 20);   // elem=1, index=0, nelems=max
		const data = parseBtfSection(Buffer.concat([h, t1, t2, Buffer.alloc(1)]));
		const size = resolveTypeSize(2, data);
		// Before the clamp this was 4 * 0xFFFFFFFF = 17179869180.
		assert.ok(size <= 0x40000000, `array size ${size} should be clamped to <= 1 GiB`);
	});
});
