/*---------------------------------------------------------------------------------------------
 * issue #55 — packer detect unit tests
 *---------------------------------------------------------------------------------------------*/

import * as assert from 'assert';
import * as fs from 'fs';
import * as path from 'path';
import { detectPacker, packerCapabilityTags } from './packerDetect';

suite('packerDetect (#55)', () => {
	test('clean buffer is not packed', () => {
		const r = detectPacker(Buffer.from('MZ\0\0not a packer'));
		assert.strictEqual(r.packed, false);
		assert.strictEqual(r.family, 'none');
		assert.deepStrictEqual(packerCapabilityTags(r), []);
	});

	test('UPX! magic sets family upx with high confidence', () => {
		const buf = Buffer.concat([
			Buffer.from([0x7f, 0x45, 0x4c, 0x46]),
			Buffer.alloc(100, 0),
			Buffer.from('UPX!'),
			Buffer.from('....'),
			Buffer.from('$Id: UPX 5.20 Copyright'),
		]);
		const r = detectPacker(buf);
		assert.strictEqual(r.packed, true);
		assert.strictEqual(r.family, 'upx');
		assert.ok(r.confidence >= 85, `conf ${r.confidence}`);
		assert.ok(packerCapabilityTags(r).includes('packed'));
		assert.ok(packerCapabilityTags(r).includes('packed:upx'));
		assert.ok(/unpack|do NOT decompile/i.test(r.recommendation));
	});

	test('section name UPX0 counts', () => {
		const r = detectPacker(Buffer.alloc(16), {
			sections: [{ name: 'UPX0', isCode: true, rawSize: 0, virtualSize: 0x10000 }],
		});
		assert.strictEqual(r.packed, true);
		assert.strictEqual(r.family, 'upx');
	});

	test('string table UPX banner', () => {
		const r = detectPacker(Buffer.alloc(8), {
			strings: [{ string: 'This file is packed with the UPX executable packer' }],
		});
		assert.strictEqual(r.packed, true);
		assert.strictEqual(r.family, 'upx');
	});

	test('reports an unknown encrypted payload instead of no packer markers', () => {
		const bytes = Buffer.alloc(0x2000);
		for (let i = 0; i < bytes.length; i++) { bytes[i] = i & 0xff; }
		const r = detectPacker(bytes, {
			sections: [{
				name: '.payload', permissions: 'rw-', rawAddress: 0, rawSize: bytes.length, virtualSize: bytes.length,
			}],
		});
		assert.strictEqual(r.packed, true);
		assert.strictEqual(r.family, 'unknown');
		assert.ok(r.confidence >= 55, `conf ${r.confidence}`);
		assert.ok(r.markers.some(marker => marker.kind === 'entropy'));
		assert.match(r.recommendation, /encrypted payload|unknown packer/i);
	});

	test('live HTB ransom packed binary if present', function () {
		const p = path.join(
			process.env.USERPROFILE || '',
			'Desktop', 'Benchv2', 'HTB Medium', 'ransom',
		);
		if (!fs.existsSync(p)) {
			this.skip();
			return;
		}
		const r = detectPacker(fs.readFileSync(p));
		assert.strictEqual(r.packed, true, JSON.stringify(r));
		assert.strictEqual(r.family, 'upx');
		assert.ok(r.confidence >= 85);
	});
});
