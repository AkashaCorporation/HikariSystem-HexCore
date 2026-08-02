/*---------------------------------------------------------------------------------------------
 * Issue #52 — import/PLT call-target naming regression tests
 *---------------------------------------------------------------------------------------------*/

import * as assert from 'assert';
import {
	buildImportSymbolMap,
	applyImportSymbolNamesToSource,
} from './importSymbolNames';

suite('importSymbolNames (#52)', () => {
	test('renames sub_<va> when VA is an import GOT slot', () => {
		const map = buildImportSymbolMap(
			[],
			[{ functions: [{ address: 0x14002c6e0, name: 'ExAllocatePoolWithTag' }] }],
		);
		const src = 'result = sub_14002c6e0(pool, 0x568, tag);';
		const { source, renamed } = applyImportSymbolNamesToSource(src, map);
		assert.strictEqual(renamed, 1);
		assert.strictEqual(source, 'result = ExAllocatePoolWithTag(pool, 0x568, tag);');
	});

	test('renames ELF PLT: dlopen@plt → dlopen', () => {
		const map = buildImportSymbolMap(
			[{ address: 0x555555555260, name: 'dlopen@plt' }],
			[],
		);
		const src = 'void *h = sub_555555555260("./lib.so", 2);';
		const { source, renamed } = applyImportSymbolNamesToSource(src, map);
		assert.strictEqual(renamed, 1);
		assert.ok(source.includes('dlopen('));
		assert.ok(!source.includes('sub_555555555260'));
	});

	test('does NOT rename anonymous local helpers', () => {
		const map = buildImportSymbolMap(
			[
				{ address: 0x401000, name: 'sub_401000' }, // anonymous — skipped in map
				{ address: 0x402000, name: 'helper_real' },
			],
			[],
		);
		assert.strictEqual(map.has(0x401000), false);
		assert.strictEqual(map.get(0x402000), 'helper_real');
		const src = 'sub_401000(); sub_402000();';
		const { source, renamed } = applyImportSymbolNamesToSource(src, map);
		assert.strictEqual(renamed, 1);
		assert.ok(source.includes('sub_401000()')); // local stays
		assert.ok(source.includes('helper_real()'));
	});

	test('does NOT rewrite partial identifiers', () => {
		const map = buildImportSymbolMap([], [{ functions: [{ address: 0x14002c6e0, name: 'ExAllocatePoolWithTag' }] }]);
		// substring must not match mid-token
		const src = 'int sub_14002c6e0_extra = 0;';
		const { source, renamed } = applyImportSymbolNamesToSource(src, map);
		assert.strictEqual(renamed, 0);
		assert.strictEqual(source, src);
	});

	test('g_<va> globals also renamed when in map', () => {
		const map = buildImportSymbolMap([], [{ functions: [{ address: 0x601000, name: 'stderr@@GLIBC_2.2.5' }] }]);
		assert.strictEqual(map.get(0x601000), 'stderr'); // @@ stripped
		const { source, renamed } = applyImportSymbolNamesToSource('fputs(s, g_601000);', map);
		assert.strictEqual(renamed, 1);
		assert.strictEqual(source, 'fputs(s, stderr);');
	});
});
