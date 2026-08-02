import * as assert from 'assert';
import { ELFLoader } from './elfLoader';
import { addressRangesOverlap, PELoader } from './peLoader';

suite('PE/ELF loader hardening (#50)', () => {
	test('PE loader reports a clean error for a truncated DOS header', () => {
		const loader = new PELoader({} as any, {} as any);
		assert.throws(
			() => loader.load(Buffer.from([0x4d, 0x5a]), 'x86'),
			/Truncated PE file/,
		);
	});

	test('ELF loader reports a clean error for a truncated identification/header', () => {
		const loader = new ELFLoader({} as any, {} as any);
		assert.throws(
			() => loader.load(Buffer.from([0x7f, 0x45, 0x4c, 0x46]), 'x64'),
			/Truncated ELF file/,
		);
	});

	test('range overlap rejects image collisions but permits adjacent ranges', () => {
		assert.strictEqual(addressRangesOverlap(0x70000000n, 0x1000n, 0x70000800n, 0x1000n), true);
		assert.strictEqual(addressRangesOverlap(0x70000000n, 0x1000n, 0x70001000n, 0x1000n), false);
	});

	test('PE section writer skips destinations outside the mapped image', () => {
		let writes = 0;
		const emulator = {
			getPageSize: () => 0x1000,
			mapMemoryRaw: () => undefined,
			writeMemory: () => { writes++; },
		};
		const memory = { trackAllocation: () => undefined };
		const loader = new PELoader(emulator as any, memory as any);
		(loader as any).mapSections(
			Buffer.alloc(0x200),
			[{ name: '.bad', virtualAddress: 0x500000n, virtualSize: 0x100, rawOffset: 0, rawSize: 0x100, permissions: 'r' }],
			0x400000n,
			0x2000,
		);
		// One write is the PE header; the out-of-image section is not written.
		assert.strictEqual(writes, 1);
	});

	test('zero-stride ELF header tables return no entries', () => {
		const loader = new ELFLoader({} as any, {} as any) as any;
		loader.is64Bit = true;
		const header = Buffer.alloc(64);
		header.writeBigUInt64LE(64n, 32); // phoff
		header.writeUInt16LE(0, 54);      // phentsize
		header.writeUInt16LE(0xffff, 56); // phnum
		header.writeBigUInt64LE(64n, 40); // shoff
		header.writeUInt16LE(0, 58);      // shentsize
		header.writeUInt16LE(0xffff, 60); // shnum
		assert.deepStrictEqual(loader.parseProgramHeaders(header), []);
		assert.deepStrictEqual(loader.parseSectionHeaders(header), []);
	});
});
