/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

// Feature: v3.5.2-pipeline-maturity, Property 8: ELF Parser parseia binários válidos completamente

import * as assert from 'assert';
import * as fc from 'fast-check';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { analyzeELFFile } from './elfParser';

/**
 * Builds a minimal valid ELF64 little-endian binary header (64 bytes).
 *
 * The generated header has:
 * - Valid magic bytes (\x7fELF)
 * - Class: 2 (ELF64)
 * - Data: 1 (little-endian)
 * - Version: 1
 * - OS/ABI: 0 (System V)
 * - Type: one of REL(1), EXEC(2), DYN(3)
 * - Machine: one of x86_64(0x3E), AArch64(0xB7), x86(0x03)
 * - Random entry point
 * - Section/program header offsets: 0 (no sections/segments — still valid)
 */
function buildMinimalELF64(elfType: number, machine: number, entryPoint: number): Buffer {
	const buf = Buffer.alloc(64, 0);

	// e_ident[0..3]: magic
	buf[0] = 0x7f;
	buf[1] = 0x45; // E
	buf[2] = 0x4c; // L
	buf[3] = 0x46; // F

	// e_ident[4]: class = ELFCLASS64
	buf[4] = 2;
	// e_ident[5]: data = ELFDATA2LSB (little-endian)
	buf[5] = 1;
	// e_ident[6]: version = EV_CURRENT
	buf[6] = 1;
	// e_ident[7]: OS/ABI = ELFOSABI_NONE (System V)
	buf[7] = 0;
	// e_ident[8..15]: padding (already zero)

	// e_type (offset 16, 2 bytes LE)
	buf.writeUInt16LE(elfType, 16);
	// e_machine (offset 18, 2 bytes LE)
	buf.writeUInt16LE(machine, 18);
	// e_version (offset 20, 4 bytes LE)
	buf.writeUInt32LE(1, 20);
	// e_entry (offset 24, 8 bytes LE) — use only lower 32 bits for simplicity
	buf.writeUInt32LE(entryPoint >>> 0, 24);
	// e_phoff (offset 32, 8 bytes LE) = 0 (no program headers)
	// e_shoff (offset 40, 8 bytes LE) = 0 (no section headers)
	// e_flags (offset 48, 4 bytes LE) = 0
	// e_ehsize (offset 52, 2 bytes LE) = 64
	buf.writeUInt16LE(64, 52);
	// e_phentsize (offset 54, 2 bytes LE) = 56 (standard ELF64 phdr size)
	buf.writeUInt16LE(56, 54);
	// e_phnum (offset 56, 2 bytes LE) = 0
	buf.writeUInt16LE(0, 56);
	// e_shentsize (offset 58, 2 bytes LE) = 64 (standard ELF64 shdr size)
	buf.writeUInt16LE(64, 58);
	// e_shnum (offset 60, 2 bytes LE) = 0
	buf.writeUInt16LE(0, 60);
	// e_shstrndx (offset 62, 2 bytes LE) = 0
	buf.writeUInt16LE(0, 62);

	return buf;
}

/**
 * Arbitrary for valid ELF type values: REL(1), EXEC(2), DYN(3).
 */
const elfTypeArb = fc.constantFrom(1, 2, 3);

/**
 * Arbitrary for valid ELF machine values: x86(0x03), x86_64(0x3E), AArch64(0xB7).
 */
const machineArb = fc.constantFrom(0x03, 0x3E, 0xB7);

/**
 * Arbitrary for a 32-bit unsigned entry point address.
 */
const entryPointArb = fc.nat({ max: 0xFFFFFFFF });

/**
 * Map from ELF type number to expected string.
 */
const TYPE_MAP: Record<number, string> = {
	1: 'REL',
	2: 'EXEC',
	3: 'DYN',
};

/**
 * Map from ELF machine number to expected string.
 */
const MACHINE_MAP: Record<number, string> = {
	0x03: 'x86',
	0x3E: 'x86_64',
	0xB7: 'AArch64',
};

suite('Property 8: ELF Parser parseia binários válidos completamente', () => {

	let tmpDir: string;

	setup(() => {
		tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'elftest-'));
	});

	teardown(() => {
		fs.rmSync(tmpDir, { recursive: true, force: true });
	});

	/**
	 * **Validates: Requirements 4.1, 4.7**
	 *
	 * For any valid ELF64 file (minimal header with valid class/data/type/machine),
	 * analyzeELFFile MUST return an ELFAnalysis with:
	 * - isELF: true
	 * - non-null arrays for sections, segments, symbols
	 * - a security object with all fields (relro, stackCanary, nx, pie) defined
	 * - correct elfClass, endianness, type, and machine strings
	 */
	test('minimal valid ELF64 headers produce complete ELFAnalysis', () => {
		fc.assert(
			fc.property(
				elfTypeArb,
				machineArb,
				entryPointArb,
				(elfType, machine, entry) => {
					const buf = buildMinimalELF64(elfType, machine, entry);
					const filePath = path.join(tmpDir, `test-${elfType}-${machine}-${entry}.elf`);
					fs.writeFileSync(filePath, buf);

					const result = analyzeELFFile(filePath);

					// Must be recognized as valid ELF
					assert.strictEqual(result.isELF, true, 'isELF must be true');
					assert.strictEqual(result.error, undefined, 'error must be undefined');

					// ELF class and endianness
					assert.strictEqual(result.elfClass, 'ELF64');
					assert.strictEqual(result.endianness, 'little');

					// Type and machine match the generated values
					assert.strictEqual(result.type, TYPE_MAP[elfType],
						`type mismatch: expected ${TYPE_MAP[elfType]}, got ${result.type}`);
					assert.strictEqual(result.machine, MACHINE_MAP[machine],
						`machine mismatch: expected ${MACHINE_MAP[machine]}, got ${result.machine}`);

					// Arrays must be non-null (empty is fine for minimal headers)
					assert.ok(Array.isArray(result.sections), 'sections must be an array');
					assert.ok(Array.isArray(result.segments), 'segments must be an array');
					assert.ok(Array.isArray(result.symbols), 'symbols must be an array');

					// Security object must have all fields defined
					assert.ok(result.security !== null && result.security !== undefined,
						'security must be defined');
					assert.ok(typeof result.security.relro === 'string',
						'security.relro must be a string');
					assert.ok(['full', 'partial', 'none'].includes(result.security.relro),
						`security.relro must be full/partial/none, got ${result.security.relro}`);
					assert.ok(typeof result.security.stackCanary === 'boolean',
						'security.stackCanary must be a boolean');
					assert.ok(typeof result.security.nx === 'boolean',
						'security.nx must be a boolean');
					assert.ok(typeof result.security.pie === 'boolean',
						'security.pie must be a boolean');

					// File metadata
					assert.strictEqual(result.fileSize, 64);
					assert.ok(result.fileName.endsWith('.elf'));
					assert.strictEqual(result.filePath, filePath);

					// Cleanup
					fs.unlinkSync(filePath);
				}
			),
			{ numRuns: 100 }
		);
	});
});


// Feature: v3.5.2-pipeline-maturity, Property 9: ELF Parser rejeita arquivos não-ELF

/**
 * Arbitrary that generates a byte (0–255) guaranteed NOT to be 0x7f (the first ELF magic byte).
 */
const nonElfFirstByteArb = fc.integer({ min: 0, max: 254 }).map(v => v >= 0x7f ? v + 1 : v);

suite('Property 9: ELF Parser rejeita arquivos não-ELF', () => {

	let tmpDir: string;

	setup(() => {
		tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'elftest-noelf-'));
	});

	teardown(() => {
		fs.rmSync(tmpDir, { recursive: true, force: true });
	});

	/**
	 * **Validates: Requirements 4.3**
	 *
	 * For any buffer that does NOT start with \x7fELF,
	 * analyzeELFFile MUST return { isELF: false, error: non-empty string }.
	 */
	test('random buffers without ELF magic are rejected', () => {
		fc.assert(
			fc.property(
				nonElfFirstByteArb,
				fc.uint8Array({ minLength: 3, maxLength: 1023 }),
				(firstByte, restBytes) => {
					// Build a buffer of 4–1024 bytes where the first byte is NOT 0x7f
					const buf = Buffer.alloc(1 + restBytes.length);
					buf[0] = firstByte;
					buf.set(restBytes, 1);

					const filePath = path.join(tmpDir, `noelf-${Date.now()}-${Math.random().toString(36).slice(2, 8)}.bin`);
					fs.writeFileSync(filePath, buf);

					const result = analyzeELFFile(filePath);

					assert.strictEqual(result.isELF, false, 'isELF must be false for non-ELF data');
					assert.ok(
						typeof result.error === 'string' && result.error.length > 0,
						`error must be a non-empty string, got: ${JSON.stringify(result.error)}`
					);

					fs.unlinkSync(filePath);
				}
			),
			{ numRuns: 100 }
		);
	});

	/**
	 * **Validates: Requirements 4.3**
	 *
	 * Buffers that start with 0x7f but have wrong bytes at positions 1-3
	 * (not 'E','L','F') must also be rejected.
	 */
	test('buffers with 0x7f but wrong ELF signature bytes are rejected', () => {
		fc.assert(
			fc.property(
				fc.uint8Array({ minLength: 3, maxLength: 1023 }),
				(tailBytes) => {
					// Start with 0x7f but ensure bytes 1-3 are NOT [0x45, 0x4c, 0x46]
					const buf = Buffer.alloc(1 + tailBytes.length);
					buf[0] = 0x7f;
					buf.set(tailBytes, 1);

					// If by chance the random bytes form valid 'ELF' at positions 1-3, mutate one
					if (buf.length >= 4 && buf[1] === 0x45 && buf[2] === 0x4c && buf[3] === 0x46) {
						buf[1] = 0x00; // break the magic
					}

					const filePath = path.join(tmpDir, `partial-${Date.now()}-${Math.random().toString(36).slice(2, 8)}.bin`);
					fs.writeFileSync(filePath, buf);

					const result = analyzeELFFile(filePath);

					assert.strictEqual(result.isELF, false, 'isELF must be false for partial magic');
					assert.ok(
						typeof result.error === 'string' && result.error.length > 0,
						`error must be a non-empty string, got: ${JSON.stringify(result.error)}`
					);

					fs.unlinkSync(filePath);
				}
			),
			{ numRuns: 100 }
		);
	});
});


// ============================================================================
// Unit Tests for ELF Parser — Task 5.11
// Requirements: 4.1, 4.3, 4.7
// ============================================================================

/**
 * Helper: builds a synthetic ELF64 little-endian binary with sections,
 * program headers (segments), a symbol table, and a dynamic section.
 *
 * Layout:
 *   [0..63]     ELF64 header
 *   [64..175]   2 program headers (56 bytes each): PT_LOAD, PT_GNU_STACK
 *   [176..303]  2 section headers (64 bytes each): SHT_NULL, SHT_STRTAB (shstrtab)
 *   [304..319]  shstrtab data: "\0.shstrtab\0"
 *
 * This is a minimal but structurally valid ELF64 x86_64 binary.
 */
function buildSyntheticELF64(): Buffer {
	// Layout offsets
	const HEADER_SIZE = 64;
	const PH_OFF = 64;
	const PH_ENT_SIZE = 56;
	const PH_NUM = 2;
	const SH_OFF = PH_OFF + PH_NUM * PH_ENT_SIZE; // 176
	const SH_ENT_SIZE = 64;
	const SH_NUM = 2;
	const STRTAB_OFF = SH_OFF + SH_NUM * SH_ENT_SIZE; // 304
	const STRTAB_DATA = '\0.shstrtab\0';
	const TOTAL_SIZE = STRTAB_OFF + STRTAB_DATA.length;

	const buf = Buffer.alloc(TOTAL_SIZE, 0);

	// --- ELF header ---
	buf[0] = 0x7f; buf[1] = 0x45; buf[2] = 0x4c; buf[3] = 0x46; // magic
	buf[4] = 2;  // ELFCLASS64
	buf[5] = 1;  // ELFDATA2LSB
	buf[6] = 1;  // EV_CURRENT
	buf[7] = 0;  // ELFOSABI_NONE
	buf.writeUInt16LE(2, 16);   // e_type = ET_EXEC
	buf.writeUInt16LE(0x3E, 18); // e_machine = x86_64
	buf.writeUInt32LE(1, 20);   // e_version
	// e_entry = 0x400000
	buf.writeUInt32LE(0x400000, 24);
	// e_phoff
	buf.writeBigUInt64LE(BigInt(PH_OFF), 32);
	// e_shoff
	buf.writeBigUInt64LE(BigInt(SH_OFF), 40);
	buf.writeUInt16LE(HEADER_SIZE, 52); // e_ehsize
	buf.writeUInt16LE(PH_ENT_SIZE, 54); // e_phentsize
	buf.writeUInt16LE(PH_NUM, 56);      // e_phnum
	buf.writeUInt16LE(SH_ENT_SIZE, 58); // e_shentsize
	buf.writeUInt16LE(SH_NUM, 60);      // e_shnum
	buf.writeUInt16LE(1, 62);           // e_shstrndx = 1

	// --- Program header 0: PT_LOAD (type=1), flags=READ|EXECUTE ---
	const ph0 = PH_OFF;
	buf.writeUInt32LE(1, ph0);       // p_type = PT_LOAD
	buf.writeUInt32LE(0x5, ph0 + 4); // p_flags = PF_R | PF_X
	buf.writeBigUInt64LE(0n, ph0 + 8);  // p_offset
	buf.writeBigUInt64LE(BigInt(0x400000), ph0 + 16); // p_vaddr
	buf.writeBigUInt64LE(BigInt(0x400000), ph0 + 24); // p_paddr
	buf.writeBigUInt64LE(BigInt(TOTAL_SIZE), ph0 + 32); // p_filesz
	buf.writeBigUInt64LE(BigInt(TOTAL_SIZE), ph0 + 40); // p_memsz
	buf.writeBigUInt64LE(BigInt(0x200000), ph0 + 48);   // p_align

	// --- Program header 1: PT_GNU_STACK (type=0x6474e551), flags=READ|WRITE (no EXECUTE → NX) ---
	const ph1 = PH_OFF + PH_ENT_SIZE;
	buf.writeUInt32LE(0x6474e551, ph1);   // p_type = PT_GNU_STACK
	buf.writeUInt32LE(0x6, ph1 + 4);      // p_flags = PF_R | PF_W (no PF_X)

	// --- Section header 0: SHT_NULL (required) ---
	// Already zeroed

	// --- Section header 1: SHT_STRTAB (.shstrtab) ---
	const sh1 = SH_OFF + SH_ENT_SIZE;
	buf.writeUInt32LE(1, sh1);           // sh_name = offset 1 in strtab (".shstrtab")
	buf.writeUInt32LE(3, sh1 + 4);       // sh_type = SHT_STRTAB
	// sh_flags = 0
	// sh_addr = 0
	buf.writeBigUInt64LE(BigInt(STRTAB_OFF), sh1 + 24); // sh_offset
	buf.writeBigUInt64LE(BigInt(STRTAB_DATA.length), sh1 + 32); // sh_size

	// --- String table data ---
	buf.write(STRTAB_DATA, STRTAB_OFF, 'ascii');

	return buf;
}

/**
 * Helper: builds a synthetic ELF32 little-endian ARM binary.
 *
 * Layout:
 *   [0..51]    ELF32 header (52 bytes)
 *   [52..83]   1 program header (32 bytes): PT_LOAD
 *   [84..123]  1 section header (40 bytes): SHT_NULL
 *
 * Minimal but structurally valid ELF32 ARM binary.
 */
function buildSyntheticELF32ARM(): Buffer {
	const HEADER_SIZE = 52;
	const PH_OFF = 52;
	const PH_ENT_SIZE = 32;
	const PH_NUM = 1;
	const SH_OFF = PH_OFF + PH_NUM * PH_ENT_SIZE; // 84
	const SH_ENT_SIZE = 40;
	const SH_NUM = 1;
	const TOTAL_SIZE = SH_OFF + SH_NUM * SH_ENT_SIZE; // 124

	const buf = Buffer.alloc(TOTAL_SIZE, 0);

	// --- ELF header ---
	buf[0] = 0x7f; buf[1] = 0x45; buf[2] = 0x4c; buf[3] = 0x46; // magic
	buf[4] = 1;  // ELFCLASS32
	buf[5] = 1;  // ELFDATA2LSB
	buf[6] = 1;  // EV_CURRENT
	buf[7] = 0;  // ELFOSABI_NONE
	buf.writeUInt16LE(2, 16);   // e_type = ET_EXEC
	buf.writeUInt16LE(0x28, 18); // e_machine = ARM
	buf.writeUInt32LE(1, 20);   // e_version
	buf.writeUInt32LE(0x10000, 24); // e_entry
	buf.writeUInt32LE(PH_OFF, 28);  // e_phoff
	buf.writeUInt32LE(SH_OFF, 32);  // e_shoff
	buf.writeUInt32LE(0, 36);       // e_flags
	buf.writeUInt16LE(HEADER_SIZE, 40); // e_ehsize
	buf.writeUInt16LE(PH_ENT_SIZE, 42); // e_phentsize
	buf.writeUInt16LE(PH_NUM, 44);      // e_phnum
	buf.writeUInt16LE(SH_ENT_SIZE, 46); // e_shentsize
	buf.writeUInt16LE(SH_NUM, 48);      // e_shnum
	buf.writeUInt16LE(0, 50);           // e_shstrndx

	// --- Program header 0: PT_LOAD ---
	buf.writeUInt32LE(1, PH_OFF);       // p_type = PT_LOAD
	buf.writeUInt32LE(0, PH_OFF + 4);   // p_offset
	buf.writeUInt32LE(0x10000, PH_OFF + 8);  // p_vaddr
	buf.writeUInt32LE(0x10000, PH_OFF + 12); // p_paddr
	buf.writeUInt32LE(TOTAL_SIZE, PH_OFF + 16); // p_filesz
	buf.writeUInt32LE(TOTAL_SIZE, PH_OFF + 20); // p_memsz
	buf.writeUInt32LE(0x5, PH_OFF + 24);        // p_flags = PF_R | PF_X
	buf.writeUInt32LE(0x10000, PH_OFF + 28);    // p_align

	// --- Section header 0: SHT_NULL ---
	// Already zeroed

	return buf;
}

/**
 * Helper: builds a synthetic ELF64 DYN binary with configurable security mitigations.
 *
 * Sections: SHT_NULL, .shstrtab, .dynamic, .dynsym, .dynstr
 * Segments: PT_LOAD + optional PT_GNU_STACK, PT_GNU_RELRO, PT_DYNAMIC
 */
function buildSecurityELF64(opts: {
	hasGnuRelro?: boolean;
	hasBindNow?: boolean;
	hasDfBindNow?: boolean;
	hasDf1Now?: boolean;
	hasDf1Pie?: boolean;
	hasGnuStack?: boolean;
	gnuStackExec?: boolean;
	hasStackCanary?: boolean;
	elfType?: number;
}): Buffer {
	const {
		hasGnuRelro = false,
		hasBindNow = false,
		hasDfBindNow = false,
		hasDf1Now = false,
		hasDf1Pie = false,
		hasGnuStack = false,
		gnuStackExec = false,
		hasStackCanary = false,
		elfType = 3,
	} = opts;

	// Program headers
	const phList: Array<{ type: number; flags: number }> = [
		{ type: 1, flags: 0x5 }, // PT_LOAD
	];
	if (hasGnuStack) {
		phList.push({ type: 0x6474e551, flags: gnuStackExec ? 0x7 : 0x6 });
	}
	if (hasGnuRelro) {
		phList.push({ type: 0x6474e552, flags: 0x4 });
	}
	phList.push({ type: 2, flags: 0x6 }); // PT_DYNAMIC

	const PH_ENT = 56;
	const PH_NUM = phList.length;
	const PH_OFF = 64;

	const SH_ENT = 64;
	const SH_NUM = 5; // NULL, .shstrtab, .dynamic, .dynsym, .dynstr
	const SH_OFF = PH_OFF + PH_NUM * PH_ENT;

	// shstrtab: "\0.shstrtab\0.dynamic\0.dynsym\0.dynstr\0"
	const shstrtab = '\0.shstrtab\0.dynamic\0.dynsym\0.dynstr\0';
	const SHSTRTAB_OFF = SH_OFF + SH_NUM * SH_ENT;

	// Dynamic entries
	const dynList: Array<{ tag: number; val: number }> = [];
	if (hasBindNow) {
		dynList.push({ tag: 24, val: 0 });
	}
	if (hasDfBindNow) {
		dynList.push({ tag: 30, val: 0x8 });
	}
	const f1 = (hasDf1Now ? 0x1 : 0) | (hasDf1Pie ? 0x8000000 : 0);
	if (f1 !== 0) {
		dynList.push({ tag: 0x6ffffffb, val: f1 });
	}
	dynList.push({ tag: 0, val: 0 }); // DT_NULL

	const DYN_ENT = 16;
	const DYN_OFF = SHSTRTAB_OFF + shstrtab.length;
	const DYN_SIZE = dynList.length * DYN_ENT;

	// dynstr: "\0__stack_chk_fail\0" or "\0"
	const dynstr = hasStackCanary ? '\0__stack_chk_fail\0' : '\0';
	const DYNSTR_OFF = DYN_OFF + DYN_SIZE;

	// dynsym: null entry + optional __stack_chk_fail
	const SYM_ENT = 24;
	const symCount = hasStackCanary ? 2 : 1;
	const DYNSYM_OFF = DYNSTR_OFF + dynstr.length;
	const DYNSYM_SIZE = symCount * SYM_ENT;

	const TOTAL = DYNSYM_OFF + DYNSYM_SIZE;
	const buf = Buffer.alloc(TOTAL, 0);

	// --- ELF header ---
	buf[0] = 0x7f; buf[1] = 0x45; buf[2] = 0x4c; buf[3] = 0x46;
	buf[4] = 2; buf[5] = 1; buf[6] = 1; buf[7] = 0;
	buf.writeUInt16LE(elfType, 16);
	buf.writeUInt16LE(0x3E, 18);
	buf.writeUInt32LE(1, 20);
	buf.writeUInt32LE(0x1000, 24);
	buf.writeBigUInt64LE(BigInt(PH_OFF), 32);
	buf.writeBigUInt64LE(BigInt(SH_OFF), 40);
	buf.writeUInt16LE(64, 52);
	buf.writeUInt16LE(PH_ENT, 54);
	buf.writeUInt16LE(PH_NUM, 56);
	buf.writeUInt16LE(SH_ENT, 58);
	buf.writeUInt16LE(SH_NUM, 60);
	buf.writeUInt16LE(1, 62);

	// --- Program headers ---
	for (let i = 0; i < PH_NUM; i++) {
		const off = PH_OFF + i * PH_ENT;
		buf.writeUInt32LE(phList[i].type, off);
		buf.writeUInt32LE(phList[i].flags, off + 4);
	}

	// --- Section headers ---
	// SH[0]: NULL (zeroed)

	// SH[1]: .shstrtab (SHT_STRTAB=3)
	const s1 = SH_OFF + SH_ENT;
	buf.writeUInt32LE(1, s1);
	buf.writeUInt32LE(3, s1 + 4);
	buf.writeBigUInt64LE(BigInt(SHSTRTAB_OFF), s1 + 24);
	buf.writeBigUInt64LE(BigInt(shstrtab.length), s1 + 32);

	// SH[2]: .dynamic (SHT_DYNAMIC=6)
	const s2 = SH_OFF + 2 * SH_ENT;
	buf.writeUInt32LE(11, s2); // ".dynamic" starts at offset 11 in shstrtab
	buf.writeUInt32LE(6, s2 + 4);
	buf.writeBigUInt64LE(BigInt(DYN_OFF), s2 + 24);
	buf.writeBigUInt64LE(BigInt(DYN_SIZE), s2 + 32);
	buf.writeBigUInt64LE(BigInt(DYN_ENT), s2 + 56);

	// SH[3]: .dynsym (SHT_DYNSYM=11), sh_link=4 (points to .dynstr)
	const s3 = SH_OFF + 3 * SH_ENT;
	buf.writeUInt32LE(20, s3); // ".dynsym" starts at offset 20 in shstrtab
	buf.writeUInt32LE(11, s3 + 4);
	buf.writeBigUInt64LE(BigInt(DYNSYM_OFF), s3 + 24);
	buf.writeBigUInt64LE(BigInt(DYNSYM_SIZE), s3 + 32);
	buf.writeUInt32LE(4, s3 + 40); // sh_link = 4 (.dynstr section index)
	buf.writeBigUInt64LE(BigInt(SYM_ENT), s3 + 56);

	// SH[4]: .dynstr (SHT_STRTAB=3)
	const s4 = SH_OFF + 4 * SH_ENT;
	buf.writeUInt32LE(28, s4); // ".dynstr" starts at offset 28 in shstrtab
	buf.writeUInt32LE(3, s4 + 4);
	buf.writeBigUInt64LE(BigInt(DYNSTR_OFF), s4 + 24);
	buf.writeBigUInt64LE(BigInt(dynstr.length), s4 + 32);

	// --- Data: shstrtab ---
	buf.write(shstrtab, SHSTRTAB_OFF, 'ascii');

	// --- Data: dynamic entries ---
	for (let i = 0; i < dynList.length; i++) {
		const off = DYN_OFF + i * DYN_ENT;
		buf.writeBigInt64LE(BigInt(dynList[i].tag), off);
		buf.writeBigInt64LE(BigInt(dynList[i].val), off + 8);
	}

	// --- Data: dynstr ---
	buf.write(dynstr, DYNSTR_OFF, 'ascii');

	// --- Data: dynsym ---
	// Entry 0: null symbol (already zeroed)
	if (hasStackCanary) {
		const symOff = DYNSYM_OFF + SYM_ENT;
		// st_name = 1 (offset of "__stack_chk_fail" in dynstr)
		buf.writeUInt32LE(1, symOff);
		// st_info: binding=GLOBAL(1), type=FUNC(2) → (1 << 4) | 2 = 0x12
		buf[symOff + 4] = 0x12;
	}

	return buf;
}


suite('Unit Tests: ELF Parser (Task 5.11)', () => {

	let tmpDir: string;

	setup(() => {
		tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'elfunit-'));
	});

	teardown(() => {
		fs.rmSync(tmpDir, { recursive: true, force: true });
	});

	// -----------------------------------------------------------------
	// ELF64 x86_64 — sections, segments, known structure
	// Requirements: 4.1, 4.7
	// -----------------------------------------------------------------
	test('ELF64 x86_64: parses header, sections, and segments correctly', () => {
		const buf = buildSyntheticELF64();
		const filePath = path.join(tmpDir, 'test64.elf');
		fs.writeFileSync(filePath, buf);

		const result = analyzeELFFile(filePath);

		assert.strictEqual(result.isELF, true);
		assert.strictEqual(result.elfClass, 'ELF64');
		assert.strictEqual(result.endianness, 'little');
		assert.strictEqual(result.machine, 'x86_64');
		assert.strictEqual(result.type, 'EXEC');
		assert.strictEqual(result.entryPoint, '0x400000');

		// Should have 2 sections (NULL + .shstrtab)
		assert.strictEqual(result.sections.length, 2);
		assert.strictEqual(result.sections[1].name, '.shstrtab');
		assert.strictEqual(result.sections[1].type, 'STRTAB');

		// Should have 2 segments (PT_LOAD + PT_GNU_STACK)
		assert.strictEqual(result.segments.length, 2);
		assert.strictEqual(result.segments[0].type, 'LOAD');
		assert.ok(result.segments[0].flags.includes('READ'));
		assert.ok(result.segments[0].flags.includes('EXECUTE'));
		assert.strictEqual(result.segments[1].type, 'GNU_STACK');
		assert.ok(result.segments[1].flags.includes('READ'));
		assert.ok(result.segments[1].flags.includes('WRITE'));
		assert.ok(!result.segments[1].flags.includes('EXECUTE'));

		// Security: NX should be true (GNU_STACK without EXECUTE)
		assert.strictEqual(result.security.nx, true);
	});

	// -----------------------------------------------------------------
	// ELF32 ARM — verify 32-bit parsing
	// Requirements: 4.1, 4.7
	// -----------------------------------------------------------------
	test('ELF32 ARM: parses 32-bit header correctly', () => {
		const buf = buildSyntheticELF32ARM();
		const filePath = path.join(tmpDir, 'test32.elf');
		fs.writeFileSync(filePath, buf);

		const result = analyzeELFFile(filePath);

		assert.strictEqual(result.isELF, true);
		assert.strictEqual(result.elfClass, 'ELF32');
		assert.strictEqual(result.endianness, 'little');
		assert.strictEqual(result.machine, 'ARM');
		assert.strictEqual(result.type, 'EXEC');
		assert.strictEqual(result.entryPoint, '0x10000');

		// Should have 1 segment (PT_LOAD)
		assert.strictEqual(result.segments.length, 1);
		assert.strictEqual(result.segments[0].type, 'LOAD');

		// Arrays must be present
		assert.ok(Array.isArray(result.sections));
		assert.ok(Array.isArray(result.symbols));
		assert.ok(Array.isArray(result.dynamicEntries));
		assert.ok(Array.isArray(result.imports));

		// Security object must be defined
		assert.ok(result.security !== undefined);
		assert.strictEqual(typeof result.security.relro, 'string');
		assert.strictEqual(typeof result.security.stackCanary, 'boolean');
		assert.strictEqual(typeof result.security.nx, 'boolean');
		assert.strictEqual(typeof result.security.pie, 'boolean');
	});

	// -----------------------------------------------------------------
	// Truncated file — returns error
	// Requirements: 4.3
	// -----------------------------------------------------------------
	test('truncated file with ELF magic returns error', () => {
		// 8 bytes: valid magic + partial header (< 16 bytes minimum)
		const buf = Buffer.from([0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00]);
		const filePath = path.join(tmpDir, 'truncated.elf');
		fs.writeFileSync(filePath, buf);

		const result = analyzeELFFile(filePath);

		assert.strictEqual(result.isELF, false);
		assert.ok(typeof result.error === 'string' && result.error.length > 0);
		assert.ok(result.error!.includes('Truncated'));
	});

	// -----------------------------------------------------------------
	// RELRO detection: full vs partial vs none
	// Requirements: 4.1
	// -----------------------------------------------------------------
	test('RELRO none: no PT_GNU_RELRO segment', () => {
		const buf = buildSecurityELF64({ hasGnuRelro: false });
		const filePath = path.join(tmpDir, 'relro-none.elf');
		fs.writeFileSync(filePath, buf);

		const result = analyzeELFFile(filePath);
		assert.strictEqual(result.isELF, true);
		assert.strictEqual(result.security.relro, 'none');
	});

	test('RELRO partial: PT_GNU_RELRO without BIND_NOW', () => {
		const buf = buildSecurityELF64({ hasGnuRelro: true });
		const filePath = path.join(tmpDir, 'relro-partial.elf');
		fs.writeFileSync(filePath, buf);

		const result = analyzeELFFile(filePath);
		assert.strictEqual(result.isELF, true);
		assert.strictEqual(result.security.relro, 'partial');
	});

	test('RELRO full: PT_GNU_RELRO + DT_BIND_NOW', () => {
		const buf = buildSecurityELF64({ hasGnuRelro: true, hasBindNow: true });
		const filePath = path.join(tmpDir, 'relro-full-bindnow.elf');
		fs.writeFileSync(filePath, buf);

		const result = analyzeELFFile(filePath);
		assert.strictEqual(result.isELF, true);
		assert.strictEqual(result.security.relro, 'full');
	});

	test('RELRO full: PT_GNU_RELRO + DF_BIND_NOW in DT_FLAGS', () => {
		const buf = buildSecurityELF64({ hasGnuRelro: true, hasDfBindNow: true });
		const filePath = path.join(tmpDir, 'relro-full-dfbindnow.elf');
		fs.writeFileSync(filePath, buf);

		const result = analyzeELFFile(filePath);
		assert.strictEqual(result.isELF, true);
		assert.strictEqual(result.security.relro, 'full');
	});

	test('RELRO full: PT_GNU_RELRO + DF_1_NOW in DT_FLAGS_1', () => {
		const buf = buildSecurityELF64({ hasGnuRelro: true, hasDf1Now: true });
		const filePath = path.join(tmpDir, 'relro-full-df1now.elf');
		fs.writeFileSync(filePath, buf);

		const result = analyzeELFFile(filePath);
		assert.strictEqual(result.isELF, true);
		assert.strictEqual(result.security.relro, 'full');
	});

	// -----------------------------------------------------------------
	// PIE detection
	// Requirements: 4.1
	// -----------------------------------------------------------------
	test('PIE detected: ET_DYN + DF_1_PIE', () => {
		const buf = buildSecurityELF64({ elfType: 3, hasDf1Pie: true });
		const filePath = path.join(tmpDir, 'pie.elf');
		fs.writeFileSync(filePath, buf);

		const result = analyzeELFFile(filePath);
		assert.strictEqual(result.isELF, true);
		assert.strictEqual(result.security.pie, true);
	});

	test('PIE not detected: ET_EXEC (not DYN)', () => {
		const buf = buildSecurityELF64({ elfType: 2, hasDf1Pie: true });
		const filePath = path.join(tmpDir, 'no-pie-exec.elf');
		fs.writeFileSync(filePath, buf);

		const result = analyzeELFFile(filePath);
		assert.strictEqual(result.isELF, true);
		assert.strictEqual(result.security.pie, false);
	});

	// -----------------------------------------------------------------
	// NX detection
	// Requirements: 4.1
	// -----------------------------------------------------------------
	test('NX enabled: PT_GNU_STACK without EXECUTE flag', () => {
		const buf = buildSecurityELF64({ hasGnuStack: true, gnuStackExec: false });
		const filePath = path.join(tmpDir, 'nx-on.elf');
		fs.writeFileSync(filePath, buf);

		const result = analyzeELFFile(filePath);
		assert.strictEqual(result.isELF, true);
		assert.strictEqual(result.security.nx, true);
	});

	test('NX disabled: PT_GNU_STACK with EXECUTE flag', () => {
		const buf = buildSecurityELF64({ hasGnuStack: true, gnuStackExec: true });
		const filePath = path.join(tmpDir, 'nx-off.elf');
		fs.writeFileSync(filePath, buf);

		const result = analyzeELFFile(filePath);
		assert.strictEqual(result.isELF, true);
		assert.strictEqual(result.security.nx, false);
	});

	test('NX disabled: no PT_GNU_STACK segment', () => {
		const buf = buildSecurityELF64({ hasGnuStack: false });
		const filePath = path.join(tmpDir, 'nx-nostack.elf');
		fs.writeFileSync(filePath, buf);

		const result = analyzeELFFile(filePath);
		assert.strictEqual(result.isELF, true);
		assert.strictEqual(result.security.nx, false);
	});

	// -----------------------------------------------------------------
	// Stack Canary detection
	// Requirements: 4.1
	// -----------------------------------------------------------------
	test('Stack Canary detected: __stack_chk_fail in symbol table', () => {
		const buf = buildSecurityELF64({ hasStackCanary: true });
		const filePath = path.join(tmpDir, 'canary-on.elf');
		fs.writeFileSync(filePath, buf);

		const result = analyzeELFFile(filePath);
		assert.strictEqual(result.isELF, true);
		assert.strictEqual(result.security.stackCanary, true);
	});

	test('Stack Canary not detected: no __stack_chk_fail symbol', () => {
		const buf = buildSecurityELF64({ hasStackCanary: false });
		const filePath = path.join(tmpDir, 'canary-off.elf');
		fs.writeFileSync(filePath, buf);

		const result = analyzeELFFile(filePath);
		assert.strictEqual(result.isELF, true);
		assert.strictEqual(result.security.stackCanary, false);
	});
});
