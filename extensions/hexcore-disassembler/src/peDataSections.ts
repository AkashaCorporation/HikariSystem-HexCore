// peDataSections.ts — minimal PE/COFF parser to extract data sections.
//
// Helix's RecoverSwitchTables pass needs to read jump-table entries from
// the binary's data sections (typically `.rdata` for MSVC-compiled PE).
// Without those bytes the pass skips itself and every `switch (...)` in
// the source binary collapses to `goto default` in the decompiled output.
//
// We parse only what we need: the PE header, section table, and the raw
// bytes of any read-only data section.  No imports, no relocations, no
// resource tree.  ~120 LOC, zero dependencies.

import * as fs from 'fs/promises';

export interface DataSection {
    /** Virtual address (image base + RVA) where the section is loaded. */
    vaStart: bigint;
    /** Raw bytes of the section as they appear at vaStart at runtime. */
    bytes: Buffer;
    /** Section name (".rdata", ".data", etc.) — for debugging only. */
    name: string;
}

/**
 * Read a PE/COFF binary and return every section that may contain
 * read-only or constant data (jump tables, vtables, string literals).
 *
 * Returns `null` if the file is not a recognised PE.  The caller can
 * fall back to passing no data sections — Helix will skip switch
 * recovery and emit a banner saying so.
 */
export async function readPeDataSections(filePath: string): Promise<DataSection[] | null> {
    const buf = await fs.readFile(filePath);

    // DOS header: 'MZ' at offset 0, e_lfanew (LE u32) at offset 0x3C.
    if (buf.length < 0x40 || buf[0] !== 0x4D || buf[1] !== 0x5A) {
        return null;
    }
    const peOffset = buf.readUInt32LE(0x3C);
    if (peOffset + 24 > buf.length) {
        return null;
    }

    // PE signature: 'PE\0\0'.
    if (buf.readUInt32LE(peOffset) !== 0x00004550) {
        return null;
    }

    // COFF header (right after signature, 20 bytes).
    const coffOff = peOffset + 4;
    const numSections = buf.readUInt16LE(coffOff + 2);
    const sizeOptHdr  = buf.readUInt16LE(coffOff + 16);

    // Optional header magic — 0x10B = PE32, 0x20B = PE32+ (64-bit).
    const optOff = coffOff + 20;
    if (optOff + 24 > buf.length) {
        return null;
    }
    const magic = buf.readUInt16LE(optOff);
    const isPe32Plus = magic === 0x20B;
    if (!isPe32Plus && magic !== 0x10B) {
        return null;
    }

    // Image base lives at different offsets in PE32 vs PE32+.
    //   PE32:  optOff + 28  (u32)
    //   PE32+: optOff + 24  (u64)
    const imageBase: bigint = isPe32Plus
        ? buf.readBigUInt64LE(optOff + 24)
        : BigInt(buf.readUInt32LE(optOff + 28));

    // Section table starts immediately after the optional header.
    const secTableOff = optOff + sizeOptHdr;
    const SECTION_HEADER_SIZE = 40;
    if (secTableOff + numSections * SECTION_HEADER_SIZE > buf.length) {
        return null;
    }

    const out: DataSection[] = [];
    for (let i = 0; i < numSections; ++i) {
        const off = secTableOff + i * SECTION_HEADER_SIZE;
        // Name: 8 bytes, null-padded ASCII.
        const nameRaw = buf.subarray(off, off + 8);
        const nullIdx = nameRaw.indexOf(0);
        const name = nameRaw.toString('ascii', 0, nullIdx === -1 ? 8 : nullIdx);

        const virtualSize  = buf.readUInt32LE(off + 8);
        const virtualAddr  = buf.readUInt32LE(off + 12);
        const sizeOfRawData = buf.readUInt32LE(off + 16);
        const ptrToRawData  = buf.readUInt32LE(off + 20);
        const characteristics = buf.readUInt32LE(off + 36);

        // IMAGE_SCN_MEM_EXECUTE = 0x20000000 — skip code sections.  We want
        // *data* — anything readable that isn't executable.  This catches
        // .rdata, .data, .pdata (exception tables), .xdata, custom data
        // sections from /SECTION pragmas, etc.
        const isExecutable = (characteristics & 0x20000000) !== 0;
        if (isExecutable) {
            continue;
        }
        // IMAGE_SCN_MEM_READ = 0x40000000.
        const isReadable = (characteristics & 0x40000000) !== 0;
        if (!isReadable) {
            continue;
        }

        // Skip uninitialised .bss-like sections (zero raw size).
        if (sizeOfRawData === 0 || ptrToRawData === 0) {
            continue;
        }

        // Read the raw bytes — clamp to virtualSize so we don't include
        // file alignment padding that runtime memory wouldn't have.
        const usable = Math.min(sizeOfRawData, virtualSize || sizeOfRawData);
        if (ptrToRawData + usable > buf.length) {
            continue;
        }
        const sectionBytes = Buffer.from(
            buf.subarray(ptrToRawData, ptrToRawData + usable)
        );

        out.push({
            name,
            vaStart: imageBase + BigInt(virtualAddr),
            bytes: sectionBytes,
        });
    }

    return out;
}
