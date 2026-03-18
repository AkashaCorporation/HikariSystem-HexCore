/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface PESectionInfo {
	name: string;
	offset: number;       // PointerToRawData
	size: number;          // SizeOfRawData
	virtualAddress: number;
	virtualSize: number;
}

export interface PESectionMap {
	isPE: boolean;
	sections: PESectionInfo[];
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Size of a single COFF section header entry */
const SECTION_HEADER_SIZE = 40;

/** Minimum buffer size to attempt PE parsing */
const MIN_BUFFER_SIZE = 64;

// ---------------------------------------------------------------------------
// parsePESections
// ---------------------------------------------------------------------------

/**
 * Parse PE headers from a buffer to extract section information.
 * This is a lightweight parser that does not depend on hexcore-peanalyzer.
 * Reads only from the provided buffer (no file I/O).
 *
 * @param buffer Buffer containing at least the first ~2KB of a PE file
 * @returns PESectionMap with isPE flag and array of section info
 */
export function parsePESections(buffer: Buffer): PESectionMap {
	const fail: PESectionMap = { isPE: false, sections: [] };

	// 1. Check buffer length >= 64 bytes
	if (buffer.length < MIN_BUFFER_SIZE) {
		return fail;
	}

	// 2. Verify MZ signature (0x4D, 0x5A) at offset 0
	if (buffer[0] !== 0x4D || buffer[1] !== 0x5A) {
		return fail;
	}

	// 3. Read e_lfanew as UInt32LE at offset 0x3C
	const eLfanew = buffer.readUInt32LE(0x3C);

	// 4. Verify e_lfanew + 4 is within buffer bounds
	if (eLfanew + 4 > buffer.length) {
		return fail;
	}

	// 5. Verify PE signature (0x50, 0x45, 0x00, 0x00) at e_lfanew
	if (
		buffer[eLfanew] !== 0x50 ||
		buffer[eLfanew + 1] !== 0x45 ||
		buffer[eLfanew + 2] !== 0x00 ||
		buffer[eLfanew + 3] !== 0x00
	) {
		return fail;
	}

	// 6. Read COFF header at e_lfanew + 4
	const coffOffset = eLfanew + 4;

	// NumberOfSections at coffOffset + 2 (UInt16LE)
	if (coffOffset + 20 > buffer.length) {
		return fail;
	}
	const numberOfSections = buffer.readUInt16LE(coffOffset + 2);

	// SizeOfOptionalHeader at coffOffset + 16 (UInt16LE)
	const sizeOfOptionalHeader = buffer.readUInt16LE(coffOffset + 16);

	// 7. Calculate section table offset: e_lfanew + 4 + 20 + SizeOfOptionalHeader
	const sectionTableOffset = coffOffset + 20 + sizeOfOptionalHeader;

	// 8. Parse each section (as many as fit in the buffer)
	const sections: PESectionInfo[] = [];
	for (let i = 0; i < numberOfSections; i++) {
		const entryOffset = sectionTableOffset + i * SECTION_HEADER_SIZE;

		// Check if the full section entry fits in the buffer
		if (entryOffset + SECTION_HEADER_SIZE > buffer.length) {
			break; // parse as many sections as fit
		}

		// Name: 8 bytes at offset 0 (null-terminated ASCII)
		let nameEnd = 8;
		for (let j = 0; j < 8; j++) {
			if (buffer[entryOffset + j] === 0x00) {
				nameEnd = j;
				break;
			}
		}
		const name = buffer.toString('ascii', entryOffset, entryOffset + nameEnd);

		// VirtualSize: UInt32LE at offset 8
		const virtualSize = buffer.readUInt32LE(entryOffset + 8);

		// VirtualAddress: UInt32LE at offset 12
		const virtualAddress = buffer.readUInt32LE(entryOffset + 12);

		// SizeOfRawData: UInt32LE at offset 16
		const size = buffer.readUInt32LE(entryOffset + 16);

		// PointerToRawData: UInt32LE at offset 20
		const offset = buffer.readUInt32LE(entryOffset + 20);

		sections.push({ name, offset, size, virtualAddress, virtualSize });
	}

	// 9. Return result
	return { isPE: true, sections };
}

// ---------------------------------------------------------------------------
// getSectionForOffset
// ---------------------------------------------------------------------------

/**
 * Determine which PE section a file offset falls within.
 *
 * @param sections Array of PE section info
 * @param offset File offset to look up
 * @returns Section name if found, undefined otherwise
 */
export function getSectionForOffset(sections: PESectionInfo[], offset: number): string | undefined {
	for (const section of sections) {
		if (offset >= section.offset && offset < section.offset + section.size) {
			return section.name;
		}
	}
	return undefined;
}
