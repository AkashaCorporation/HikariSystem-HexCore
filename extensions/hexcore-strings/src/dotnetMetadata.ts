/*---------------------------------------------------------------------------------------------
 *  HexCore Strings Extractor — .NET metadata-heap string reader
 *
 *  Managed (.NET / CLI) assemblies keep their string literals in metadata
 *  heaps, NOT as contiguous ASCII/UTF-16 runs in a data section. The byte-scan
 *  extractor therefore misses:
 *    - #Strings : UTF-8 identifier heap (type/method/field names, etc.)
 *    - #US      : UTF-16LE user-string heap (the `"..."` literals in code)
 *
 *  This module is self-contained (no dependency on hexcore-peanalyzer) and
 *  fully bounds-checked: any malformed field => the heap is skipped, never a
 *  throw. It is only invoked when the file is detected as .NET.
 *
 *  References (verified against source, do not reconstruct from memory):
 *    - PE format / CLR Runtime Header is data directory index 14:
 *      ref: https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
 *    - CLI header (IMAGE_COR20_HEADER): MetaData RVA @ +8, MetaData size @ +12.
 *    - Metadata root: BSJB sig 0x424A5342, length-prefixed version string
 *      (4-byte aligned), u16 flags, u16 stream count, then stream headers
 *      (u32 offset, u32 size, null-terminated name padded to 4 bytes).
 *      ref: ECMA-335 II.24.2.1 (Metadata root) / II.24.2.2 (Stream header)
 *    - #US is a blob heap of UTF-16 strings, each prefixed by a compressed
 *      unsigned integer length; the final byte after the UTF-16 data is a
 *      terminal flag (ignored). ref: ECMA-335 II.24.2.4 (#US and #Blob heaps)
 *    - Compressed unsigned integer (II.23.2):
 *        bit7 clear            => 1 byte,  value = b0
 *        bits7..6 == 10        => 2 bytes, value = ((b0 & 0x3F)<<8) | b1
 *        bits7..6 == 11        => 4 bytes, value = ((b0 & 0x1F)<<24)|(b1<<16)|(b2<<8)|b3
 *      ref: https://github.com/stakx/ecma-335/blob/master/docs/ii.23.2-blobs-and-signatures.md
 *--------------------------------------------------------------------------------------------*/

/** A string recovered from a .NET metadata heap. */
export interface DotNetMetadataString {
	/** File offset where the string's bytes begin (for attribution). */
	offset: number;
	value: string;
	/** Encoding bucket, mirrors ExtractedString in extension.ts. */
	encoding: 'ASCII' | 'UTF-16LE';
	/** Which heap it came from. */
	heap: '#Strings' | '#US';
}

export interface DotNetScanResult {
	/** True if the file is a managed (.NET) PE. */
	isDotNet: boolean;
	strings: DotNetMetadataString[];
}

/** A minimal section-table entry, used only for RVA -> file-offset mapping. */
interface RvaSection {
	virtualAddress: number;
	virtualSize: number;
	rawOffset: number;
	rawSize: number;
}

/** Safety cap so a corrupt/huge heap can never blow up the result set. */
const MAX_DOTNET_STRINGS = 50000;

/** Minimum kept length, mirrors the byte-scanner's spirit (skip 1-2 char noise). */
const MIN_DOTNET_LENGTH = 1;

/**
 * Detect a .NET assembly and, if found, read its #Strings and #US heaps.
 *
 * @param buffer The FULL file buffer. (.NET metadata lives wherever the CLI
 *               header points; we need random access across the file. Callers
 *               must only invoke this on files small enough to hold in memory —
 *               the scan path gates on .NET detection from a header pre-scan.)
 * @returns isDotNet flag + recovered strings. Never throws.
 */
export function scanDotNetMetadata(buffer: Buffer): DotNetScanResult {
	const empty: DotNetScanResult = { isDotNet: false, strings: [] };
	try {
		const layout = locateMetadataRoot(buffer);
		if (!layout) {
			return empty;
		}

		const strings: DotNetMetadataString[] = [];
		const root = layout.metadataOffset;

		// Parse the metadata root to find stream headers.
		const streams = parseStreamHeaders(buffer, root, layout.metadataSize);
		if (!streams) {
			// Detected as .NET (CLI header present) but metadata root malformed.
			return { isDotNet: true, strings: [] };
		}

		for (const s of streams) {
			if (strings.length >= MAX_DOTNET_STRINGS) {
				break;
			}
			// Stream offsets are relative to the metadata root.
			const streamStart = root + s.offset;
			const streamEnd = streamStart + s.size;
			if (streamStart < 0 || streamEnd > buffer.length || streamStart > streamEnd) {
				continue; // points outside the file — reject, never clamp
			}
			if (s.name === '#Strings') {
				readStringsHeap(buffer, streamStart, streamEnd, strings);
			} else if (s.name === '#US') {
				readUserStringHeap(buffer, streamStart, streamEnd, strings);
			}
		}

		return { isDotNet: true, strings };
	} catch {
		// Defensive: any parse error => behave as "not .NET" so native scans
		// are never disrupted.
		return empty;
	}
}

// ---------------------------------------------------------------------------
// PE / CLI header navigation
// ---------------------------------------------------------------------------

interface MetadataLayout {
	metadataOffset: number;
	metadataSize: number;
}

/**
 * Walk MZ -> PE -> optional header -> data directory[14] (CLR header) ->
 * CLI header -> metadata root, returning the file offset+size of the
 * metadata root. Returns null if the file is not a managed PE.
 */
function locateMetadataRoot(buffer: Buffer): MetadataLayout | null {
	if (buffer.length < 0x40) {
		return null;
	}
	// MZ
	if (buffer[0] !== 0x4D || buffer[1] !== 0x5A) {
		return null;
	}
	const eLfanew = buffer.readUInt32LE(0x3C);
	if (eLfanew + 24 > buffer.length) {
		return null;
	}
	// "PE\0\0"
	if (
		buffer[eLfanew] !== 0x50 || buffer[eLfanew + 1] !== 0x45 ||
		buffer[eLfanew + 2] !== 0x00 || buffer[eLfanew + 3] !== 0x00
	) {
		return null;
	}

	const coffOffset = eLfanew + 4;
	const numberOfSections = buffer.readUInt16LE(coffOffset + 2);
	const sizeOfOptionalHeader = buffer.readUInt16LE(coffOffset + 16);
	const optionalHeaderOffset = coffOffset + 20;
	if (optionalHeaderOffset + 2 > buffer.length) {
		return null;
	}

	// Magic decides the data-directory base offset within the optional header.
	const magic = buffer.readUInt16LE(optionalHeaderOffset);
	let dataDirBase: number;
	if (magic === 0x10b) {
		// PE32: data directories start at optional-header + 96.
		dataDirBase = optionalHeaderOffset + 96;
	} else if (magic === 0x20b) {
		// PE32+: data directories start at optional-header + 112.
		dataDirBase = optionalHeaderOffset + 112;
	} else {
		return null;
	}

	// CLR Runtime Header = data directory index 14 (8 bytes: RVA u32, size u32).
	// ref: https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
	const dir14 = dataDirBase + 14 * 8;
	if (dir14 + 8 > buffer.length) {
		return null;
	}
	const clrRva = buffer.readUInt32LE(dir14);
	const clrSize = buffer.readUInt32LE(dir14 + 4);
	if (clrRva === 0 || clrSize === 0) {
		return null; // not a .NET image
	}

	// Build the section table for RVA -> file-offset conversion.
	const sectionTableOffset = optionalHeaderOffset + sizeOfOptionalHeader;
	const sections = parseSections(buffer, sectionTableOffset, numberOfSections);
	if (sections.length === 0) {
		return null;
	}

	// Convert the CLR header RVA to a file offset and read the CLI header.
	const clrFileOffset = rvaToOffset(clrRva, sections);
	if (clrFileOffset === null || clrFileOffset + 16 > buffer.length) {
		return null;
	}
	// CLI header: MetaData RVA @ +8, MetaData size @ +12.
	const metaRva = buffer.readUInt32LE(clrFileOffset + 8);
	const metaSize = buffer.readUInt32LE(clrFileOffset + 12);
	if (metaRva === 0 || metaSize === 0) {
		return null;
	}
	const metaOffset = rvaToOffset(metaRva, sections);
	if (metaOffset === null || metaOffset + 4 > buffer.length) {
		return null;
	}
	// Verify the BSJB signature before trusting the offset.
	if (buffer.readUInt32LE(metaOffset) !== 0x424A5342) {
		return null;
	}
	// Clamp the usable metadata size to the file's actual extent.
	const usableSize = Math.min(metaSize, buffer.length - metaOffset);
	return { metadataOffset: metaOffset, metadataSize: usableSize };
}

/** Parse COFF section headers (40 bytes each) for RVA mapping. */
function parseSections(buffer: Buffer, tableOffset: number, count: number): RvaSection[] {
	const sections: RvaSection[] = [];
	const SECTION_HEADER_SIZE = 40;
	for (let i = 0; i < count; i++) {
		const entry = tableOffset + i * SECTION_HEADER_SIZE;
		if (entry + SECTION_HEADER_SIZE > buffer.length) {
			break;
		}
		const virtualSize = buffer.readUInt32LE(entry + 8);
		const virtualAddress = buffer.readUInt32LE(entry + 12);
		const rawSize = buffer.readUInt32LE(entry + 16);
		const rawOffset = buffer.readUInt32LE(entry + 20);
		sections.push({ virtualAddress, virtualSize, rawOffset, rawSize });
	}
	return sections;
}

/** Convert an RVA to a file offset using the section table. Null if unmapped. */
function rvaToOffset(rva: number, sections: RvaSection[]): number | null {
	for (const s of sections) {
		// Use the larger of virtual/raw size as the containment window so RVAs
		// in zero-padded virtual tails still resolve.
		const span = Math.max(s.virtualSize, s.rawSize);
		if (rva >= s.virtualAddress && rva < s.virtualAddress + span) {
			return s.rawOffset + (rva - s.virtualAddress);
		}
	}
	return null;
}

// ---------------------------------------------------------------------------
// Metadata root / stream headers
// ---------------------------------------------------------------------------

interface StreamHeader {
	name: string;
	offset: number; // relative to metadata root
	size: number;
}

/**
 * Parse the metadata root header and enumerate its stream headers.
 * Layout: BSJB(4) | major(2) | minor(2) | reserved(4) | versionLen(4) |
 *         version[versionLen, 4-byte aligned] | flags(2) | streamCount(2) |
 *         streamHeaders...
 */
function parseStreamHeaders(buffer: Buffer, root: number, metadataSize: number): StreamHeader[] | null {
	const rootEnd = root + metadataSize;
	if (root + 4 > buffer.length || buffer.readUInt32LE(root) !== 0x424A5342) {
		return null;
	}
	// version length is at root + 12 (after sig, major, minor, reserved).
	const versionLenOffset = root + 12;
	if (versionLenOffset + 4 > buffer.length) {
		return null;
	}
	const versionLen = buffer.readUInt32LE(versionLenOffset);
	if (versionLen < 0 || versionLen > 0x1000) {
		return null; // implausible version string length
	}
	// Version string is padded to a 4-byte boundary.
	const paddedVersionLen = (versionLen + 3) & ~3;
	let cursor = versionLenOffset + 4 + paddedVersionLen;
	// flags (2) + stream count (2)
	if (cursor + 4 > buffer.length) {
		return null;
	}
	cursor += 2; // skip flags
	const streamCount = buffer.readUInt16LE(cursor);
	cursor += 2;
	if (streamCount <= 0 || streamCount > 64) {
		return null; // implausible stream count
	}

	const headers: StreamHeader[] = [];
	for (let i = 0; i < streamCount; i++) {
		if (cursor + 8 > buffer.length) {
			break;
		}
		const offset = buffer.readUInt32LE(cursor);
		const size = buffer.readUInt32LE(cursor + 4);
		cursor += 8;
		// Name: null-terminated ASCII, total length padded to a multiple of 4.
		const nameStart = cursor;
		let nameEnd = nameStart;
		while (nameEnd < buffer.length && nameEnd < rootEnd && buffer[nameEnd] !== 0x00) {
			nameEnd++;
		}
		if (nameEnd >= buffer.length) {
			break;
		}
		const name = buffer.toString('ascii', nameStart, nameEnd);
		// Advance past the name including its NUL, rounded up to 4 bytes.
		const nameFieldLen = (nameEnd - nameStart) + 1; // include NUL
		const paddedNameLen = (nameFieldLen + 3) & ~3;
		cursor = nameStart + paddedNameLen;
		headers.push({ name, offset, size });
	}
	return headers.length > 0 ? headers : null;
}

// ---------------------------------------------------------------------------
// Heap readers
// ---------------------------------------------------------------------------

/**
 * #Strings: a sequence of NUL-terminated UTF-8 strings. The first byte is
 * always an empty string (the heap is indexed and index 0 == ""), so we walk
 * NUL-to-NUL and emit each non-empty run.
 */
function readStringsHeap(
	buffer: Buffer,
	start: number,
	end: number,
	out: DotNetMetadataString[],
): void {
	let i = start;
	while (i < end) {
		if (out.length >= MAX_DOTNET_STRINGS) {
			return;
		}
		let j = i;
		while (j < end && buffer[j] !== 0x00) {
			j++;
		}
		if (j > i) {
			const value = buffer.toString('utf8', i, j);
			if (value.length >= MIN_DOTNET_LENGTH) {
				out.push({ offset: i, value, encoding: 'ASCII', heap: '#Strings' });
			}
		}
		i = j + 1; // skip the NUL terminator
	}
}

/**
 * #US: a blob heap of UTF-16LE user strings. Index 0 is a single 0x00 byte
 * (the empty blob), so real entries start at offset 1. Each entry =
 *   compressed-uint blobLength | <blobLength bytes>
 * where the blob is UTF-16LE data followed by a single terminal flag byte
 * (0x00 or 0x01) that we strip. A blobLength of 0 is the empty user string.
 */
function readUserStringHeap(
	buffer: Buffer,
	start: number,
	end: number,
	out: DotNetMetadataString[],
): void {
	let i = start + 1; // skip the leading empty-blob byte
	while (i < end) {
		if (out.length >= MAX_DOTNET_STRINGS) {
			return;
		}
		const lenInfo = readCompressedUInt(buffer, i, end);
		if (!lenInfo) {
			break; // malformed length prefix — stop walking this heap
		}
		const blobLen = lenInfo.value;
		const dataStart = lenInfo.next;
		const dataEnd = dataStart + blobLen;
		if (blobLen === 0) {
			i = dataStart; // empty user string
			continue;
		}
		if (dataEnd > end || dataEnd > buffer.length) {
			break; // length runs past the heap — reject, never clamp
		}
		// The blob is UTF-16LE data + 1 terminal flag byte. Strip the flag.
		const utf16Len = blobLen - 1;
		if (utf16Len >= 2) {
			// Round down to an even byte count for clean UTF-16 decoding.
			const evenLen = utf16Len - (utf16Len % 2);
			const value = buffer.toString('utf16le', dataStart, dataStart + evenLen);
			const cleaned = stripControlChars(value);
			if (cleaned.length >= MIN_DOTNET_LENGTH) {
				out.push({ offset: dataStart, value: cleaned, encoding: 'UTF-16LE', heap: '#US' });
			}
		}
		i = dataEnd;
	}
}

/**
 * Decode an ECMA-335 II.23.2 compressed unsigned integer (stored big-endian
 * within the compressed field). Returns the value and the offset of the byte
 * just past the encoded integer, or null if out of bounds.
 */
function readCompressedUInt(
	buffer: Buffer,
	pos: number,
	end: number,
): { value: number; next: number } | null {
	if (pos >= end || pos >= buffer.length) {
		return null;
	}
	const b0 = buffer[pos];
	if ((b0 & 0x80) === 0) {
		// 1-byte: value in bits 6..0
		return { value: b0, next: pos + 1 };
	}
	if ((b0 & 0xC0) === 0x80) {
		// 2-byte: value in bits 13..0
		if (pos + 1 >= end || pos + 1 >= buffer.length) {
			return null;
		}
		const value = ((b0 & 0x3F) << 8) | buffer[pos + 1];
		return { value, next: pos + 2 };
	}
	if ((b0 & 0xE0) === 0xC0) {
		// 4-byte: value in bits 28..0
		if (pos + 3 >= end || pos + 3 >= buffer.length) {
			return null;
		}
		const value =
			((b0 & 0x1F) << 24) |
			(buffer[pos + 1] << 16) |
			(buffer[pos + 2] << 8) |
			buffer[pos + 3];
		return { value: value >>> 0, next: pos + 4 };
	}
	return null; // invalid leading byte (top bits 111...)
}

/**
 * User strings often contain non-text control chars (e.g. format placeholders
 * embed \0). Drop control characters except common whitespace so the emitted
 * value is clean for the report/UI, mirroring the byte-scanner's printable gate.
 */
function stripControlChars(s: string): string {
	let out = '';
	for (let k = 0; k < s.length; k++) {
		const c = s.charCodeAt(k);
		if (c === 9 || c === 10 || c === 13 || c >= 32) {
			out += s[k];
		}
	}
	return out.trim();
}
