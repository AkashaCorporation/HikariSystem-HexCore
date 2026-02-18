/*---------------------------------------------------------------------------------------------
 *  HexCore Hex Viewer — Hex Dump Module
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License.
 *--------------------------------------------------------------------------------------------*/

import * as fs from 'fs';

/**
 * Result of a hex dump operation.
 */
export interface HexDumpResult {
	filePath: string;
	offset: number;
	size: number;
	hexDump: string;
	raw: string;          // base64
	generatedAt: string;
}

/**
 * Read a range of bytes from a file and produce a formatted hex dump.
 *
 * The dump format is 16 bytes per line:
 * `OFFSET  HH HH HH HH HH HH HH HH  HH HH HH HH HH HH HH HH  ASCII`
 *
 * @param filePath - Absolute path to the file.
 * @param offset   - Byte offset to start reading (default 0).
 * @param size     - Number of bytes to read (default 256).
 * @returns A {@link HexDumpResult} with the formatted dump and raw base64 data.
 * @throws If the file does not exist or offset+size exceeds file size.
 */
export function hexDumpRange(
	filePath: string,
	offset: number = 0,
	size: number = 256
): HexDumpResult {
	if (!fs.existsSync(filePath)) {
		throw new Error(`File not found: ${filePath}`);
	}

	const stats = fs.statSync(filePath);
	if (offset < 0) {
		throw new Error(`Invalid offset: ${offset}. Offset must be non-negative.`);
	}
	if (offset >= stats.size) {
		throw new Error(
			`Offset 0x${offset.toString(16)} exceeds file size (${stats.size} bytes).`
		);
	}
	if (offset + size > stats.size) {
		throw new Error(
			`Requested range (offset=${offset}, size=${size}) exceeds file size (${stats.size} bytes).`
		);
	}

	const fd = fs.openSync(filePath, 'r');
	try {
		const buffer = Buffer.alloc(size);
		const bytesRead = fs.readSync(fd, buffer, 0, size, offset);
		const data = buffer.subarray(0, bytesRead);

		const hexDump = formatHexDump(data, offset);
		const raw = data.toString('base64');

		return {
			filePath,
			offset,
			size: bytesRead,
			hexDump,
			raw,
			generatedAt: new Date().toISOString()
		};
	} finally {
		fs.closeSync(fd);
	}
}

/**
 * Format a buffer into a classic hex dump string.
 *
 * Each line: `XXXXXXXX  HH HH HH HH HH HH HH HH  HH HH HH HH HH HH HH HH  ................`
 */
function formatHexDump(data: Buffer, baseOffset: number): string {
	const lines: string[] = [];
	const bytesPerLine = 16;

	for (let i = 0; i < data.length; i += bytesPerLine) {
		const lineBytes = data.subarray(i, Math.min(i + bytesPerLine, data.length));
		const addr = (baseOffset + i).toString(16).toUpperCase().padStart(8, '0');

		// Build hex columns (two groups of 8 bytes)
		const hexParts: string[] = [];
		for (let j = 0; j < bytesPerLine; j++) {
			if (j === 8) {
				hexParts.push('');  // extra space between groups
			}
			if (j < lineBytes.length) {
				hexParts.push(lineBytes[j].toString(16).toUpperCase().padStart(2, '0'));
			} else {
				hexParts.push('  ');
			}
		}
		const hex = hexParts.join(' ');

		// Build ASCII column
		let ascii = '';
		for (let j = 0; j < lineBytes.length; j++) {
			const byte = lineBytes[j];
			ascii += (byte >= 0x20 && byte <= 0x7E) ? String.fromCharCode(byte) : '.';
		}

		lines.push(`${addr}  ${hex}  ${ascii}`);
	}

	return lines.join('\n');
}
