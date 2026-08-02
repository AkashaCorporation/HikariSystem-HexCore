/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as fs from 'fs';

const SINGLE_FILE_BUNDLE_SIGNATURE = Buffer.from([
	0x8b, 0x12, 0x02, 0xb9, 0x6a, 0x61, 0x20, 0x38,
	0x72, 0x7b, 0x93, 0x02, 0x14, 0xd7, 0xa0, 0x32,
	0x13, 0xf5, 0xb9, 0xe6, 0xef, 0xae, 0x33, 0x18,
	0xee, 0x3b, 0x2d, 0xce, 0x24, 0xb3, 0x6a, 0xae,
]);

const MAX_SINGLE_FILE_PROBE_BYTES = 64 * 1024 * 1024;
const SINGLE_FILE_PROBE_CHUNK_BYTES = 1024 * 1024;

/** Detect a validated .NET single-file bundle marker in an in-memory window. */
export function detectSingleFileBundle(window: Buffer, fileSize = window.length): boolean {
	let marker = window.indexOf(SINGLE_FILE_BUNDLE_SIGNATURE);
	while (marker >= 0) {
		if (marker >= 8) {
			const manifestOffset = window.readBigInt64LE(marker - 8);
			if (manifestOffset > 0n && manifestOffset < BigInt(fileSize)) {
				return true;
			}
		}
		marker = window.indexOf(SINGLE_FILE_BUNDLE_SIGNATURE, marker + 1);
	}
	return false;
}
/**
 * Scan the native apphost portion of a file for the .NET single-file marker.
 * The bounded, overlapping read avoids loading large appended bundles into the
 * extension host and still catches a marker split across chunk boundaries.
 */
export function isSingleFileBundle(filePath: string): boolean {
	let fd: number | undefined;
	try {
		fd = fs.openSync(filePath, 'r');
		const fileSize = fs.fstatSync(fd).size;
		if (fileSize < SINGLE_FILE_BUNDLE_SIGNATURE.length + 8) {
			return false;
		}

		const scanSize = Math.min(fileSize, MAX_SINGLE_FILE_PROBE_BYTES);
		const overlapSize = SINGLE_FILE_BUNDLE_SIGNATURE.length + 7;
		let overlap = Buffer.alloc(0);
		let position = 0;

		while (position < scanSize) {
			const count = Math.min(SINGLE_FILE_PROBE_CHUNK_BYTES, scanSize - position);
			const chunk = Buffer.allocUnsafe(count);
			const bytesRead = fs.readSync(fd, chunk, 0, count, position);
			if (bytesRead <= 0) {
				break;
			}

			const data = chunk.subarray(0, bytesRead);
			const window = overlap.length > 0 ? Buffer.concat([overlap, data]) : data;
			if (detectSingleFileBundle(window, fileSize)) {
				return true;
			}

			overlap = Buffer.from(window.subarray(Math.max(0, window.length - overlapSize)));
			position += bytesRead;
		}
		return false;
	} catch {
		return false;
	} finally {
		if (fd !== undefined) {
			try { fs.closeSync(fd); } catch { /* best effort */ }
		}
	}
}
