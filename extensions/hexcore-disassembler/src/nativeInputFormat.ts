/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import * as fs from 'fs';

export type UnsupportedNativeFormat = 'dex' | 'cdex' | 'vdex' | 'zip';

/** Recognition is deliberately independent of filename and raw architecture overrides. */
export function detectUnsupportedNativeFormat(header: Buffer): UnsupportedNativeFormat | undefined {
	if (header.length >= 8) {
		const magic = header.toString('latin1', 0, 8);
		if (/^dex\n[0-9]{3}\0$/.test(magic)) { return 'dex'; }
		if (/^cdex[0-9]{3}\0$/.test(magic)) { return 'cdex'; }
		if (/^vdex[0-9]{3}\0$/.test(magic)) { return 'vdex'; }
	}
	if (header.length >= 4 && header[0] === 0x50 && header[1] === 0x4b &&
		((header[2] === 3 && header[3] === 4) || (header[2] === 5 && header[3] === 6) || (header[2] === 7 && header[3] === 8))) {
		return 'zip';
	}
	return undefined;
}

export function inspectUnsupportedNativeFormat(filePath: string): UnsupportedNativeFormat | undefined {
	const fd = fs.openSync(filePath, 'r');
	try {
		const header = Buffer.alloc(8);
		return detectUnsupportedNativeFormat(header.subarray(0, fs.readSync(fd, header, 0, header.length, 0)));
	} finally {
		fs.closeSync(fd);
	}
}

export class UnsupportedNativeInputError extends Error {
	readonly code = 'unsupported-format';
	constructor(readonly detectedFormat: UnsupportedNativeFormat) {
		super(`unsupported-format: ${detectedFormat.toUpperCase()} is not native machine code. Native disassembly/lifting is unavailable for this input; use metadata extraction or a compatible backend.`);
		this.name = 'UnsupportedNativeInputError';
	}
}
