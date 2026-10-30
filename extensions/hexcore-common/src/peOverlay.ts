/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as fs from 'fs';

const MAX_HEADER_BYTES = 1024 * 1024;
const MAX_OVERLAY_PROBE_BYTES = 1024 * 1024;
const NSIS_FIRST_HEADER_SIGNATURE = Buffer.from('efbeadde4e756c6c736f6674496e7374', 'hex');

export interface PEOverlayInspection {
	offset: number;
	size: number;
	payloadSizeExcludingCertificate: number;
	container: 'nsis' | 'unknown-overlay';
	formatHints: string[];
	evidence: string[];
	certificateTable?: { offset: number; size: number };
	nsis?: {
		signatureOffset: number;
		headerLength?: number;
		followingDataLength?: number;
	};
}

/** Inspect a PE overlay without decoding or extracting its payload. */
export function inspectPEOverlay(filePath: string): PEOverlayInspection | undefined {
	const stat = fs.statSync(filePath);
	if (stat.size < 64) { return undefined; }
	const fd = fs.openSync(filePath, 'r');
	try {
		const initial = Buffer.alloc(Math.min(stat.size, MAX_HEADER_BYTES));
		const initialRead = fs.readSync(fd, initial, 0, initial.length, 0);
		const header = initial.subarray(0, initialRead);
		if (header.length < 64 || header.readUInt16LE(0) !== 0x5a4d) { return undefined; }
		const peOffset = header.readUInt32LE(0x3c);
		if (!Number.isSafeInteger(peOffset) || peOffset < 0 || peOffset + 24 > header.length ||
			header.toString('ascii', peOffset, peOffset + 4) !== 'PE\0\0') { return undefined; }
		const sectionCount = header.readUInt16LE(peOffset + 6);
		const optionalSize = header.readUInt16LE(peOffset + 20);
		const optionalOffset = peOffset + 24;
		const sectionOffset = optionalOffset + optionalSize;
		const sectionTableEnd = sectionOffset + sectionCount * 40;
		if (sectionCount > 4096 || optionalSize < 64 || sectionTableEnd > header.length) { return undefined; }
		const magic = header.readUInt16LE(optionalOffset);
		if (magic !== 0x10b && magic !== 0x20b) { return undefined; }
		const sizeOfHeaders = header.readUInt32LE(optionalOffset + 60);
		let imageEnd = Math.min(stat.size, sizeOfHeaders);
		for (let index = 0; index < sectionCount; index++) {
			const current = sectionOffset + index * 40;
			const rawSize = header.readUInt32LE(current + 16);
			const rawOffset = header.readUInt32LE(current + 20);
			const end = rawOffset + rawSize;
			if (Number.isSafeInteger(end) && rawOffset <= stat.size && end <= stat.size) {
				imageEnd = Math.max(imageEnd, end);
			}
		}
		if (imageEnd >= stat.size) { return undefined; }

		const dataDirectoryOffset = optionalOffset + (magic === 0x20b ? 112 : 96);
		let certificateTable: PEOverlayInspection['certificateTable'];
		if (dataDirectoryOffset + 40 <= optionalOffset + optionalSize) {
			const offset = header.readUInt32LE(dataDirectoryOffset + 32);
			const size = header.readUInt32LE(dataDirectoryOffset + 36);
			if (offset >= imageEnd && size > 0 && offset + size <= stat.size) {
				certificateTable = { offset, size };
			}
		}

		const size = stat.size - imageEnd;
		const probe = Buffer.alloc(Math.min(size, MAX_OVERLAY_PROBE_BYTES));
		const probeRead = fs.readSync(fd, probe, 0, probe.length, imageEnd);
		const view = probe.subarray(0, probeRead);
		const nsisIndex = view.indexOf(NSIS_FIRST_HEADER_SIGNATURE);
		const nsisSignatureOffset = nsisIndex >= 0 ? imageEnd + nsisIndex : undefined;
		const formatHints = nsisSignatureOffset !== undefined ? ['nsis'] : [];
		const evidence = [`overlay-after-sections:${imageEnd}`, `overlay-size:${size}`];
		let nsis: PEOverlayInspection['nsis'];
		if (nsisSignatureOffset !== undefined) {
			evidence.push(`nsis-first-header-signature:${nsisSignatureOffset}`);
			const relativeAfterSignature = nsisIndex + NSIS_FIRST_HEADER_SIGNATURE.length;
			nsis = { signatureOffset: nsisSignatureOffset };
			if (relativeAfterSignature + 8 <= view.length) {
				nsis.headerLength = view.readUInt32LE(relativeAfterSignature);
				nsis.followingDataLength = view.readUInt32LE(relativeAfterSignature + 4);
			}
		}
		return {
			offset: imageEnd,
			size,
			payloadSizeExcludingCertificate: Math.max(0, size - (certificateTable?.size ?? 0)),
			container: nsis ? 'nsis' : 'unknown-overlay',
			formatHints,
			evidence,
			...(certificateTable ? { certificateTable } : {}),
			...(nsis ? { nsis } : {}),
		};
	} finally {
		fs.closeSync(fd);
	}
}
