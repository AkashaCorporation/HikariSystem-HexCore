/*---------------------------------------------------------------------------------------------
 *  HexCore Hex Viewer — Copy Formats & Data Inspector
 *  Copyright (c) HikariSystem. All rights reserved.
 *  Licensed under the MIT License.
 *--------------------------------------------------------------------------------------------*/

/**
 * Supported copy formats for byte selection.
 */
export type CopyFormat = 'hex' | 'c-array' | 'python-bytes';

/**
 * Data Inspector values for interpreting a byte buffer in multiple formats.
 */
export interface DataInspectorValues {
	uint8: number;
	int8: number;
	uint16LE: number;
	uint16BE: number;
	int16LE: number;
	int16BE: number;
	uint32LE: number;
	uint32BE: number;
	int32LE: number;
	int32BE: number;
	uint64LE: string;
	float32LE: number;
	float32BE: number;
	float64LE: number;
	float64BE: number;
	ascii: string;
	utf16le: string;
}

/**
 * Format a byte selection into the specified copy format.
 *
 * - `hex`: space-separated uppercase hex bytes, e.g. `"48 65 6C 6C 6F"`
 * - `c-array`: C-style initializer, e.g. `"{ 0x48, 0x65, 0x6C, 0x6C, 0x6F }"`
 * - `python-bytes`: Python bytes literal, e.g. `"b'\\x48\\x65\\x6c\\x6c\\x6f'"`
 */
export function formatSelection(bytes: Uint8Array, format: CopyFormat): string {
	switch (format) {
		case 'hex':
			return Array.from(bytes).map(b => b.toString(16).padStart(2, '0').toUpperCase()).join(' ');
		case 'c-array':
			return '{ ' + Array.from(bytes).map(b => '0x' + b.toString(16).padStart(2, '0').toUpperCase()).join(', ') + ' }';
		case 'python-bytes':
			return "b'" + Array.from(bytes).map(b => '\\x' + b.toString(16).padStart(2, '0')).join('') + "'";
	}
}

/**
 * Interpret a byte buffer into multiple numeric and string formats.
 * Returns "N/A"-equivalent values when the buffer has insufficient bytes
 * for a given format (NaN for numbers, empty string for strings).
 *
 * The buffer should be at least 8 bytes for full interpretation.
 * uint64LE is returned as a decimal string (BigInt serialization for webview).
 */
export function interpretBytes(buffer: Uint8Array): DataInspectorValues {
	// Ensure we have an ArrayBuffer-backed view for DataView
	const ab = new ArrayBuffer(8);
	const u8 = new Uint8Array(ab);
	for (let i = 0; i < Math.min(buffer.length, 8); i++) {
		u8[i] = buffer[i];
	}
	const view = new DataView(ab);
	const len = buffer.length;

	return {
		uint8: len >= 1 ? view.getUint8(0) : NaN,
		int8: len >= 1 ? view.getInt8(0) : NaN,
		uint16LE: len >= 2 ? view.getUint16(0, true) : NaN,
		uint16BE: len >= 2 ? view.getUint16(0, false) : NaN,
		int16LE: len >= 2 ? view.getInt16(0, true) : NaN,
		int16BE: len >= 2 ? view.getInt16(0, false) : NaN,
		uint32LE: len >= 4 ? view.getUint32(0, true) : NaN,
		uint32BE: len >= 4 ? view.getUint32(0, false) : NaN,
		int32LE: len >= 4 ? view.getInt32(0, true) : NaN,
		int32BE: len >= 4 ? view.getInt32(0, false) : NaN,
		uint64LE: len >= 8 ? view.getBigUint64(0, true).toString() : 'N/A',
		float32LE: len >= 4 ? view.getFloat32(0, true) : NaN,
		float32BE: len >= 4 ? view.getFloat32(0, false) : NaN,
		float64LE: len >= 8 ? view.getFloat64(0, true) : NaN,
		float64BE: len >= 8 ? view.getFloat64(0, false) : NaN,
		ascii: len >= 1 ? String.fromCharCode(...Array.from(buffer.slice(0, Math.min(len, 8))).map(b => (b >= 32 && b <= 126) ? b : 46)) : '',
		utf16le: len >= 2 ? decodeUtf16LE(buffer.slice(0, Math.min(len, 8))) : '',
	};
}

/**
 * Decode a byte buffer as UTF-16 LE string.
 */
function decodeUtf16LE(bytes: Uint8Array): string {
	const chars: string[] = [];
	for (let i = 0; i + 1 < bytes.length; i += 2) {
		const code = bytes[i] | (bytes[i + 1] << 8);
		chars.push(String.fromCharCode(code));
	}
	return chars.join('');
}
