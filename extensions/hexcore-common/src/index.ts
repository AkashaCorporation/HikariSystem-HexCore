/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
/**
 * Format bytes to human-readable string
 */
export function formatBytes(bytes: number): string {
	if (bytes === 0) {
		return '0 B';
	}
	const k = 1024;
	const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
	const i = Math.floor(Math.log(bytes) / Math.log(k));
	return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

/**
 * Calculate Shannon entropy of a buffer
 */
export function calculateEntropy(buffer: Buffer): number {
	if (buffer.length === 0) {
		return 0;
	}

	const freq = new Array(256).fill(0);
	for (let i = 0; i < buffer.length; i++) {
		freq[buffer[i]]++;
	}

	let entropy = 0;
	for (let i = 0; i < 256; i++) {
		if (freq[i] > 0) {
			const p = freq[i] / buffer.length;
			entropy -= p * Math.log2(p);
		}
	}

	return Math.round(entropy * 100) / 100;
}

/**
 * Read null-terminated string from buffer
 */
export function readNullTerminatedString(buffer: Buffer, maxLength: number = 256): string {
	let end = buffer.indexOf(0);
	if (end === -1) {
		end = Math.min(buffer.length, maxLength);
	}
	return buffer.toString('ascii', 0, end);
}

/**
 * Check if byte is printable ASCII
 */
export function isPrintableASCII(byte: number): boolean {
	return (byte >= 32 && byte <= 126) || byte === 9 || byte === 10 || byte === 13;
}

/**
 * Convert buffer to hex dump string
 */
export function toHexDump(buffer: Buffer, bytesPerLine: number = 16): string {
	const lines: string[] = [];
	for (let offset = 0; offset < buffer.length; offset += bytesPerLine) {
		const chunk = buffer.subarray(offset, Math.min(offset + bytesPerLine, buffer.length));
		const hex = Array.from(chunk).map(b => b.toString(16).toUpperCase().padStart(2, '0')).join(' ');
		const ascii = Array.from(chunk).map(b => isPrintableASCII(b) ? String.fromCharCode(b) : '.').join('');
		lines.push(`${offset.toString(16).toUpperCase().padStart(8, '0')}  ${hex.padEnd(bytesPerLine * 3 - 1)}  ${ascii}`);
	}
	return lines.join('\n');
}

/**
 * Escape HTML special characters
 */
export function escapeHtml(text: string): string {
	const doubleQuote = String.fromCharCode(34);
	const singleQuote = String.fromCharCode(39);
	const map: Record<string, string> = {
		'&': '&amp;',
		'<': '&lt;',
		'>': '&gt;',
		[doubleQuote]: '&quot;',
		[singleQuote]: '&#039;'
	};
	const matcher = new RegExp(`[&<>'${doubleQuote}]`, 'g');
	return text.replace(matcher, m => map[m] || m);
}

/**
 * Format hex value with 0x prefix
 */
export function formatHex(value: number, padLength: number = 8): string {
	return '0x' + value.toString(16).toUpperCase().padStart(padLength, '0');
}

/**
 * Stream processor for large files
 * Processes file in chunks to avoid memory issues
 */
export async function processFileInChunks(
	filePath: string,
	chunkSize: number,
	processor: (chunk: Buffer, offset: number) => void | Promise<void>,
	onProgress?: (bytesProcessed: number, totalBytes: number) => void
): Promise<void> {
	const fs = await import('fs');
	const { promisify } = await import('util');

	const stat = await promisify(fs.stat)(filePath);
	const totalSize = stat.size;
	const fd = await promisify(fs.open)(filePath, 'r');

	try {
		let offset = 0;
		const buffer = Buffer.alloc(chunkSize);

		while (offset < totalSize) {
			const bytesToRead = Math.min(chunkSize, totalSize - offset);
			const { bytesRead } = await promisify(fs.read)(fd, buffer, 0, bytesToRead, offset);

			if (bytesRead === 0) {
				break;
			}

			const chunk = buffer.subarray(0, bytesRead);
			await processor(chunk, offset);

			offset += bytesRead;
			if (onProgress) {
				onProgress(offset, totalSize);
			}
		}
	} finally {
		await promisify(fs.close)(fd);
	}
}

export {
	loadNativeModule,
	type NativeModuleLoadOptions,
	type NativeModuleLoadResult
} from './nativeModuleLoader';

export { getHexCoreBaseCSS } from './webviewStyles';

export {
	riskLevelToColor,
	entropyToColor,
	type RiskLevel
} from './riskMapping';

