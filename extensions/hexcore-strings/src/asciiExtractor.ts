export interface ExtractedAsciiString {
	offset: number;
	value: string;
	encoding: 'ASCII';
	section?: string;
}

export interface AsciiChunkResult {
	strings: ExtractedAsciiString[];
	carryover: string;
	carryoverOffset: number;
}

/**
 * Extract ASCII strings while preserving runs that cross read chunks.
 * CR/LF terminate a string just like NUL: compilers commonly place separately
 * referenced messages on adjacent lines without an intervening NUL.
 */
export function extractASCIIFromChunk(
	buffer: Buffer,
	baseOffset: number,
	minLength: number,
	carryover: string,
	carryoverOffset: number
): AsciiChunkResult {
	const strings: ExtractedAsciiString[] = [];
	let currentString = carryover;
	let startOffset = carryover.length > 0 ? carryoverOffset : baseOffset;

	const flush = (): void => {
		if (currentString.length >= minLength) {
			const trimmed = currentString.trim();
			if (trimmed.length >= minLength) {
				strings.push({
					offset: startOffset,
					value: trimmed,
					encoding: 'ASCII'
				});
			}
		}
		currentString = '';
	};

	for (let i = 0; i < buffer.length; i++) {
		const byte = buffer[i];
		if ((byte >= 32 && byte <= 126) || byte === 9) {
			if (currentString.length === 0) {
				startOffset = baseOffset + i;
			}
			currentString += String.fromCharCode(byte);
		} else {
			flush();
		}
	}

	return {
		strings,
		carryover: currentString,
		carryoverOffset: startOffset
	};
}
