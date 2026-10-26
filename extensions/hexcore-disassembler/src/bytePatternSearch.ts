export interface BytePatternEntry {
	value: number;
	wildcard: boolean;
}

export interface BytePatternSearchPage {
	offsets: number[];
	truncated: boolean;
	nextOffset?: number;
}

/**
 * Returns at most maxResults matches and probes one extra match so callers can
 * distinguish an exact full page from a truncated result. nextOffset is the
 * first omitted match and can be passed back as startOffset without losing it.
 */
export function scanBytePatternPage(
	buffer: Uint8Array,
	pattern: readonly BytePatternEntry[],
	maxResults: number,
	startOffset = 0,
): BytePatternSearchPage {
	if (!Number.isInteger(maxResults) || maxResults <= 0) {
		throw new Error('maxResults must be a positive integer.');
	}
	if (!Number.isInteger(startOffset) || startOffset < 0 || startOffset > buffer.length) {
		throw new Error('startOffset must be an integer inside the input buffer.');
	}
	if (pattern.length === 0) {
		throw new Error('pattern must contain at least one byte.');
	}

	const discovered: number[] = [];
	const scanLimit = buffer.length - pattern.length;
	for (let offset = startOffset; offset <= scanLimit && discovered.length <= maxResults; offset++) {
		let matched = true;
		for (let index = 0; index < pattern.length; index++) {
			const entry = pattern[index];
			if (!entry.wildcard && buffer[offset + index] !== entry.value) {
				matched = false;
				break;
			}
		}
		if (matched) {
			discovered.push(offset);
		}
	}

	const truncated = discovered.length > maxResults;
	return {
		offsets: discovered.slice(0, maxResults),
		truncated,
		...(truncated ? { nextOffset: discovered[maxResults] } : {}),
	};
}
