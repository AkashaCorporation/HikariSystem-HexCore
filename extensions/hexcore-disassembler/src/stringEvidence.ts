export interface ByteRange {
	start: number;
	end: number;
}

export interface StringEvidenceAssessment {
	literalConfidence: number;
	evidenceClass: 'referenced-literal' | 'terminated-literal' | 'unterminated-sequence' | 'lookup-table-sequence';
	evidenceReasons: string[];
}

function buildCrc32Table(): Buffer {
	const table = Buffer.alloc(256 * 4);
	for (let index = 0; index < 256; index++) {
		let value = index;
		for (let bit = 0; bit < 8; bit++) {
			value = (value & 1) !== 0 ? (0xedb88320 ^ (value >>> 1)) : (value >>> 1);
		}
		table.writeUInt32LE(value >>> 0, index * 4);
	}
	return table;
}

const CRC32_TABLE = buildCrc32Table();

export function findCrc32LookupRanges(buffer: Buffer): ByteRange[] {
	const ranges: ByteRange[] = [];
	let from = 0;
	while (from <= buffer.length - CRC32_TABLE.length) {
		const start = buffer.indexOf(CRC32_TABLE, from);
		if (start < 0) { break; }
		ranges.push({ start, end: start + CRC32_TABLE.length });
		from = start + CRC32_TABLE.length;
	}
	return ranges;
}

export function assessStringEvidence(
	fileOffset: number,
	terminated: boolean,
	referenceCount: number,
	lookupRanges: ByteRange[],
): StringEvidenceAssessment {
	const overlapsLookupTable = lookupRanges.some(range => fileOffset >= range.start && fileOffset < range.end);
	if (overlapsLookupTable) {
		return {
			literalConfidence: 0.1,
			evidenceClass: 'lookup-table-sequence',
			evidenceReasons: ['overlaps-standard-crc32-table'],
		};
	}
	if (referenceCount > 0) {
		return {
			literalConfidence: 0.95,
			evidenceClass: 'referenced-literal',
			evidenceReasons: [`${referenceCount}-code-reference(s)`],
		};
	}
	if (terminated) {
		return {
			literalConfidence: 0.75,
			evidenceClass: 'terminated-literal',
			evidenceReasons: ['nul-terminated', 'no-code-reference'],
		};
	}
	return {
		literalConfidence: 0.3,
		evidenceClass: 'unterminated-sequence',
		evidenceReasons: ['unterminated', 'no-code-reference'],
	};
}
