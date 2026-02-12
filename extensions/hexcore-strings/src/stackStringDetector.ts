/*---------------------------------------------------------------------------------------------
 *  HexCore Strings Extractor v1.2.0
 *  Stack string detector — opcode pattern matching for x86/x64
 *  Copyright (c) HikariSystem. All rights reserved.
 *--------------------------------------------------------------------------------------------*/

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface StackString {
	/** The reconstructed string from MOV-to-stack instructions. */
	value: string;
	/** Absolute file offset where the first MOV instruction starts. */
	offset: number;
	/** Number of MOV instructions in the sequence. */
	instructionCount: number;
	/** Whether the pattern uses RBP or RSP-relative addressing. */
	addressingMode: 'rbp' | 'rsp';
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/**
 * Minimum consecutive MOV-to-stack instructions to consider it a stack string.
 * Fewer than 4 is likely coincidental.
 */
const MIN_SEQUENCE_LENGTH = 4;

/**
 * Maximum gap (in bytes) between consecutive MOV instructions in a sequence.
 * Stack string builders usually have adjacent MOVs, but compilers might insert
 * NOPs or alignment padding.
 */
const MAX_INSTRUCTION_GAP = 8;

// ---------------------------------------------------------------------------
// x86/x64 MOV Byte-to-Stack Opcode Patterns
// ---------------------------------------------------------------------------

/**
 * Stack string obfuscation typically compiles down to one of these patterns:
 *
 * Pattern 1: MOV BYTE [rbp-disp8], imm8
 *   Opcode: C6 45 XX YY
 *   Where XX = displacement (signed int8) and YY = ASCII byte
 *
 * Pattern 2: MOV BYTE [rbp+disp8], imm8
 *   Opcode: C6 45 XX YY  (same encoding, displacement sign encodes direction)
 *
 * Pattern 3: MOV BYTE [rsp+disp8], imm8
 *   REX? + C6 44 24 XX YY
 *   Where XX = displacement and YY = ASCII byte
 *
 * Pattern 4: MOV DWORD [rbp-disp8], imm32 (packs 4 chars at once)
 *   Opcode: C7 45 XX YY YY YY YY
 *
 * Pattern 5: MOV DWORD [rsp+disp8], imm32
 *   Opcode: C7 44 24 XX YY YY YY YY
 *
 * We scan for these raw byte patterns without full disassembly.
 */

interface OpcodeMatch {
	/** Position of the opcode start in the buffer. */
	position: number;
	/** Total instruction length. */
	instrLength: number;
	/** Stack displacement (can be used to order chars). */
	displacement: number;
	/** Decoded ASCII character(s). */
	chars: number[];
	/** Addressing mode. */
	mode: 'rbp' | 'rsp';
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Scan a binary buffer for x86/x64 stack string patterns.
 *
 * The detector scans the buffer linearly for MOV-to-stack opcodes, groups
 * consecutive matches into sequences, then reconstructs strings by ordering
 * characters by their stack displacement values.
 *
 * @param buffer     Raw binary data chunk
 * @param baseOffset File offset where this chunk starts
 */
export function detectStackStrings(buffer: Buffer, baseOffset: number): StackString[] {
	const matches = scanForMOVOpcodes(buffer);

	if (matches.length < MIN_SEQUENCE_LENGTH) {
		return [];
	}

	// Group consecutive matches into sequences
	const sequences = groupSequences(matches);

	// Reconstruct strings from each valid sequence
	const results: StackString[] = [];

	for (const seq of sequences) {
		if (seq.length < MIN_SEQUENCE_LENGTH) {
			continue;
		}

		const reconstructed = reconstructString(seq);
		if (reconstructed === null) {
			continue;
		}

		// Verify the string is meaningful
		if (!isLikelyString(reconstructed)) {
			continue;
		}

		results.push({
			value: reconstructed,
			offset: baseOffset + seq[0].position,
			instructionCount: seq.length,
			addressingMode: seq[0].mode,
		});
	}

	return results;
}

// ---------------------------------------------------------------------------
// Opcode Scanner
// ---------------------------------------------------------------------------

function scanForMOVOpcodes(buffer: Buffer): OpcodeMatch[] {
	const matches: OpcodeMatch[] = [];

	for (let i = 0; i < buffer.length - 4; i++) {
		const b0 = buffer[i];

		// Pattern 1: C6 45 XX YY — MOV BYTE [rbp+disp8], imm8
		if (b0 === 0xC6 && buffer[i + 1] === 0x45 && i + 3 < buffer.length) {
			const disp = buffer.readInt8(i + 2);
			const imm = buffer[i + 3];
			if (isPrintableASCII(imm)) {
				matches.push({
					position: i,
					instrLength: 4,
					displacement: disp,
					chars: [imm],
					mode: 'rbp',
				});
			}
			continue;
		}

		// Pattern 2: C6 44 24 XX YY — MOV BYTE [rsp+disp8], imm8
		if (b0 === 0xC6 && buffer[i + 1] === 0x44 && buffer[i + 2] === 0x24 && i + 4 < buffer.length) {
			const disp = buffer.readUInt8(i + 3);
			const imm = buffer[i + 4];
			if (isPrintableASCII(imm)) {
				matches.push({
					position: i,
					instrLength: 5,
					displacement: disp,
					chars: [imm],
					mode: 'rsp',
				});
			}
			continue;
		}

		// Pattern 3: C7 45 XX YY YY YY YY — MOV DWORD [rbp+disp8], imm32
		if (b0 === 0xC7 && buffer[i + 1] === 0x45 && i + 6 < buffer.length) {
			const disp = buffer.readInt8(i + 2);
			const chars = [buffer[i + 3], buffer[i + 4], buffer[i + 5], buffer[i + 6]];

			// All 4 bytes must be printable (or null terminator for last)
			const printableChars = chars.filter(c => isPrintableASCII(c) || c === 0x00);
			if (printableChars.length === 4) {
				// Strip trailing nulls
				const validChars = chars.filter(c => isPrintableASCII(c));
				if (validChars.length >= 2) {
					matches.push({
						position: i,
						instrLength: 7,
						displacement: disp,
						chars: validChars,
						mode: 'rbp',
					});
				}
			}
			continue;
		}

		// Pattern 4: C7 44 24 XX YY YY YY YY — MOV DWORD [rsp+disp8], imm32
		if (b0 === 0xC7 && buffer[i + 1] === 0x44 && buffer[i + 2] === 0x24 && i + 7 < buffer.length) {
			const disp = buffer.readUInt8(i + 3);
			const chars = [buffer[i + 4], buffer[i + 5], buffer[i + 6], buffer[i + 7]];

			const printableChars = chars.filter(c => isPrintableASCII(c) || c === 0x00);
			if (printableChars.length === 4) {
				const validChars = chars.filter(c => isPrintableASCII(c));
				if (validChars.length >= 2) {
					matches.push({
						position: i,
						instrLength: 8,
						displacement: disp,
						chars: validChars,
						mode: 'rsp',
					});
				}
			}
			continue;
		}
	}

	return matches;
}

// ---------------------------------------------------------------------------
// Sequence Grouping
// ---------------------------------------------------------------------------

/**
 * Group opcode matches into sequences of consecutive MOV instructions.
 * Two matches are "consecutive" if:
 * 1. Gap between end of one and start of next is ≤ MAX_INSTRUCTION_GAP
 * 2. They use the same addressing mode (rbp or rsp)
 */
function groupSequences(matches: OpcodeMatch[]): OpcodeMatch[][] {
	if (matches.length === 0) { return []; }

	const sequences: OpcodeMatch[][] = [];
	let currentSeq: OpcodeMatch[] = [matches[0]];

	for (let i = 1; i < matches.length; i++) {
		const prev = matches[i - 1];
		const curr = matches[i];

		const gap = curr.position - (prev.position + prev.instrLength);

		if (gap <= MAX_INSTRUCTION_GAP && gap >= 0 && curr.mode === prev.mode) {
			currentSeq.push(curr);
		} else {
			if (currentSeq.length >= MIN_SEQUENCE_LENGTH) {
				sequences.push(currentSeq);
			}
			currentSeq = [curr];
		}
	}

	if (currentSeq.length >= MIN_SEQUENCE_LENGTH) {
		sequences.push(currentSeq);
	}

	return sequences;
}

// ---------------------------------------------------------------------------
// String Reconstruction
// ---------------------------------------------------------------------------

/**
 * Reconstruct a string from a sequence of MOV instructions.
 *
 * Characters are ordered by their stack displacement value (ascending for
 * RSP-relative, descending for RBP-relative since RBP offsets are negative).
 */
function reconstructString(seq: OpcodeMatch[]): string | null {
	// Sort by displacement to reconstruct character order
	const sorted = [...seq].sort((a, b) => {
		// For RBP-relative (negative displacements), reverse order
		if (a.mode === 'rbp') {
			return b.displacement - a.displacement;
		}
		// For RSP-relative (positive displacements), normal order
		return a.displacement - b.displacement;
	});

	let result = '';
	for (const match of sorted) {
		for (const ch of match.chars) {
			result += String.fromCharCode(ch);
		}
	}

	return result.length > 0 ? result : null;
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/**
 * Verify a reconstructed string looks like real text and not random matches.
 * Checks:
 * - Contains at least one letter (not all digits/symbols)
 * - Has reasonable character variety
 * - Not a repeated character pattern
 */
function isLikelyString(str: string): boolean {
	// Must have at least one letter
	if (!/[a-zA-Z]/.test(str)) {
		return false;
	}

	// Check character variety — a real string has at least 3 unique chars
	const unique = new Set(str.split(''));
	if (unique.size < 3) {
		return false;
	}

	// Reject repeating patterns (e.g., "AAAA" or "abab")
	if (str.length >= 6) {
		const half = str.substring(0, Math.floor(str.length / 2));
		if (str.startsWith(half + half)) {
			return false;
		}
	}

	return true;
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

function isPrintableASCII(byte: number): boolean {
	return byte >= 0x20 && byte <= 0x7E;
}
