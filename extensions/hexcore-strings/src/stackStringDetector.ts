/*---------------------------------------------------------------------------------------------
 *  HexCore Strings Extractor v1.2.0
 *  Stack string detector — opcode pattern matching for x86/x64/ARM64
 *  Copyright (c) HikariSystem. All rights reserved.
 *--------------------------------------------------------------------------------------------*/

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface StackString {
	/** The reconstructed string from MOV/STRB-to-stack instructions. */
	value: string;
	/** Absolute file offset where the first instruction starts. */
	offset: number;
	/** Number of store instructions in the sequence. */
	instructionCount: number;
	/** Whether the pattern uses RBP, RSP, or ARM64 SP/FP-relative addressing. */
	addressingMode: 'rbp' | 'rsp' | 'sp-arm64' | 'fp-arm64';
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/**
 * Minimum consecutive store-to-stack instructions to consider it a stack string.
 * Fewer than 4 is likely coincidental.
 */
const MIN_SEQUENCE_LENGTH = 4;

/**
 * Maximum gap (in bytes) between consecutive instructions in a sequence.
 * Stack string builders usually have adjacent instructions, but compilers might
 * insert NOPs or alignment padding.
 */
const MAX_INSTRUCTION_GAP = 8;

/**
 * Maximum number of instructions to look backwards when searching for a MOV/MOVZ
 * that loaded the ASCII value into the source register of an ARM64 STRB/STR.
 */
const ARM64_MOV_LOOKBACK = 8;

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

// ---------------------------------------------------------------------------
// ARM64 STRB/STR-to-Stack Opcode Patterns
// ---------------------------------------------------------------------------

/**
 * ARM64 builds stack strings differently using STRB and STR instructions:
 *
 * Pattern A: STRB (store byte, unsigned offset)
 *   strb wT, [Rn, #imm12]
 *   Encoding: 0011_1001_00ii_iiii_iiii_iinn_nnnt_tttt
 *   Mask: 0xFFC00000, Value: 0x39000000
 *   Stack store when Rn = SP (31) or X29/FP (29)
 *
 * Pattern B: STR 32-bit (unsigned offset)
 *   str wT, [Rn, #imm12]
 *   Encoding: 1011_1001_00ii_iiii_iiii_iinn_nnnt_tttt
 *   Mask: 0xFFC00000, Value: 0xB9000000
 *
 * Pattern C: STR 64-bit (unsigned offset)
 *   str xT, [Rn, #imm12]
 *   Encoding: 1111_1001_00ii_iiii_iiii_iinn_nnnt_tttt
 *   Mask: 0xFFC00000, Value: 0xF9000000
 *
 * The immediate value is typically loaded with MOV/MOVZ beforehand:
 *   mov wT, #imm16  =>  MOVZ: 0101_0010_100h_hhhh_hhhh_hhhh_hhht_tttt
 *   Mask: 0xFFE00000, Value: 0x52800000
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
	mode: 'rbp' | 'rsp' | 'sp-arm64' | 'fp-arm64';
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Scan a binary buffer for x86/x64 and ARM64 stack string patterns.
 *
 * The detector scans the buffer linearly for store-to-stack opcodes, groups
 * consecutive matches into sequences, then reconstructs strings by ordering
 * characters by their stack displacement values.
 *
 * @param buffer     Raw binary data chunk
 * @param baseOffset File offset where this chunk starts
 */
export function detectStackStrings(buffer: Buffer, baseOffset: number): StackString[] {
	// Scan for both x86 and ARM64 patterns
	const x86Matches = scanForMOVOpcodes(buffer);
	const arm64Matches = scanForARM64StackOpcodes(buffer);

	// Merge and sort all matches by position
	const allMatches = [...x86Matches, ...arm64Matches].sort((a, b) => a.position - b.position);

	if (allMatches.length < MIN_SEQUENCE_LENGTH) {
		return [];
	}

	// Group consecutive matches into sequences
	const sequences = groupSequences(allMatches);

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
// x86/x64 Opcode Scanner
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
// ARM64 Opcode Scanner
// ---------------------------------------------------------------------------

/**
 * Scan a binary buffer for ARM64 STRB/STR-to-stack patterns.
 *
 * ARM64 instructions are fixed-width (4 bytes, little-endian). We scan 4 bytes
 * at a time and match against the following store instruction encodings:
 *
 * - STRB (unsigned offset): mask 0xFFC00000, value 0x39000000
 * - STR  32-bit (unsigned offset): mask 0xFFC00000, value 0xB9000000
 * - STR  64-bit (unsigned offset): mask 0xFFC00000, value 0xF9000000
 *
 * For each matched store, we check if the base register (Rn) is SP (31) or
 * X29/FP (29), indicating a stack store. We then look backwards for a
 * MOV/MOVZ instruction that loaded the ASCII value into the source register (Rt).
 */
function scanForARM64StackOpcodes(buffer: Buffer): OpcodeMatch[] {
	const matches: OpcodeMatch[] = [];

	// ARM64 instructions must be 4-byte aligned
	for (let i = 0; i <= buffer.length - 4; i += 4) {
		const instr = buffer.readUInt32LE(i);

		// --- Pattern A: STRB (unsigned offset) ---
		// Mask: 0xFFC00000, Value: 0x39000000
		if ((instr & 0xFFC00000) === 0x39000000) {
			const result = decodeARM64StoreAndMatch(buffer, i, instr, 1);
			if (result !== null) {
				matches.push(result);
			}
			continue;
		}

		// --- Pattern B: STR 32-bit (unsigned offset) ---
		// Mask: 0xFFC00000, Value: 0xB9000000
		if ((instr & 0xFFC00000) === 0xB9000000) {
			const result = decodeARM64StoreAndMatch(buffer, i, instr, 4);
			if (result !== null) {
				matches.push(result);
			}
			continue;
		}

		// --- Pattern C: STR 64-bit (unsigned offset) ---
		// Mask: 0xFFC00000, Value: 0xF9000000
		if ((instr & 0xFFC00000) === 0xF9000000) {
			const result = decodeARM64StoreAndMatch(buffer, i, instr, 8);
			if (result !== null) {
				matches.push(result);
			}
			continue;
		}
	}

	return matches;
}

/**
 * Decode an ARM64 store instruction and try to find the loaded ASCII value.
 *
 * @param buffer    Full binary buffer
 * @param pos       Position of the store instruction
 * @param instr     The 32-bit instruction word
 * @param storeSize Number of bytes being stored (1 for STRB, 4 for STR W, 8 for STR X)
 * @returns OpcodeMatch if this is a stack string store, null otherwise
 */
function decodeARM64StoreAndMatch(
	buffer: Buffer,
	pos: number,
	instr: number,
	storeSize: number,
): OpcodeMatch | null {
	// Extract fields from the instruction encoding:
	// Bits [4:0]   = Rt (source register)
	// Bits [9:5]   = Rn (base register)
	// Bits [21:10] = imm12 (unsigned offset)
	const rt = instr & 0x1F;
	const rn = (instr >>> 5) & 0x1F;
	const imm12 = (instr >>> 10) & 0xFFF;

	// Only interested in stack stores: base register must be SP (31) or FP/X29 (29)
	if (rn !== 31 && rn !== 29) {
		return null;
	}

	// Scale the offset by the store size (STRB=1, STR W=4, STR X=8)
	const displacement = imm12 * storeSize;

	// Look backwards for a MOV/MOVZ that loaded a value into register Rt
	const loadedValue = findARM64MovImmediate(buffer, pos, rt, storeSize);
	if (loadedValue === null) {
		return null;
	}

	// Extract ASCII characters from the loaded value
	const chars: number[] = [];
	if (storeSize === 1) {
		// STRB: single byte
		if (isPrintableASCII(loadedValue & 0xFF)) {
			chars.push(loadedValue & 0xFF);
		}
	} else if (storeSize === 4) {
		// STR W: up to 4 chars packed in a 32-bit value (little-endian)
		for (let byteIdx = 0; byteIdx < 4; byteIdx++) {
			const byte = (loadedValue >>> (byteIdx * 8)) & 0xFF;
			if (isPrintableASCII(byte)) {
				chars.push(byte);
			} else if (byte === 0x00) {
				// Null terminator, stop
				break;
			} else {
				// Non-printable non-null: not a string
				return null;
			}
		}
	} else if (storeSize === 8) {
		// STR X: up to 8 chars packed in a 64-bit value (little-endian)
		// We only have the low 32 bits from MOVZ (high bits require MOVK)
		// Extract what we can
		for (let byteIdx = 0; byteIdx < 8; byteIdx++) {
			const byte = (loadedValue >>> (byteIdx * 8)) & 0xFF;
			if (byteIdx >= 4 && loadedValue <= 0xFFFFFFFF) {
				// Upper bytes are zero from a 32-bit MOVZ, treat as null terminator
				break;
			}
			if (isPrintableASCII(byte)) {
				chars.push(byte);
			} else if (byte === 0x00) {
				break;
			} else {
				return null;
			}
		}
	}

	if (chars.length === 0) {
		return null;
	}

	const mode: 'sp-arm64' | 'fp-arm64' = rn === 31 ? 'sp-arm64' : 'fp-arm64';

	return {
		position: pos,
		instrLength: 4,
		displacement,
		chars,
		mode,
	};
}

/**
 * Search backwards from a store instruction to find a MOV/MOVZ that loaded
 * an immediate value into the given register.
 *
 * ARM64 MOV (wide immediate) / MOVZ encoding:
 *   For 32-bit (W registers): mask 0xFFE00000, value 0x52800000
 *   For 64-bit (X registers): mask 0xFFE00000, value 0xD2800000
 *
 * The immediate is in bits [20:5] (imm16), and hw (shift) is in bits [22:21].
 *
 * @param buffer    Full binary buffer
 * @param storePos  Position of the store instruction
 * @param targetReg Register number (Rt from the store)
 * @param storeSize Store size to determine if we look for W or X register MOV
 * @returns The immediate value loaded, or null if not found
 */
function findARM64MovImmediate(
	buffer: Buffer,
	storePos: number,
	targetReg: number,
	storeSize: number,
): number | null {
	// Search backwards through preceding instructions
	for (let step = 1; step <= ARM64_MOV_LOOKBACK; step++) {
		const movPos = storePos - (step * 4);
		if (movPos < 0) {
			break;
		}

		const movInstr = buffer.readUInt32LE(movPos);

		// MOVZ 32-bit (W register): mask 0xFFE00000, value 0x52800000
		if ((movInstr & 0xFFE00000) === 0x52800000) {
			const rd = movInstr & 0x1F;
			if (rd === targetReg) {
				const imm16 = (movInstr >>> 5) & 0xFFFF;
				const hw = (movInstr >>> 21) & 0x3;
				return imm16 << (hw * 16);
			}
		}

		// MOVZ 64-bit (X register): mask 0xFFE00000, value 0xD2800000
		if ((movInstr & 0xFFE00000) === 0xD2800000) {
			const rd = movInstr & 0x1F;
			if (rd === targetReg) {
				const imm16 = (movInstr >>> 5) & 0xFFFF;
				const hw = (movInstr >>> 21) & 0x3;
				// For 64-bit, the shift can be 0, 16, 32, or 48.
				// JavaScript bitwise ops are 32-bit, so use multiplication for larger shifts.
				return imm16 * Math.pow(2, hw * 16);
			}
		}

		// Also check ORR (immediate) which compilers use for MOV aliases:
		// MOV Wd, #imm is sometimes encoded as ORR Wd, WZR, #imm
		// 32-bit ORR immediate: mask 0xFF800000, value 0x32000000
		// This is complex (bitmask immediate encoding), skip for now — MOVZ covers
		// the vast majority of stack string patterns.

		// If we see the target register being written by something else, stop looking
		// (the register was clobbered between the MOV and the STRB)
		const rdCandidate = movInstr & 0x1F;
		if (rdCandidate === targetReg) {
			// Some other instruction writes to our target register — give up
			break;
		}
	}

	return null;
}

// ---------------------------------------------------------------------------
// Sequence Grouping
// ---------------------------------------------------------------------------

/**
 * Group opcode matches into sequences of consecutive store instructions.
 * Two matches are "consecutive" if:
 * 1. Gap between end of one and start of next is <= MAX_INSTRUCTION_GAP
 * 2. They use the same addressing mode category (x86 with x86, ARM64 with ARM64)
 */
function groupSequences(matches: OpcodeMatch[]): OpcodeMatch[][] {
	if (matches.length === 0) { return []; }

	const sequences: OpcodeMatch[][] = [];
	let currentSeq: OpcodeMatch[] = [matches[0]];

	for (let i = 1; i < matches.length; i++) {
		const prev = matches[i - 1];
		const curr = matches[i];

		const gap = curr.position - (prev.position + prev.instrLength);

		if (gap <= MAX_INSTRUCTION_GAP && gap >= 0 && areModesCompatible(curr.mode, prev.mode)) {
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

/**
 * Check if two addressing modes are compatible for grouping into the same sequence.
 * x86 modes group together, ARM64 modes group together, but they don't mix.
 */
function areModesCompatible(a: OpcodeMatch['mode'], b: OpcodeMatch['mode']): boolean {
	const aIsArm64 = a === 'sp-arm64' || a === 'fp-arm64';
	const bIsArm64 = b === 'sp-arm64' || b === 'fp-arm64';

	// Must be same architecture family
	if (aIsArm64 !== bIsArm64) {
		return false;
	}

	// Within the same family, allow mixing SP and FP (compilers sometimes do this)
	return true;
}

// ---------------------------------------------------------------------------
// String Reconstruction
// ---------------------------------------------------------------------------

/**
 * Reconstruct a string from a sequence of store instructions.
 *
 * Characters are ordered by their stack displacement value:
 * - RSP-relative and ARM64 SP/FP-relative: ascending order (positive offsets)
 * - RBP-relative: descending order (negative offsets from frame pointer)
 */
function reconstructString(seq: OpcodeMatch[]): string | null {
	// Sort by displacement to reconstruct character order
	const sorted = [...seq].sort((a, b) => {
		// For RBP-relative (negative displacements), reverse order
		if (a.mode === 'rbp') {
			return b.displacement - a.displacement;
		}
		// For RSP-relative and ARM64 SP/FP-relative (positive displacements), normal order
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
