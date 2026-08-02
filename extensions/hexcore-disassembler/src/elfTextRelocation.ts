/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

const SHF_EXECINSTR = 0x4;
const STT_FUNC = 2;
const R_X86_64_PC32 = 2;

export interface ElfRelocationTarget {
	relocationType: number;
	symbolType: number;
	symbolValue: number;
	addend: number;
	targetSectionFlags?: number;
}

/**
 * R_X86_64_PC32 is used by both control-flow and RIP-relative data operands.
 * A defined symbol in a non-executable section is data, even when it has a
 * name; treating it as a call target corrupts the instruction operand.
 */
export function isX86PcRelativeDataRelocation(target: ElfRelocationTarget): boolean {
	return target.relocationType === R_X86_64_PC32
		&& target.symbolType !== STT_FUNC
		&& target.targetSectionFlags !== undefined
		&& (target.targetSectionFlags & SHF_EXECINSTR) === 0;
}

/**
 * ELF stores PC32 as S + A - P, while an x86 RIP-relative operand evaluates
 * from the end of its four-byte displacement: P + 4 + disp. Therefore the
 * effective offset inside the target section is st_value + addend + 4.
 */
export function x86PcRelativeDataSectionOffset(symbolValue: number, addend: number): number {
	return symbolValue + addend + 4;
}

/** Encode a RIP-relative four-byte operand for a synthetic data address. */
export function encodeX86PcRelativeDataDisplacement(
	targetAddress: number,
	relocationAddress: number,
): number {
	return (targetAddress - (relocationAddress + 4)) | 0;
}
