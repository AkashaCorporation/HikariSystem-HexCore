/*---------------------------------------------------------------------------------------------
 *  HexCore Debugger - Pure ELF relocation planning
 *  Copyright (c) HikariSystem. All rights reserved.
 *--------------------------------------------------------------------------------------------*/

const R_X86_64_GLOB_DAT = 6;
const R_X86_64_JUMP_SLOT = 7;
const R_X86_64_RELATIVE = 8;

export interface ElfRelocationSectionShape {
	offset: number;
	size: number;
}

export interface ElfRelocationCoverage {
	total: number;
	relative: number;
	appliedRelative: number;
	deferredImports: number;
	unsupported: number;
	failed: number;
}

export interface ElfBaseRelocation {
	targetAddress: bigint;
	value: bigint;
}

export interface ElfRelocationPlan {
	relocations: ElfBaseRelocation[];
	coverage: ElfRelocationCoverage;
}

export function emptyElfRelocationCoverage(): ElfRelocationCoverage {
	return { total: 0, relative: 0, appliedRelative: 0, deferredImports: 0, unsupported: 0, failed: 0 };
}

/** Plan ELF64 RELA base relocations without touching emulator memory. */
export function planElf64RelaDyn(
	buffer: Buffer,
	section: ElfRelocationSectionShape,
	loadBias: bigint,
): ElfRelocationPlan {
	const coverage = emptyElfRelocationCoverage();
	const relocations: ElfBaseRelocation[] = [];
	const entrySize = 24;
	const entryCount = Math.floor(section.size / entrySize);

	for (let index = 0; index < entryCount; index++) {
		const entryOffset = section.offset + index * entrySize;
		if (entryOffset < 0 || entryOffset + entrySize > buffer.length) {
			coverage.failed += entryCount - index;
			break;
		}
		coverage.total++;
		const targetOffset = buffer.readBigUInt64LE(entryOffset);
		const info = buffer.readBigUInt64LE(entryOffset + 8);
		const type = Number(info & 0xffffffffn);
		if (type === R_X86_64_RELATIVE) {
			const addend = buffer.readBigInt64LE(entryOffset + 16);
			coverage.relative++;
			relocations.push({ targetAddress: loadBias + targetOffset, value: BigInt.asUintN(64, loadBias + addend) });
		} else if (type === R_X86_64_GLOB_DAT || type === R_X86_64_JUMP_SLOT) {
			coverage.deferredImports++;
		} else {
			coverage.unsupported++;
		}
	}

	return { relocations, coverage };
}
