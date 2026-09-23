export type LiftPreambleTransformationKind =
	| 'cet-preamble'
	| 'ftrace-preamble'
	| 'nop-preamble';

export interface LiftPreambleTransformation {
	kind: LiftPreambleTransformationKind;
	address: number;
	bytes: number;
}

export interface LiftPreamblePlan {
	skipBytes: number;
	transformations: LiftPreambleTransformation[];
}

export interface LiftPreambleEvidence {
	architecture: string;
	textSectionAddress?: number;
	textRelocations?: ReadonlyMap<number, { name: string; type: number; addend: number }>;
}

const LINUX_KERNEL_NOP9 = Buffer.from([
	0x66, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00,
]);

function matchesAt(bytes: Uint8Array, offset: number, pattern: Uint8Array): boolean {
	if (bytes.length < offset + pattern.length) {
		return false;
	}
	for (let index = 0; index < pattern.length; index++) {
		if (bytes[offset + index] !== pattern[index]) {
			return false;
		}
	}
	return true;
}

/**
 * Plans x86 entry transformations only with architecture and relocation evidence.
 * ELF container type alone cannot distinguish ftrace from a real unresolved call.
 */
export function planLiftPreamble(
	bytes: Uint8Array,
	startAddress: number,
	isRelocatableElf: boolean,
	evidence?: LiftPreambleEvidence,
): LiftPreamblePlan {
	const transformations: LiftPreambleTransformation[] = [];
	let skipBytes = 0;
	if (!Number.isSafeInteger(startAddress) || startAddress < 0) { throw new Error('Invalid preamble address'); }
	if (!evidence || !['x86', 'x64'].includes(evidence.architecture)) { return { skipBytes, transformations }; }

	const cet = evidence.architecture === 'x64' ? 0xfa : 0xfb;
	if (matchesAt(bytes, skipBytes, Buffer.from([0xf3, 0x0f, 0x1e, cet]))) {
		transformations.push({
			kind: 'cet-preamble',
			address: startAddress + skipBytes,
			bytes: 4,
		});
		skipBytes += 4;
	}

	const relocationOffset = Number.isSafeInteger(evidence.textSectionAddress)
		? startAddress + skipBytes + 1 - evidence.textSectionAddress! : undefined;
	const relocation = relocationOffset !== undefined ? evidence.textRelocations?.get(relocationOffset) : undefined;
	if (isRelocatableElf && relocation?.name === '__fentry__' &&
		[2, 4].includes(relocation.type) && relocation.addend === -4 &&
		matchesAt(bytes, skipBytes, Buffer.from([0xe8, 0x00, 0x00, 0x00, 0x00]))) {
		transformations.push({
			kind: 'ftrace-preamble',
			address: startAddress + skipBytes,
			bytes: 5,
		});
		skipBytes += 5;
	}

	// Only skip the exact 9-byte kernel NOP encoding. Treating every 66 0f
	// prefix as a two-byte NOP can cut through a valid instruction.
	if (matchesAt(bytes, skipBytes, LINUX_KERNEL_NOP9)) {
		transformations.push({
			kind: 'nop-preamble',
			address: startAddress + skipBytes,
			bytes: LINUX_KERNEL_NOP9.length,
		});
		skipBytes += LINUX_KERNEL_NOP9.length;
	}

	return { skipBytes, transformations };
}
