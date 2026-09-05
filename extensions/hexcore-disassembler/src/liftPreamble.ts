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
 * Plans only evidence-backed entry transformations. A zero-displacement CALL
 * is an ftrace placeholder in relocatable ELF objects, but is observable PIC
 * (`call $+5; pop reg`) in PE and raw x86.
 */
export function planLiftPreamble(
	bytes: Uint8Array,
	startAddress: number,
	isRelocatableElf: boolean,
): LiftPreamblePlan {
	const transformations: LiftPreambleTransformation[] = [];
	let skipBytes = 0;

	if (matchesAt(bytes, skipBytes, Buffer.from([0xf3, 0x0f, 0x1e, 0xfa])) ||
		matchesAt(bytes, skipBytes, Buffer.from([0xf3, 0x0f, 0x1e, 0xfb]))) {
		transformations.push({
			kind: 'cet-preamble',
			address: startAddress + skipBytes,
			bytes: 4,
		});
		skipBytes += 4;
	}

	if (isRelocatableElf &&
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
