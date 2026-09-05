export interface VmLadderInstruction {
	address: number;
	mnemonic: string;
	opStr: string;
	isConditional: boolean;
	isJump: boolean;
	targetAddress?: number;
}

export interface CompareDispatcherLadder {
	address: number | null;
	opcodeCount: number;
}

function parseComparison(opStr: string): { lhs: string; rhs: string } | undefined {
	const separator = opStr.lastIndexOf(',');
	if (separator < 0) {
		return undefined;
	}
	const lhs = opStr.slice(0, separator).trim().toLowerCase().replace(/\s+/g, ' ');
	const rhs = opStr.slice(separator + 1).trim().toLowerCase();
	if (!lhs || !/^-?(?:0x[\da-f]+|\d+)$/i.test(rhs)) {
		return undefined;
	}
	return { lhs, rhs };
}

function branchTarget(inst: VmLadderInstruction): string | undefined {
	if (inst.targetAddress !== undefined) {
		return `0x${inst.targetAddress.toString(16)}`;
	}
	const match = inst.opStr.trim().match(/^0x[\da-f]+$/i);
	return match?.[0].toLowerCase();
}

/**
 * Detect a linear opcode dispatcher made from repeated `cmp opcode, imm` +
 * conditional-branch pairs.
 *
 * A sequence of unrelated guard comparisons is not a dispatcher. Requiring a
 * stable compared operand, distinct opcode constants, and multiple handler
 * destinations rejects conjunctions such as anti-sandbox username/path checks
 * where every failed comparison jumps to one common failure block.
 */
export function detectCompareDispatcherLadder(
	instructions: readonly VmLadderInstruction[],
	minimumComparisons = 6
): CompareDispatcherLadder {
	let bestAddress: number | null = null;
	let bestCount = 0;

	for (let start = 0; start + 1 < instructions.length; start++) {
		let index = start;
		let lhs: string | undefined;
		const constants = new Set<string>();
		const targets = new Set<string>();
		let count = 0;

		while (index + 1 < instructions.length) {
			const compare = instructions[index];
			const branch = instructions[index + 1];
			if (compare.mnemonic.toLowerCase() !== 'cmp' || !branch.isConditional || !branch.isJump) {
				break;
			}

			const parsed = parseComparison(compare.opStr);
			const target = branchTarget(branch);
			if (!parsed || !target) {
				break;
			}
			if (lhs === undefined) {
				lhs = parsed.lhs;
			} else if (parsed.lhs !== lhs) {
				break;
			}

			constants.add(parsed.rhs);
			targets.add(target);
			count++;
			index += 2;
		}

		const enoughDistinctHandlers = targets.size >= Math.max(2, Math.ceil(count / 2));
		if (
			count >= minimumComparisons &&
			constants.size === count &&
			enoughDistinctHandlers &&
			count > bestCount
		) {
			bestAddress = instructions[start].address;
			bestCount = count;
		}
	}

	return { address: bestAddress, opcodeCount: bestCount };
}
