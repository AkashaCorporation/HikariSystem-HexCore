/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

export interface ElfStartupInstruction {
	address: number;
	size: number;
	mnemonic: string;
	opStr: string;
	isCall: boolean;
	targetAddress?: number;
}

export interface ElfStartupMainEvidence {
	mainAddress: number;
	assignmentAddress: number;
	callAddress: number;
	callTarget: number;
	evidence: 'sysv-x64-libc-startup';
}

function assignedRdiAddress(instruction: ElfStartupInstruction): number | undefined {
	const mnemonic = instruction.mnemonic.toLowerCase().trim();
	const operands = instruction.opStr.trim();
	if (mnemonic === 'mov') {
		const match = operands.match(/^rdi\s*,\s*(0x[0-9a-f]+|[0-9]+)$/i);
		if (match) {
			const value = Number.parseInt(match[1], match[1].toLowerCase().startsWith('0x') ? 16 : 10);
			return Number.isSafeInteger(value) ? value : undefined;
		}
	}
	if (mnemonic === 'lea') {
		const match = operands.match(/^rdi\s*,\s*\[rip\s*([+-])\s*(?:0x)?([0-9a-f]+)\]$/i);
		if (match) {
			const displacement = Number.parseInt(match[2], 16);
			const signed = match[1] === '-' ? -displacement : displacement;
			const value = instruction.address + instruction.size + signed;
			return Number.isSafeInteger(value) ? value : undefined;
		}
	}
	return undefined;
}

/**
 * Recover main only from the canonical SysV x64 process-entry setup. This is
 * deliberately stricter than a generic "constant moved to RDI before call"
 * heuristic so ordinary functions cannot mint a false main.
 */
export function recoverElfX64StartupMain(
	entryPoint: number,
	instructions: readonly ElfStartupInstruction[],
	isExecutableAddress: (address: number) => boolean,
): ElfStartupMainEvidence | undefined {
	if (!Number.isSafeInteger(entryPoint) || instructions.length < 6 || instructions[0].address !== entryPoint) {
		return undefined;
	}
	const preamble = instructions.slice(0, Math.min(instructions.length, 24));
	const evidence = {
		clearsFrame: preamble.some(instruction => instruction.mnemonic.toLowerCase() === 'xor' && /^ebp\s*,\s*ebp$/i.test(instruction.opStr)),
		popsArgc: preamble.some(instruction => instruction.mnemonic.toLowerCase() === 'pop' && /^rsi$/i.test(instruction.opStr.trim())),
		capturesStack: preamble.some(instruction => instruction.mnemonic.toLowerCase() === 'mov' && /^rdx\s*,\s*rsp$/i.test(instruction.opStr)),
		alignsStack: preamble.some(instruction => instruction.mnemonic.toLowerCase() === 'and' && /^rsp\s*,/i.test(instruction.opStr)),
	};
	if (Object.values(evidence).filter(Boolean).length < 3) {
		return undefined;
	}

	for (let callIndex = 1; callIndex < preamble.length; callIndex++) {
		const call = preamble[callIndex];
		if (!call.isCall || call.targetAddress === undefined || !isExecutableAddress(call.targetAddress)) {
			continue;
		}
		for (let index = callIndex - 1; index >= Math.max(0, callIndex - 4); index--) {
			const mainAddress = assignedRdiAddress(preamble[index]);
			if (mainAddress === undefined || mainAddress === entryPoint || !isExecutableAddress(mainAddress)) {
				continue;
			}
			return {
				mainAddress,
				assignmentAddress: preamble[index].address,
				callAddress: call.address,
				callTarget: call.targetAddress,
				evidence: 'sysv-x64-libc-startup',
			};
		}
	}
	return undefined;
}
