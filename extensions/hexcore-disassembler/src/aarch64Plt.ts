/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import type { DisassembledInstruction } from './capstoneWrapper';

export interface Aarch64PltBinding {
	address: number;
	endExclusive: number;
	gotAddress: number;
	symbol: string;
}

/** Match decoded PLT dataflow; never derive a symbol from entry order or stride. */
export function resolveAarch64PltBindings(
	instructions: readonly DisassembledInstruction[], gotSymbols: ReadonlyMap<number, string>,
	registerName: (id: number) => string | undefined,
): Aarch64PltBinding[] {
	const bindings: Aarch64PltBinding[] = [];
	for (let index = 0; index < instructions.length; index++) {
		const start = index;
		let cursor = index;
		if (instructions[cursor]?.mnemonic === 'bti') { cursor++; }
		const adrp = instructions[cursor++];
		const load = instructions[cursor++];
		if (adrp?.mnemonic !== 'adrp' || load?.mnemonic !== 'ldr') { continue; }
		const a = adrp.detail?.arm64;
		const l = load.detail?.arm64;
		const base = a?.operands[0];
		const page = a?.operands[1];
		const destination = l?.operands[0];
		const memory = l?.operands[1];
		if (base?.type !== 1 || base.reg === undefined || registerName(base.reg) !== 'x16' ||
			page?.type !== 2 || page.imm === undefined || !Number.isSafeInteger(page.imm) || page.imm % 4096 !== 0 ||
			destination?.type !== 1 || destination.reg === undefined || registerName(destination.reg) !== 'x17' ||
			memory?.type !== 3 || memory.mem?.base !== base.reg || memory.mem.index !== 0 ||
			!Number.isSafeInteger(memory.mem.disp) || l?.writeback || a?.updateFlags || memory.shift?.value) { continue; }
		const gotAddress = page.imm + memory.mem.disp;
		if (!Number.isSafeInteger(gotAddress) || gotAddress % 8 !== 0) { continue; }
		let addressPrepared = false;
		if (instructions[cursor]?.mnemonic === 'add') {
			const add = instructions[cursor++].detail?.arm64;
			if (add?.updateFlags || add?.operands[0]?.reg !== base.reg || add.operands[1]?.reg !== base.reg ||
				add.operands[2]?.type !== 2 || add.operands[2].imm !== memory.mem.disp || add.operands[2].shift?.value) { continue; }
			addressPrepared = true;
		}
		if (instructions[cursor]?.mnemonic === 'autia1716') {
			if (!addressPrepared) { continue; }
			cursor++;
		}
		const branch = instructions[cursor++];
		const operands = branch?.detail?.arm64?.operands;
		if (branch?.mnemonic === 'br') {
			if (operands?.length !== 1 || operands[0].reg !== destination.reg) { continue; }
		} else if (branch?.mnemonic === 'braa' || branch?.mnemonic === 'brab') {
			if (!addressPrepared || operands?.length !== 2 || operands[0].reg !== destination.reg || operands[1].reg !== base.reg) { continue; }
		} else { continue; }
		const chain = instructions.slice(start, cursor);
		if (chain.some((instruction, i) => instruction.size !== 4 || (i > 0 && instruction.address !== chain[i - 1].address + 4))) { continue; }
		const symbol = gotSymbols.get(gotAddress);
		if (!symbol) { continue; }
		bindings.push({ address: instructions[start].address, endExclusive: branch.address + branch.size, gotAddress, symbol });
		index = cursor - 1;
	}
	return bindings;
}
