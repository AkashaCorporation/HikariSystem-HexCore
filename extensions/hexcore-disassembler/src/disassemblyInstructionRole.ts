/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

export type DisassemblyInstructionRole =
	| 'context'
	| 'semantic-body'
	| 'alignment-padding'
	| 'unclassified';

export interface InstructionRoleInput {
	address: number;
	mnemonic: string;
	isContext: boolean;
	semanticAddresses: ReadonlySet<number>;
	semanticEnd?: number;
	boundaryEndExclusive?: number;
}

/** Classify presentation bytes without claiming unknown instructions are semantic. */
export function classifyDisassemblyInstructionRole(input: InstructionRoleInput): DisassemblyInstructionRole {
	if (input.isContext) {
		return 'context';
	}
	if (input.semanticAddresses.has(input.address)) {
		return 'semantic-body';
	}
	const mnemonic = input.mnemonic.toLowerCase();
	if (input.semanticEnd !== undefined && input.boundaryEndExclusive !== undefined &&
		input.address >= input.semanticEnd && input.address < input.boundaryEndExclusive &&
		(mnemonic === 'int3' || mnemonic === 'nop')) {
		return 'alignment-padding';
	}
	return 'unclassified';
}
