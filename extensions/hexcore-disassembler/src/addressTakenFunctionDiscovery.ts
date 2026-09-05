/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import type { DisassembledInstruction } from './capstoneWrapper';

export interface HalfOpenFunctionRange {
	start: number;
	endExclusive: number;
}

export interface AddressTakenFunctionCandidate {
	address: number;
	leaAddress: number;
	storeAddress: number;
	registerId: number;
	confidence: number;
	reasons: readonly string[];
}

export interface AddressTakenDiscoveryOptions {
	isExecutableAddress(address: number): boolean;
	registerName(registerId: number): string | undefined;
	knownFunctions: readonly HalfOpenFunctionRange[];
	maxConsumerDistance?: number;
}

export interface ValidatedFunctionExtent {
	semanticEnd: number;
	endExclusive: number;
	terminalAddress: number;
	terminalKind: 'return';
}

function isInteriorToKnownFunction(address: number, ranges: readonly HalfOpenFunctionRange[]): boolean {
	return ranges.some(range => address > range.start && address < range.endExclusive);
}

/**
 * Collect x86/x64 function pointers materialized by RIP-relative LEA and then
 * stored through memory. Text is never parsed; all decisions use Capstone
 * operand detail. Candidate decoding/terminal validation is performed by the
 * engine before promotion to the function index.
 */
export function collectAddressTakenFunctionCandidates(
	instructions: readonly DisassembledInstruction[],
	options: AddressTakenDiscoveryOptions,
): AddressTakenFunctionCandidate[] {
	const candidates: AddressTakenFunctionCandidate[] = [];
	const maxConsumerDistance = Math.max(1, options.maxConsumerDistance ?? 4);

	for (let index = 0; index < instructions.length; index++) {
		const instruction = instructions[index];
		const operands = instruction.detail?.x86?.operands;
		if (instruction.mnemonic.toLowerCase() !== 'lea' || !operands || operands.length < 2) {
			continue;
		}
		const destination = operands[0];
		const source = operands[1];
		if (destination.reg === undefined || !source.mem) {
			continue;
		}
		if (options.registerName(source.mem.base)?.toLowerCase() !== 'rip') {
			continue;
		}

		const target = instruction.address + instruction.size + source.mem.disp;
		if (!Number.isSafeInteger(target) || !options.isExecutableAddress(target) ||
			isInteriorToKnownFunction(target, options.knownFunctions)) {
			continue;
		}

		let storeAddress: number | undefined;
		const destinationName = options.registerName(destination.reg)?.toLowerCase();
		for (let consumerIndex = index + 1;
			consumerIndex < instructions.length && consumerIndex <= index + maxConsumerDistance;
			consumerIndex++) {
			const consumer = instructions[consumerIndex];
			const consumerOperands = consumer.detail?.x86?.operands;
			if (!consumerOperands || consumerOperands.length < 2) {
				continue;
			}
			const consumerDestination = consumerOperands[0];
			const consumerSource = consumerOperands[1];
			if (consumer.mnemonic.toLowerCase() === 'mov' && consumerDestination.mem &&
				consumerSource.reg !== undefined &&
				options.registerName(consumerSource.reg)?.toLowerCase() === destinationName) {
				storeAddress = consumer.address;
				break;
			}
			if (consumerDestination.reg !== undefined &&
				options.registerName(consumerDestination.reg)?.toLowerCase() === destinationName) {
				break;
			}
		}
		if (storeAddress === undefined) {
			continue;
		}

		candidates.push({
			address: target,
			leaAddress: instruction.address,
			storeAddress,
			registerId: destination.reg,
			confidence: 0.9,
			reasons: ['rip-relative-lea', 'stored-function-pointer', 'executable-target'],
		});
	}

	const unique = new Map<number, AddressTakenFunctionCandidate>();
	for (const candidate of candidates) {
		const current = unique.get(candidate.address);
		if (!current || candidate.confidence > current.confidence) {
			unique.set(candidate.address, candidate);
		}
	}
	return [...unique.values()].sort((left, right) => left.address - right.address);
}

/** Validate a candidate as contiguous code ending in a real architectural return. */
export function validateAddressTakenFunctionExtent(
	start: number,
	instructions: readonly DisassembledInstruction[],
	nextKnownStart?: number,
): ValidatedFunctionExtent | undefined {
	if (instructions.length === 0 || instructions[0].address !== start) {
		return undefined;
	}
	let expectedAddress = start;
	for (const instruction of instructions) {
		if (instruction.address !== expectedAddress || instruction.size <= 0) {
			return undefined;
		}
		if (nextKnownStart !== undefined && instruction.address >= nextKnownStart) {
			break;
		}
		const mnemonic = instruction.mnemonic.toLowerCase();
		if (mnemonic === 'ret' || mnemonic === 'retn' || mnemonic === 'retf') {
			const semanticEnd = instruction.address + instruction.size;
			if (nextKnownStart !== undefined && semanticEnd > nextKnownStart) {
				return undefined;
			}
			return {
				semanticEnd,
				endExclusive: nextKnownStart ?? semanticEnd,
				terminalAddress: instruction.address,
				terminalKind: 'return',
			};
		}
		expectedAddress = instruction.address + instruction.size;
	}
	return undefined;
}
