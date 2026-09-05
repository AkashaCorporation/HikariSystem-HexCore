/*---------------------------------------------------------------------------------------------
 *  HexCore Debugger - Headless terminal outcome classification
 *  Copyright (c) HikariSystem. All rights reserved.
 *--------------------------------------------------------------------------------------------*/

export type HeadlessStatus = 'ok' | 'partial' | 'failed';
export type HeadlessStopKind = 'breakpoint' | 'sentinel-return' | 'configured-terminal' | 'instruction-budget' | 'unexpected-zero-pc' | 'unsupported-instruction' | 'fault' | 'stopped';

export interface UnsupportedInstructionEvidence {
	address?: string;
	mnemonic?: string;
	opStr?: string;
	bytes?: string;
}

export interface BackendCapabilityEvidence {
	backend: string;
	architecture?: string;
	requiredFeature: 'avx512' | 'unknown';
	supported: false;
	fallbackAvailable: false;
	instruction?: UnsupportedInstructionEvidence;
}

export interface HeadlessOutcome {
	success: boolean;
	status: HeadlessStatus;
	stopReason: {
		kind: HeadlessStopKind;
		address?: string;
		message: string;
		terminalKind?: string;
		capability?: BackendCapabilityEvidence;
	};
}

export interface HeadlessOutcomeInput {
	crashed: boolean;
	error?: string;
	currentAddress?: bigint;
	breakpoints?: readonly bigint[];
	instructionsRan: number;
	instructionBudget: number;
	backend?: string;
	architecture?: string;
	unsupportedInstruction?: UnsupportedInstructionEvidence;
	terminalAddresses?: readonly bigint[];
	terminalKind?: string;
}

const SUCCESS_SENTINELS = new Set([0xdead0000n, 0xdeaddeadn, 0xdeaddeaddeaddeadn]);

export function parseTerminalAddresses(value: unknown): bigint[] {
	if (value === undefined) return [];
	if (!Array.isArray(value) || value.length > 256) {
		throw new Error('terminalAddresses must be an array with at most 256 addresses.');
	}
	return value.map((entry, index) => {
		if (typeof entry !== 'string' && typeof entry !== 'number' && typeof entry !== 'bigint') {
			throw new Error(`terminalAddresses[${index}] must be an integer or address string.`);
		}
		if (typeof entry === 'number' && !Number.isSafeInteger(entry)) {
			throw new Error(`terminalAddresses[${index}] must use a string for addresses above Number.MAX_SAFE_INTEGER.`);
		}
		try {
			const parsed = BigInt(entry);
			if (parsed < 0n || parsed > 0xFFFFFFFFFFFFFFFFn) throw new Error();
			return parsed;
		} catch {
			throw new Error(`terminalAddresses[${index}] is not a valid unsigned 64-bit address.`);
		}
	});
}

export function isInvalidInstructionError(error: unknown): boolean {
	return typeof error === 'string' && /UC_ERR_INSN_INVALID|invalid instruction/i.test(error);
}

function inferRequiredFeature(instruction?: UnsupportedInstructionEvidence): 'avx512' | 'unknown' {
	if (!instruction) { return 'unknown'; }
	const rendered = `${instruction.mnemonic ?? ''} ${instruction.opStr ?? ''}`;
	if (/\bzmm\d+\b|\bk[0-7]\b/i.test(rendered)) { return 'avx512'; }
	return 'unknown';
}

export function classifyHeadlessOutcome(input: HeadlessOutcomeInput): HeadlessOutcome {
	const address = input.currentAddress;
	const formattedAddress = address === undefined ? undefined : `0x${address.toString(16)}`;
	if (isInvalidInstructionError(input.error)) {
		const instruction = input.unsupportedInstruction;
		const requiredFeature = inferRequiredFeature(instruction);
		const mnemonic = instruction?.mnemonic?.trim();
		const instructionLabel = mnemonic ? ` ${mnemonic}` : '';
		const featureLabel = requiredFeature === 'unknown' ? 'an unsupported ISA feature' : requiredFeature.toUpperCase();
		return {
			success: false,
			status: 'failed',
			stopReason: {
				kind: 'unsupported-instruction',
				address: instruction?.address ?? formattedAddress,
				message: `${input.backend ?? 'Emulation backend'} cannot execute${instructionLabel}; ${featureLabel} is required and no fallback is registered.`,
				capability: {
					backend: input.backend ?? 'unknown',
					architecture: input.architecture,
					requiredFeature,
					supported: false,
					fallbackAvailable: false,
					...(instruction ? { instruction } : {}),
				},
			}
		};
	}
	if (address !== undefined && input.terminalAddresses?.includes(address)) {
		return {
			success: true,
			status: 'ok',
			stopReason: {
				kind: 'configured-terminal',
				address: formattedAddress,
				message: 'Execution reached a configured terminal address.',
				terminalKind: input.terminalKind ?? 'return_sentinel',
			}
		};
	}
	if (address !== undefined && SUCCESS_SENTINELS.has(address)) {
		return {
			success: true,
			status: 'ok',
			stopReason: { kind: 'sentinel-return', address: formattedAddress, message: 'Execution reached a configured return sentinel.' }
		};
	}
	if (input.crashed || input.error) {
		return {
			success: false,
			status: 'failed',
			stopReason: { kind: 'fault', address: formattedAddress, message: input.error || 'Emulation raised an exception.' }
		};
	}
	if (address === undefined || address === 0n) {
		return {
			success: false,
			status: 'failed',
			stopReason: { kind: 'unexpected-zero-pc', address: formattedAddress, message: 'Execution reached a null program counter without a recognized exit.' }
		};
	}
	if (input.breakpoints?.some(breakpoint => breakpoint === address)) {
		return {
			success: true,
			status: 'ok',
			stopReason: { kind: 'breakpoint', address: formattedAddress, message: 'Execution paused at a requested breakpoint.' }
		};
	}
	if (input.instructionBudget > 0 && input.instructionsRan >= input.instructionBudget) {
		return {
			success: false,
			status: 'partial',
			stopReason: { kind: 'instruction-budget', address: formattedAddress, message: 'Execution exhausted its instruction budget.' }
		};
	}
	return {
		success: false,
		status: 'partial',
		stopReason: { kind: 'stopped', address: formattedAddress, message: 'Execution stopped without a recognized terminal condition.' }
	};
}
