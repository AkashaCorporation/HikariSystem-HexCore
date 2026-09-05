/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

export type FunctionSeedKind =
	| 'entry'
	| 'export'
	| 'tls-callback'
	| 'address-taken'
	| 'direct-call'
	| 'validated-tail-call'
	| 'import-thunk'
	| 'unwind'
	| 'symbol'
	| 'validated-prologue'
	| 'prologue'
	| 'cache';

export interface FunctionSeedEvidence {
	kind: FunctionSeedKind;
	sourceAddress?: number;
	consumerAddress?: number;
	confidence?: number;
}

const STRONG_SEED_KINDS = new Set<FunctionSeedKind>([
	'entry',
	'export',
	'tls-callback',
	'address-taken',
	'direct-call',
	'validated-tail-call',
	'import-thunk',
	'unwind',
	'symbol',
]);

/** Tracks why an address is allowed to own a function. */
export class FunctionSeedRegistry {
	private readonly evidence = new Map<number, FunctionSeedEvidence[]>();

	clear(): void {
		this.evidence.clear();
	}

	record(address: number, seed: FunctionSeedEvidence): void {
		if (!Number.isSafeInteger(address) || address <= 0) {
			return;
		}
		const entries = this.evidence.get(address) ?? [];
		if (!entries.some(entry => entry.kind === seed.kind &&
			entry.sourceAddress === seed.sourceAddress &&
			entry.consumerAddress === seed.consumerAddress &&
			entry.confidence === seed.confidence)) {
			entries.push(seed);
			this.evidence.set(address, entries);
		}
	}

	isStrong(address: number): boolean {
		return (this.evidence.get(address) ?? []).some(seed => STRONG_SEED_KINDS.has(seed.kind));
	}

	strongAddresses(): number[] {
		return [...this.evidence.keys()].filter(address => this.isStrong(address)).sort((a, b) => a - b);
	}

	get(address: number): readonly FunctionSeedEvidence[] {
		return this.evidence.get(address) ?? [];
	}
}
