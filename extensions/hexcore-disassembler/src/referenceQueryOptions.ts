/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Akasha Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import type { ReferenceQuery } from './typedReferenceGraph';
import type { ReferenceGraphProducerBudgets } from './typedReferenceGraphProducer';

export interface ReferenceGraphQueryCommandOptions {
	query?: ReferenceQuery;
	to?: string | number;
	from?: string | number;
	address?: string | number;
	functionIdentity?: string;
	target?: string | number;
	kinds?: string[];
	resolveThunks?: boolean;
	owner?: boolean;
	maxResults?: number;
	producerBudgets?: Partial<ReferenceGraphProducerBudgets>;
}

const KIND_RELATIONS: Readonly<Record<string, readonly NonNullable<ReferenceQuery['relations']>[number][]>> = Object.freeze({
	call: ['code-call-near', 'code-call-far', 'code-indirect-candidate', 'code-indirect-resolved'],
	jump: ['code-jump', 'code-tail-call', 'code-flow'],
	lea: ['data-address-taken', 'data-offset-pointer-construction'],
	data: ['data-read', 'data-write', 'data-read-write', 'data-address-taken', 'data-offset-pointer-construction'],
	string: ['string-reference'],
});

function queryAddress(value: string | number, label: string): string {
	if (typeof value === 'number') {
		if (!Number.isSafeInteger(value) || value < 0) { throw new Error(`${label} must be a non-negative safe integer or 0x address.`); }
		return `0x${value.toString(16)}`;
	}
	if (typeof value !== 'string' || !/^0x[0-9a-f]+$/i.test(value.trim())) {
		throw new Error(`${label} must be a non-negative safe integer or 0x address.`);
	}
	return `0x${value.trim().slice(2).toLowerCase()}`;
}

function applyEndpoint(query: ReferenceQuery, value: string | number, direction: 'incoming' | 'outgoing', label: string): ReferenceQuery {
	if (typeof value === 'string' && !/^0x/i.test(value.trim())) {
		const identity = value.trim();
		if (!identity) { throw new Error(`${label} identity must not be empty.`); }
		if (direction === 'outgoing' && identity.startsWith('function:')) {
			return { ...query, direction, functionIdentity: identity };
		}
		return { ...query, direction, targetIdentity: identity };
	}
	return { ...query, direction, address: queryAddress(value, label) };
}

export function normalizeReferenceGraphQueryOptions(options: ReferenceGraphQueryCommandOptions): ReferenceQuery {
	if (options.owner !== undefined && typeof options.owner !== 'boolean') {
		throw new Error('references.query owner must be boolean.');
	}
	let query: ReferenceQuery = Object.freeze({ ...(options.query ?? {}) });
	const incoming = options.to ?? options.target;
	if (options.to !== undefined && options.target !== undefined && options.to !== options.target) {
		throw new Error('references.query to and target conflict.');
	}
	if (incoming !== undefined && options.from !== undefined) {
		throw new Error('references.query cannot combine from with to/target in one query.');
	}
	if (incoming !== undefined) { query = applyEndpoint(query, incoming, 'incoming', 'references.query to'); }
	if (options.from !== undefined) { query = applyEndpoint(query, options.from, 'outgoing', 'references.query from'); }
	if (options.address !== undefined) {
		if (query.address !== undefined) { throw new Error('references.query address conflicts with another address endpoint.'); }
		query = { ...query, address: queryAddress(options.address, 'references.query address') };
	}
	if (options.functionIdentity !== undefined) {
		if (typeof options.functionIdentity !== 'string' || options.functionIdentity.trim().length === 0) {
			throw new Error('references.query functionIdentity must be a non-empty string.');
		}
		query = { ...query, functionIdentity: options.functionIdentity.trim() };
	}
	if (options.kinds !== undefined) {
		if (!Array.isArray(options.kinds) || options.kinds.length === 0 || options.kinds.some(kind => typeof kind !== 'string')) {
			throw new Error('references.query kinds must be a non-empty string array.');
		}
		const relations = new Set<NonNullable<ReferenceQuery['relations']>[number]>();
		for (const raw of options.kinds) {
			const kind = raw.toLowerCase();
			const mapped = KIND_RELATIONS[kind];
			if (!mapped) { throw new Error(`references.query unknown kind: ${raw}`); }
			for (const relation of mapped) { relations.add(relation); }
		}
		query = { ...query, relations: [...relations] };
	}
	return Object.freeze(query);
}
