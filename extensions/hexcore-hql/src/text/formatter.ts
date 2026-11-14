/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Akasha Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import { assertValidSignature } from '../signatures/schema.js';
import type {
	HQLCondition,
	HQLQuery,
	HQLSemanticCondition,
	HQLSemanticQuery,
	HQLSignature,
} from '../types/hql.js';
import { compileHql } from './compiler.js';
import { HQL_TEXT_VERSION, type HqlCompileOptions } from './syntax.js';

export function formatHql(source: string, options: HqlCompileOptions = {}): string {
	return formatHqlSignature(compileHql(source, options));
}

export function formatHqlSignature(signature: HQLSignature): string {
	assertValidSignature(signature, '<formatter>');
	const lines = [`hql ${HQL_TEXT_VERSION};`, '', `rule ${JSON.stringify(signature.id)} {`];
	const scalar = (name: string, value: string | undefined): void => {
		if (value !== undefined) lines.push(`  ${name} ${JSON.stringify(value)};`);
	};
	scalar('version', signature.version);
	scalar('namespace', signature.namespace);
	if (signature.status) lines.push(`  status ${signature.status};`);
	scalar('author', signature.author);
	scalar('license', signature.license);
	if (signature.provenance) {
		lines.push('  provenance {');
		lines.push(`    kind ${signature.provenance.kind};`);
		lines.push(`    source ${JSON.stringify(signature.provenance.source)};`);
		for (const key of ['url', 'commit', 'path'] as const) {
			if (signature.provenance[key] !== undefined) lines.push(`    ${key} ${JSON.stringify(signature.provenance[key])};`);
		}
		if (signature.provenance.modified !== undefined) lines.push(`    modified ${signature.provenance.modified};`);
		lines.push('  }');
	}
	if (signature.compatibility) {
		lines.push('  compatibility {');
		lines.push(`    hql ${JSON.stringify(signature.compatibility.hql)};`);
		if (signature.compatibility.helix !== undefined) lines.push(`    helix ${JSON.stringify(signature.compatibility.helix)};`);
		lines.push(`    hast ${signature.compatibility.hastSchema};`);
		lines.push('  }');
	}
	if (signature.fixtures) lines.push(`  fixtures ${JSON.stringify(signature.fixtures.manifest)};`);
	if (signature.limitations !== undefined) lines.push(`  limitations ${formatStringArray(signature.limitations)};`);
	if (signature.supersedes !== undefined) lines.push(`  supersedes ${formatStringArray(signature.supersedes)};`);
	lines.push(`  name ${JSON.stringify(signature.name)};`);
	lines.push(`  description ${JSON.stringify(signature.description)};`);
	lines.push(`  severity ${signature.severity};`);
	if (signature.mitre !== undefined) lines.push(`  mitre ${formatStringArray(signature.mitre)};`);
	if (signature.evidenceLevel !== undefined) lines.push(`  evidence ${signature.evidenceLevel};`);
	if (signature.calibration) {
		lines.push('  calibration {');
		lines.push(`    confidence ${formatNumber(signature.calibration.confidence)};`);
		lines.push(`    corpus ${JSON.stringify(signature.calibration.corpus)};`);
		lines.push(`    sha256 ${JSON.stringify(signature.calibration.corpusSha256)};`);
		lines.push('  }');
	}
	if (signature.queries) {
		lines.push('  queries {');
		for (const query of signature.queries) lines.push(...formatAstQuery(query, 2, true));
		lines.push('  }');
	} else if (signature.condition) {
		lines.push(...formatConditionSection('where', signature.condition, 1));
	}
	if (signature.semanticCondition) lines.push(...formatSemanticSection(signature.semanticCondition, 1));
	lines.push('}', '');
	return lines.join('\n');
}

function formatConditionSection(label: string, condition: HQLCondition, depth: number): string[] {
	const prefix = `${'  '.repeat(depth)}${label} `;
	const body = formatCondition(condition, depth, false);
	body[0] = prefix + body[0].trimStart();
	return body;
}

function formatSemanticSection(condition: HQLSemanticCondition, depth: number): string[] {
	const body = formatSemanticCondition(condition, depth, false);
	body[0] = `${'  '.repeat(depth)}semantic ` + body[0].trimStart();
	return body;
}

function formatCondition(condition: HQLCondition, depth: number, terminate: boolean): string[] {
	const indent = '  '.repeat(depth);
	if ('query' in condition) return formatAstQuery(condition.query, depth, terminate);
	if ('not' in condition) {
		const child = formatCondition(condition.not, depth, false);
		child[0] = `${indent}not ` + child[0].trimStart();
		if (terminate) child[child.length - 1] += ';';
		return child;
	}
	if ('count' in condition) {
		const bounds = formatBounds(condition.count);
		const child = formatAstQuery(condition.count.query, depth, false);
		child[0] = `${indent}count ${bounds} ` + child[0].trimStart();
		if (terminate) child[child.length - 1] += ';';
		return child;
	}
	const key = 'all' in condition ? 'all' : 'any';
	const children = 'all' in condition ? condition.all : condition.any;
	const lines = [`${indent}${key} {`];
	for (const child of children) lines.push(...formatCondition(child, depth + 1, true));
	lines.push(`${indent}}${terminate ? ';' : ''}`);
	return lines;
}

function formatSemanticCondition(condition: HQLSemanticCondition, depth: number, terminate: boolean): string[] {
	const indent = '  '.repeat(depth);
	if ('fact' in condition) return formatFactQuery(condition.fact, depth, terminate);
	if ('not' in condition) {
		const child = formatSemanticCondition(condition.not, depth, false);
		child[0] = `${indent}not ` + child[0].trimStart();
		if (terminate) child[child.length - 1] += ';';
		return child;
	}
	if ('count' in condition) {
		const bounds = formatBounds(condition.count);
		const child = formatFactQuery(condition.count.fact, depth, false);
		child[0] = `${indent}count ${bounds} ` + child[0].trimStart();
		if (terminate) child[child.length - 1] += ';';
		return child;
	}
	const key = 'all' in condition ? 'all' : 'any';
	const children = 'all' in condition ? condition.all : condition.any;
	const lines = [`${indent}${key} {`];
	for (const child of children) lines.push(...formatSemanticCondition(child, depth + 1, true));
	lines.push(`${indent}}${terminate ? ';' : ''}`);
	return lines;
}

function formatAstQuery(query: HQLQuery, depth: number, terminate: boolean): string[] {
	const indent = '  '.repeat(depth);
	const lines = [`${indent}ast ${query.target} {`];
	for (const attribute of query.attributes ?? []) lines.push(`${indent}  ${attribute.field} == ${formatValue(attribute.value)};`);
	for (const operand of query.operands ?? []) {
		const nested = formatAstQuery(operand.query, depth + 1, false);
		nested[0] = `${indent}  operand ${operand.position} ` + nested[0].trimStart();
		nested[nested.length - 1] += ';';
		lines.push(...nested);
	}
	for (const contained of query.contains ?? []) {
		const nested = formatAstQuery(contained, depth + 1, false);
		nested[0] = `${indent}  contains ` + nested[0].trimStart();
		nested[nested.length - 1] += ';';
		lines.push(...nested);
	}
	if (query.minDepth !== undefined) lines.push(`${indent}  minDepth ${query.minDepth};`);
	if (query.maxDepth !== undefined) lines.push(`${indent}  maxDepth ${query.maxDepth};`);
	lines.push(`${indent}}${terminate ? ';' : ''}`);
	return lines;
}

function formatFactQuery(query: HQLSemanticQuery, depth: number, terminate: boolean): string[] {
	const indent = '  '.repeat(depth);
	const lines = [`${indent}fact ${query.fact} {`];
	for (const attribute of query.attributes ?? []) lines.push(`${indent}  ${attribute.field} == ${formatValue(attribute.value)};`);
	lines.push(`${indent}}${terminate ? ';' : ''}`);
	return lines;
}

function formatBounds(value: { min?: number; max?: number; exactly?: number }): string {
	if (value.exactly !== undefined) return `exactly ${value.exactly}`;
	return [value.min !== undefined ? `min ${value.min}` : '', value.max !== undefined ? `max ${value.max}` : ''].filter(Boolean).join(' ');
}

function formatValue(value: string | number | boolean): string {
	if (typeof value !== 'string') return typeof value === 'number' ? formatNumber(value) : String(value);
	return JSON.stringify(value);
}

function formatStringArray(values: readonly string[]): string {
	return `[${values.map(value => JSON.stringify(value)).join(', ')}]`;
}

function formatNumber(value: number): string {
	if (!Number.isFinite(value)) throw new Error('HQL formatter cannot emit a non-finite number');
	return Object.is(value, -0) ? '0' : String(value);
}
