/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Akasha Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import { canonicalJson, canonicalSha256 } from '../atlas/canonical.js';
import { validateSignature } from '../signatures/schema.js';
import type { HQLCondition, HQLSemanticCondition, HQLSignature } from '../types/hql.js';
import { parseHql } from './parser.js';
import {
	HQL_TEXT_COMPILER_VERSION,
	HQL_TEXT_VERSION,
	HqlCompileError,
	type HqlCompileOptions,
	type HqlCompileResult,
	type HqlDiagnostic,
	type HqlTextCondition,
	type LoweredHqlConditions,
	type ParsedHqlRule,
} from './syntax.js';

type ConditionDomain = 'ast' | 'semantic' | 'mixed';

export function compileHql(source: string, options: HqlCompileOptions = {}): HQLSignature {
	return compileHqlDetailed(source, options).signature;
}

export function compileHqlDetailed(source: string, options: HqlCompileOptions = {}): HqlCompileResult {
	const parsed = parseHql(source, options);
	if (options.hqlVersion !== undefined && options.hqlVersion !== parsed.hqlVersion) {
		throw compileDiagnostic(source, options, parsed, 'HQL1003',
			`requested HQL grammar ${options.hqlVersion} does not match source grammar ${parsed.hqlVersion}`);
	}
	const lowered = lowerRuleConditions(source, options, parsed);
	if (parsed.queries && lowered.condition) {
		throw compileDiagnostic(source, options, parsed, 'HQL1012', "'queries' and structural 'where' are mutually exclusive");
	}
	const signature: HQLSignature = {
		...parsed.metadata,
		...(parsed.queries ? { queries: parsed.queries } : {}),
		...(lowered.condition ? { condition: lowered.condition } : {}),
		...(lowered.semanticCondition ? { semanticCondition: lowered.semanticCondition } : {}),
	};
	const errors = validateSignature(signature);
	if (errors.length > 0) {
		throw compileDiagnostic(source, options, parsed, 'HQL1013', errors.join('; '));
	}
	const serialized = canonicalJson(signature);
	return {
		hqlVersion: HQL_TEXT_VERSION,
		compilerVersion: HQL_TEXT_COMPILER_VERSION,
		signature,
		canonicalJson: serialized,
		signatureSha256: canonicalSha256(signature),
	};
}

function lowerRuleConditions(
	source: string,
	options: HqlCompileOptions,
	parsed: ParsedHqlRule,
): LoweredHqlConditions {
	let condition: HQLCondition | undefined;
	let semanticCondition: HQLSemanticCondition | undefined;
	if (parsed.where) {
		const split = splitWhere(source, options, parsed, parsed.where);
		condition = split.condition;
		semanticCondition = split.semanticCondition;
	}
	if (parsed.semantic) {
		const domain = conditionDomain(parsed.semantic);
		if (domain !== 'semantic') {
			throw compileDiagnostic(source, options, parsed, 'HQL1012', "the 'semantic' section accepts only fact conditions", parsed.semantic);
		}
		const lowered = lowerSemantic(parsed.semantic);
		semanticCondition = semanticCondition ? { all: [semanticCondition, lowered] } : lowered;
	}
	return { ...(condition ? { condition } : {}), ...(semanticCondition ? { semanticCondition } : {}) };
}

function splitWhere(
	source: string,
	options: HqlCompileOptions,
	parsed: ParsedHqlRule,
	condition: HqlTextCondition,
): LoweredHqlConditions {
	const domain = conditionDomain(condition);
	if (domain === 'ast') return { condition: lowerAst(condition) };
	if (domain === 'semantic') return { semanticCondition: lowerSemantic(condition) };
	if (condition.kind !== 'all') {
		throw compileDiagnostic(source, options, parsed, 'HQL1012',
			'mixed AST/fact conditions can be lowered only through a top-level all block', condition);
	}
	const ast: HQLCondition[] = [];
	const semantic: HQLSemanticCondition[] = [];
	for (const child of condition.children) {
		const childDomain = conditionDomain(child);
		if (childDomain === 'mixed') {
			throw compileDiagnostic(source, options, parsed, 'HQL1012',
				'nested mixed AST/fact boolean expressions are not representable by the canonical HQL 0.3.1 IR', child);
		}
		if (childDomain === 'ast') ast.push(lowerAst(child));
		else semantic.push(lowerSemantic(child));
	}
	return {
		...(ast.length ? { condition: ast.length === 1 ? ast[0] : { all: ast } } : {}),
		...(semantic.length ? { semanticCondition: semantic.length === 1 ? semantic[0] : { all: semantic } } : {}),
	};
}

function conditionDomain(condition: HqlTextCondition): ConditionDomain {
	if (condition.kind === 'ast') return 'ast';
	if (condition.kind === 'fact') return 'semantic';
	if (condition.kind === 'count') return condition.child.kind === 'ast' ? 'ast' : 'semantic';
	if (condition.kind === 'not') return conditionDomain(condition.child);
	const domains = new Set(condition.children.map(conditionDomain));
	if (domains.size === 1) return [...domains][0];
	return 'mixed';
}

function lowerAst(condition: HqlTextCondition): HQLCondition {
	switch (condition.kind) {
		case 'ast': return { query: condition.query };
		case 'all': return { all: condition.children.map(lowerAst) };
		case 'any': return { any: condition.children.map(lowerAst) };
		case 'not': return { not: lowerAst(condition.child) };
		case 'count':
			if (condition.child.kind !== 'ast') throw new Error('internal HQL domain mismatch');
			return { count: { query: condition.child.query, ...countBounds(condition) } };
		case 'fact': throw new Error('internal HQL domain mismatch');
	}
}

function lowerSemantic(condition: HqlTextCondition): HQLSemanticCondition {
	switch (condition.kind) {
		case 'fact': return { fact: condition.query };
		case 'all': return { all: condition.children.map(lowerSemantic) };
		case 'any': return { any: condition.children.map(lowerSemantic) };
		case 'not': return { not: lowerSemantic(condition.child) };
		case 'count':
			if (condition.child.kind !== 'fact') throw new Error('internal HQL domain mismatch');
			return { count: { fact: condition.child.query, ...countBounds(condition) } };
		case 'ast': throw new Error('internal HQL domain mismatch');
	}
}

function countBounds(condition: Extract<HqlTextCondition, { kind: 'count' }>): { min?: number; max?: number; exactly?: number } {
	return {
		...(condition.min !== undefined ? { min: condition.min } : {}),
		...(condition.max !== undefined ? { max: condition.max } : {}),
		...(condition.exactly !== undefined ? { exactly: condition.exactly } : {}),
	};
}

function compileDiagnostic(
	source: string,
	options: HqlCompileOptions,
	parsed: ParsedHqlRule,
	code: string,
	message: string,
	condition?: HqlTextCondition,
): HqlCompileError {
	const span = condition?.span ?? parsed.span;
	const diagnostic: HqlDiagnostic = {
		severity: 'error', code, message, filename: options.filename ?? '<hql>', span,
		excerpt: source.split(/\r?\n/)[span.start.line - 1] ?? '',
	};
	return new HqlCompileError([diagnostic]);
}
