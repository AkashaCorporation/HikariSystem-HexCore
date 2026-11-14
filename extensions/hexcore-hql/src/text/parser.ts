/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Akasha Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import type { CNodeKind } from '../types/ast.js';
import type {
	HQLAttributeCheck,
	HQLCompatibility,
	HQLQuery,
	HQLRuleProvenance,
	HQLSemanticFactKind,
	HQLSemanticQuery,
	HQLSignature,
} from '../types/hql.js';
import {
	hqlNodeFields,
	hqlNodeKinds,
	hqlOperatorValues,
	hqlSemanticFactFields,
	hqlSemanticFactKinds,
	validateQuery,
	validateSemanticQuery,
} from '../signatures/schema.js';
import { HqlLexer } from './lexer.js';
import {
	HQL_TEXT_VERSION,
	HqlCompileError,
	type HqlCompileOptions,
	type HqlDiagnostic,
	type HqlSourceSpan,
	type HqlTextCondition,
	type HqlTextToken,
	type ParsedHqlRule,
} from './syntax.js';

const RULE_FIELDS = [
	'version', 'namespace', 'status', 'author', 'license', 'provenance', 'compatibility', 'fixtures',
	'limitations', 'supersedes', 'name', 'description', 'severity', 'mitre', 'evidence', 'calibration',
	'queries', 'where', 'semantic',
] as const;

type MutableMetadata = Record<string, unknown> & { id: string };

export function parseHql(source: string, options: HqlCompileOptions = {}): ParsedHqlRule {
	return new HqlParser(source, options).parse();
}

class HqlParser {
	private readonly filename: string;
	private readonly lines: string[];
	private readonly tokens: HqlTextToken[];
	private readonly maxDepth: number;
	private index = 0;

	constructor(private readonly source: string, options: HqlCompileOptions) {
		this.filename = options.filename ?? '<hql>';
		this.lines = source.split(/\r?\n/);
		this.tokens = new HqlLexer(source, options).tokenize();
		this.maxDepth = options.maxDepth ?? 128;
		if (!Number.isSafeInteger(this.maxDepth) || this.maxDepth < 1) throw new Error('HQL maxDepth must be a positive safe integer');
	}

	parse(): ParsedHqlRule {
		const start = this.peek().span.start;
		this.expectWord('hql');
		const version = this.consume();
		if (!['number', 'identifier'].includes(version.kind) || version.text !== HQL_TEXT_VERSION) {
			this.fail(version, 'HQL1003', `unsupported HQL grammar version '${version.text || '<missing>'}'`, `use 'hql ${HQL_TEXT_VERSION};'`);
		}
		this.expectSymbol(';');
		this.expectWord('rule');
		const idToken = this.consume();
		if (!['identifier', 'string'].includes(idToken.kind) || typeof idToken.value !== 'string' || !idToken.value) {
			this.fail(idToken, 'HQL1002', 'rule requires a non-empty identifier or string ID');
		}
		const metadata: MutableMetadata = { id: idToken.value as string };
		this.expectSymbol('{');
		const seen = new Set<string>();
		let where: HqlTextCondition | undefined;
		let semantic: HqlTextCondition | undefined;
		let queries: HQLQuery[] | undefined;
		while (!this.matchSymbol('}')) {
			if (this.peek().kind === 'eof') this.fail(this.peek(), 'HQL1002', 'unterminated rule block');
			const keyToken = this.expectKind('identifier', 'rule field');
			const key = keyToken.text;
			if (!(RULE_FIELDS as readonly string[]).includes(key)) {
				this.fail(keyToken, 'HQL1004', `unknown rule field '${key}'`, suggestion(key, RULE_FIELDS));
			}
			if (seen.has(key)) this.fail(keyToken, 'HQL1004', `duplicate rule field '${key}'`);
			seen.add(key);
			switch (key) {
				case 'queries':
					queries = this.parseLegacyQueries();
					break;
				case 'where':
					where = this.parseCondition(0);
					this.consumeOptionalSymbol(';');
					break;
				case 'semantic':
					semantic = this.parseCondition(0);
					this.consumeOptionalSymbol(';');
					break;
				case 'version': case 'namespace': case 'author': case 'license': case 'name': case 'description':
					metadata[key] = this.expectString(key).value;
					this.expectSymbol(';');
					break;
				case 'status': case 'severity':
					metadata[key] = this.expectKind('identifier', key).text;
					this.expectSymbol(';');
					break;
				case 'evidence':
					metadata.evidenceLevel = this.expectKind('identifier', key).text;
					this.expectSymbol(';');
					break;
				case 'fixtures':
					metadata.fixtures = { manifest: this.expectString('fixtures').value as string };
					this.expectSymbol(';');
					break;
				case 'limitations': case 'supersedes': case 'mitre':
					metadata[key] = this.parseStringArray();
					this.expectSymbol(';');
					break;
				case 'provenance': metadata.provenance = this.parseProvenance(); break;
				case 'compatibility': metadata.compatibility = this.parseCompatibility(); break;
				case 'calibration': metadata.calibration = this.parseCalibration(); break;
			}
		}
		const end = this.previous().span.end;
		this.expectKind('eof', 'end of file');
		for (const required of ['name', 'description', 'severity']) {
			if (!seen.has(required)) this.fail(idToken, 'HQL1005', `rule is missing required field '${required}'`);
		}
		if (!queries && !where && !semantic) this.fail(idToken, 'HQL1005', "rule requires 'queries', 'where', or 'semantic'");
		return {
			hqlVersion: HQL_TEXT_VERSION,
			metadata: metadata as unknown as ParsedHqlRule['metadata'],
			...(queries ? { queries } : {}),
			...(where ? { where } : {}),
			...(semantic ? { semantic } : {}),
			span: { start, end },
		};
	}

	private parseLegacyQueries(): HQLQuery[] {
		const queries: HQLQuery[] = [];
		this.expectSymbol('{');
		while (!this.matchSymbol('}')) {
			const ast = this.expectWord('ast');
			const condition = this.parseAstQuery(ast, 1) as Extract<HqlTextCondition, { kind: 'ast' }>;
			queries.push(condition.query);
			this.expectSymbol(';');
		}
		if (queries.length === 0) this.fail(this.previous(), 'HQL1002', 'queries requires at least one ast query');
		return queries;
	}

	private parseCondition(depth: number): HqlTextCondition {
		this.requireDepth(depth);
		const token = this.expectKind('identifier', 'condition');
		if (token.text === 'ast') return this.parseAstQuery(token, depth + 1);
		if (token.text === 'fact') return this.parseFactQuery(token);
		if (token.text === 'all' || token.text === 'any') {
			this.expectSymbol('{');
			const children: HqlTextCondition[] = [];
			while (!this.matchSymbol('}')) {
				if (this.peek().kind === 'eof') this.fail(this.peek(), 'HQL1002', `unterminated ${token.text} block`);
				children.push(this.parseCondition(depth + 1));
				this.expectSymbol(';');
			}
			if (children.length === 0) this.fail(token, 'HQL1002', `${token.text} requires at least one condition`);
			return { kind: token.text, children, span: mergeSpan(token.span, this.previous().span) };
		}
		if (token.text === 'not') {
			const child = this.parseCondition(depth + 1);
			return { kind: 'not', child, span: mergeSpan(token.span, child.span) };
		}
		if (token.text === 'count') {
			let min: number | undefined;
			let max: number | undefined;
			let exactly: number | undefined;
			while (this.peek().kind === 'identifier' && ['min', 'max', 'exactly'].includes(this.peek().text)) {
				const bound = this.consume().text as 'min' | 'max' | 'exactly';
				const valueToken = this.expectKind('number', `${bound} count`);
				if (typeof valueToken.value !== 'number' || !Number.isSafeInteger(valueToken.value) || valueToken.value < 0) {
					this.fail(valueToken, 'HQL1002', `${bound} requires a non-negative safe integer`);
				}
				if (bound === 'min') min = valueToken.value;
				if (bound === 'max') max = valueToken.value;
				if (bound === 'exactly') exactly = valueToken.value;
			}
			if (min === undefined && max === undefined && exactly === undefined) this.fail(token, 'HQL1002', 'count requires min, max, or exactly');
			if (exactly !== undefined && (min !== undefined || max !== undefined)) this.fail(token, 'HQL1002', 'count exactly cannot be combined with min/max');
			if (min !== undefined && max !== undefined && min > max) this.fail(token, 'HQL1002', 'count min exceeds max');
			const child = this.parseCondition(depth + 1);
			if (child.kind !== 'ast' && child.kind !== 'fact') this.fail(token, 'HQL1002', 'count accepts one ast or fact leaf');
			return { kind: 'count', child, ...(min !== undefined ? { min } : {}), ...(max !== undefined ? { max } : {}), ...(exactly !== undefined ? { exactly } : {}), span: mergeSpan(token.span, child.span) };
		}
		this.fail(token, 'HQL1002', `unknown condition '${token.text}'`, suggestion(token.text, ['ast', 'fact', 'all', 'any', 'not', 'count']));
	}

	private parseAstQuery(astToken: HqlTextToken, depth: number): HqlTextCondition {
		this.requireDepth(depth);
		const kindToken = this.expectKind('identifier', 'C-AST node kind');
		const kinds = hqlNodeKinds();
		if (!kinds.includes(kindToken.text as CNodeKind)) {
			this.fail(kindToken, 'HQL1006', `unknown C-AST node kind '${kindToken.text}'`, suggestion(kindToken.text, kinds));
		}
		const target = kindToken.text as CNodeKind;
		const query: HQLQuery = { target };
		const attributes: HQLAttributeCheck[] = [];
		const contains: HQLQuery[] = [];
		const operands: NonNullable<HQLQuery['operands']> = [];
		const fields = hqlNodeFields(target);
		const seenFields = new Set<string>();
		const seenOperands = new Set<number>();
		this.expectSymbol('{');
		while (!this.matchSymbol('}')) {
			const token = this.expectKind('identifier', 'query clause');
			if (token.text === 'contains') {
				const nestedStart = this.expectWord('ast');
				const nested = this.parseAstQuery(nestedStart, depth + 1);
				contains.push((nested as Extract<HqlTextCondition, { kind: 'ast' }>).query);
				this.expectSymbol(';');
				continue;
			}
			if (token.text === 'operand') {
				const positionToken = this.expectKind('number', 'operand position');
				if (typeof positionToken.value !== 'number' || !Number.isSafeInteger(positionToken.value) || positionToken.value < 0) {
					this.fail(positionToken, 'HQL1002', 'operand position must be a non-negative safe integer');
				}
				if (seenOperands.has(positionToken.value)) this.fail(positionToken, 'HQL1004', `duplicate operand ${positionToken.value}`);
				seenOperands.add(positionToken.value);
				const nestedStart = this.expectWord('ast');
				const nested = this.parseAstQuery(nestedStart, depth + 1);
				operands.push({ position: positionToken.value, query: (nested as Extract<HqlTextCondition, { kind: 'ast' }>).query });
				this.expectSymbol(';');
				continue;
			}
			if (token.text === 'minDepth' || token.text === 'maxDepth') {
				const valueToken = this.expectKind('number', token.text);
				if (typeof valueToken.value !== 'number' || !Number.isSafeInteger(valueToken.value) || valueToken.value < 0) {
					this.fail(valueToken, 'HQL1002', `${token.text} must be a non-negative safe integer`);
				}
				if (seenFields.has(token.text)) this.fail(token, 'HQL1004', `duplicate query field '${token.text}'`);
				seenFields.add(token.text);
				query[token.text] = valueToken.value;
				this.expectSymbol(';');
				continue;
			}
			if (!fields.includes(token.text)) this.fail(token, 'HQL1007', `field '${token.text}' does not exist on ${target}`, suggestion(token.text, fields));
			if (seenFields.has(token.text)) this.fail(token, 'HQL1004', `duplicate attribute '${token.text}'`);
			seenFields.add(token.text);
			const operator = this.expectKind('symbol', 'attribute comparison');
			if (operator.text !== '==') this.fail(operator, 'HQL1008', `unsupported comparison operator '${operator.text}'`, "use '=='");
			const valueToken = this.consumeScalar();
			const value = scalarValue(valueToken);
			if (token.text === 'operator' && typeof value === 'string' && !value.startsWith('re:') && !value.includes('*')) {
				const allowed = hqlOperatorValues(target);
				if (allowed.length > 0 && !allowed.includes(value)) this.fail(valueToken, 'HQL1008', `invalid ${target} operator '${value}'`, suggestion(value, allowed));
			}
			attributes.push({ field: token.text, value });
			this.expectSymbol(';');
		}
		if (attributes.length) query.attributes = attributes;
		if (contains.length) query.contains = contains;
		if (operands.length) query.operands = operands;
		const errors: string[] = [];
		validateQuery(query, '$.query', errors);
		if (errors.length) this.fail(kindToken, 'HQL1013', errors.join('; '));
		return { kind: 'ast', query, span: mergeSpan(astToken.span, this.previous().span) };
	}

	private parseFactQuery(factToken: HqlTextToken): HqlTextCondition {
		const kindToken = this.expectKind('identifier', 'semantic fact kind');
		const kinds = hqlSemanticFactKinds();
		if (!kinds.includes(kindToken.text)) this.fail(kindToken, 'HQL1009', `unknown semantic fact kind '${kindToken.text}'`, suggestion(kindToken.text, kinds));
		const fact = kindToken.text as HQLSemanticFactKind;
		const fields = hqlSemanticFactFields(fact);
		const attributes: HQLAttributeCheck[] = [];
		const seen = new Set<string>();
		this.expectSymbol('{');
		while (!this.matchSymbol('}')) {
			const fieldToken = this.expectKind('identifier', 'semantic fact field');
			if (!fields.includes(fieldToken.text)) this.fail(fieldToken, 'HQL1010', `field '${fieldToken.text}' does not exist on fact ${fact}`, suggestion(fieldToken.text, fields));
			if (seen.has(fieldToken.text)) this.fail(fieldToken, 'HQL1004', `duplicate fact attribute '${fieldToken.text}'`);
			seen.add(fieldToken.text);
			const operator = this.expectKind('symbol', 'fact comparison');
			if (operator.text !== '==') this.fail(operator, 'HQL1008', `unsupported comparison operator '${operator.text}'`, "use '=='");
			const valueToken = this.consumeScalar();
			attributes.push({ field: fieldToken.text, value: scalarValue(valueToken) });
			this.expectSymbol(';');
		}
		const query: HQLSemanticQuery = { fact, ...(attributes.length ? { attributes } : {}) };
		const errors: string[] = [];
		validateSemanticQuery(query, '$.fact', errors);
		if (errors.length) this.fail(kindToken, 'HQL1013', errors.join('; '));
		return { kind: 'fact', query, span: mergeSpan(factToken.span, this.previous().span) };
	}

	private parseProvenance(): HQLRuleProvenance {
		const result: Record<string, unknown> = {};
		const allowed = ['kind', 'source', 'url', 'commit', 'path', 'modified'];
		this.parseObjectFields(allowed, (key) => {
			if (key === 'kind') result.kind = this.expectKind('identifier', key).text;
			else if (key === 'modified') result.modified = this.expectBoolean();
			else result[key] = this.expectString(key).value;
			this.expectSymbol(';');
		});
		return result as unknown as HQLRuleProvenance;
	}

	private parseCompatibility(): HQLCompatibility {
		const result: Record<string, unknown> = {};
		this.parseObjectFields(['hql', 'helix', 'hast'], (key) => {
			if (key === 'hast') result.hastSchema = this.expectPositiveInteger('hast');
			else result[key] = this.expectString(key).value;
			this.expectSymbol(';');
		});
		return result as unknown as HQLCompatibility;
	}

	private parseCalibration(): HQLSignature['calibration'] {
		const result: Record<string, unknown> = {};
		this.parseObjectFields(['confidence', 'corpus', 'sha256'], (key) => {
			if (key === 'confidence') {
				const token = this.expectKind('number', key);
				if (typeof token.value !== 'number' || token.value < 0 || token.value > 1) this.fail(token, 'HQL1002', 'confidence must be between 0 and 1');
				result.confidence = token.value;
			} else if (key === 'sha256') result.corpusSha256 = this.expectString(key).value;
			else result.corpus = this.expectString(key).value;
			this.expectSymbol(';');
		});
		return result as HQLSignature['calibration'];
	}

	private parseObjectFields(allowed: readonly string[], parseValue: (key: string, token: HqlTextToken) => void): void {
		this.expectSymbol('{');
		const seen = new Set<string>();
		while (!this.matchSymbol('}')) {
			const token = this.expectKind('identifier', 'object field');
			if (!allowed.includes(token.text)) this.fail(token, 'HQL1004', `unknown field '${token.text}'`, suggestion(token.text, allowed));
			if (seen.has(token.text)) this.fail(token, 'HQL1004', `duplicate field '${token.text}'`);
			seen.add(token.text);
			parseValue(token.text, token);
		}
	}

	private parseStringArray(): string[] {
		const result: string[] = [];
		this.expectSymbol('[');
		if (this.matchSymbol(']')) return result;
		while (true) {
			result.push(this.expectString('array value').value as string);
			if (this.matchSymbol(']')) return result;
			this.expectSymbol(',');
			if (this.matchSymbol(']')) return result;
		}
	}

	private consumeScalar(): HqlTextToken {
		const token = this.consume();
		if (token.kind === 'string' || token.kind === 'number' || token.kind === 'regex') return token;
		if (token.kind === 'identifier' && (token.value === true || token.value === false)) return token;
		this.fail(token, 'HQL1002', 'expected string, regex, number, or boolean');
	}

	private expectBoolean(): boolean {
		const token = this.expectKind('identifier', 'boolean');
		if (token.value !== true && token.value !== false) this.fail(token, 'HQL1002', 'expected true or false');
		return token.value;
	}

	private expectPositiveInteger(label: string): number {
		const token = this.expectKind('number', label);
		if (typeof token.value !== 'number' || !Number.isSafeInteger(token.value) || token.value <= 0) this.fail(token, 'HQL1002', `${label} must be a positive safe integer`);
		return token.value;
	}

	private expectString(label: string): HqlTextToken {
		const token = this.expectKind('string', label);
		if (typeof token.value !== 'string') this.fail(token, 'HQL1002', `${label} must be a string`);
		return token;
	}

	private expectWord(word: string): HqlTextToken {
		const token = this.expectKind('identifier', `'${word}'`);
		if (token.text !== word) this.fail(token, 'HQL1002', `expected '${word}', received '${token.text}'`);
		return token;
	}

	private expectSymbol(symbol: string): HqlTextToken {
		const token = this.expectKind('symbol', `'${symbol}'`);
		if (token.text !== symbol) this.fail(token, 'HQL1002', `expected '${symbol}', received '${token.text || '<eof>'}'`);
		return token;
	}

	private expectKind(kind: HqlTextToken['kind'], label: string): HqlTextToken {
		const token = this.consume();
		if (token.kind !== kind) this.fail(token, 'HQL1002', `expected ${label}, received '${token.text || '<eof>'}'`);
		return token;
	}

	private matchSymbol(symbol: string): boolean {
		if (this.peek().kind === 'symbol' && this.peek().text === symbol) { this.index++; return true; }
		return false;
	}

	private consumeOptionalSymbol(symbol: string): void { this.matchSymbol(symbol); }
	private peek(): HqlTextToken { return this.tokens[this.index]; }
	private previous(): HqlTextToken { return this.tokens[Math.max(0, this.index - 1)]; }
	private consume(): HqlTextToken { return this.tokens[this.index++]; }

	private requireDepth(depth: number): void {
		if (depth <= this.maxDepth) return;
		this.fail(this.peek(), 'HQL1015', `condition nesting exceeds ${this.maxDepth}`);
	}

	private fail(token: HqlTextToken, code: string, message: string, suggestionText?: string): never {
		const diagnostic: HqlDiagnostic = {
			severity: 'error', code, message, filename: this.filename, span: token.span,
			excerpt: this.lines[token.span.start.line - 1] ?? '',
			...(suggestionText ? { suggestion: suggestionText } : {}),
		};
		throw new HqlCompileError([diagnostic]);
	}
}

function scalarValue(token: HqlTextToken): string | number | boolean {
	if (token.kind === 'regex') return `re:${String(token.value ?? '')}`;
	return token.value as string | number | boolean;
}

function mergeSpan(left: HqlSourceSpan, right: HqlSourceSpan): HqlSourceSpan {
	return { start: left.start, end: right.end };
}

function suggestion(value: string, candidates: readonly string[]): string | undefined {
	let best: { value: string; distance: number } | undefined;
	for (const candidate of candidates) {
		const distance = levenshtein(value, candidate);
		if (!best || distance < best.distance || distance === best.distance && candidate < best.value) best = { value: candidate, distance };
	}
	if (!best || best.distance > Math.max(2, Math.floor(value.length / 3))) return undefined;
	return `did you mean '${best.value}'?`;
}

function levenshtein(left: string, right: string): number {
	const previous = Array.from({ length: right.length + 1 }, (_, index) => index);
	for (let i = 1; i <= left.length; i++) {
		let diagonal = previous[0];
		previous[0] = i;
		for (let j = 1; j <= right.length; j++) {
			const above = previous[j];
			previous[j] = Math.min(previous[j] + 1, previous[j - 1] + 1, diagonal + (left[i - 1] === right[j - 1] ? 0 : 1));
			diagonal = above;
		}
	}
	return previous[right.length];
}
