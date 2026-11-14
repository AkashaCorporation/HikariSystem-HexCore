/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Akasha Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import type {
	HQLCondition,
	HQLQuery,
	HQLSemanticCondition,
	HQLSemanticQuery,
	HQLSignature,
} from '../types/hql.js';

export const HQL_TEXT_VERSION = '1.0' as const;
export const HQL_TEXT_COMPILER_VERSION = '1.0.0' as const;

export interface HqlSourcePosition {
	offset: number;
	line: number;
	column: number;
}

export interface HqlSourceSpan {
	start: HqlSourcePosition;
	end: HqlSourcePosition;
}

export interface HqlDiagnostic {
	severity: 'error';
	code: string;
	message: string;
	filename: string;
	span: HqlSourceSpan;
	excerpt: string;
	suggestion?: string;
}

export class HqlCompileError extends Error {
	constructor(public readonly diagnostics: readonly HqlDiagnostic[]) {
		super(diagnostics.map(formatHqlDiagnostic).join('\n\n'));
		this.name = 'HqlCompileError';
	}
}

export function formatHqlDiagnostic(diagnostic: HqlDiagnostic): string {
	const lineText = diagnostic.excerpt;
	const lineNo = String(diagnostic.span.start.line);
	const width = Math.max(1, diagnostic.span.end.offset - diagnostic.span.start.offset);
	const caret = `${' '.repeat(lineNo.length)} | ${' '.repeat(Math.max(0, diagnostic.span.start.column - 1))}${'^'.repeat(Math.min(width, Math.max(1, lineText.length - diagnostic.span.start.column + 2)))}`;
	return [
		`${diagnostic.filename}:${diagnostic.span.start.line}:${diagnostic.span.start.column}`,
		`${diagnostic.severity} ${diagnostic.code}: ${diagnostic.message}`,
		`${lineNo} | ${lineText}`,
		caret,
		...(diagnostic.suggestion ? [diagnostic.suggestion] : []),
	].join('\n');
}

export type HqlTextTokenKind = 'identifier' | 'string' | 'number' | 'regex' | 'symbol' | 'eof';

export interface HqlTextToken {
	kind: HqlTextTokenKind;
	text: string;
	value?: string | number | boolean;
	span: HqlSourceSpan;
}

export type HqlTextCondition =
	| { kind: 'ast'; query: HQLQuery; span: HqlSourceSpan }
	| { kind: 'fact'; query: HQLSemanticQuery; span: HqlSourceSpan }
	| { kind: 'all' | 'any'; children: HqlTextCondition[]; span: HqlSourceSpan }
	| { kind: 'not'; child: HqlTextCondition; span: HqlSourceSpan }
	| { kind: 'count'; child: Extract<HqlTextCondition, { kind: 'ast' | 'fact' }>; min?: number; max?: number; exactly?: number; span: HqlSourceSpan };

export interface ParsedHqlRule {
	hqlVersion: typeof HQL_TEXT_VERSION;
	metadata: Omit<HQLSignature, 'condition' | 'semanticCondition' | 'queries'>;
	queries?: HQLQuery[];
	where?: HqlTextCondition;
	semantic?: HqlTextCondition;
	span: HqlSourceSpan;
}

export interface HqlCompileOptions {
	filename?: string;
	hqlVersion?: string;
	maxSourceBytes?: number;
	maxTokens?: number;
	maxDepth?: number;
}

export interface HqlCompileResult {
	hqlVersion: typeof HQL_TEXT_VERSION;
	compilerVersion: typeof HQL_TEXT_COMPILER_VERSION;
	signature: HQLSignature;
	canonicalJson: string;
	signatureSha256: string;
}

export interface LoweredHqlConditions {
	condition?: HQLCondition;
	semanticCondition?: HQLSemanticCondition;
}
