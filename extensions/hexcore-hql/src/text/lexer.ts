/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Akasha Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import {
	HqlCompileError,
	type HqlCompileOptions,
	type HqlDiagnostic,
	type HqlSourcePosition,
	type HqlSourceSpan,
	type HqlTextToken,
} from './syntax.js';

const DEFAULT_MAX_SOURCE_BYTES = 1024 * 1024;
const DEFAULT_MAX_TOKENS = 100_000;

export class HqlLexer {
	private offset = 0;
	private line = 1;
	private column = 1;
	private readonly diagnostics: HqlDiagnostic[] = [];
	private readonly filename: string;
	private readonly maxTokens: number;
	private readonly lines: string[];

	constructor(private readonly source: string, options: HqlCompileOptions = {}) {
		this.filename = options.filename ?? '<hql>';
		this.maxTokens = options.maxTokens ?? DEFAULT_MAX_TOKENS;
		this.lines = source.split(/\r?\n/);
		const maxSourceBytes = options.maxSourceBytes ?? DEFAULT_MAX_SOURCE_BYTES;
		if (!Number.isSafeInteger(maxSourceBytes) || maxSourceBytes < 1) {
			throw new Error('HQL maxSourceBytes must be a positive safe integer');
		}
		if (Buffer.byteLength(source, 'utf8') > maxSourceBytes) {
			this.fail(this.position(), this.position(), 'HQL1015', `source exceeds ${maxSourceBytes} bytes`);
		}
	}

	tokenize(): HqlTextToken[] {
		const tokens: HqlTextToken[] = [];
		while (true) {
			this.skipTrivia();
			if (this.offset >= this.source.length) break;
			if (tokens.length >= this.maxTokens) {
				const position = this.position();
				this.fail(position, position, 'HQL1015', `token budget exceeds ${this.maxTokens}`);
			}
			const start = this.position();
			const ch = this.peek();
			if (ch === '"') tokens.push(this.readString(start));
			else if (ch === '/' && this.peek(1) !== '/' && this.peek(1) !== '*') tokens.push(this.readRegex(start));
			else if (/[0-9]/.test(ch) || ch === '-' && /[0-9]/.test(this.peek(1))) tokens.push(this.readNumber(start));
			else if (/[A-Za-z_$]/.test(ch)) tokens.push(this.readIdentifier(start));
			else tokens.push(this.readSymbol(start));
		}
		const eof = this.position();
		tokens.push({ kind: 'eof', text: '', span: { start: eof, end: eof } });
		return tokens;
	}

	private skipTrivia(): void {
		while (this.offset < this.source.length) {
			if (/\s/.test(this.peek())) { this.advance(); continue; }
			if (this.peek() === '/' && this.peek(1) === '/') {
				while (this.offset < this.source.length && this.peek() !== '\n') this.advance();
				continue;
			}
			if (this.peek() === '/' && this.peek(1) === '*') {
				const start = this.position();
				this.advance(); this.advance();
				while (this.offset < this.source.length && !(this.peek() === '*' && this.peek(1) === '/')) this.advance();
				if (this.offset >= this.source.length) this.fail(start, this.position(), 'HQL1002', 'unterminated block comment');
				this.advance(); this.advance();
				continue;
			}
			break;
		}
	}

	private readString(start: HqlSourcePosition): HqlTextToken {
		let raw = '"';
		this.advance();
		let escaped = false;
		while (this.offset < this.source.length) {
			const ch = this.peek();
			if (!escaped && ch === '"') {
				raw += ch; this.advance();
				try {
					const value = JSON.parse(raw) as string;
					return { kind: 'string', text: raw, value, span: { start, end: this.position() } };
				} catch {
					this.fail(start, this.position(), 'HQL1002', 'invalid string escape');
				}
			}
			if (!escaped && (ch === '\n' || ch === '\r')) this.fail(start, this.position(), 'HQL1002', 'unterminated string literal');
			raw += ch;
			this.advance();
			if (escaped) escaped = false;
			else if (ch === '\\') escaped = true;
		}
		this.fail(start, this.position(), 'HQL1002', 'unterminated string literal');
	}

	private readRegex(start: HqlSourcePosition): HqlTextToken {
		this.advance();
		let pattern = '';
		let escaped = false;
		let inClass = false;
		while (this.offset < this.source.length) {
			const ch = this.peek();
			if (!escaped && ch === '\\') {
				if (this.peek(1) === '/') {
					pattern += '/';
					this.advance(); this.advance();
					continue;
				}
				pattern += '\\';
				this.advance();
				escaped = true;
				continue;
			}
			if (!escaped && ch === '[') inClass = true;
			if (!escaped && ch === ']') inClass = false;
			if (!escaped && ch === '/' && !inClass) {
				this.advance();
				if (/[A-Za-z]/.test(this.peek())) this.fail(start, this.position(), 'HQL1011', 'regex flags are not supported');
				try { new RegExp(pattern); } catch (error) {
					this.fail(start, this.position(), 'HQL1011', `invalid regex: ${error instanceof Error ? error.message : String(error)}`);
				}
				return { kind: 'regex', text: this.source.slice(start.offset, this.offset), value: pattern, span: { start, end: this.position() } };
			}
			if (!escaped && (ch === '\n' || ch === '\r')) this.fail(start, this.position(), 'HQL1011', 'unterminated regex literal');
			pattern += ch;
			this.advance();
			if (escaped) escaped = false;
		}
		this.fail(start, this.position(), 'HQL1011', 'unterminated regex literal');
	}

	private readNumber(start: HqlSourcePosition): HqlTextToken {
		const begin = this.offset;
		if (this.peek() === '-') this.advance();
		if (this.peek() === '0' && /[xX]/.test(this.peek(1))) {
			this.advance(); this.advance();
			const digits = this.offset;
			while (/[0-9a-fA-F]/.test(this.peek())) this.advance();
			if (digits === this.offset) this.fail(start, this.position(), 'HQL1002', 'hexadecimal literal requires digits');
		} else {
			while (/[0-9]/.test(this.peek())) this.advance();
			if (this.peek() === '.') {
				this.advance();
				if (!/[0-9]/.test(this.peek())) this.fail(start, this.position(), 'HQL1002', 'fractional literal requires digits');
				while (/[0-9]/.test(this.peek())) this.advance();
			}
		}
		const raw = this.source.slice(begin, this.offset);
		let value: string | number;
		if (/^-?0x/i.test(raw) || !raw.includes('.')) {
			const integer = /^-0x/i.test(raw) ? -BigInt(raw.slice(1)) : BigInt(raw);
			value = integer <= BigInt(Number.MAX_SAFE_INTEGER) && integer >= BigInt(Number.MIN_SAFE_INTEGER)
				? Number(integer) : integer.toString(10);
		} else {
			value = Number(raw);
			if (!Number.isFinite(value)) this.fail(start, this.position(), 'HQL1002', 'number must be finite');
		}
		return { kind: 'number', text: raw, value, span: { start, end: this.position() } };
	}

	private readIdentifier(start: HqlSourcePosition): HqlTextToken {
		const begin = this.offset;
		while (/[A-Za-z0-9_.$:@-]/.test(this.peek())) this.advance();
		const text = this.source.slice(begin, this.offset);
		const value = text === 'true' ? true : text === 'false' ? false : text;
		return { kind: 'identifier', text, value, span: { start, end: this.position() } };
	}

	private readSymbol(start: HqlSourcePosition): HqlTextToken {
		const pair = this.source.slice(this.offset, this.offset + 2);
		if (['==', '!=', '<=', '>=', '=>'].includes(pair)) {
			this.advance(); this.advance();
			return { kind: 'symbol', text: pair, span: { start, end: this.position() } };
		}
		const ch = this.peek();
		if (!'{}[]();,'.includes(ch)) this.fail(start, this.position(), 'HQL1002', `unexpected character ${JSON.stringify(ch)}`);
		this.advance();
		return { kind: 'symbol', text: ch, span: { start, end: this.position() } };
	}

	private peek(ahead = 0): string { return this.source[this.offset + ahead] ?? ''; }

	private advance(): void {
		const ch = this.source[this.offset++];
		if (ch === '\n') { this.line++; this.column = 1; }
		else this.column++;
	}

	private position(): HqlSourcePosition { return { offset: this.offset, line: this.line, column: this.column }; }

	private fail(start: HqlSourcePosition, end: HqlSourcePosition, code: string, message: string): never {
		const span: HqlSourceSpan = { start, end };
		this.diagnostics.push({ severity: 'error', code, message, filename: this.filename, span, excerpt: this.lines[start.line - 1] ?? '' });
		throw new HqlCompileError(this.diagnostics);
	}
}
