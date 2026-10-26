/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

export interface LiftExternalSymbolResult { ir: string; rewrittenTargets: number; renamedGlobals: number; issues: string[] }

/** Keep machine entry identity in LLVM before replacing its encoded symbol name. */
export function renameLiftedEntry(ir: string, address: number, name: string): string {
	if (!Number.isSafeInteger(address) || address < 0 || !name || name.length > 1024 || name.includes('\0')) { throw new Error('Invalid lifted entry identity'); }
	const original = `lifted_${address}`;
	const definition = new RegExp(`^(\\s*define\\b[^\\n]*@${original}\\([^\\n]*\\)[^\\n{]*)(\\{)`, 'm');
	const match = definition.exec(ir);
	if (!match) { throw new Error('Canonical lifted definition required before entry rename'); }
	if (match[1].includes('"hexcore.entry_address"')) { throw new Error('Lifted definition already carries explicit entry identity'); }
	const targetDefinition = new RegExp(`^\\s*define\\b[^\\n]*(${globalToken})\\s*\\(`, 'gm');
	for (const existing of ir.matchAll(targetDefinition)) {
		if (decodeGlobal(existing[1]) === name && name !== original) { throw new Error('Entry rename conflicts with an existing definition'); }
	}
	const stamped = ir.slice(0, match.index) + match[1] + ` "hexcore.entry_address"="0x${address.toString(16)}" {` + ir.slice(match.index + match[0].length);
	return rewriteGlobals(stamped, candidate => candidate === original ? name : undefined);
}
const globalToken = '@(?:"(?:\\\\[0-9a-fA-F]{2}|[^"\\\\])*"|[-a-zA-Z$._0-9]+)';
function quoteEnd(text: string, start: number): number {
	for (let end = start + 1; end < text.length; end++) {
		if (text[end] === '\\') { end += 2; }
		else if (text[end] === '"') { return end + 1; }
	}
	return text.length;
}
function decodeGlobal(token: string): string {
	const value = token.slice(1);
	if (value[0] !== '"') { return value; }
	const bytes: Buffer[] = [];
	const body = value.slice(1, -1);
	let from = 0;
	for (const match of body.matchAll(/\\([0-9a-fA-F]{2})/g)) {
		bytes.push(Buffer.from(body.slice(from, match.index), 'utf8'), Buffer.from([Number.parseInt(match[1], 16)]));
		from = match.index! + 3;
	}
	bytes.push(Buffer.from(body.slice(from), 'utf8'));
	return Buffer.concat(bytes).toString('utf8');
}
function llvmGlobal(name: string): string {
	if (/^[-a-zA-Z$._][-a-zA-Z$._0-9]*$/.test(name)) { return `@${name}`; }
	return '@"' + [...Buffer.from(name)].map(byte => byte >= 32 && byte < 127 && byte !== 34 && byte !== 92 ? String.fromCharCode(byte) : '\\' + byte.toString(16).padStart(2, '0').toUpperCase()).join('') + '"';
}

/** Rewrite LLVM global tokens only, never comments, metadata strings or C string data. */
function rewriteGlobals(text: string, rewrite: (name: string) => string | undefined): string {
	let out = '', from = 0;
	for (let index = 0; index < text.length;) {
		if (text[index] === ';') { const end = text.indexOf('\n', index); index = end < 0 ? text.length : end; continue; }
		if (text[index] === '"') { index = quoteEnd(text, index); continue; }
		if (text[index] !== '@') { index++; continue; }
		let end = index + 1;
		if (text[end] === '"') { end = quoteEnd(text, end); }
		else { while (end < text.length && /[-a-zA-Z$._0-9]/.test(text[end])) { end++; } }
		const name = decodeGlobal(text.slice(index, end));
		const replacement = rewrite(name);
		if (replacement !== undefined) { out += text.slice(from, index) + llvmGlobal(replacement); from = end; }
		index = end;
	}
	return out + text.slice(from);
}

function argumentSpans(line: string, open: number): Array<[number, number]> | undefined {
	let depth = 0, start = open + 1;
	const spans: Array<[number, number]> = [];
	for (let index = open + 1; index < line.length; index++) {
		const ch = line[index];
		if (ch === '"') { index = quoteEnd(line, index) - 1; continue; }
		if (ch === ';') { return undefined; }
		if (ch === ')' && depth === 0) { spans.push([start, index]); return spans; }
		if ('([{<'.includes(ch)) { depth++; }
		else if (')]}>'.includes(ch)) { if (--depth < 0) { return undefined; } }
		else if (ch === ',' && depth === 0) { spans.push([start, index]); start = index + 1; }
	}
	return undefined;
}

/** Resolve synthetic external targets without rewriting ordinary integer data. */
export function resolveLiftExternalSymbols(ir: string, symbols: ReadonlyMap<number, string>, callTargets: readonly number[] = []): LiftExternalSymbolResult {
	const result: LiftExternalSymbolResult = { ir, rewrittenTargets: 0, renamedGlobals: 0, issues: [] };
	if (!symbols.size) { return result; }
	if (symbols.size > 65536 || Buffer.byteLength(ir) > 32 * 1024 * 1024) { throw new Error('Lift symbol resolution budget exceeded'); }
	for (const [address, name] of symbols) if (!Number.isSafeInteger(address) || address < 0 || typeof name !== 'string' || !name || name.length > 1024 || name.includes('\0')) { throw new Error('Invalid lift external symbol'); }
	const headers = new Map<string, 'declare' | 'define' | 'global'>();
	const header = new RegExp(`^\\s*(declare|define)\\b[^\\n]*?(${globalToken})\\s*\\(`);
	const global = new RegExp(`^\\s*(${globalToken})\\s*=`);
	for (const line of ir.split('\n')) {
		const match = header.exec(line);
		if (match) { headers.set(decodeGlobal(match[2]), match[1] as 'declare' | 'define'); }
		else { const defined = global.exec(line); if (defined) { headers.set(decodeGlobal(defined[1]), 'global'); } }
	}
	const aliases = new Map<string, string>();
	const blocked = new Set<number>();
	const claimedNames = new Set(headers.keys());
	const syntheticHeaders = new Map<number, Array<{ candidate: string; kind: string }>>();
	for (const [candidate, kind] of headers) {
		const match = /^(?:sub|lifted)_([0-9a-f]{1,16})$/i.exec(candidate);
		if (!match) { continue; }
		const at = Number(BigInt(`0x${match[1]}`));
		if (Number.isSafeInteger(at)) { syntheticHeaders.set(at, [...(syntheticHeaders.get(at) ?? []), { candidate, kind }]); }
	}
	for (const [address, name] of symbols) {
		if (headers.get(name) === 'global') { blocked.add(address); result.issues.push(`External target is a non-function global: ${name}`); continue; }
		for (const { candidate, kind } of syntheticHeaders.get(address) ?? []) {
			if (candidate === name) { continue; }
			if (kind !== 'declare' || claimedNames.has(name)) { blocked.add(address); result.issues.push(`Preserved conflicting synthetic symbol: ${candidate}`); continue; }
			aliases.set(candidate, name);
			claimedNames.add(name);
		}
	}
	for (const [candidate] of aliases) {
		const match = /^(?:sub|lifted)_([0-9a-f]{1,16})$/i.exec(candidate);
		if (match && blocked.has(Number(BigInt(`0x${match[1]}`)))) { aliases.delete(candidate); }
	}
	result.ir = rewriteGlobals(ir, name => {
		const alias = aliases.get(name);
		if (alias) { result.renamedGlobals++; }
		return alias;
	});
	for (const name of aliases.values()) { headers.set(name, 'declare'); }
	const introduced = new Set<string>();
	const resolved = new Set<number>();
	const resolvedNames = new Set<string>();
	const aliasedNames = new Set(aliases.values());
	// Current Remill emits opaque-pointer-returning direct calls. Other forms stay untouched.
	const call = new RegExp(`^\\s*(?:%[^=\\n]+\\s*=\\s*)?(?:(?:tail|musttail|notail)\\s+)?call\\s+(?:[a-zA-Z_][a-zA-Z_0-9]*\\s+)*ptr\\s+(${globalToken})\\s*\\(`);
	const symbolicTarget = new RegExp(`^\\s*i64\\s+ptrtoint\\s*\\(ptr\\s+(${globalToken})\\s+to\\s+i64\\)\\s*$`);
	result.ir = result.ir.split('\n').map(line => {
		const match = call.exec(line); if (!match) { return line; }
		const callee = decodeGlobal(match[1]);
		const targetIndex = callee === '__remill_function_call' || callee === '__remill_jump' ? 1 : /^_ZN12_GLOBAL__N_1\d+(?:CALLI|JMPI)/.test(callee) ? 2 : undefined;
		if (targetIndex === undefined) { return line; }
		const spans = argumentSpans(line, match.index + match[0].length - 1);
		const span = spans?.[targetIndex]; if (!span) { result.issues.push('Unparsed Remill call target'); return line; }
		const symbolic = symbolicTarget.exec(line.slice(...span));
		if (symbolic) { resolvedNames.add(decodeGlobal(symbolic[1])); return line; }
		const value = /^(\s*)i64\s+(\d+)(\s*)$/.exec(line.slice(...span));
		if (!value) { return line; }
		const address = Number(value[2]);
		const name = symbols.get(address);
		if (!Number.isSafeInteger(address) || !name || blocked.has(address)) { return line; }
		resolved.add(address); result.rewrittenTargets++;
		if (!headers.has(name)) { introduced.add(name); }
		return line.slice(0, span[0]) + `${value[1]}i64 ptrtoint (ptr ${llvmGlobal(name)} to i64)${value[3]}` + line.slice(span[1]);
	}).join('\n');
	if (introduced.size) { result.ir += '\n; External targets resolved from accepted relocations\n' + [...introduced].sort().map(name => `declare ptr ${llvmGlobal(name)}(...)`).join('\n') + '\n'; }
	for (const target of callTargets) {
		const name = symbols.get(target);
		if (name && !resolved.has(target) && !aliasedNames.has(name) && !resolvedNames.has(name)) { result.issues.push(`External call target remains unresolved: ${name}`); }
	}
	result.issues = [...new Set(result.issues)].sort();
	return result;
}
