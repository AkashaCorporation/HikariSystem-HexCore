/*---------------------------------------------------------------------------------------------
 * Bounded Win64 value/handle def-use for Windows filesystem audit callsites.
 *--------------------------------------------------------------------------------------------*/

import type { Function as DisassembledFunction, Instruction } from './disassemblerEngine';

export interface ValueFlowFactSeed {
	kind: string;
	functionAddress: string;
	functionName: string;
	api: string;
	callSite?: string;
}

export interface ResolvedValueExpression {
	canonical: string;
	display: string;
	confidence: 'exact' | 'candidate' | 'unresolved';
	definitions: string[];
}

export interface CallArgumentBinding {
	index: number;
	name: string;
	location: string;
	value: ResolvedValueExpression;
}

export interface CallsiteValueSummary {
	functionAddress: string;
	functionName: string;
	api: string;
	callSite: string;
	arguments: CallArgumentBinding[];
	returnBindings: ResolvedValueExpression[];
}

export interface ValueIdentityProof {
	kind: 'same-handle' | 'same-acl' | 'same-sid' | 'same-path';
	status: 'proven';
	canonicalIdentity: string;
	producer: { api: string; callSite: string; argument?: string };
	consumer: { api: string; callSite: string; argument: string };
	functionAddress: string;
	evidence: string[];
}

export interface ValueIdentitySignal {
	kind: ValueIdentityProof['kind'];
	status: 'signal';
	canonicalIdentity: string;
	producer: ValueIdentityProof['producer'];
	consumer: ValueIdentityProof['consumer'];
	functionAddress: string;
	evidence: string[];
	blockers: string[];
}

export interface DeepWindowsValueDataflow {
	status: 'assessed' | 'not-assessed';
	architecture: string;
	callsites: CallsiteValueSummary[];
	proofs: ValueIdentityProof[];
	signals: ValueIdentitySignal[];
	limitations: string[];
}

interface ApiArgument {
	name: string;
}

const API_ARGUMENTS: Array<{ pattern: RegExp; args: ApiArgument[] }> = [
	{ pattern: /!CreateFile(?:A|W)?$/i, args: ['path', 'desiredAccess', 'shareMode', 'securityAttributes', 'creationDisposition', 'flagsAndAttributes', 'templateFile'].map(name => ({ name })) },
	{ pattern: /!WriteFile(?:Ex)?$/i, args: ['handle', 'buffer', 'bytesToWrite', 'bytesWritten', 'overlapped'].map(name => ({ name })) },
	{ pattern: /!CloseHandle$/i, args: [{ name: 'handle' }] },
	{ pattern: /!GetFinalPathNameByHandleW$/i, args: ['handle', 'buffer', 'bufferLength', 'flags'].map(name => ({ name })) },
	{ pattern: /!SetFileInformationByHandle$/i, args: ['handle', 'infoClass', 'info', 'infoSize'].map(name => ({ name })) },
	{ pattern: /!MoveFile(?:Ex)?(?:A|W)?$/i, args: ['existingPath', 'newPath', 'flags'].map(name => ({ name })) },
	{ pattern: /!InitializeAcl$/i, args: ['acl', 'aclLength', 'aclRevision'].map(name => ({ name })) },
	{ pattern: /!AddAccess(?:Allowed|Denied)Ace$/i, args: ['acl', 'aceRevision', 'accessMask', 'sid'].map(name => ({ name })) },
	{ pattern: /!AllocateAndInitializeSid$/i, args: ['identifierAuthority', 'subAuthorityCount', 'subAuthority0', 'subAuthority1', 'subAuthority2', 'subAuthority3', 'subAuthority4', 'subAuthority5', 'subAuthority6', 'subAuthority7', 'sidOut'].map(name => ({ name })) },
	{ pattern: /!CreateWellKnownSid$/i, args: ['sidType', 'domainSid', 'sidOut', 'sidSize'].map(name => ({ name })) },
	{ pattern: /!SetFileSecurityW$/i, args: ['path', 'securityInformation', 'securityDescriptor'].map(name => ({ name })) },
	{ pattern: /!SetNamedSecurityInfoW$/i, args: ['path', 'objectType', 'securityInformation', 'owner', 'group', 'dacl', 'sacl'].map(name => ({ name })) },
	{ pattern: /!GetNamedSecurityInfoW$/i, args: ['path', 'objectType', 'securityInformation', 'ownerOut', 'groupOut', 'daclOut', 'saclOut', 'descriptorOut'].map(name => ({ name })) },
	{ pattern: /!GetTempPathW$/i, args: ['bufferLength', 'pathOut'].map(name => ({ name })) },
	{ pattern: /!GetTempFileNameW$/i, args: ['path', 'prefix', 'unique', 'fileNameOut'].map(name => ({ name })) },
	{ pattern: /!GetFullPathNameW$/i, args: ['inputPath', 'bufferLength', 'pathOut', 'filePartOut'].map(name => ({ name })) },
	{ pattern: /!SHGetFolderPathW$/i, args: ['window', 'folder', 'token', 'flags', 'pathOut'].map(name => ({ name })) },
	{ pattern: /!(?:fopen|_wfopen)$/i, args: ['path', 'mode'].map(name => ({ name })) },
];

const ARG_REGISTERS = ['rcx', 'rdx', 'r8', 'r9'];

const READ_ONLY_POINTER_ARGUMENTS: Array<{ pattern: RegExp; indexes: ReadonlySet<number> }> = [
	{ pattern: /!lstrlen(?:A|W)$/i, indexes: new Set([0]) },
	{ pattern: /!GetFileAttributes(?:A|W)$/i, indexes: new Set([0]) },
	{ pattern: /!PathFileExists(?:A|W)$/i, indexes: new Set([0]) },
];

function toHex(address: number): string {
	return `0x${Math.max(0, address).toString(16).toUpperCase()}`;
}

function normalizeRegister(register: string): string {
	const value = register.trim().toLowerCase();
	const aliases: Record<string, string> = {
		eax: 'rax', ax: 'rax', al: 'rax', ah: 'rax',
		ecx: 'rcx', cx: 'rcx', cl: 'rcx', ch: 'rcx',
		edx: 'rdx', dx: 'rdx', dl: 'rdx', dh: 'rdx',
		ebx: 'rbx', bx: 'rbx', bl: 'rbx', bh: 'rbx',
		esi: 'rsi', si: 'rsi', sil: 'rsi',
		edi: 'rdi', di: 'rdi', dil: 'rdi',
		ebp: 'rbp', esp: 'rsp',
	};
	if (/^r(?:8|9|10|11|12|13|14|15)[dwb]$/.test(value)) { return value.replace(/[dwb]$/, ''); }
	return aliases[value] ?? value;
}

function splitOperands(opStr: string): [string, string] | undefined {
	let bracketDepth = 0;
	for (let index = 0; index < opStr.length; index++) {
		if (opStr[index] === '[') { bracketDepth++; }
		if (opStr[index] === ']') { bracketDepth--; }
		if (opStr[index] === ',' && bracketDepth === 0) {
			return [opStr.slice(0, index).trim(), opStr.slice(index + 1).trim()];
		}
	}
	return undefined;
}

function normalizeStorage(operand: string): string | undefined {
	const match = /\[([^\]]+)\]/.exec(operand.toLowerCase());
	if (!match) { return undefined; }
	return `[${match[1].replace(/\s+/g, '').replace(/\+\-/g, '-')}]`;
}

function unresolved(display: string): ResolvedValueExpression {
	return { canonical: `unresolved:${display}`, display, confidence: 'unresolved', definitions: [] };
}

function immediateExpression(operand: string, definition: number): ResolvedValueExpression | undefined {
	const text = operand.trim().toLowerCase();
	if (/^0x[0-9a-f]+$/.test(text) || /^\d+$/.test(text)) {
		const value = text.startsWith('0x') ? parseInt(text, 16) : parseInt(text, 10);
		return { canonical: `imm:${value}`, display: toHex(value), confidence: 'exact', definitions: [toHex(definition)] };
	}
	return undefined;
}

function apiAtCallSite(seeds: readonly ValueFlowFactSeed[]): Map<number, string> {
	return new Map(seeds.filter(seed => seed.callSite).map(seed => [parseInt(seed.callSite!.slice(2), 16), seed.api]));
}

function resolveStoredValue(
	fn: DisassembledFunction,
	beforeIndex: number,
	storage: string,
	callApis: Map<number, string>,
	depth: number,
): ResolvedValueExpression | undefined {
	if (depth > 12) { return undefined; }
	for (let index = beforeIndex - 1; index >= Math.max(0, beforeIndex - 96); index--) {
		const instruction = fn.instructions[index];
		const operands = splitOperands(instruction.opStr);
		if (!operands || !/^mov$/i.test(instruction.mnemonic) || normalizeStorage(operands[0]) !== storage) { continue; }
		const source = operands[1].trim();
		const immediate = immediateExpression(source, instruction.address);
		if (immediate) { return immediate; }
		if (/^[a-z][a-z0-9]*$/i.test(source)) {
			const resolved = resolveRegister(fn, index, source, callApis, depth + 1);
			return { ...resolved, definitions: [toHex(instruction.address), ...resolved.definitions] };
		}
		const sourceStorage = normalizeStorage(source);
		if (sourceStorage) {
			const resolved = resolveStoredValue(fn, index, sourceStorage, callApis, depth + 1);
			return resolved
				? { ...resolved, definitions: [toHex(instruction.address), ...resolved.definitions] }
				: { canonical: `load:${sourceStorage}`, display: `load ${sourceStorage}`, confidence: 'exact', definitions: [toHex(instruction.address)] };
		}
		return undefined;
	}
	return undefined;
}

function resolveRegister(
	fn: DisassembledFunction,
	beforeIndex: number,
	register: string,
	callApis: Map<number, string>,
	depth = 0,
): ResolvedValueExpression {
	if (depth > 12) { return unresolved(`reg:${register}`); }
	const target = normalizeRegister(register);
	for (let index = beforeIndex - 1; index >= Math.max(0, beforeIndex - 64); index--) {
		const instruction = fn.instructions[index];
		if (instruction.isCall) {
			if (target === 'rax') {
				const api = callApis.get(instruction.address) ?? `call@${toHex(instruction.address)}`;
				return {
					canonical: `ret:${fn.address.toString(16)}:${instruction.address.toString(16)}:${api.toLowerCase()}`,
					display: `return(${api}@${toHex(instruction.address)})`,
					confidence: 'exact',
					definitions: [toHex(instruction.address)],
				};
			}
			if (['rcx', 'rdx', 'r8', 'r9', 'r10', 'r11'].includes(target)) {
				return unresolved(`reg:${target}:clobbered@${toHex(instruction.address)}`);
			}
		}
		const operands = splitOperands(instruction.opStr);
		if (!operands) { continue; }
		const destination = normalizeRegister(operands[0]);
		if (destination !== target) { continue; }
		const source = operands[1].trim();
		if (/^(mov|movzx|movsxd)$/i.test(instruction.mnemonic)) {
			const immediate = immediateExpression(source, instruction.address);
			if (immediate) { return immediate; }
			if (/^[a-z][a-z0-9]*$/i.test(source)) {
				const resolved = resolveRegister(fn, index, source, callApis, depth + 1);
				return { ...resolved, definitions: [toHex(instruction.address), ...resolved.definitions] };
			}
			const storage = normalizeStorage(source);
			if (storage) {
				const stored = resolveStoredValue(fn, index, storage, callApis, depth + 1);
				return stored
					? { ...stored, definitions: [toHex(instruction.address), ...stored.definitions] }
					: { canonical: `load:${storage}`, display: `load ${storage}`, confidence: 'exact', definitions: [toHex(instruction.address)] };
			}
		}
		if (/^lea$/i.test(instruction.mnemonic)) {
			const storage = normalizeStorage(source);
			if (storage) {
				return { canonical: `addr:${storage}`, display: `address ${storage}`, confidence: 'exact', definitions: [toHex(instruction.address)] };
			}
		}
		if (/^xor$/i.test(instruction.mnemonic) && normalizeRegister(source) === target) {
			return { canonical: 'imm:0', display: '0x0', confidence: 'exact', definitions: [toHex(instruction.address)] };
		}
		return { canonical: `expr:${instruction.mnemonic}:${source.toLowerCase()}`, display: `${instruction.mnemonic} ${source}`, confidence: 'candidate', definitions: [toHex(instruction.address)] };
	}
	return unresolved(`reg:${target}`);
}

function resolveStackArgument(
	fn: DisassembledFunction,
	callIndex: number,
	offset: number,
	callApis: Map<number, string>,
): ResolvedValueExpression {
	const expected = `[rsp+0x${offset.toString(16)}]`;
	for (let index = callIndex - 1; index >= Math.max(0, callIndex - 64); index--) {
		const instruction = fn.instructions[index];
		if (instruction.isCall) { break; }
		const operands = splitOperands(instruction.opStr);
		if (!operands || !/^mov$/i.test(instruction.mnemonic)) { continue; }
		if (normalizeStorage(operands[0]) !== expected) { continue; }
		const immediate = immediateExpression(operands[1], instruction.address);
		if (immediate) { return immediate; }
		if (/^[a-z][a-z0-9]*$/i.test(operands[1])) {
			const resolved = resolveRegister(fn, index, operands[1], callApis);
			return { ...resolved, definitions: [toHex(instruction.address), ...resolved.definitions] };
		}
		const storage = normalizeStorage(operands[1]);
		if (storage) {
			const stored = resolveStoredValue(fn, index, storage, callApis, 1);
			return stored
				? { ...stored, definitions: [toHex(instruction.address), ...stored.definitions] }
				: { canonical: `load:${storage}`, display: `load ${storage}`, confidence: 'exact', definitions: [toHex(instruction.address)] };
		}
	}
	return unresolved(`stack:${expected}`);
}

function captureReturnBindings(
	fn: DisassembledFunction,
	callIndex: number,
	api: string,
): ResolvedValueExpression[] {
	if (!/!(?:CreateFile(?:A|W)?|fopen|_wfopen)$/i.test(api)) { return []; }
	const token: ResolvedValueExpression = {
		canonical: `ret:${fn.address.toString(16)}:${fn.instructions[callIndex].address.toString(16)}:${api.toLowerCase()}`,
		display: `return(${api}@${toHex(fn.instructions[callIndex].address)})`,
		confidence: 'exact',
		definitions: [toHex(fn.instructions[callIndex].address)],
	};
	for (let index = callIndex + 1; index < Math.min(fn.instructions.length, callIndex + 13); index++) {
		const instruction = fn.instructions[index];
		if (instruction.isCall || instruction.isRet) { break; }
		const operands = splitOperands(instruction.opStr);
		if (!operands || !/^mov$/i.test(instruction.mnemonic) || normalizeRegister(operands[1]) !== 'rax') { continue; }
		const storage = normalizeStorage(operands[0]);
		if (storage) {
			return [{ canonical: `storage:${storage}`, display: `stored in ${storage}`, confidence: 'exact', definitions: [toHex(instruction.address), ...token.definitions] }, token];
		}
	}
	return [token];
}

function argumentSpec(api: string): ApiArgument[] {
	return API_ARGUMENTS.find(entry => entry.pattern.test(api))?.args ?? [];
}

function storageIdentity(value: ResolvedValueExpression): string | undefined {
	if (value.confidence !== 'exact') { return undefined; }
	for (const prefix of ['storage:', 'load:', 'addr:']) {
		if (value.canonical.startsWith(prefix)) { return `storage:${value.canonical.slice(prefix.length)}`; }
	}
	if (value.canonical.startsWith('ret:')) { return value.canonical; }
	return value.canonical.startsWith('imm:') ? value.canonical : undefined;
}

interface StorageRegion {
	base: string;
	offset: number;
	byteLength: number;
}

interface ValuePreservationBarrier {
	address: number;
	reason: string;
}

function parseInteger(text: string): number | undefined {
	const normalized = text.trim().toLowerCase();
	if (!/^[+-]?(?:0x[0-9a-f]+|\d+)$/.test(normalized)) { return undefined; }
	const negative = normalized.startsWith('-');
	const unsigned = normalized.startsWith('-') || normalized.startsWith('+') ? normalized.slice(1) : normalized;
	const value = unsigned.startsWith('0x') ? parseInt(unsigned, 16) : parseInt(unsigned, 10);
	return negative ? -value : value;
}

function parseStorageRegion(identity: string, byteLength = 1): StorageRegion | undefined {
	const storage = identity.startsWith('storage:') ? identity.slice('storage:'.length) : identity;
	const match = /^\[([a-z][a-z0-9]*)([+-](?:0x[0-9a-f]+|\d+))?\]$/i.exec(storage);
	if (!match) { return undefined; }
	const offset = match[2] ? parseInteger(match[2]) : 0;
	if (offset === undefined) { return undefined; }
	return { base: normalizeRegister(match[1]), offset, byteLength: Math.max(1, byteLength) };
}

function pathBufferByteLength(producer: CallsiteValueSummary): number {
	const length = findArgument(producer, 'bufferLength')?.value.canonical;
	const count = length?.startsWith('imm:') ? parseInt(length.slice('imm:'.length), 10) : NaN;
	if (Number.isFinite(count) && count > 0) {
		const width = /W$/i.test(producer.api) ? 2 : 1;
		return Math.min(count * width, 1024 * 1024);
	}
	if (/!(?:GetTempFileNameW|SHGetFolderPathW)$/i.test(producer.api)) { return 260 * 2; }
	return 1;
}

function regionsOverlap(left: StorageRegion, right: StorageRegion): boolean {
	if (left.base !== right.base) { return false; }
	return left.offset < right.offset + right.byteLength && right.offset < left.offset + left.byteLength;
}

function expressionRegion(value: ResolvedValueExpression): StorageRegion | undefined {
	const identity = storageIdentity(value);
	return identity ? parseStorageRegion(identity) : undefined;
}

function callName(
	instruction: Instruction,
	callApis: Map<number, string>,
	functionNames: Map<number, string>,
): string {
	const known = callApis.get(instruction.address);
	if (known) { return known; }
	const commentApi = /([A-Za-z0-9_.-]+![A-Za-z0-9_@$?]+)/.exec(instruction.comment ?? '')?.[1];
	if (commentApi) { return commentApi; }
	if (instruction.targetAddress !== undefined) {
		return functionNames.get(Number(instruction.targetAddress)) ?? `sub_${Number(instruction.targetAddress).toString(16).toUpperCase()}`;
	}
	return `call@${toHex(instruction.address)}`;
}

function isSummarizedReadOnlyPointer(callee: string, argumentIndex: number): boolean {
	const summary = READ_ONLY_POINTER_ARGUMENTS.find(entry => entry.pattern.test(callee));
	return summary?.indexes.has(argumentIndex) === true;
}

function operandWriteWidth(operand: string, mnemonic: string): number {
	const width = /\b(byte|word|dword|qword|xmmword|ymmword|zmmword)\s+ptr\b/i.exec(operand)?.[1]?.toLowerCase();
	const widths: Record<string, number> = { byte: 1, word: 2, dword: 4, qword: 8, xmmword: 16, ymmword: 32, zmmword: 64 };
	if (width) { return widths[width]; }
	const suffix = /(?:stos|movs)([bwdq])$/i.exec(mnemonic)?.[1]?.toLowerCase();
	return suffix ? ({ b: 1, w: 2, d: 4, q: 8 } as Record<string, number>)[suffix] : 1;
}

function resolveWriteRegion(
	fn: DisassembledFunction,
	instructionIndex: number,
	operand: string,
	byteLength: number,
	callApis: Map<number, string>,
): StorageRegion | undefined {
	const storage = normalizeStorage(operand);
	if (!storage) { return undefined; }
	const direct = parseStorageRegion(`storage:${storage}`, byteLength);
	if (!direct) { return undefined; }
	if (['rsp', 'rbp'].includes(direct.base)) { return direct; }
	const baseValue = resolveRegister(fn, instructionIndex, direct.base, callApis);
	const baseRegion = expressionRegion(baseValue);
	return baseRegion ? { base: baseRegion.base, offset: baseRegion.offset + direct.offset, byteLength } : undefined;
}

function directWriteBarrier(
	fn: DisassembledFunction,
	instructionIndex: number,
	tracked: StorageRegion,
	identity: string,
	callApis: Map<number, string>,
): ValuePreservationBarrier | undefined {
	const instruction = fn.instructions[instructionIndex];
	const mnemonic = instruction.mnemonic.toLowerCase().replace(/^rep(?:e|ne)?\s+/, '');
	if (/^(?:stos|movs)[bwdq]$/.test(mnemonic)) {
		const destination = resolveRegister(fn, instructionIndex, 'rdi', callApis);
		const region = expressionRegion(destination);
		if (!region) {
			return { address: instruction.address, reason: `Implicit memory write at ${toHex(instruction.address)} has an unresolved destination; ${identity} preservation is unproven.` };
		}
		const write = { ...region, byteLength: operandWriteWidth('', mnemonic) };
		return regionsOverlap(tracked, write)
			? { address: instruction.address, reason: `Implicit memory write at ${toHex(instruction.address)} may overlap ${identity}; stored-value preservation is unproven.` }
			: undefined;
	}
	if (!/^(?:mov|xchg|add|sub|adc|sbb|and|or|xor|inc|dec|not|neg|shl|shr|sar|rol|ror)$/.test(mnemonic)) {
		return undefined;
	}
	const operands = splitOperands(instruction.opStr);
	if (!operands || !normalizeStorage(operands[0])) { return undefined; }
	const width = operandWriteWidth(operands[0], mnemonic);
	const write = resolveWriteRegion(fn, instructionIndex, operands[0], width, callApis);
	if (!write) {
		return { address: instruction.address, reason: `Memory write at ${toHex(instruction.address)} has an unresolved effective address; ${identity} preservation is unproven.` };
	}
	return regionsOverlap(tracked, write)
		? { address: instruction.address, reason: `Direct write at ${toHex(instruction.address)} may overlap ${identity}; stored-value preservation is unproven.` }
		: undefined;
}

function findPathPreservationBarrier(
	fn: DisassembledFunction,
	producer: CallsiteValueSummary,
	consumer: CallsiteValueSummary,
	identity: string,
	callApis: Map<number, string>,
	functionNames: Map<number, string>,
): ValuePreservationBarrier | undefined {
	const producerAddress = parseInt(producer.callSite.slice(2), 16);
	const consumerAddress = parseInt(consumer.callSite.slice(2), 16);
	const producerIndex = fn.instructions.findIndex(instruction => instruction.address === producerAddress);
	const consumerIndex = fn.instructions.findIndex(instruction => instruction.address === consumerAddress);
	if (producerIndex < 0 || consumerIndex < 0 || producerIndex === consumerIndex) { return undefined; }
	const tracked = parseStorageRegion(identity, pathBufferByteLength(producer));
	if (!tracked) {
		return {
			address: producerAddress,
			reason: `Stored-value preservation is unavailable for non-simple storage ${identity}.`,
		};
	}

	const successors = buildInstructionSuccessors(fn);
	const forward = reachableInstructionIndexes(producerIndex, successors);
	const predecessors = reverseInstructionEdges(successors, fn.instructions.length);
	const toConsumer = reachableInstructionIndexes(consumerIndex, predecessors);
	const barrierIndexes = [...forward]
		.filter(index => toConsumer.has(index) && index !== producerIndex && index !== consumerIndex)
		.sort((left, right) => left - right);
	for (const index of barrierIndexes) {
		const instruction = fn.instructions[index];
		const writeBarrier = directWriteBarrier(fn, index, tracked, identity, callApis);
		if (writeBarrier) { return writeBarrier; }
		if (!instruction.isCall) { continue; }

		const callee = callName(instruction, callApis, functionNames);
		for (let argumentIndex = 0; argumentIndex < 8; argumentIndex++) {
			const value = argumentIndex < ARG_REGISTERS.length
				? resolveRegister(fn, index, ARG_REGISTERS[argumentIndex], callApis)
				: resolveStackArgument(fn, index, 0x20 + (argumentIndex - 4) * 8, callApis);
			const argumentRegion = expressionRegion(value);
			if (!argumentRegion || !regionsOverlap(tracked, argumentRegion)) { continue; }
			if (isSummarizedReadOnlyPointer(callee, argumentIndex)) { continue; }
			return {
				address: instruction.address,
				reason: `Storage address escapes through argument ${argumentIndex + 1} to ${callee}@${toHex(instruction.address)} without a read-only summary; stored-value preservation is unproven.`,
			};
		}
	}
	return undefined;
}

function findArgument(summary: CallsiteValueSummary, name: string): CallArgumentBinding | undefined {
	return summary.arguments.find(argument => argument.name === name);
}

function buildInstructionSuccessors(fn: DisassembledFunction): Map<number, number[]> {
	const indexByAddress = new Map(fn.instructions.map((instruction, index) => [Number(instruction.address), index]));
	const successors = new Map<number, number[]>();
	for (let index = 0; index < fn.instructions.length; index++) {
		const instruction = fn.instructions[index];
		const edges: number[] = [];
		const next = index + 1 < fn.instructions.length ? index + 1 : undefined;
		if (!instruction.isRet && instruction.isJump) {
			const target = instruction.targetAddress === undefined ? undefined : indexByAddress.get(Number(instruction.targetAddress));
			if (target !== undefined) { edges.push(target); }
			if (instruction.isConditional && next !== undefined) { edges.push(next); }
		} else if (!instruction.isRet && next !== undefined) {
			edges.push(next);
		}
		successors.set(index, [...new Set(edges)]);
	}
	return successors;
}

function reverseInstructionEdges(edges: Map<number, number[]>, nodeCount: number): Map<number, number[]> {
	const reversed = new Map<number, number[]>(Array.from({ length: nodeCount }, (_, index) => [index, []]));
	for (const [source, targets] of edges) {
		for (const target of targets) {
			reversed.get(target)!.push(source);
		}
	}
	return reversed;
}

function reachableInstructionIndexes(start: number, edges: Map<number, number[]>): Set<number> {
	const pending = [start];
	const visited = new Set<number>();
	while (pending.length > 0) {
		const index = pending.pop()!;
		if (visited.has(index)) { continue; }
		visited.add(index);
		pending.push(...(edges.get(index) ?? []));
	}
	return visited;
}

function producerDominatesConsumer(fn: DisassembledFunction, producerAddress: number, consumerAddress: number): boolean {
	const indexByAddress = new Map(fn.instructions.map((instruction, index) => [Number(instruction.address), index]));
	const producerIndex = indexByAddress.get(producerAddress);
	const consumerIndex = indexByAddress.get(consumerAddress);
	if (producerIndex === undefined || consumerIndex === undefined || producerIndex === consumerIndex || fn.instructions.length === 0) { return false; }
	const successors = buildInstructionSuccessors(fn);
	const reachableFromEntry = reachableInstructionIndexes(0, successors);
	if (!reachableFromEntry.has(producerIndex) || !reachableFromEntry.has(consumerIndex)) { return false; }
	const predecessors = reverseInstructionEdges(successors, fn.instructions.length);
	const allReachable = new Set(reachableFromEntry);
	const dominators = new Map<number, Set<number>>();
	for (const node of reachableFromEntry) {
		dominators.set(node, node === 0 ? new Set([0]) : new Set(allReachable));
	}
	let changed = true;
	while (changed) {
		changed = false;
		for (const node of reachableFromEntry) {
			if (node === 0) { continue; }
			const incoming = (predecessors.get(node) ?? []).filter(predecessor => reachableFromEntry.has(predecessor));
			const intersection = incoming.length === 0
				? new Set<number>()
				: new Set([...dominators.get(incoming[0])!].filter(candidate =>
					incoming.slice(1).every(predecessor => dominators.get(predecessor)!.has(candidate))));
			intersection.add(node);
			const previous = dominators.get(node)!;
			if (previous.size !== intersection.size || [...previous].some(candidate => !intersection.has(candidate))) {
				dominators.set(node, intersection);
				changed = true;
			}
		}
	}
	return dominators.get(consumerIndex)?.has(producerIndex) === true;
}

export function analyzeWindowsValueDataflow(
	functions: readonly DisassembledFunction[],
	seeds: readonly ValueFlowFactSeed[],
	architecture = 'x64',
): DeepWindowsValueDataflow {
	if (architecture !== 'x64') {
		return {
			status: 'not-assessed', architecture, callsites: [], proofs: [], signals: [],
			limitations: ['Deep value identity is currently implemented only for the Win64 calling convention.'],
		};
	}
	const functionByAddress = new Map(functions.map(fn => [toHex(fn.address).toLowerCase(), fn]));
	const functionNames = new Map(functions.map(fn => [fn.address, fn.name || `sub_${fn.address.toString(16).toUpperCase()}`]));
	const callApis = apiAtCallSite(seeds);
	const callsites: CallsiteValueSummary[] = [];
	for (const seed of seeds) {
		if (!seed.callSite) { continue; }
		const fn = functionByAddress.get(seed.functionAddress.toLowerCase());
		if (!fn) { continue; }
		const callAddress = parseInt(seed.callSite.slice(2), 16);
		const callIndex = fn.instructions.findIndex(instruction => instruction.address === callAddress);
		if (callIndex < 0) { continue; }
		const args = argumentSpec(seed.api);
		const bindings = args.map((argument, index) => {
			const location = index < 4 ? ARG_REGISTERS[index] : `[rsp+0x${(0x20 + (index - 4) * 8).toString(16)}]`;
			const value = index < 4
				? resolveRegister(fn, callIndex, location, callApis)
				: resolveStackArgument(fn, callIndex, 0x20 + (index - 4) * 8, callApis);
			return { index, name: argument.name, location, value };
		});
		callsites.push({
			functionAddress: seed.functionAddress,
			functionName: seed.functionName,
			api: seed.api,
			callSite: seed.callSite,
			arguments: bindings,
			returnBindings: captureReturnBindings(fn, callIndex, seed.api),
		});
	}

	const proofs: ValueIdentityProof[] = [];
	const signals: ValueIdentitySignal[] = [];
	const byFunction = new Map<string, CallsiteValueSummary[]>();
	for (const summary of callsites) {
		const list = byFunction.get(summary.functionAddress) ?? [];
		list.push(summary);
		byFunction.set(summary.functionAddress, list);
	}
	const addProof = (
		kind: ValueIdentityProof['kind'],
		producer: CallsiteValueSummary,
		producerValue: ResolvedValueExpression | undefined,
		consumer: CallsiteValueSummary,
		consumerArgument: CallArgumentBinding | undefined,
		producerArgument?: string,
	): void => {
		if (!producerValue || !consumerArgument) { return; }
		const left = storageIdentity(producerValue);
		const right = storageIdentity(consumerArgument.value);
		if (!left || left !== right) { return; }
		const key = `${kind}:${producer.callSite}:${consumer.callSite}:${left}`;
		if (proofs.some(proof => `${proof.kind}:${proof.producer.callSite}:${proof.consumer.callSite}:${proof.canonicalIdentity}` === key)) { return; }
		const addSignal = (blocker: string, barrierAddress?: number): void => {
			if (signals.some(signal => `${signal.kind}:${signal.producer.callSite}:${signal.consumer.callSite}:${signal.canonicalIdentity}` === key)) { return; }
			signals.push({
				kind,
				status: 'signal',
				canonicalIdentity: left,
				producer: { api: producer.api, callSite: producer.callSite, ...(producerArgument ? { argument: producerArgument } : {}) },
				consumer: { api: consumer.api, callSite: consumer.callSite, argument: consumerArgument.name },
				functionAddress: producer.functionAddress,
				evidence: [...producerValue.definitions, ...(barrierAddress !== undefined ? [toHex(barrierAddress)] : []), ...consumerArgument.value.definitions],
				blockers: [blocker],
			});
		};
		const fn = functionByAddress.get(producer.functionAddress.toLowerCase());
		const producerAddress = parseInt(producer.callSite.slice(2), 16);
		const consumerAddress = parseInt(consumer.callSite.slice(2), 16);
		if (!fn || !producerDominatesConsumer(fn, producerAddress, consumerAddress)) {
			addSignal('Producer does not dominate the consumer on every feasible intra-function control-flow path.');
			return;
		}
		if (kind === 'same-path') {
			const barrier = findPathPreservationBarrier(fn, producer, consumer, left, callApis, functionNames);
			if (barrier) {
				addSignal(barrier.reason, barrier.address);
				return;
			}
		}
		proofs.push({
			kind,
			status: 'proven',
			canonicalIdentity: left,
			producer: { api: producer.api, callSite: producer.callSite, ...(producerArgument ? { argument: producerArgument } : {}) },
			consumer: { api: consumer.api, callSite: consumer.callSite, argument: consumerArgument.name },
			functionAddress: producer.functionAddress,
			evidence: [...producerValue.definitions, ...consumerArgument.value.definitions],
		});
	};

	for (const summaries of byFunction.values()) {
		const opens = summaries.filter(summary => /!(?:CreateFile(?:A|W)?|fopen|_wfopen)$/i.test(summary.api));
		const handleConsumers = summaries.filter(summary => /!(?:WriteFile(?:Ex)?|CloseHandle|GetFinalPathNameByHandleW|SetFileInformationByHandle)$/i.test(summary.api));
		for (const producer of opens) {
			for (const binding of producer.returnBindings) {
				for (const consumer of handleConsumers) {
					if (parseInt(consumer.callSite.slice(2), 16) <= parseInt(producer.callSite.slice(2), 16)) { continue; }
					addProof('same-handle', producer, binding, consumer, findArgument(consumer, 'handle'));
				}
			}
		}

		const aclInitializers = summaries.filter(summary => /!InitializeAcl$/i.test(summary.api));
		const aceWriters = summaries.filter(summary => /!AddAccess(?:Allowed|Denied)Ace$/i.test(summary.api));
		for (const initializer of aclInitializers) {
			for (const writer of aceWriters) {
				addProof('same-acl', initializer, findArgument(initializer, 'acl')?.value, writer, findArgument(writer, 'acl'), 'acl');
			}
		}

		const sidProducers = summaries.filter(summary => /!(?:AllocateAndInitializeSid|CreateWellKnownSid)$/i.test(summary.api));
		for (const producer of sidProducers) {
			const output = findArgument(producer, 'sidOut');
			for (const writer of aceWriters) {
				addProof('same-sid', producer, output?.value, writer, findArgument(writer, 'sid'), 'sidOut');
			}
		}

		const pathProducers = summaries.filter(summary => /!(?:GetTempPathW|GetTempFileNameW|GetFullPathNameW|SHGetFolderPathW)$/i.test(summary.api));
		for (const producer of pathProducers) {
			const output = producer.arguments.find(argument => /pathOut|fileNameOut/.test(argument.name));
			for (const consumer of opens) {
				addProof('same-path', producer, output?.value, consumer, findArgument(consumer, 'path'), output?.name);
			}
		}
	}

	return {
		status: 'assessed',
		architecture,
		callsites,
		proofs,
		signals,
		limitations: [
			'Proofs are intra-function and require exact canonical storage/return identity.',
			'Path value proofs are invalidated by overlapping direct writes or pointer escape to calls without a read-only argument summary.',
			'Unknown calls terminate volatile-register slices; memory aliasing beyond bounded stack-region overlap is not inferred.',
			'Interprocedural and heap/object-field identity remains unproven.',
		],
	};
}
