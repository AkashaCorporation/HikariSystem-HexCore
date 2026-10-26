/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import * as crypto from 'crypto';
import { encodeX86PcRelativeDataDisplacement } from './elfTextRelocation';

export interface LiftRelocationInput {
	bytes: Buffer;
	startAddress: number;
	textSectionAddress?: number;
	relocatable: boolean;
	architecture: string;
	textRelocations: ReadonlyMap<number, { name: string; type: number; addend: number }>;
	dataRelocations: ReadonlyMap<number, { sectionName: string; type: number; addend: number }>;
	readDataSection(name: string): Buffer | undefined;
	maxDataBytes?: number;
}
export interface LiftRelocationPatch { offset: number; relocationAddress: number; kind: 'symbol' | 'data'; name: string; targetAddress: number; beforeHex: string; afterHex: string }
export interface LiftRelocationResult {
	bytes: Buffer;
	symbolMap: Map<number, string>;
	dataSections: Array<{ vaStart: number; bytes: Buffer }>;
	patches: LiftRelocationPatch[];
	issues: string[];
	sourceSha256: string;
	preparedSha256: string;
}
const infrastructure = new Set(['__fentry__', '__cfi_check', ...['rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15'].map(register => `__x86_indirect_thunk_${register}`)]);
const sha256 = (bytes: Buffer) => crypto.createHash('sha256').update(bytes).digest('hex');

/** Pure byte fixups. Synthetic symbol addresses do not prove a call/data semantic role. */
export function prepareLiftRelocations(input: LiftRelocationInput): LiftRelocationResult {
	if (!Buffer.isBuffer(input.bytes) || !Number.isSafeInteger(input.startAddress) || input.startAddress < 0) { throw new Error('Invalid lift relocation input'); }
	const maxDataBytes = input.maxDataBytes ?? 64 * 1024 * 1024;
	if (!Number.isSafeInteger(maxDataBytes) || maxDataBytes < 0 || maxDataBytes > 64 * 1024 * 1024) { throw new Error('Invalid relocation data budget'); }
	const result: LiftRelocationResult = { bytes: Buffer.from(input.bytes), symbolMap: new Map(), dataSections: [], patches: [], issues: [], sourceSha256: sha256(input.bytes), preparedSha256: '' };
	const finish = () => { result.issues = [...new Set(result.issues)].sort(); result.preparedSha256 = sha256(result.bytes); return result; };
	if (!input.relocatable) { return finish(); }
	if (input.architecture !== 'x64') { result.issues.push('ET_REL relocation preparation is not implemented for this architecture'); return finish(); }
	if (!Number.isSafeInteger(input.textSectionAddress) || Number(input.textSectionAddress) < 0) { result.issues.push('ET_REL .text address is unavailable'); return finish(); }
	const textAddress = input.textSectionAddress!;
	const windowOffset = input.startAddress - textAddress;
	const occupied = new Set<number>();
	const patchOffset = (offset: number): number | undefined => {
		if (!Number.isSafeInteger(offset) || offset < 0) { result.issues.push('Invalid relocation offset'); return undefined; }
		const at = offset - windowOffset;
		if (at < 0) { if (at + 4 > 0) { result.issues.push(`Relocation at ${offset} crosses the lift boundary`); } return undefined; }
		if (at >= result.bytes.length) { return undefined; }
		if (at + 4 > result.bytes.length) { result.issues.push(`Relocation at ${offset} crosses the lift boundary`); return undefined; }
		return at;
	};
	const patch = (at: number, relocationAddress: number, value: number, kind: 'symbol' | 'data', name: string, targetAddress: number): boolean => {
		if (!Number.isSafeInteger(value) || value < -0x80000000 || value > 0x7fffffff) { result.issues.push(`Relocation value out of signed 32-bit range: ${name}`); return false; }
		if ([0, 1, 2, 3].some(index => occupied.has(at + index))) { result.issues.push(`Overlapping relocation at ${relocationAddress}`); return false; }
		const beforeHex = result.bytes.subarray(at, at + 4).toString('hex');
		result.bytes.writeInt32LE(value, at);
		for (let index = 0; index < 4; index++) { occupied.add(at + index); }
		result.patches.push({ offset: at, relocationAddress, kind, name, targetAddress, beforeHex, afterHex: result.bytes.subarray(at, at + 4).toString('hex') });
		return true;
	};
	const symbolAddresses = new Map<string, number>();
	let nextSymbol = 0x7fff0000;
	for (const [offset, relocation] of input.textRelocations) {
		const at = patchOffset(offset); if (at === undefined) { continue; }
		if (infrastructure.has(relocation.name) && relocation.name !== '__fentry__') { result.issues.push(`Deferred infrastructure relocation: ${relocation.name}`); continue; }
		if (relocation.name === '__fentry__') { result.issues.push('Unqualified instrumentation semantics: __fentry__'); }
		if (![2, 4].includes(relocation.type) || !relocation.name || !Number.isSafeInteger(relocation.addend)) { result.issues.push(`Unsupported symbol relocation: ${relocation.name} (type ${relocation.type})`); continue; }
		let target = symbolAddresses.get(relocation.name);
		if (target === undefined) { target = nextSymbol; nextSymbol += 16; symbolAddresses.set(relocation.name, target); }
		if (target >= 0x80000000) { result.issues.push('Synthetic symbol address range exhausted'); continue; }
		const place = textAddress + offset;
		const displacement = target + relocation.addend - place;
		const resolved = place + 4 + displacement;
		if (result.symbolMap.has(resolved) && result.symbolMap.get(resolved) !== relocation.name) { result.issues.push(`Ambiguous synthetic symbol target: ${resolved}`); continue; }
		if (patch(at, place, displacement, 'symbol', relocation.name, resolved)) { result.symbolMap.set(resolved, relocation.name); }
	}
	const sections = new Map<string, { base: number; bytes: Buffer }>();
	let nextBase = 0x7f000000, dataBytes = 0;
	for (const [offset, relocation] of input.dataRelocations) {
		const at = patchOffset(offset); if (at === undefined) { continue; }
		if (!relocation.sectionName.startsWith('.rodata') || ![2, 10, 11].includes(relocation.type) || !Number.isSafeInteger(relocation.addend)) { result.issues.push(`Unsupported data relocation: ${relocation.sectionName} (type ${relocation.type})`); continue; }
		let section = sections.get(relocation.sectionName);
		if (!section) {
			const bytes = input.readDataSection(relocation.sectionName);
			if (!bytes?.length) { result.issues.push(`Relocation data section unavailable: ${relocation.sectionName}`); continue; }
			const span = Math.ceil(bytes.length / 0x100000) * 0x100000;
			if (dataBytes + bytes.length > maxDataBytes || nextBase + span > 0x7fff0000) { result.issues.push(`Relocation data budget/address range exceeded: ${relocation.sectionName}`); continue; }
			section = { base: nextBase, bytes: Buffer.from(bytes) }; nextBase += span; dataBytes += bytes.length;
			sections.set(relocation.sectionName, section);
		}
		const place = textAddress + offset;
		const target = section.base + relocation.addend;
		if (relocation.addend < 0 || relocation.addend > section.bytes.length) { result.issues.push(`Relocation addend outside data section: ${relocation.sectionName}`); continue; }
		if (relocation.type === 2 && (target - place - 4 < -0x80000000 || target - place - 4 > 0x7fffffff)) { result.issues.push(`PC-relative data displacement out of range: ${relocation.sectionName}`); continue; }
		const value = relocation.type === 2 ? encodeX86PcRelativeDataDisplacement(target, place) : target;
		patch(at, place, value, 'data', relocation.sectionName, target);
	}
	for (const section of sections.values()) { result.dataSections.push({ vaStart: section.base, bytes: section.bytes }); }
	return finish();
}
