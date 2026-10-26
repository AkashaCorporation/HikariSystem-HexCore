/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import type { DisassemblerEngine } from './disassemblerEngine';
import type { ReadOnlyHelixCapture } from './readOnlyHelixCapture';
import { nativeBytesSha256, validateReadonlyNativeRequest, type ReadonlyNativeRequest } from './readonlyNativeProtocol';
import { prepareLiftRelocations } from './liftRelocationPreparation';
import { planLiftPreamble } from './liftPreamble';

/** Build a transport descriptor from accepted memory, never a path the child can reopen. */
export function prepareReadonlyNativeRequest(engine: DisassemblerEngine, capture: ReadOnlyHelixCapture, options: { irText?: string; irAncestry?: ReadonlyNativeRequest['irAncestry']; targetOs?: 'windows' | 'linux'; maxDataBytes?: number; maxOutputBytes?: number } = {}): ReadonlyNativeRequest {
	capture.assertCurrent(engine);
	const maxDataBytes = options.maxDataBytes ?? 16 * 1024 * 1024;
	if (!Number.isSafeInteger(maxDataBytes) || maxDataBytes < 0 || maxDataBytes > 64 * 1024 * 1024) { throw new Error('native-query: invalid data budget'); }
	const targetOs = options.targetOs ?? (capture.context.abi.platform === 'windows' ? 'windows' : 'linux');
	const relocatable = engine.getFileInfo()?.isRelocatable === true;
	const originalBytes = options.irText === undefined ? capture.copyBytes() : undefined;
	const preamble = originalBytes ? planLiftPreamble(originalBytes, capture.address, relocatable, {
		architecture: engine.getArchitecture(), textSectionAddress: engine.getSections().find(section => section.name === '.text')?.virtualAddress,
		textRelocations: engine.getTextRelocations(),
	}) : undefined;
	const relocationPreparation = options.irText === undefined ? prepareLiftRelocations({
		bytes: originalBytes!, startAddress: capture.address, architecture: engine.getArchitecture(), relocatable,
		textSectionAddress: engine.getSections().find(section => section.name === '.text')?.virtualAddress,
		textRelocations: engine.getTextRelocations(), dataRelocations: engine.getDataRelocations(),
		readDataSection: name => engine.getSectionBytesByName(name), maxDataBytes,
	}) : undefined;
	const preparationIssues = [...(relocationPreparation?.issues ?? [])];
	if (options.irText === undefined) {
		const fn = engine.getFunctionAt(capture.address);
		if (!capture.context.analysis.complete || !capture.context.analysis.functionStartsAuthoritative) { preparationIssues.push('function-start table is not authoritative'); }
		if (preamble?.transformations.some(item => item.kind === 'ftrace-preamble')) { preparationIssues.push('ftrace entry is preserved but semantic parity is not qualified'); }
		if (fn?.instructions.some(instruction => (instruction.isCall || instruction.isJump) && !instruction.isRet && instruction.targetAddress === undefined)) { preparationIssues.push('indirect control-flow target requires Pathfinder parity'); }
		if (engine.detectCallfuscation().detected) { preparationIssues.push('callfuscation preparation requires Pathfinder parity'); }
	} else if (!options.irAncestry) { preparationIssues.push('prepared IR producer ancestry must be verified by command routing'); }
	const dataSections: ReadonlyNativeRequest['dataSections'] = [];
	let total = 0;
	for (const section of engine.getSections()) {
		if (relocatable && options.irText === undefined) { continue; }
		if (section.isCode || section.rawSize === 0) { continue; }
		if (section.rawSize < 0 || !Number.isSafeInteger(section.rawSize) || total + section.rawSize > maxDataBytes) { throw new Error('native-query: data capture budget exceeded'); }
		const bytes = engine.getBytes(section.virtualAddress, section.rawSize);
		if (!bytes || bytes.length !== section.rawSize) { throw new Error(`native-query: data section unavailable: ${section.name}`); }
		total += bytes.length;
		dataSections.push({ address: `0x${section.virtualAddress.toString(16)}`, bytesBase64: bytes.toString('base64') });
	}
	for (const section of relocationPreparation?.dataSections ?? []) { dataSections.push({ address: `0x${section.vaStart.toString(16)}`, bytesBase64: section.bytes.toString('base64') }); }
	const request: ReadonlyNativeRequest = {
		version: 1, context: capture.context, architecture: engine.getArchitecture(), targetOs,
		input: options.irText !== undefined ? { kind: 'ir', text: options.irText, irSha256: nativeBytesSha256(options.irText) }
			: { kind: 'bytes', bytesBase64: relocationPreparation!.bytes.toString('base64'), byteSha256: relocationPreparation!.preparedSha256, address: capture.address,
				options: { maxBytes: capture.endExclusive - capture.address, maxInstructions: 250000, maxBasicBlocks: 64000,
					liftMode: relocatable ? 'elf_relocatable' : /^PE/i.test(capture.context.target.format) ? 'pe64' : 'generic', knownFunctionEnds: [capture.endExclusive], entryAddress: capture.address, reachableOnly: true } },
		dataSections,
		externalSymbols: relocatable && relocationPreparation ? [...relocationPreparation.symbolMap].map(([address, name]) => ({ address, name }))
			: capture.context.imports.map(symbol => ({ address: Number.parseInt(symbol.address, 16), name: symbol.name })),
		preparationIssues,
		...(relocationPreparation ? { relocationPreparation: { sourceSha256: relocationPreparation.sourceSha256, preparedSha256: relocationPreparation.preparedSha256, patchCount: relocationPreparation.patches.length } } : {}),
		// Keep original entry coordinates; native semantic coverage decides whether these instructions are supported.
		...(preamble ? { entryPreparation: { policy: 'preserve' as const, sourceSha256: capture.byteSha256, observedSkipBytes: preamble.skipBytes, observedKinds: preamble.transformations.map(item => item.kind) } } : {}),
		...(options.irAncestry ? { irAncestry: { ...options.irAncestry } } : {}),
		maxOutputBytes: options.maxOutputBytes ?? 16 * 1024 * 1024,
	};
	capture.assertCurrent(engine);
	validateReadonlyNativeRequest(request);
	return request;
}
