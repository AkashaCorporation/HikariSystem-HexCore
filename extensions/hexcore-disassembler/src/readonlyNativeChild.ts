/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import { RemillWrapper } from './remillWrapper';
import { HelixWrapper } from './helixWrapper';
import { assessLiftSemanticCoverage } from './liftSemanticCoverage';
import { inspectHelixIrInput } from './helixIrInputContract';
import { inspectHelixOutputQuality } from './helixOutputQuality';
import { renameLiftedEntry, resolveLiftExternalSymbols } from './liftExternalSymbols';
import { nativeBytesSha256, nativeRequestSha256, validateNativeFunctionIdentity, validateReadonlyNativeRequest, nativeError, type ReadonlyNativeRequest, type ReadonlyNativeResult } from './readonlyNativeProtocol';

process.once('message', async (message: { request: ReadonlyNativeRequest; requestSha256: string }) => {
	const { request, requestSha256 } = message;
	let remill: RemillWrapper | undefined;
	let helix: HelixWrapper | undefined;
	const phase = (value: ReadonlyNativeResult['phase']) => { process.send?.({ requestSha256, phase: value }); };
	let result: ReadonlyNativeResult;
	try {
		validateReadonlyNativeRequest(request);
		if (nativeRequestSha256(request) !== requestSha256) { throw new Error('native-query: request digest mismatch'); }
		phase('initializing');
		const issues = [...request.preparationIssues];
		let ir: string;
		if (request.input.kind === 'bytes') {
			remill = new RemillWrapper();
			if (!remill.isAvailable()) { throw new Error(remill.getLastError() ?? 'Remill unavailable'); }
			remill.setExternalSymbols(new Map(request.externalSymbols.map(symbol => [symbol.address, symbol.name])));
			phase('lifting');
			const lifted = await remill.liftBytes(Buffer.from(request.input.bytesBase64, 'base64'), request.input.address, request.architecture, request.targetOs, request.input.options);
			if (!lifted.success || !lifted.ir) { throw new Error(lifted.error || 'Remill returned no IR'); }
			const resolved = resolveLiftExternalSymbols(lifted.ir, new Map(request.externalSymbols.map(symbol => [symbol.address, symbol.name])), lifted.callTargets);
			ir = resolved.ir;
			issues.push(...resolved.issues);
			const encodedName = `lifted_${request.input.address}`;
			if (request.context.function.name !== encodedName) { ir = renameLiftedEntry(ir, request.input.address, request.context.function.name); }
			const assessment = assessLiftSemanticCoverage(ir, lifted);
			if (assessment.status !== 'ok') { issues.push(assessment.reason ?? 'partial lift'); }
			if (!Number.isSafeInteger(lifted.decodedInstructions) || Number(lifted.decodedInstructions) < 1) { issues.push('lift semantic metrics unavailable'); }
			if (lifted.truncated) { issues.push(`native lift truncated: ${lifted.truncationReason ?? 'unspecified'}`); }
			if (lifted.bytesConsumed !== Buffer.from(request.input.bytesBase64, 'base64').length) { issues.push('lift byte coverage is not complete'); }
		} else { ir = request.input.text; }
		const contract = inspectHelixIrInput(ir, request.architecture, request.architecture);
		issues.push(...contract.reasons);
		if (!/@__remill_|%struct\.State\b|%State\b/.test(ir)) { throw new Error('native-query: expected Remill-compatible IR'); }
		if (Buffer.byteLength(ir) > 32 * 1024 * 1024) { throw new Error('native-query: lifted IR budget exceeded'); }
		phase('decompiling');
		helix = new HelixWrapper();
		if (!helix.isAvailable()) { throw new Error('Helix unavailable'); }
		const decompiled = await helix.decompileIr(ir, request.architecture, {
			forceSync: true, useCastLayer: true, semanticContext: request.context,
			functionName: request.context.function.name,
			functionStarts: request.context.analysis.functionStartsAuthoritative ? [...request.context.functionStarts] : undefined,
			dataSections: request.dataSections.map(section => ({ vaStart: BigInt(section.address), bytes: Buffer.from(section.bytesBase64, 'base64') })),
		});
		if (!decompiled.success || !decompiled.astBuffer?.length) { throw new Error(decompiled.error || 'Helix returned no HAST'); }
		validateNativeFunctionIdentity(request.context, decompiled);
		const quality = inspectHelixOutputQuality(decompiled.source);
		if (quality.status !== 'ok') { issues.push(quality.reason ?? 'partial Helix output'); }
		if (request.context.abi.platform === 'unknown') { issues.push('raw target ABI not assessed'); }
		result = { status: issues.length ? 'partial' : 'ok', success: true, requestSha256, contextSha256: request.context.contextSha256,
			phase: 'terminal', architecture: request.architecture, source: decompiled.source, hastBase64: decompiled.astBuffer.toString('base64'),
			irSha256: nativeBytesSha256(ir), hastSha256: nativeBytesSha256(decompiled.astBuffer), qualityIssues: [...new Set(issues)], semanticEligible: issues.length === 0 };
		if (Buffer.byteLength(JSON.stringify(result)) > request.maxOutputBytes) { throw new Error('native-query: result byte budget exceeded'); }
	} catch (error) {
		result = nativeError(request, requestSha256, error instanceof Error ? error.message : String(error));
	} finally { remill?.dispose(); helix?.dispose(); }
	process.send?.({ requestSha256, result }, () => { process.disconnect?.(); });
});
