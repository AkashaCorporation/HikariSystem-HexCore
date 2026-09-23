/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
// Test-only executable. The production launcher never accepts a worker path or this mode.
if (process.env.HEXCORE_READONLY_NATIVE_TEST === '1') {
	process.once('message', (message: any) => {
		const mode = process.argv[2];
		if (mode === 'crash') { process.exit(17); }
		if (mode === 'wrong-id') { process.send?.({ requestSha256: 'wrong' }); return; }
		process.send?.({ requestSha256: message.requestSha256, phase: 'lifting' });
		if (mode === 'hang') { while (true) { /* Deliberate blocked worker for the external watchdog test. */ } }
		if (mode === 'error') {
			process.send?.({ requestSha256: message.requestSha256, result: {
				status: 'error', success: false, requestSha256: message.requestSha256, contextSha256: message.request.context.contextSha256,
				phase: 'terminal', architecture: message.request.architecture, source: '', hastBase64: '', qualityIssues: ['fixture'], semanticEligible: false, error: 'fixture',
			} });
		}
	});
}
