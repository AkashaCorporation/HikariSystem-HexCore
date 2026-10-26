/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
export const STEP_ID_PATTERN = /^[A-Za-z][A-Za-z0-9_-]{0,63}$/;

export interface StepIdentityIssue {
	level: 'error';
	code: 'STEP_ID_INVALID' | 'STEP_ID_DUPLICATE';
	message: string;
	stepIndex: number;
}

export function inspectStepIdentities(steps: readonly unknown[]): { ids: ReadonlyMap<string, number>; issues: StepIdentityIssue[] } {
	const ids = new Map<string, number>();
	const issues: StepIdentityIssue[] = [];
	steps.forEach((step, index) => {
		if (!step || typeof step !== 'object' || !('id' in step) || step.id === undefined) { return; }
		const id = step.id;
		if (typeof id !== 'string' || !STEP_ID_PATTERN.test(id) || id === 'prev') {
			issues.push({ level: 'error', code: 'STEP_ID_INVALID', stepIndex: index + 1,
				message: `Step ${index + 1} id must match [A-Za-z][A-Za-z0-9_-]{0,63}; 'prev' is reserved` });
		} else if (ids.has(id)) {
			issues.push({ level: 'error', code: 'STEP_ID_DUPLICATE', stepIndex: index + 1,
				message: `Duplicate step id '${id}' at steps ${ids.get(id)! + 1} and ${index + 1}` });
		} else { ids.set(id, index); }
	});
	return { ids, issues };
}

export function isNamedStepToken(token: string): boolean {
	return token !== 'prev' && STEP_ID_PATTERN.test(token);
}

export function resolveStepToken(token: string, currentIndex: number, ids?: ReadonlyMap<string, number>): number {
	if (token === 'prev') { return currentIndex - 1; }
	if (/^\d+$/.test(token)) {
		const index = Number(token);
		if (Number.isSafeInteger(index)) { return index; }
	}
	if (isNamedStepToken(token) && ids?.has(token)) { return ids.get(token)!; }
	throw new Error(`Unknown or invalid step reference '${token}'`);
}

export function resolveGotoTarget(value: string | number | undefined, totalSteps: number, ids?: ReadonlyMap<string, number>): number {
	if (typeof value !== 'string' && typeof value !== 'number') { throw new Error('onResult goto target must be an integer index or step ID'); }
	const target = typeof value === 'string' && ids?.has(value) ? ids.get(value)! : Number(value);
	if (!Number.isSafeInteger(target) || target < 0 || target >= totalSteps) {
		throw new Error(`onResult goto target ${JSON.stringify(value)} must be an integer step index in [0, ${totalSteps - 1}] or a declared step ID`);
	}
	return target;
}

/** Capture malformed names too, so they cannot silently remain literal text. */
export function stepReferencePattern(): RegExp {
	return /\$step\[(?<token>[^\]\r\n]*)\]\.(?<accessor>output|result\.[a-zA-Z0-9_]+(?:\.[a-zA-Z0-9_]+)*)/g;
}
