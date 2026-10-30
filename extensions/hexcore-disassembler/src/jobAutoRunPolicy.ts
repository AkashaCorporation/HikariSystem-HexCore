/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import * as fs from 'fs';

export interface JobAutoRunPolicy {
	autoRun: boolean;
	authority: 'job-file' | 'default' | 'unreadable';
	reason: string;
}

/** Reads only the watcher policy. Full job validation remains the runner's job. */
export function inspectJobAutoRunPolicyText(text: string): JobAutoRunPolicy {
	try {
		const parsed = JSON.parse(text) as unknown;
		if (typeof parsed === 'object' && parsed !== null && !Array.isArray(parsed)) {
			const value = (parsed as Record<string, unknown>).autoRun;
			if (value === false) {
				return { autoRun: false, authority: 'job-file', reason: 'autoRun:false' };
			}
			if (value === true) {
				return { autoRun: true, authority: 'job-file', reason: 'autoRun:true' };
			}
		}
		return { autoRun: true, authority: 'default', reason: 'autoRun omitted or invalid; runner validation remains authoritative' };
	} catch {
		return { autoRun: true, authority: 'unreadable', reason: 'job JSON unreadable; allow runner preflight to report the error' };
	}
}

export function readJobAutoRunPolicy(filePath: string): JobAutoRunPolicy {
	try {
		return inspectJobAutoRunPolicyText(fs.readFileSync(filePath, 'utf8'));
	} catch {
		return { autoRun: true, authority: 'unreadable', reason: 'job file unreadable; allow runner preflight to report the error' };
	}
}
