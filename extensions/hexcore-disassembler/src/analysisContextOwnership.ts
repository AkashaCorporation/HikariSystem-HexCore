/*---------------------------------------------------------------------------------------------
 *  Copyright (c) HikariSystem. All rights reserved.
 *--------------------------------------------------------------------------------------------*/

import * as path from 'path';

export type AnalysisContextOwnership = 'matched' | 'mismatched' | 'unbound';

export interface AnalysisContextDecision {
	sourceTargetFile?: string;
	activeTargetFile?: string;
	ownership: AnalysisContextOwnership;
	activeEngineEvidenceUsed: boolean;
}

/**
 * Produces the stable identity used for target ownership checks. Windows paths
 * are case-insensitive even when Node preserves the caller's drive-letter case.
 */
export function analysisPathIdentity(filePath: string, platform: NodeJS.Platform = process.platform): string {
	const resolved = path.resolve(filePath);
	return platform === 'win32' ? resolved.toLowerCase() : resolved;
}

/**
 * Decides whether target-derived evidence from the active Disassembler engine
 * may be applied to an incoming IR artifact. Unbound IR is deliberately denied:
 * callers must name the target that produced it to inherit session state.
 */
export function decideAnalysisContextOwnership(
	sourceTargetFile: string | undefined,
	activeTargetFile: string | undefined,
	platform: NodeJS.Platform = process.platform,
): AnalysisContextDecision {
	if (!sourceTargetFile) {
		return {
			...(activeTargetFile ? { activeTargetFile: path.resolve(activeTargetFile) } : {}),
			ownership: 'unbound',
			activeEngineEvidenceUsed: false,
		};
	}

	const source = path.resolve(sourceTargetFile);
	const active = activeTargetFile ? path.resolve(activeTargetFile) : undefined;
	const matched = active !== undefined
		&& analysisPathIdentity(source, platform) === analysisPathIdentity(active, platform);
	return {
		sourceTargetFile: source,
		...(active ? { activeTargetFile: active } : {}),
		ownership: matched ? 'matched' : 'mismatched',
		activeEngineEvidenceUsed: matched,
	};
}
