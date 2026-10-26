import * as crypto from 'crypto';

export interface SouperOutcomeStats {
	candidatesFound: number;
	candidatesAttempted: number;
	candidatesInferred: number;
	candidatesReplaced: number;
	solverTimeouts: number;
}

export interface SouperOutcome {
	status: 'optimized' | 'no-op' | 'partial';
	semanticChanged: boolean;
	textChanged: boolean;
	inputSha256: string;
	nativeOutputSha256: string;
	partialReasons: string[];
	noOpReason?: 'no-candidates' | 'no-replacements';
}

function sha256(value: string): string {
	return crypto.createHash('sha256').update(value, 'utf8').digest('hex');
}

export function classifySouperOutcome(
	inputIr: string,
	nativeOutputIr: string,
	stats: SouperOutcomeStats,
): SouperOutcome {
	const partialReasons: string[] = [];
	if (stats.solverTimeouts > 0) {
		partialReasons.push(`${stats.solverTimeouts} solver candidate(s) timed out`);
	}
	if (stats.candidatesAttempted < stats.candidatesFound) {
		partialReasons.push(
			`candidate budget evaluated ${stats.candidatesAttempted}/${stats.candidatesFound}`,
		);
	}
	const semanticChanged = stats.candidatesReplaced > 0;
	const status = partialReasons.length > 0
		? 'partial' as const
		: semanticChanged ? 'optimized' as const : 'no-op' as const;
	return {
		status,
		semanticChanged,
		textChanged: inputIr !== nativeOutputIr,
		inputSha256: sha256(inputIr),
		nativeOutputSha256: sha256(nativeOutputIr),
		partialReasons,
		...(!semanticChanged ? {
			noOpReason: stats.candidatesFound === 0 ? 'no-candidates' as const : 'no-replacements' as const,
		} : {}),
	};
}

export function stampSouperOutcome(
	nativeOutputIr: string,
	outcome: SouperOutcome,
	stats: SouperOutcomeStats,
): string {
	const header = [
		'; HexCore-Souper:',
		`status=${outcome.status}`,
		`semanticChanged=${outcome.semanticChanged}`,
		`textChanged=${outcome.textChanged}`,
		`candidates=${stats.candidatesAttempted}/${stats.candidatesFound}`,
		`inferred=${stats.candidatesInferred}`,
		`replaced=${stats.candidatesReplaced}`,
		`timeouts=${stats.solverTimeouts}`,
		`inputSha256=${outcome.inputSha256}`,
		`nativeOutputSha256=${outcome.nativeOutputSha256}`,
	].join(' ');
	const withoutPriorHeader = nativeOutputIr.replace(/^; HexCore-Souper:.*(?:\r?\n)?/m, '');
	return `${header}\n${withoutPriorHeader}`;
}
