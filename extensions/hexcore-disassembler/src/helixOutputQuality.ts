/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Akasha Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

export interface HelixOutputQuality {
	status: 'ok' | 'partial';
	confidence?: number;
	rating?: string;
	issues: string[];
	qualityIssues: HelixStructuredQualityIssue[];
	securityEvidenceUsable: boolean;
	reason?: string;
	confidenceAxes: {
		translation?: number;
		liftCoverage?: number;
		semanticType: null;
		semanticTypeStatus: 'not-assessed';
	};
}

export interface HelixStructuredQualityIssue {
	kind: 'placeholder-variable' | 'self-reference' | 'uninitialized-return' | 'duplicate-local' | 'damning-defect';
	severity: 'damning';
	count: number;
	detail: string;
}

function issueCount(issues: readonly string[], pattern: RegExp): number {
	for (const issue of issues) {
		const match = issue.match(pattern);
		if (match) { return Number(match[1]); }
	}
	return 0;
}

function findDuplicateLocals(source: string): string[] {
	const declarations = new Map<string, number>();
	const declarationPattern = /^\s*(?:struct\s+\w+\s*\*|void\s*\*|bool|u?int(?:8|16|32|64)_t|float|double|char\s*\*)\s+([A-Za-z_]\w*)\s*(?:=|;|\/\*)/gm;
	for (const match of source.matchAll(declarationPattern)) {
		const name = match[1];
		declarations.set(name, (declarations.get(name) ?? 0) + 1);
	}
	return [...declarations.entries()]
		.filter(([, count]) => count > 1)
		.map(([name]) => name)
		.sort();
}

export function stampHelixConfidenceAxes(source: string, axes: HelixOutputQuality['confidenceAxes']): string {
	const line = `// ConfidenceAxes: ${JSON.stringify(axes)}`;
	if (/^\/\/\s*ConfidenceAxes:/mi.test(source)) {
		return source.replace(/^\/\/\s*ConfidenceAxes:.*$/mi, line);
	}
	const liftDiag = /^\/\/\s*LiftDiag:.*$/mi;
	if (liftDiag.test(source)) {
		return source.replace(liftDiag, match => `${match}\n${line}`);
	}
	const confidence = /^\/\/\s*Confidence:.*$/mi;
	if (confidence.test(source)) {
		return source.replace(confidence, match => `${match}\n${line}`);
	}
	return `${line}\n${source}`;
}

/** Convert the honesty header emitted by Helix into pipeline semantics. */
export function inspectHelixOutputQuality(source: string): HelixOutputQuality {
	const confidenceMatch = source.match(/^\/\/\s*Confidence:\s*([0-9]+(?:\.[0-9]+)?)%\s*\(([^)]+)\)/mi);
	const confidence = confidenceMatch ? Number(confidenceMatch[1]) : undefined;
	const rating = confidenceMatch?.[2]?.trim();
	const issues = Array.from(source.matchAll(/^\/\/\s*Issues?:\s*(.+)$/gmi), match => match[1].trim());
	const liftCoverageMatch = source.match(/\bsemanticCoverage=([0-9]+(?:\.[0-9]+)?)%/i);
	const liftCoverage = liftCoverageMatch ? Number(liftCoverageMatch[1]) : undefined;
	const damning = issues.some(issue => /damning honesty defect/i.test(issue));
	const placeholderCount = issueCount(issues, /(\d+)\s+auto-declared placeholder variable/i);
	const selfReferenceCount = issueCount(issues, /(\d+)\s+suspicious self-referencing assignment/i);
	const uninitializedReturn = issues.some(issue => /uninitialized (?:return value|result)/i.test(issue));
	const duplicateLocals = findDuplicateLocals(source);
	const qualityIssues: HelixStructuredQualityIssue[] = [];
	if (placeholderCount > 0) {
		qualityIssues.push({ kind: 'placeholder-variable', severity: 'damning', count: placeholderCount, detail: `${placeholderCount} auto-declared placeholder variable(s)` });
	}
	if (selfReferenceCount > 0) {
		qualityIssues.push({ kind: 'self-reference', severity: 'damning', count: selfReferenceCount, detail: `${selfReferenceCount} suspicious self-referencing assignment(s)` });
	}
	if (uninitializedReturn) {
		qualityIssues.push({ kind: 'uninitialized-return', severity: 'damning', count: 1, detail: 'uninitialized return value' });
	}
	if (duplicateLocals.length > 0) {
		qualityIssues.push({ kind: 'duplicate-local', severity: 'damning', count: duplicateLocals.length, detail: `duplicate local definition(s): ${duplicateLocals.join(', ')}` });
	}
	if (damning && !uninitializedReturn) {
		qualityIssues.push({ kind: 'damning-defect', severity: 'damning', count: 1, detail: issues.find(issue => /damning honesty defect/i.test(issue)) ?? 'damning honesty defect' });
	}
	const lowConfidence = rating?.toLowerCase() === 'low' || (confidence !== undefined && confidence < 60);
	const partial = qualityIssues.length > 0 || lowConfidence;
	const reason = qualityIssues.length > 0
		? qualityIssues.map(issue => issue.detail).join('; ')
		: (lowConfidence ? `Helix confidence is ${confidence ?? 'unknown'}% (${rating ?? 'Low'})` : undefined);

	return {
		status: partial ? 'partial' : 'ok',
		...(confidence !== undefined ? { confidence } : {}),
		...(rating ? { rating } : {}),
		issues,
		qualityIssues,
		securityEvidenceUsable: !partial,
		...(reason ? { reason } : {}),
		confidenceAxes: {
			...(confidence !== undefined ? { translation: confidence } : {}),
			...(liftCoverage !== undefined ? { liftCoverage } : {}),
			semanticType: null,
			semanticTypeStatus: 'not-assessed',
		},
	};
}
