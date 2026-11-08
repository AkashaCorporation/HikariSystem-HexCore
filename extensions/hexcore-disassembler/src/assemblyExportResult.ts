import type { AssemblyExportResult } from './disassemblerEngine';

export function formatAssemblyExportSemanticWarning(result: AssemblyExportResult): string | undefined {
	if (result.status !== 'partial') {
		return undefined;
	}

	const reasons: string[] = [];
	if (result.emptyFunctions.length > 0 || result.functionsWithoutInstructions > 0) {
		reasons.push(
			`${result.functionsWithoutInstructions}/${result.totalFunctions} function ` +
			`${result.functionsWithoutInstructions === 1 ? 'body' : 'bodies'} decoded no instructions`,
		);
	}
	if (result.incompleteFunctions.length > 0) {
		const samples = result.incompleteFunctions.slice(0, 3).map(item =>
			`0x${item.address.toString(16).toUpperCase()} ` +
			`(${(item.byteCoverage * 100).toFixed(2)}%, ${item.stopReason})`
		);
		reasons.push(
			`${result.incompleteFunctions.length}/${result.totalFunctions} function ` +
			`${result.incompleteFunctions.length === 1 ? 'body is' : 'bodies are'} incomplete: ` +
			samples.join(', '),
		);
	}

	return reasons.length > 0
		? reasons.join('; ')
		: `assembly export is partial for ${result.totalFunctions} function bodies`;
}
