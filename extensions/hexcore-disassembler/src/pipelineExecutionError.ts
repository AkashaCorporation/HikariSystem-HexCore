function errorMessage(error: unknown): string {
	if (error instanceof Error) {
		return error.message;
	}
	return typeof error === 'string' ? error : String(error);
}

/** Preserve activation/owner diagnostics while keeping a stable leading class. */
export function normalizePipelineExecutionError(error: unknown, resolvedCommand: string): string {
	const base = errorMessage(error);
	if (/command\b.*\b(?:not found|is not available)\b/i.test(base)) {
		return `Command is not available: ${resolvedCommand}. Diagnostic: ${base}`;
	}
	return base;
}
