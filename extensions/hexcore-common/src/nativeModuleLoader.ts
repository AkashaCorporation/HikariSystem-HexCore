/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import * as fs from 'fs';
import * as path from 'path';

export interface NativeModuleLoadOptions {
	moduleName: string;
	candidatePaths?: string[];
}

export interface NativeModuleLoadResult<T> {
	module?: T;
	error?: Error;
	attemptedPaths: string[];
	errorMessage: string;
}

function resolveCandidatePath(candidate: string): string {
	if (path.isAbsolute(candidate)) {
		return candidate;
	}
	return path.resolve(candidate);
}

function formatErrorMessage(moduleName: string, attemptedPaths: string[], errors: string[]): string {
	const lines: string[] = [];
	lines.push(`Failed to load native module "${moduleName}".`);
	lines.push(`Platform: ${process.platform}, Arch: ${process.arch}, Node: ${process.versions.node}`);

	if (attemptedPaths.length > 0) {
		lines.push('Attempted paths:');
		for (const entry of attemptedPaths) {
			lines.push(`- ${entry}`);
		}
	}

	if (errors.length > 0) {
		lines.push('Errors:');
		for (const entry of errors) {
			lines.push(`- ${entry}`);
		}
	}

	lines.push('Suggested actions:');
	lines.push('- Run npm install in the engine package folder.');
	lines.push('- Verify build tools and runtime dependencies are installed.');
	lines.push('- Ensure prebuilds are available for your platform.');

	return lines.join('\n');
}

export function loadNativeModule<T = unknown>(options: NativeModuleLoadOptions): NativeModuleLoadResult<T> {
	const attemptedPaths: string[] = [];
	const errors: string[] = [];

	const candidates: string[] = [];
	candidates.push(options.moduleName);
	if (options.candidatePaths) {
		for (const entry of options.candidatePaths) {
			candidates.push(resolveCandidatePath(entry));
		}
	}

	for (const candidate of candidates) {
		try {
			attemptedPaths.push(candidate);
			const module = require(candidate) as T;
			return { module, attemptedPaths, errorMessage: '' };
		} catch (error: any) {
			const message = error instanceof Error ? error.message : String(error);
			errors.push(`${candidate}: ${message}`);
		}
	}

	const errorMessage = formatErrorMessage(options.moduleName, attemptedPaths, errors);
	return {
		error: new Error(errorMessage),
		attemptedPaths,
		errorMessage
	};
}

