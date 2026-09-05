/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Akasha Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import { normalizeAddressValue } from 'hexcore-common';
import type { PipelineJobFile } from './automationPipelineRunner';

export interface InvestigationJobInput {
	targetPath: string;
	outputDirectory: string;
	name: string;
	query: string;
	functionAddress: string;
	instructionCount?: number;
}

export interface InvestigationJobDefinition {
	slug: string;
	fileName: string;
	job: PipelineJobFile;
}

export function sanitizeInvestigationJobName(value: string): string {
	const slug = value
		.trim()
		.replace(/[^a-zA-Z0-9._-]+/g, '-')
		.replace(/-+/g, '-')
		.replace(/^[-.]+|[-.]+$/g, '')
		.toLowerCase();
	if (!slug) {
		throw new Error('Job name must contain at least one letter or number.');
	}
	return slug.slice(0, 80);
}

export function createInvestigationJob(input: InvestigationJobInput): InvestigationJobDefinition {
	const slug = sanitizeInvestigationJobName(input.name);
	const query = input.query.trim();
	if (!query) {
		throw new Error('The saved finding does not contain a search query.');
	}
	const functionAddress = normalizeAddressValue(input.functionAddress);
	const instructionCount = input.instructionCount ?? 300;
	if (!Number.isSafeInteger(instructionCount) || instructionCount < 1 || instructionCount > 10000) {
		throw new Error('Instruction count must be an integer between 1 and 10000.');
	}

	return {
		slug,
		fileName: `${slug}.hexcore_job.json`,
		job: {
			file: input.targetPath,
			outDir: input.outputDirectory,
			quiet: true,
			priority: 'normal',
			steps: [
				{
					cmd: 'hexcore.disasm.analyzeAll',
					args: { forceReload: true },
					expectOutput: false,
					timeoutMs: 300000,
				},
				{
					cmd: 'hexcore.disasm.searchStringHeadless',
					args: { query },
					output: { path: `${slug}.references.json`, format: 'json' },
					timeoutMs: 120000,
				},
				{
					cmd: 'hexcore.disasm.liftToIR',
					args: { address: functionAddress, count: instructionCount },
					output: { path: `${slug}.ll` },
					timeoutMs: 120000,
				},
				{
					cmd: 'hexcore.helix.decompileIR',
					args: { irPath: '$step[2].output' },
					output: { path: `${slug}.helix.c` },
					allowPartial: true,
					timeoutMs: 180000,
				},
			],
		},
	};
}
