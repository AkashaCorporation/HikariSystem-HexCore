/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as fs from 'fs';
import * as path from 'path';

export interface PipelinePresetStep {
	cmd: string;
	args?: Record<string, unknown>;
	output?: {
		path?: string;
		format?: 'json' | 'md';
	};
	timeoutMs?: number;
	expectOutput?: boolean;
	continueOnError?: boolean;
	retryCount?: number;
	retryDelayMs?: number;
}

export interface PipelineJobTemplate {
	file: string;
	outDir: string;
	quiet?: boolean;
	steps: PipelinePresetStep[];
}

export interface PipelinePreset {
	id: string;
	name: string;
	description: string;
	source: 'builtin' | 'workspace';
	template: PipelineJobTemplate;
}

interface WorkspacePresetFile {
	version: 1;
	presets: Array<{
		id: string;
		name: string;
		description: string;
		template: PipelineJobTemplate;
	}>;
}

const PRESET_FILE_NAME = '.hexcore_profiles.json';

export function getBuiltInPipelinePresets(): PipelinePreset[] {
	return [
		{
			id: 'quick-triage',
			name: 'Quick Triage',
			description: 'Fast static triage for immediate indicators.',
			source: 'builtin',
			template: {
				file: '${file}',
				outDir: '${outDir}',
				quiet: true,
				steps: [
					{ cmd: 'hexcore.filetype.detect' },
					{ cmd: 'hexcore.hashcalc.calculate', args: { algorithms: 'all' } },
					{ cmd: 'hexcore.entropy.analyze', args: { blockSize: 4096 } },
					{ cmd: 'hexcore.strings.extract', args: { minLength: 4, maxStrings: 50000 } }
				]
			}
		},
		{
			id: 'full-static',
			name: 'Full Static',
			description: 'Complete static workflow for malware/research reports.',
			source: 'builtin',
			template: {
				file: '${file}',
				outDir: '${outDir}',
				quiet: true,
				steps: [
					{ cmd: 'hexcore.filetype.detect' },
					{ cmd: 'hexcore.hashcalc.calculate', args: { algorithms: 'all' } },
					{ cmd: 'hexcore.entropy.analyze', args: { blockSize: 4096 } },
					{ cmd: 'hexcore.strings.extract', args: { minLength: 4, maxStrings: 200000 } },
					{ cmd: 'hexcore.ioc.extract' },
					{ cmd: 'hexcore.peanalyzer.analyze', continueOnError: true },
					{ cmd: 'hexcore.disasm.analyzeAll', args: { includeInstructions: true }, timeoutMs: 240000 },
					{ cmd: 'hexcore.yara.scan', continueOnError: true }
				]
			}
		},
		{
			id: 'ctf-reverse',
			name: 'CTF Reverse',
			description: 'Reverse-focused profile for challenge binaries.',
			source: 'builtin',
			template: {
				file: '${file}',
				outDir: '${outDir}',
				quiet: true,
				steps: [
					{ cmd: 'hexcore.strings.extract', args: { minLength: 3, maxStrings: 300000 } },
					{ cmd: 'hexcore.disasm.analyzeAll', args: { includeInstructions: true }, timeoutMs: 300000 },
					{ cmd: 'hexcore.disasm.exportASMHeadless', output: { path: '03-full.asm' }, timeoutMs: 180000 }
				]
			}
		}
	];
}

export function loadWorkspacePipelinePresets(workspaceRoot: string): PipelinePreset[] {
	const presetFile = getWorkspacePresetFilePath(workspaceRoot);
	if (!fs.existsSync(presetFile)) {
		return [];
	}

	let parsed: WorkspacePresetFile;
	try {
		parsed = JSON.parse(fs.readFileSync(presetFile, 'utf8')) as WorkspacePresetFile;
	} catch {
		return [];
	}

	if (!parsed || !Array.isArray(parsed.presets)) {
		return [];
	}

	return parsed.presets.map(preset => ({
		id: preset.id,
		name: preset.name,
		description: preset.description,
		source: 'workspace',
		template: preset.template
	}));
}

export function saveWorkspacePipelinePreset(
	workspaceRoot: string,
	name: string,
	description: string,
	jobTemplate: PipelineJobTemplate
): PipelinePreset {
	const id = sanitizePresetId(name);
	const existing = loadWorkspacePresetFile(workspaceRoot);
	const others = existing.presets.filter(preset => preset.id !== id);
	others.push({
		id,
		name,
		description,
		template: jobTemplate
	});

	const updated: WorkspacePresetFile = {
		version: 1,
		presets: others.sort((left, right) => left.name.localeCompare(right.name))
	};
	writeWorkspacePresetFile(workspaceRoot, updated);

	return {
		id,
		name,
		description,
		source: 'workspace',
		template: jobTemplate
	};
}

export function materializePresetJob(
	template: PipelineJobTemplate,
	filePath: string,
	outDir: string
): PipelineJobTemplate {
	const templateText = JSON.stringify(template);
	const replaced = templateText
		.replace(/\$\{file\}/g, normalizePathForJson(filePath))
		.replace(/\$\{outDir\}/g, normalizePathForJson(outDir));
	return JSON.parse(replaced) as PipelineJobTemplate;
}

export function normalizeJobTemplateFromExistingJob(job: PipelineJobTemplate): PipelineJobTemplate {
	const cloned = JSON.parse(JSON.stringify(job)) as PipelineJobTemplate;
	const originalOutDir = job.outDir;

	cloned.file = '${file}';
	cloned.outDir = '${outDir}';
	cloned.quiet = job.quiet ?? true;

	for (const step of cloned.steps) {
		const outputPath = step.output?.path;
		if (!outputPath) {
			continue;
		}

		if (path.isAbsolute(outputPath)) {
			const relative = path.relative(originalOutDir, outputPath);
			if (relative && !relative.startsWith('..') && !path.isAbsolute(relative)) {
				step.output = {
					...step.output,
					path: relative.replace(/\\/g, '/')
				};
			}
		}
	}

	return cloned;
}

export function getWorkspacePresetFilePath(workspaceRoot: string): string {
	return path.join(workspaceRoot, PRESET_FILE_NAME);
}

function loadWorkspacePresetFile(workspaceRoot: string): WorkspacePresetFile {
	const presetFile = getWorkspacePresetFilePath(workspaceRoot);
	if (!fs.existsSync(presetFile)) {
		return { version: 1, presets: [] };
	}

	try {
		const parsed = JSON.parse(fs.readFileSync(presetFile, 'utf8')) as WorkspacePresetFile;
		if (!parsed || !Array.isArray(parsed.presets)) {
			return { version: 1, presets: [] };
		}
		return {
			version: 1,
			presets: parsed.presets
		};
	} catch {
		return { version: 1, presets: [] };
	}
}

function writeWorkspacePresetFile(workspaceRoot: string, data: WorkspacePresetFile): void {
	const presetFile = getWorkspacePresetFilePath(workspaceRoot);
	fs.writeFileSync(presetFile, JSON.stringify(data, null, 2), 'utf8');
}

function sanitizePresetId(name: string): string {
	return name
		.trim()
		.toLowerCase()
		.replace(/[^a-z0-9._-]+/g, '-')
		.replace(/-+/g, '-')
		.replace(/^-|-$/g, '') || 'profile';
}

function normalizePathForJson(value: string): string {
	return value.replace(/\\/g, '\\\\');
}
