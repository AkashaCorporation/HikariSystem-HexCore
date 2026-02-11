/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as fs from 'fs';
import * as path from 'path';
import { Instruction } from './disassemblerEngine';

export interface ConstantSanityCheckOptions {
	notesFilePath?: string;
	maxFindings?: number;
}

export interface ConstantSanityLiteral {
	literal: string;
	value: string;
}

export interface ConstantSanityFinding {
	address: string;
	instruction: string;
	source: 'comment' | 'notes';
	sourceLocation: string;
	sourceText: string;
	expected: ConstantSanityLiteral;
	immediates: ConstantSanityLiteral[];
}

export interface ConstantSanityAnalysis {
	scannedInstructions: number;
	instructionsWithImmediates: number;
	annotationsConsidered: number;
	matchedAnnotations: number;
	mismatchedAnnotations: number;
	ambiguousAnnotations: number;
	maxFindingsReached: boolean;
	notesFilePath?: string;
	findings: ConstantSanityFinding[];
	reportMarkdown: string;
}

interface ParsedLiteral extends ConstantSanityLiteral {
	isDecimal: boolean;
}

interface AnnotationCandidate {
	source: 'comment' | 'notes';
	sourceLocation: string;
	sourceText: string;
}

interface NoteEntry {
	line: number;
	text: string;
}

const DEFAULT_MAX_FINDINGS = 300;

export function analyzeConstantSanity(
	instructions: Instruction[],
	options: ConstantSanityCheckOptions = {}
): ConstantSanityAnalysis {
	const sortedInstructions = [...instructions].sort((left, right) => left.address - right.address);
	const maxFindings = normalizeMaxFindings(options.maxFindings);
	const noteEntriesByAddress = loadNotesEntriesByAddress(options.notesFilePath);

	let scannedInstructions = 0;
	let instructionsWithImmediates = 0;
	let annotationsConsidered = 0;
	let matchedAnnotations = 0;
	let mismatchedAnnotations = 0;
	let ambiguousAnnotations = 0;
	let maxFindingsReached = false;
	const findings: ConstantSanityFinding[] = [];

	for (const instruction of sortedInstructions) {
		scannedInstructions++;

		const immediates = extractInstructionImmediates(instruction.opStr);
		if (immediates.length === 0) {
			continue;
		}
		instructionsWithImmediates++;

		const annotationCandidates = collectAnnotationCandidates(instruction, noteEntriesByAddress);
		if (annotationCandidates.length === 0) {
			continue;
		}

		for (const annotation of annotationCandidates) {
			annotationsConsidered++;
			const annotationLiterals = extractLiterals(annotation.sourceText);
			const expected = chooseExpectedLiteral(annotationLiterals);
			if (!expected) {
				ambiguousAnnotations++;
				continue;
			}

			const hasMatch = immediates.some(immediate => immediate.value === expected.value);
			if (hasMatch) {
				matchedAnnotations++;
				continue;
			}

			mismatchedAnnotations++;
			if (findings.length >= maxFindings) {
				maxFindingsReached = true;
				continue;
			}

			findings.push({
				address: toHexAddress(instruction.address),
				instruction: `${instruction.mnemonic} ${instruction.opStr}`.trim(),
				source: annotation.source,
				sourceLocation: annotation.sourceLocation,
				sourceText: annotation.sourceText,
				expected: {
					literal: expected.literal,
					value: expected.value
				},
				immediates: immediates.map(item => ({
					literal: item.literal,
					value: item.value
				}))
			});
		}
	}

	const reportMarkdown = generateReportMarkdown({
		scannedInstructions,
		instructionsWithImmediates,
		annotationsConsidered,
		matchedAnnotations,
		mismatchedAnnotations,
		ambiguousAnnotations,
		maxFindingsReached,
		notesFilePath: options.notesFilePath,
		findings,
		reportMarkdown: ''
	});

	return {
		scannedInstructions,
		instructionsWithImmediates,
		annotationsConsidered,
		matchedAnnotations,
		mismatchedAnnotations,
		ambiguousAnnotations,
		maxFindingsReached,
		notesFilePath: options.notesFilePath,
		findings,
		reportMarkdown
	};
}

function normalizeMaxFindings(maxFindings: number | undefined): number {
	if (typeof maxFindings !== 'number' || !Number.isFinite(maxFindings)) {
		return DEFAULT_MAX_FINDINGS;
	}
	return Math.max(1, Math.floor(maxFindings));
}

function collectAnnotationCandidates(
	instruction: Instruction,
	notesByAddress: Map<number, NoteEntry[]>
): AnnotationCandidate[] {
	const annotations: AnnotationCandidate[] = [];

	if (typeof instruction.comment === 'string' && instruction.comment.trim().length > 0) {
		annotations.push({
			source: 'comment',
			sourceLocation: 'inline comment',
			sourceText: instruction.comment.trim()
		});
	}

	const noteEntries = notesByAddress.get(instruction.address) ?? [];
	for (const entry of noteEntries) {
		annotations.push({
			source: 'notes',
			sourceLocation: `notes line ${entry.line}`,
			sourceText: entry.text
		});
	}

	return annotations;
}

function loadNotesEntriesByAddress(notesFilePath: string | undefined): Map<number, NoteEntry[]> {
	const notesByAddress = new Map<number, NoteEntry[]>();
	if (!notesFilePath) {
		return notesByAddress;
	}

	if (!fs.existsSync(notesFilePath)) {
		throw new Error(`Notes file not found: ${notesFilePath}`);
	}

	const content = fs.readFileSync(notesFilePath, 'utf8');
	const lines = content.split(/\r?\n/);
	for (let index = 0; index < lines.length; index++) {
		const line = lines[index].trim();
		if (line.length === 0) {
			continue;
		}

		const match = line.match(/0x[0-9a-f]+/i);
		if (!match) {
			continue;
		}

		const address = parseInt(match[0], 16);
		if (!Number.isFinite(address)) {
			continue;
		}

		const entry: NoteEntry = {
			line: index + 1,
			text: line
		};
		const existing = notesByAddress.get(address);
		if (existing) {
			existing.push(entry);
		} else {
			notesByAddress.set(address, [entry]);
		}
	}

	return notesByAddress;
}

function extractInstructionImmediates(opStr: string): ParsedLiteral[] {
	const immediates: ParsedLiteral[] = [];
	const seen = new Set<string>();

	for (const operand of splitOperands(opStr)) {
		const trimmed = operand.trim();
		if (trimmed.length === 0) {
			continue;
		}
		if (trimmed.includes('[') && trimmed.includes(']')) {
			continue;
		}

		for (const literal of extractLiterals(trimmed)) {
			const key = `${literal.literal}|${literal.value}`;
			if (seen.has(key)) {
				continue;
			}
			seen.add(key);
			immediates.push(literal);
		}
	}

	return immediates;
}

function splitOperands(opStr: string): string[] {
	const operands: string[] = [];
	let current = '';
	let bracketDepth = 0;

	for (const ch of opStr) {
		if (ch === '[') {
			bracketDepth++;
		} else if (ch === ']') {
			bracketDepth = Math.max(0, bracketDepth - 1);
		}

		if (ch === ',' && bracketDepth === 0) {
			const token = current.trim();
			if (token.length > 0) {
				operands.push(token);
			}
			current = '';
			continue;
		}

		current += ch;
	}

	const tail = current.trim();
	if (tail.length > 0) {
		operands.push(tail);
	}
	return operands;
}

function extractLiterals(text: string): ParsedLiteral[] {
	const literals: ParsedLiteral[] = [];
	const pattern = /(?<![A-Za-z0-9_])(?<literal>-?(?:0x[0-9a-f]+|[0-9a-f]+h|\d+))(?![A-Za-z0-9_])/gi;
	let match: RegExpExecArray | null = null;
	while ((match = pattern.exec(text)) !== null) {
		const token = match.groups?.literal ?? '';
		if (!token) {
			continue;
		}
		const value = parseNumericLiteral(token);
		if (value === undefined) {
			continue;
		}
		literals.push({
			literal: token,
			value: value.toString(),
			isDecimal: /^-?\d+$/.test(token)
		});
	}
	return literals;
}

function chooseExpectedLiteral(literals: ParsedLiteral[]): ParsedLiteral | undefined {
	if (literals.length === 0) {
		return undefined;
	}

	const decimalLiterals = literals.filter(literal => literal.isDecimal);
	if (decimalLiterals.length === 1) {
		return decimalLiterals[0];
	}
	if (literals.length === 1) {
		return literals[0];
	}

	return undefined;
}

function parseNumericLiteral(token: string): bigint | undefined {
	try {
		if (/^-?0x[0-9a-f]+$/i.test(token)) {
			return BigInt(token);
		}

		if (/^-?[0-9a-f]+h$/i.test(token)) {
			const isNegative = token.startsWith('-');
			const raw = token.replace(/^-/, '').slice(0, -1);
			const value = BigInt(`0x${raw}`);
			return isNegative ? -value : value;
		}

		if (/^-?\d+$/.test(token)) {
			return BigInt(token);
		}
	} catch {
		return undefined;
	}

	return undefined;
}

function generateReportMarkdown(result: ConstantSanityAnalysis): string {
	let markdown = `# HexCore Constant Sanity Report

## Summary

- Scanned instructions: \`${result.scannedInstructions}\`
- Instructions with immediates: \`${result.instructionsWithImmediates}\`
- Annotations considered: \`${result.annotationsConsidered}\`
- Matched annotations: \`${result.matchedAnnotations}\`
- Mismatched annotations: \`${result.mismatchedAnnotations}\`
- Ambiguous annotations: \`${result.ambiguousAnnotations}\`
- Notes file: \`${result.notesFilePath ? path.basename(result.notesFilePath) : 'none'}\`
- Findings truncated: \`${result.maxFindingsReached ? 'yes' : 'no'}\`

`;

	if (result.findings.length === 0) {
		markdown += `## Findings

No mismatches were detected.
`;
		return markdown;
	}

	markdown += `## Mismatch Findings

| Address | Instruction | Source | Expected | Immediates |
|---------|-------------|--------|----------|------------|
`;

	for (const finding of result.findings) {
		const immediates = finding.immediates
			.map(immediate => `${immediate.literal} (${immediate.value})`)
			.join(', ');
		const expected = `${finding.expected.literal} (${finding.expected.value})`;
		const source = `${finding.source} - ${finding.sourceLocation}`;
		markdown += `| ${finding.address} | \`${escapeMarkdown(finding.instruction)}\` | ${escapeMarkdown(source)} | \`${escapeMarkdown(expected)}\` | \`${escapeMarkdown(immediates)}\` |\n`;
	}

	return markdown;
}

function toHexAddress(address: number): string {
	return `0x${address.toString(16).toUpperCase()}`;
}

function escapeMarkdown(value: string): string {
	return value.replace(/\|/g, '\\|').replace(/`/g, '\\`');
}

