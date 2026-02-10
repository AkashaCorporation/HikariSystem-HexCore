/*---------------------------------------------------------------------------------------------
 *  HexCore Entropy Analyzer v1.1.0
 *  Shared contracts for entropy analysis pipeline
 *  Copyright (c) HikariSystem. All rights reserved.
 *--------------------------------------------------------------------------------------------*/

export type OutputFormat = 'json' | 'md';

export interface CommandOutputOptions {
	path: string;
	format?: OutputFormat;
}

export interface EntropyCommandOptions {
	file?: string;
	output?: CommandOutputOptions;
	quiet?: boolean;
	blockSize?: number;
	sampleRatio?: number;
}

export interface EntropyProgressEvent {
	processedBytes: number;
	totalBytes: number;
	percent: number;
}

export interface EntropyBlock {
	offset: number;
	size: number;
	entropy: number;
}

export interface EntropySummary {
	averageEntropy: number;
	maxEntropy: number;
	minEntropy: number;
	highEntropyBlocks: EntropyBlock[];
	lowEntropyBlocks: EntropyBlock[];
	assessment: string;
	assessmentDetails: string;
}

export interface CryptoSignal {
	type: 'aes-candidate';
	confidence: number;
	offset?: number;
	details: string;
}

export interface EntropyCoreResult {
	filePath: string;
	fileSize: number;
	blockSize: number;
	totalBlocks: number;
	blocks: EntropyBlock[];
	summary: EntropySummary;
	cryptoSignals: CryptoSignal[];
}

export interface EntropyAnalysisResult extends EntropyCoreResult {
	fileName: string;
	graph: string;
	reportMarkdown: string;
}
