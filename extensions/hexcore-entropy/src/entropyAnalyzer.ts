/*---------------------------------------------------------------------------------------------
 *  HexCore Entropy Analyzer v1.1.0
 *  Streaming entropy engine and summary logic
 *  Copyright (c) HikariSystem. All rights reserved.
 *--------------------------------------------------------------------------------------------*/

import * as fs from 'fs';
import {
	CryptoSignal,
	EntropyBlock,
	EntropyCoreResult,
	EntropyProgressEvent,
	EntropySummary
} from './types';

export interface AnalyzeEntropyOptions {
	blockSize?: number;
	sampleRatio?: number;
	onProgress?: (event: EntropyProgressEvent) => void;
}

const MIN_BLOCK_SIZE = 16;
const MAX_BLOCK_SIZE = 1024 * 1024;
const STREAM_CHUNK_SIZE = 1024 * 1024;
const LOG2_LOOKUP_MAX = MAX_BLOCK_SIZE;
const LOG2_LOOKUP = createLog2Lookup(LOG2_LOOKUP_MAX);

export async function analyzeEntropyFile(filePath: string, options: AnalyzeEntropyOptions = {}): Promise<EntropyCoreResult> {
	const stats = fs.statSync(filePath);
	const blockSize = normalizeBlockSize(options.blockSize, stats.size);
	const sampleRatio = normalizeSampleRatio(options.sampleRatio);
	const blocks = await analyzeEntropyBlocksStream(
		filePath,
		blockSize,
		stats.size,
		sampleRatio,
		options.onProgress
	);
	const summary = summarizeEntropy(blocks);
	const cryptoSignals = detectCryptoSignalsStub(summary, blocks);

	return {
		filePath,
		fileSize: stats.size,
		blockSize,
		totalBlocks: blocks.length,
		blocks,
		summary,
		cryptoSignals
	};
}

function normalizeBlockSize(blockSize: number | undefined, fileSize: number): number {
	if (typeof blockSize === 'number' && Number.isFinite(blockSize)) {
		return Math.min(MAX_BLOCK_SIZE, Math.max(MIN_BLOCK_SIZE, Math.floor(blockSize)));
	}
	return chooseAdaptiveBlockSize(fileSize);
}

function normalizeSampleRatio(sampleRatio: number | undefined): number {
	if (typeof sampleRatio !== 'number' || !Number.isFinite(sampleRatio)) {
		return 1;
	}
	return Math.min(1, Math.max(0.01, sampleRatio));
}

function chooseAdaptiveBlockSize(fileSize: number): number {
	if (fileSize < 1024 * 1024) {
		return 256;
	}
	if (fileSize < 100 * 1024 * 1024) {
		return 4096;
	}
	if (fileSize < 1024 * 1024 * 1024) {
		return 64 * 1024;
	}
	return 1024 * 1024;
}

async function analyzeEntropyBlocksStream(
	filePath: string,
	blockSize: number,
	fileSize: number,
	sampleRatio: number,
	onProgress?: (event: EntropyProgressEvent) => void
): Promise<EntropyBlock[]> {
	const blocks: EntropyBlock[] = [];
	const streamChunkSize = Math.max(blockSize, STREAM_CHUNK_SIZE);

	let offset = 0;
	let blockIndex = 0;
	let bufferedRemainder: Buffer<ArrayBufferLike> = Buffer.alloc(0);
	let bytesRead = 0;
	let lastReportedPercent = -1;

	await new Promise<void>((resolve, reject) => {
		const stream = fs.createReadStream(filePath, { highWaterMark: streamChunkSize });

		stream.on('data', chunk => {
			const chunkBuffer = typeof chunk === 'string' ? Buffer.from(chunk) : chunk;
			bytesRead += chunkBuffer.length;

			const data = bufferedRemainder.length > 0
				? Buffer.concat([bufferedRemainder, chunkBuffer])
				: chunkBuffer;

			let cursor = 0;
			while ((cursor + blockSize) <= data.length) {
				const currentBlock = data.subarray(cursor, cursor + blockSize);
				if (shouldIncludeBlock(blockIndex, sampleRatio)) {
					blocks.push({
						offset,
						size: blockSize,
						entropy: calculateEntropy(currentBlock)
					});
				}
				offset += blockSize;
				cursor += blockSize;
				blockIndex++;
			}

			bufferedRemainder = data.subarray(cursor);
			reportProgress(bytesRead, fileSize, onProgress, () => lastReportedPercent, value => lastReportedPercent = value);
		});

		stream.on('end', () => {
			if (bufferedRemainder.length > 0 && shouldIncludeBlock(blockIndex, sampleRatio)) {
				blocks.push({
					offset,
					size: bufferedRemainder.length,
					entropy: calculateEntropy(bufferedRemainder)
				});
			}
			reportProgress(fileSize, fileSize, onProgress, () => lastReportedPercent, value => lastReportedPercent = value, true);
			resolve();
		});

		stream.on('error', reject);
	});

	return blocks;
}

function shouldIncludeBlock(blockIndex: number, sampleRatio: number): boolean {
	if (sampleRatio >= 1) {
		return true;
	}
	const samplingStep = Math.max(1, Math.round(1 / sampleRatio));
	return (blockIndex % samplingStep) === 0;
}

function reportProgress(
	processedBytes: number,
	totalBytes: number,
	onProgress: ((event: EntropyProgressEvent) => void) | undefined,
	getLastPercent: () => number,
	setLastPercent: (value: number) => void,
	force?: boolean
): void {
	if (!onProgress || totalBytes <= 0) {
		return;
	}

	const percent = Math.min(100, Math.floor((processedBytes / totalBytes) * 100));
	if (!force && percent < (getLastPercent() + 5)) {
		return;
	}

	onProgress({
		processedBytes,
		totalBytes,
		percent
	});
	setLastPercent(percent);
}

function summarizeEntropy(blocks: EntropyBlock[]): EntropySummary {
	if (blocks.length === 0) {
		return {
			averageEntropy: 0,
			maxEntropy: 0,
			minEntropy: 0,
			highEntropyBlocks: [],
			lowEntropyBlocks: [],
			assessment: 'Empty File',
			assessmentDetails: 'The selected file has no data blocks to analyze.'
		};
	}

	let entropySum = 0;
	let maxEntropy = Number.NEGATIVE_INFINITY;
	let minEntropy = Number.POSITIVE_INFINITY;
	const highEntropyBlocks: EntropyBlock[] = [];
	const lowEntropyBlocks: EntropyBlock[] = [];

	for (const block of blocks) {
		entropySum += block.entropy;
		if (block.entropy > maxEntropy) {
			maxEntropy = block.entropy;
		}
		if (block.entropy < minEntropy) {
			minEntropy = block.entropy;
		}
		if (block.entropy > 7.0) {
			highEntropyBlocks.push(block);
		}
		if (block.entropy < 1.0) {
			lowEntropyBlocks.push(block);
		}
	}

	const averageEntropy = entropySum / blocks.length;

	let assessment = 'Normal';
	let assessmentDetails = 'File appears to be uncompressed and unencrypted.';

	if (averageEntropy > 7.5) {
		assessment = 'Highly Encrypted/Compressed';
		assessmentDetails = 'Very high entropy suggests encryption or strong compression.';
	} else if (averageEntropy > 6.5) {
		assessment = 'Possibly Packed';
		assessmentDetails = 'Elevated entropy may indicate packing or compression.';
	} else if (highEntropyBlocks.length > blocks.length * 0.5) {
		assessment = 'Mixed Content';
		assessmentDetails = 'Significant portions have high entropy - possible encrypted sections.';
	}

	return {
		averageEntropy,
		maxEntropy,
		minEntropy,
		highEntropyBlocks,
		lowEntropyBlocks,
		assessment,
		assessmentDetails
	};
}

function calculateEntropy(buffer: Uint8Array): number {
	if (buffer.length === 0) {
		return 0;
	}

	const freq = new Uint32Array(256);
	for (let i = 0; i < buffer.length; i++) {
		freq[buffer[i]]++;
	}

	const logLen = fastLog2(buffer.length);
	let entropy = 0;

	for (let i = 0; i < 256; i++) {
		const count = freq[i];
		if (count > 0) {
			const probability = count / buffer.length;
			entropy -= probability * (fastLog2(count) - logLen);
		}
	}

	return entropy;
}

function createLog2Lookup(maxValue: number): Float64Array {
	const table = new Float64Array(maxValue + 1);
	table[0] = Number.NEGATIVE_INFINITY;
	for (let i = 1; i <= maxValue; i++) {
		table[i] = Math.log2(i);
	}
	return table;
}

function fastLog2(value: number): number {
	if (value > 0 && value <= LOG2_LOOKUP_MAX && Number.isInteger(value)) {
		return LOG2_LOOKUP[value];
	}
	return Math.log2(value);
}

function detectCryptoSignalsStub(summary: EntropySummary, blocks: EntropyBlock[]): CryptoSignal[] {
	// Future hook for dedicated AES heuristics:
	// - S-Box constants scan
	// - AES-NI opcode patterns
	// - round-key schedule structures
	// Kept conservative for now to avoid false positives.
	void summary;
	void blocks;
	return [];
}
