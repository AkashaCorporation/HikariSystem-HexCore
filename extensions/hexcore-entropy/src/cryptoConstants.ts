/*---------------------------------------------------------------------------------------------
 *  HexCore Entropy Analyzer
 *  Known-crypto-constant detection (streaming, boundary-safe).
 *  Copyright (c) HikariSystem. All rights reserved.
 *--------------------------------------------------------------------------------------------*/

import { CryptoSignal } from './types';

/**
 * A known byte-constant whose presence is a strong, low-false-positive
 * signal for a specific cipher. Today this covers the ChaCha20 / Salsa20
 * sigma + tau constants; the table is intentionally extensible (AES S-box,
 * hash init vectors, etc. -- the old detectCryptoSignalsStub "future hook").
 */
export interface CryptoConstant {
	/** CryptoSignal.type emitted on a hit. */
	signalType: CryptoSignal['type'];
	/** Raw bytes to scan for. */
	bytes: Buffer;
	/** Confidence (0..1) -- a specific 16-byte ASCII constant is near-certain. */
	confidence: number;
	/** Human-readable label for the report. */
	label: string;
}

// ChaCha20 and Salsa20 BOTH derive their initial state from these ASCII
// "sigma"/"tau" constants (RFC 8439 / Bernstein's Salsa20). A 16-byte ASCII
// match is an extremely specific fingerprint of the cipher family and is
// what FLOSS / crypto-detectors key on. The constant alone cannot tell
// ChaCha from Salsa (they share it) -- distinguishing the two needs the ARX
// quarter-round structure, which is an IR/disassembly pass (deferred).
export const KNOWN_CRYPTO_CONSTANTS: CryptoConstant[] = [
	{
		signalType: 'chacha-salsa-constant',
		bytes: Buffer.from('expand 32-byte k', 'latin1'),
		confidence: 0.95,
		label: "ChaCha20/Salsa20 256-bit sigma constant 'expand 32-byte k'",
	},
	{
		signalType: 'chacha-salsa-constant',
		bytes: Buffer.from('expand 16-byte k', 'latin1'),
		confidence: 0.9,
		label: "ChaCha20/Salsa20 128-bit tau constant 'expand 16-byte k'",
	},
];

/** One located occurrence of a known crypto constant. */
export interface CryptoConstantHit {
	signalType: CryptoSignal['type'];
	offset: number;
	confidence: number;
	label: string;
}

/**
 * Scans a byte stream (fed chunk-by-chunk) for known crypto constants.
 * Boundary-safe: it carries a small overlap tail between chunks so a
 * constant straddling a chunk boundary is still found, and de-duplicates
 * hits by (type, absolute offset). Memory use is O(largest constant),
 * independent of file size -- it never buffers the whole file.
 */
export class CryptoConstantScanner {
	private tail: Buffer = Buffer.alloc(0);
	private tailBaseOffset = 0;
	private readonly maxLen: number;
	private readonly seen = new Set<string>();
	readonly hits: CryptoConstantHit[] = [];

	constructor(private readonly constants: CryptoConstant[] = KNOWN_CRYPTO_CONSTANTS) {
		this.maxLen = constants.reduce((m, c) => Math.max(m, c.bytes.length), 1);
	}

	/** Feed the next raw chunk; baseOffset is its absolute file offset. */
	scanChunk(chunk: Buffer, baseOffset: number): void {
		if (chunk.length === 0) {
			return;
		}
		// Prepend the carried tail so a match spanning the previous chunk
		// boundary is still seen exactly once.
		const hasTail = this.tail.length > 0;
		const buf = hasTail ? Buffer.concat([this.tail, chunk]) : chunk;
		const bufBase = hasTail ? this.tailBaseOffset : baseOffset;

		for (const c of this.constants) {
			let from = 0;
			for (;;) {
				const idx = buf.indexOf(c.bytes, from);
				if (idx < 0) {
					break;
				}
				const absOffset = bufBase + idx;
				const key = `${c.signalType}@${absOffset}`;
				if (!this.seen.has(key)) {
					this.seen.add(key);
					this.hits.push({
						signalType: c.signalType,
						offset: absOffset,
						confidence: c.confidence,
						label: c.label,
					});
				}
				from = idx + 1;
			}
		}

		// Carry the last (maxLen-1) bytes so the next chunk can complete a
		// boundary-spanning match. Copy out so the large buf can be released.
		const keep = Math.min(this.maxLen - 1, buf.length);
		this.tail = Buffer.from(buf.subarray(buf.length - keep));
		this.tailBaseOffset = bufBase + (buf.length - keep);
	}
}

/** Convert scanner hits into the report's CryptoSignal rows. */
export function cryptoConstantHitsToSignals(hits: CryptoConstantHit[]): CryptoSignal[] {
	return hits.map(h => ({
		type: h.signalType,
		confidence: h.confidence,
		offset: h.offset,
		details: h.label,
	}));
}
