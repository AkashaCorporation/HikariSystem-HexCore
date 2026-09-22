import * as crypto from 'crypto';

export interface TransformChainCandidate {
	value: string;
	offset: number;
	source: 'extracted' | 'deobfuscated';
}

export interface EvidenceTransformChain {
	offset: number;
	source: TransformChainCandidate['source'];
	transforms: ['hex-to-ascii', 'base64-to-bytes', 'json-probe'];
	hexPreview: string;
	asciiPreview: string;
	decodedPreview: string;
	decodedSha256: string;
	jsonValid: boolean;
	confidence: number;
}

export interface TransformChainBudget {
	candidates: number;
	accepted: number;
	discardedBudget: number;
	rejectedInvalidHex: number;
	rejectedNonPrintableHex: number;
	rejectedBase64Shape: number;
	rejectedDecodedPayload: number;
	rejectedNonJsonLike: number;
	rejectedDuplicate: number;
	accountedCandidates: number;
	unaccountedCandidates: number;
	maxChains: number;
}

function printableRatio(buffer: Buffer): number {
	if (buffer.length === 0) { return 0; }
	let printable = 0;
	for (const byte of buffer) {
		if ((byte >= 0x20 && byte <= 0x7e) || byte === 0x09 || byte === 0x0a || byte === 0x0d) {
			printable++;
		}
	}
	return printable / buffer.length;
}

function preview(value: string, limit = 160): string {
	return value.replace(/[\r\n\t]+/g, ' ').slice(0, limit);
}

export function detectEvidenceTransformChains(
	candidates: TransformChainCandidate[],
	maxChains = 100,
): { chains: EvidenceTransformChain[]; budget: TransformChainBudget } {
	const limit = Math.max(1, Math.min(1000, Math.floor(maxChains)));
	const accepted: EvidenceTransformChain[] = [];
	const seen = new Set<string>();
	const rejected = {
		invalidHex: 0,
		nonPrintableHex: 0,
		base64Shape: 0,
		decodedPayload: 0,
		nonJsonLike: 0,
		duplicate: 0,
	};

	for (const candidate of candidates) {
		const hex = candidate.value.trim();
		if (hex.length < 32 || hex.length > 8192 || hex.length % 2 !== 0 || !/^[0-9a-f]+$/i.test(hex)) {
			rejected.invalidHex++;
			continue;
		}
		const asciiBytes = Buffer.from(hex, 'hex');
		if (printableRatio(asciiBytes) < 0.95) { rejected.nonPrintableHex++; continue; }
		const ascii = asciiBytes.toString('ascii').trim();
		if (ascii.length < 16 || !/^[A-Za-z0-9+/]+={0,2}$/.test(ascii)) { rejected.base64Shape++; continue; }

		const padded = ascii.padEnd(Math.ceil(ascii.length / 4) * 4, '=');
		const decoded = Buffer.from(padded, 'base64');
		if (decoded.length < 4 || printableRatio(decoded) < 0.85) { rejected.decodedPayload++; continue; }
		const decodedText = decoded.toString('utf8').trim();
		if (!decodedText.startsWith('{') && !decodedText.startsWith('[')) { rejected.nonJsonLike++; continue; }

		let jsonValid = false;
		try {
			JSON.parse(decodedText);
			jsonValid = true;
		} catch {
			// Truncated JSON prefixes remain useful evidence, but score lower.
		}
		const hash = crypto.createHash('sha256').update(decoded).digest('hex');
		const key = `${candidate.offset}:${hash}`;
		if (seen.has(key)) { rejected.duplicate++; continue; }
		seen.add(key);
		accepted.push({
			offset: candidate.offset,
			source: candidate.source,
			transforms: ['hex-to-ascii', 'base64-to-bytes', 'json-probe'],
			hexPreview: preview(hex),
			asciiPreview: preview(ascii),
			decodedPreview: preview(decodedText),
			decodedSha256: hash,
			jsonValid,
			confidence: jsonValid ? 0.95 : 0.8,
		});
	}

	const chains = accepted.slice(0, limit);
	const discardedBudget = Math.max(0, accepted.length - chains.length);
	const accountedCandidates = chains.length + discardedBudget +
		rejected.invalidHex + rejected.nonPrintableHex + rejected.base64Shape +
		rejected.decodedPayload + rejected.nonJsonLike + rejected.duplicate;
	return {
		chains,
		budget: {
			candidates: candidates.length,
			accepted: chains.length,
			discardedBudget,
			rejectedInvalidHex: rejected.invalidHex,
			rejectedNonPrintableHex: rejected.nonPrintableHex,
			rejectedBase64Shape: rejected.base64Shape,
			rejectedDecodedPayload: rejected.decodedPayload,
			rejectedNonJsonLike: rejected.nonJsonLike,
			rejectedDuplicate: rejected.duplicate,
			accountedCandidates,
			unaccountedCandidates: Math.max(0, candidates.length - accountedCandidates),
			maxChains: limit,
		},
	};
}
