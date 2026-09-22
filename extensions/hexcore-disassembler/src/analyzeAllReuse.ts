import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';

export interface AnalyzeAllReuseIdentity {
	targetPath: string;
	fileSha256: string;
	architecture?: string;
	baseAddress?: number;
	maxFunctions: number;
	maxFunctionSize: number;
	filterJunk: boolean;
	detectVM: boolean;
	detectPRNG: boolean;
}

function canonicalPath(value: string): string {
	const resolved = path.resolve(value);
	return process.platform === 'win32' ? resolved.toLowerCase() : resolved;
}

export function createAnalyzeAllReuseKey(identity: AnalyzeAllReuseIdentity): string {
	const canonical = {
		...identity,
		targetPath: canonicalPath(identity.targetPath),
		fileSha256: identity.fileSha256.toLowerCase(),
	};
	return crypto.createHash('sha256').update(JSON.stringify(canonical), 'utf8').digest('hex');
}

export function sha256AnalyzeAllFile(filePath: string): Promise<string> {
	return new Promise((resolve, reject) => {
		const hash = crypto.createHash('sha256');
		const stream = fs.createReadStream(filePath);
		stream.on('error', reject);
		stream.on('data', chunk => hash.update(chunk));
		stream.on('end', () => resolve(hash.digest('hex')));
	});
}

export function canReuseAnalyzeAll(input: {
	forceReload: boolean;
	lastAcceptedKey?: string;
	requestedKey: string;
	analysisComplete: boolean;
	loadedPath?: string;
	requestedPath: string;
	loadedImageSha256?: string;
	requestedFileSha256: string;
}): { reusable: boolean; reason: string } {
	if (input.forceReload) return { reusable: false, reason: 'forceReload requested' };
	if (!input.lastAcceptedKey) return { reusable: false, reason: 'no accepted in-process analysis identity' };
	if (input.lastAcceptedKey !== input.requestedKey) return { reusable: false, reason: 'target or analysis configuration changed' };
	if (!input.analysisComplete) return { reusable: false, reason: 'active analysis is incomplete' };
	if (!input.loadedPath || canonicalPath(input.loadedPath) !== canonicalPath(input.requestedPath)) {
		return { reusable: false, reason: 'active engine owns a different target' };
	}
	if (!input.loadedImageSha256 || input.loadedImageSha256.toLowerCase() !== input.requestedFileSha256.toLowerCase()) {
		return { reusable: false, reason: 'active image bytes differ from the requested file' };
	}
	return { reusable: true, reason: 'exact target and analysis configuration already accepted' };
}
