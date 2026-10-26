'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

class FrozenProducerUnavailableError extends Error {
	constructor(expectedSha256, candidates) {
		super(`HOLD-MISSING-FROZEN-PRODUCER: no verified Helix node matches ${expectedSha256}`);
		this.name = 'FrozenProducerUnavailableError';
		this.code = 'HOLD-MISSING-FROZEN-PRODUCER';
		this.expectedSha256 = expectedSha256;
		this.candidates = candidates;
	}
}

function sha256File(filePath) {
	return crypto.createHash('sha256').update(fs.readFileSync(filePath)).digest('hex');
}

function defaultCacheRoot() {
	const local = process.env.LOCALAPPDATA;
	return local
		? path.join(local, 'HexCore', 'producer-cache')
		: path.join(os.homedir(), '.hexcore', 'producer-cache');
}

function resolveFrozenHelixProducer(options = {}) {
	const benchmarkRoot = options.benchmarkRoot || __dirname;
	const manifestPath = options.manifestPath || path.join(benchmarkRoot, 'producer-manifest.json');
	const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
	if (manifest.schemaVersion !== 1 || manifest.component !== 'hexcore-helix') {
		throw new Error('Unsupported Function Atlas producer manifest');
	}
	const expectedSha256 = String(options.expectedSha256 || manifest.artifact?.sha256 || '').toLowerCase();
	if (!/^[a-f0-9]{64}$/.test(expectedSha256)) throw new Error('Invalid frozen producer SHA-256');
	if (manifest.artifact.sha256.toLowerCase() !== expectedSha256) {
		throw new Error('Function Atlas engine lock and producer manifest disagree');
	}
	const cacheRoot = process.env[manifest.resolution.cacheRootEnv] || defaultCacheRoot();
	const candidates = [
		process.env[manifest.resolution.explicitPathEnv],
		path.resolve(benchmarkRoot, manifest.resolution.localDevelopmentPath),
		path.resolve(cacheRoot, manifest.resolution.cacheRelativePath),
		...(Array.isArray(options.additionalCandidates) ? options.additionalCandidates : []),
	].filter(value => typeof value === 'string' && value.length > 0)
		.map(value => path.resolve(value));
	for (const candidate of [...new Set(candidates)]) {
		if (!fs.existsSync(candidate) || !fs.statSync(candidate).isFile()) continue;
		if (fs.statSync(candidate).size !== manifest.artifact.bytes) continue;
		if (sha256File(candidate) === expectedSha256) {
			return { path: candidate, sha256: expectedSha256, manifest, cacheRoot };
		}
	}
	throw new FrozenProducerUnavailableError(expectedSha256, candidates);
}

module.exports = {
	FrozenProducerUnavailableError,
	resolveFrozenHelixProducer,
	sha256File,
};
