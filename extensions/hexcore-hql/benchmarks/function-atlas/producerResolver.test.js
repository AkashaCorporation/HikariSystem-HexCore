'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const {
	FrozenProducerUnavailableError,
	resolveFrozenHelixProducer,
} = require('./producerResolver.js');

const root = fs.mkdtempSync(path.join(os.tmpdir(), 'hexcore-producer-resolver-'));
const priorCache = process.env.HEXCORE_PRODUCER_CACHE;
try {
	const bytes = Buffer.from('producer-fixture');
	const sha256 = crypto.createHash('sha256').update(bytes).digest('hex');
	const cacheRelativePath = `sha256/${sha256}/fixture.node`;
	const cacheRoot = path.join(root, 'cache');
	const cached = path.join(cacheRoot, cacheRelativePath);
	fs.mkdirSync(path.dirname(cached), { recursive: true });
	fs.writeFileSync(cached, bytes);
	const manifestPath = path.join(root, 'producer-manifest.json');
	fs.writeFileSync(manifestPath, JSON.stringify({
		schemaVersion: 1,
		component: 'hexcore-helix',
		artifact: { sha256, bytes: bytes.length },
		resolution: {
			explicitPathEnv: 'HEXCORE_HELIX_HAST_NODE_TEST',
			cacheRootEnv: 'HEXCORE_PRODUCER_CACHE',
			cacheRelativePath,
			localDevelopmentPath: 'missing.node',
		},
	}));
	process.env.HEXCORE_PRODUCER_CACHE = cacheRoot;
	assert.equal(resolveFrozenHelixProducer({ benchmarkRoot: root, manifestPath, expectedSha256: sha256 }).path, cached);
	assert.throws(() => resolveFrozenHelixProducer({
		benchmarkRoot: root,
		manifestPath,
		expectedSha256: '0'.repeat(64),
	}), /engine lock and producer manifest disagree/);

	const real = resolveFrozenHelixProducer({ benchmarkRoot: __dirname });
	assert.equal(real.sha256, 'cfce13b7999abd0f3e2feaec90600bb722912b3ae84026084071ea3dff18ca71');
	assert.ok(fs.existsSync(real.path));

	const unavailableManifest = path.join(root, 'unavailable.json');
	fs.writeFileSync(unavailableManifest, JSON.stringify({
		schemaVersion: 1,
		component: 'hexcore-helix',
		artifact: { sha256: '1'.repeat(64), bytes: 99 },
		resolution: {
			explicitPathEnv: 'HEXCORE_HELIX_HAST_NODE_MISSING_TEST',
			cacheRootEnv: 'HEXCORE_PRODUCER_CACHE_MISSING_TEST',
			cacheRelativePath: 'missing.node',
			localDevelopmentPath: 'missing.node',
		},
	}));
	assert.throws(() => resolveFrozenHelixProducer({ benchmarkRoot: root, manifestPath: unavailableManifest }), error =>
		error instanceof FrozenProducerUnavailableError && error.code === 'HOLD-MISSING-FROZEN-PRODUCER');

	console.log('Function Atlas producer resolver: PASS');
} finally {
	if (priorCache === undefined) delete process.env.HEXCORE_PRODUCER_CACHE;
	else process.env.HEXCORE_PRODUCER_CACHE = priorCache;
	fs.rmSync(root, { recursive: true, force: true });
}
