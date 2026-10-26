'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { pathToFileURL } = require('node:url');
const { resolveFrozenHelixProducer } = require('../producerResolver.js');

async function main() {
	const metadata = require('./x86-width-and-unary-regression.json');
	const resolvedNode = resolveFrozenHelixProducer({
		benchmarkRoot: path.resolve(__dirname, '..'),
		expectedSha256: metadata.producer.helix.nodeSha256,
	}).path;
	const nodeSha256 = crypto.createHash('sha256').update(fs.readFileSync(resolvedNode)).digest('hex');
	if (nodeSha256 !== metadata.producer.helix.nodeSha256) {
		throw new Error(`Helix node hash drift: ${nodeSha256}`);
	}
	const helix = require(resolvedNode);
	const ir = fs.readFileSync(path.join(__dirname, 'x86-width-and-unary-regression.ll'), 'utf8');
	const actualSha256 = crypto.createHash('sha256').update(ir).digest('hex');
	if (actualSha256 !== metadata.irSha256 || Buffer.byteLength(ir, 'utf8') !== metadata.irBytes) {
		throw new Error(`IR identity drift: ${actualSha256}`);
	}

	const engine = new helix.HelixEngine(0);
	engine.setUseCastLayer(true);
	let result;
	try {
		result = engine.decompileIr(ir);
	} finally {
		engine.dispose();
	}
	if (result.pipeline !== metadata.expected.pipeline || !result.astBuffer?.length) {
		throw new Error('Resolved x86 regression did not produce an MLIR HAST artifact');
	}
	const sourceSha256 = crypto.createHash('sha256').update(result.source).digest('hex');
	const hastSha256 = crypto.createHash('sha256').update(result.astBuffer).digest('hex');
	if (sourceSha256 !== metadata.expected.sourceSha256 || hastSha256 !== metadata.expected.hastSha256) {
		throw new Error(`Resolved x86 regression artifact drift: C=${sourceSha256} HAST=${hastSha256}`);
	}
	const hql = await import(pathToFileURL(path.resolve(__dirname, '../../../dist/index.js')).href);
	const functions = hql.hydrateHAST(result.astBuffer);
	if (functions.length !== 1
		|| functions[0].hast?.schemaMajor !== metadata.expected.hastSchema
		|| functions[0].hast?.schemaMinor !== metadata.expected.hastSchemaMinor
		|| functions[0].address?.toLowerCase() !== metadata.expected.functionAddress
		|| functions[0].hast?.nativeQuality?.status !== metadata.expected.nativeQualityStatus
		|| !functions[0].hast?.nativeQuality?.issues?.includes('damning-defect')
		|| functions[0].hast?.semanticEligible !== metadata.expected.semanticEligible
		|| functions[0].adapterCoverage?.coverage !== metadata.expected.adapterCoverage) {
		throw new Error(`Resolved x86 regression failed HAST gate: ${JSON.stringify(functions.map(fn => ({
			address: fn.address, hast: fn.hast, adapterCoverage: fn.adapterCoverage,
		})))}`);
	}
	console.log(`x86 current-producer regression passed with honest native-quality barrier: ${metadata.function} ${metadata.irSha256}`);
}

main().catch(error => {
	console.error(error);
	process.exitCode = 1;
});
