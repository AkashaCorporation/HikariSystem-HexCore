'use strict';

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const Module = require('module');

const target = process.argv[2];
if (!target || !fs.existsSync(target)) {
	throw new Error('Usage: node test/validate-race-worker.cjs <cl__aggressive__O0__buggy_large.exe>');
}

const originalResolveFilename = Module._resolveFilename;
Module._resolveFilename = function (request, parent, isMain, options) {
	if (request === 'vscode') { return '__vscode_mock_race_worker_acceptance__'; }
	return originalResolveFilename.call(this, request, parent, isMain, options);
};
require.cache.__vscode_mock_race_worker_acceptance__ = {
	id: '__vscode_mock_race_worker_acceptance__',
	filename: '__vscode_mock_race_worker_acceptance__',
	loaded: true,
	exports: {
		workspace: {
			getConfiguration: () => ({ get: (_key, fallback) => fallback }),
			onDidChangeConfiguration: () => ({ dispose() {} }),
		},
		commands: { executeCommand: async () => undefined },
		extensions: { getExtension: () => undefined },
		Uri: { file: file => ({ fsPath: file, scheme: 'file' }) },
	},
};

const { DisassemblerEngine } = require('../out/disassemblerEngine.js');
const { runPathfinder } = require('../out/pathfinder.js');

(async () => {
	const engine = new DisassemblerEngine();
	try {
		assert.strictEqual(await engine.loadFile(path.resolve(target)), true, 'target must load');
		await engine.analyzeAll();
		const worker = engine.getFunctionAt(0x140001200);
		assert.ok(worker, 'analyzeAll must discover race_worker at 0x140001200');
		assert.strictEqual(worker.endAddress, 0x140001210, 'worker boundary must be end-exclusive at decode_mode');
		assert.ok(worker.instructions.every(instruction => Number(instruction.address) < 0x140001210),
			'worker instructions must not bleed into decode_mode');
		const evidence = engine.functionSeeds.get(0x140001200);
		assert.ok(evidence.some(seed => seed.kind === 'address-taken' &&
			seed.sourceAddress === 0x140001e5f && seed.consumerAddress === 0x140001e66),
			'worker must retain LEA and STORE provenance');
		const hints = await runPathfinder(engine, 0x140001200, engine.getBytes(0x140001200, 0x20));
		assert.strictEqual(hints.scanEnd, 0x140001220, 'available byte window remains visible');
		assert.strictEqual(hints.ownershipEnd, 0x140001210, 'semantic ownership stops at decode_mode');
		assert.ok(hints.leaders.every(address => address < 0x140001210),
			'Pathfinder must not emit leaders owned by the adjacent function');
		assert.ok(hints.confidence < 90, 'confidence must be evidence-derived, not decode=90');
		process.stdout.write(JSON.stringify({
			target: path.resolve(target),
			functionCount: engine.getFunctions().length,
			worker: {
				start: `0x${worker.address.toString(16)}`,
				endExclusive: `0x${worker.endAddress.toString(16)}`,
				size: worker.size,
				instructionCount: worker.instructions.length,
			},
			evidence,
			pathfinder: {
				scanEnd: `0x${hints.scanEnd.toString(16)}`,
				ownershipEnd: `0x${hints.ownershipEnd.toString(16)}`,
				leaders: hints.leaders.map(address => `0x${address.toString(16)}`),
				confidence: hints.confidence,
				confidenceAxes: hints.confidenceAxes,
				confidenceReasons: hints.confidenceReasons,
			},
		}, null, 2) + '\n');
	} finally {
		engine.dispose();
	}
})().catch(error => {
	console.error(error);
	process.exitCode = 1;
});
