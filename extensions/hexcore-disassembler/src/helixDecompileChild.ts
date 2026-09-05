/*---------------------------------------------------------------------------------------------
 *  Copyright (c) HikariSystem. All rights reserved.
 *--------------------------------------------------------------------------------------------*/

import * as path from 'path';

interface DecompileRequest {
	irText: string;
	arch: number;
	modulePaths: string[];
	skipOptimization: boolean;
	useCastLayer: boolean;
	variableRenames: Array<{ oldName: string; newName: string }>;
	functionStarts: number[];
	dataSections: Array<{ vaStart: bigint; bytes: Buffer }>;
	debugTypeInfoJson: string;
}

interface NativeEngine {
	decompileIr(irText: string): unknown;
	dispose(): void;
	setSkipOptimization?(enabled: boolean): void;
	setUseCastLayer?(enabled: boolean): void;
	clearVariableRenames?(): void;
	addVariableRename?(oldName: string, newName: string): void;
	setFunctionStarts?(starts: number[]): void;
	setDebugTypeInfoJson?(json: string): void;
	clearDataSections?(): void;
	addDataSection?(vaStart: bigint, bytes: Buffer): void;
}

interface NativeBinding {
	HelixEngine: new (arch: number) => NativeEngine;
}

function reply(message: { result?: unknown; error?: string }): void {
	if (!process.send) { return; }
	process.send(message, () => process.disconnect());
}

process.once('message', (request: DecompileRequest) => {
	let engine: NativeEngine | undefined;
	try {
		let binding: NativeBinding | undefined;
		for (const modulePath of request.modulePaths) {
			try {
				binding = require(path.join(modulePath, 'index.js')) as NativeBinding;
				break;
			} catch {
				try {
					binding = require(modulePath) as NativeBinding;
					break;
				} catch { /* try the next candidate */ }
			}
		}
		if (!binding) {
			throw new Error('Failed to load hexcore-helix in isolated process');
		}

		engine = new binding.HelixEngine(request.arch);
		if (request.skipOptimization && engine.setSkipOptimization) {
			engine.setSkipOptimization(true);
		}
		if (request.useCastLayer && engine.setUseCastLayer) {
			engine.setUseCastLayer(true);
		}
		if (request.variableRenames.length > 0) {
			engine.clearVariableRenames?.();
			for (const rename of request.variableRenames) {
				engine.addVariableRename?.(rename.oldName, rename.newName);
			}
		}
		if (request.functionStarts.length > 0) {
			engine.setFunctionStarts?.(request.functionStarts);
		}
		engine.setDebugTypeInfoJson?.(request.debugTypeInfoJson);
		if (request.dataSections.length > 0) {
			engine.clearDataSections?.();
			for (const section of request.dataSections) {
				engine.addDataSection?.(section.vaStart, section.bytes);
			}
		}

		const result = engine.decompileIr(request.irText);
		engine.dispose();
		engine = undefined;
		reply({ result });
	} catch (error: unknown) {
		try { engine?.dispose(); } catch { /* process exit is the final cleanup boundary */ }
		const message = error instanceof Error ? error.message : String(error);
		reply({ error: message });
	}
});
