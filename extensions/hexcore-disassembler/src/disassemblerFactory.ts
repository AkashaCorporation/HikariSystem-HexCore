/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import { DisassemblerEngine } from './disassemblerEngine';

/**
 * Factory class to manage DisassemblerEngine instances.
 * Implements the Singleton/Flyweight pattern to ensure we don't creating duplicate engines
 * for the same file, while allowing multiple files to be open simultaneously.
 */
export class DisassemblerFactory {
	private static instance: DisassemblerFactory;
	private engines: Map<string, DisassemblerEngine>;

	private constructor() {
		this.engines = new Map<string, DisassemblerEngine>();
	}

	/**
	 * Get the singleton factory instance
	 */
	public static getInstance(): DisassemblerFactory {
		if (!DisassemblerFactory.instance) {
			DisassemblerFactory.instance = new DisassemblerFactory();
		}
		return DisassemblerFactory.instance;
	}

	/**
	 * Get or create an engine for a specific file path context.
	 * If the engine already exists for this path, it is returned.
	 * If path is undefined, a default shared engine is returned (mostly for UI components that haven't bound to a file yet).
	 */
	public getEngine(filePath?: string): DisassemblerEngine {
		// For global UI components that need an engine instance but haven't loaded a file yet
		if (!filePath) {
			return this.getGlobalEngine();
		}

		const normalizePath = filePath.toLowerCase();

		if (!this.engines.has(normalizePath)) {
			console.log(`[DisassemblerFactory] Creating new engine for: ${filePath}`);
			const engine = new DisassemblerEngine();
			// TODO: We technically should load the file here if we changed the engine constructor
			this.engines.set(normalizePath, engine);
		}

		return this.engines.get(normalizePath)!;
	}

	/**
	 * Gets a "default" global engine for views that are not yet bound to a specific file,
	 * or for generic commands.
	 */
	private getGlobalEngine(): DisassemblerEngine {
		if (!this.engines.has('__global__')) {
			this.engines.set('__global__', new DisassemblerEngine());
		}
		return this.engines.get('__global__')!;
	}

	/**
	 * Explicitly remove an engine instance (e.g. when tab is closed)
	 */
	public disposeEngine(filePath: string): void {
		const normalizePath = filePath.toLowerCase();
		const engine = this.engines.get(normalizePath);
		if (engine) {
			engine.dispose();
			this.engines.delete(normalizePath);
			console.log(`[DisassemblerFactory] Disposed engine for: ${filePath}`);
		}
	}

	public disposeAll(): void {
		for (const engine of this.engines.values()) {
			engine.dispose();
		}
		this.engines.clear();
	}
}

