/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as path from 'path';
import { DisassemblerEngine } from './disassemblerEngine';

export interface DisassemblerEngineLease {
	readonly engine: DisassemblerEngine;
	dispose(): void;
}

/**
 * Factory class to manage DisassemblerEngine instances.
 * Implements the Singleton/Flyweight pattern to ensure we don't creating duplicate engines
 * for the same file, while allowing multiple files to be open simultaneously.
 */
export class DisassemblerFactory {
	private static instance: DisassemblerFactory;
	private engines: Map<string, DisassemblerEngine>;
	private readonly pinnedKeys = new Set<string>();
	private readonly leaseCounts = new Map<string, number>();
	private readonly leaseTails = new Map<string, Promise<void>>();

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

		const key = this.normalizeKey(filePath);
		this.pinnedKeys.add(key);
		return this.getOrCreateEngine(key, filePath);
	}

	/**
	 * Acquire a transient per-file engine. Concurrent callers for the same file
	 * share one instance; the final release disposes its SessionStore and removes
	 * the engine from the cache unless an interactive owner explicitly pinned it
	 * through getEngine(filePath).
	 */
	public async acquireEngine(filePath: string): Promise<DisassemblerEngineLease> {
		const key = this.normalizeKey(filePath);
		this.leaseCounts.set(key, (this.leaseCounts.get(key) ?? 0) + 1);

		const previous = this.leaseTails.get(key) ?? Promise.resolve();
		let releaseTurn!: () => void;
		const turn = new Promise<void>(resolve => { releaseTurn = resolve; });
		const tail = previous.then(() => turn);
		this.leaseTails.set(key, tail);
		await previous;

		const engine = this.getOrCreateEngine(key, filePath);
		let released = false;
		return {
			engine,
				dispose: () => {
				if (released) {
					return;
				}
				released = true;
				const remaining = Math.max(0, (this.leaseCounts.get(key) ?? 1) - 1);
				if (remaining === 0) {
					this.leaseCounts.delete(key);
				} else {
					this.leaseCounts.set(key, remaining);
				}
				this.disposeIfUnused(key, filePath);
				releaseTurn();
				void tail.finally(() => {
					if (this.leaseTails.get(key) === tail) {
						this.leaseTails.delete(key);
					}
				});
			}
		};
	}

	/**
	 * Gets a "default" global engine for views that are not yet bound to a specific file,
	 * or for generic commands.
	 */
	private getGlobalEngine(): DisassemblerEngine {
		if (!this.engines.has('__global__')) {
			this.engines.set('__global__', new DisassemblerEngine());
		}
		this.pinnedKeys.add('__global__');
		return this.engines.get('__global__')!;
	}

	/**
	 * Explicitly remove an engine instance (e.g. when tab is closed)
	 */
	public disposeEngine(filePath: string): void {
		const key = this.normalizeKey(filePath);
		this.pinnedKeys.delete(key);
		this.disposeIfUnused(key, filePath);
	}

	public disposeAll(): void {
		for (const engine of this.engines.values()) {
			engine.dispose();
		}
		this.engines.clear();
		this.pinnedKeys.clear();
		this.leaseCounts.clear();
		this.leaseTails.clear();
	}

	private normalizeKey(filePath: string): string {
		const resolved = path.resolve(filePath);
		return process.platform === 'win32' ? resolved.toLowerCase() : resolved;
	}

	private getOrCreateEngine(key: string, displayPath: string): DisassemblerEngine {
		let engine = this.engines.get(key);
		if (!engine) {
			console.log(`[DisassemblerFactory] Creating new engine for: ${displayPath}`);
			engine = new DisassemblerEngine();
			this.engines.set(key, engine);
		}
		return engine;
	}

	private disposeIfUnused(key: string, displayPath: string): void {
		if (this.pinnedKeys.has(key) || (this.leaseCounts.get(key) ?? 0) > 0) {
			return;
		}
		const engine = this.engines.get(key);
		if (!engine) {
			return;
		}
		engine.dispose();
		this.engines.delete(key);
		console.log(`[DisassemblerFactory] Disposed engine for: ${displayPath}`);
	}
}

