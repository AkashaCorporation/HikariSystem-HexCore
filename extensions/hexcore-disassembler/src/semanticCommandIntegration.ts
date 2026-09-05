/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Akasha Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as fs from 'fs';
import * as path from 'path';
import {
	SemanticCommandService,
	type SemanticCommandChangeEvent,
	type SemanticCommandServiceOptions,
} from './semanticCommandService';
import type { SessionStore } from './sessionStore';
import type { DisassemblerEngine } from './disassemblerEngine';

export type SemanticCommandOutput = string | { path?: string };

export interface SemanticCommandInvocationOptions {
	file?: string;
	output?: SemanticCommandOutput;
	quiet?: boolean;
}

export interface SemanticCommandHost {
	isFileLoaded(): boolean;
	getFilePath(): string | undefined;
	loadFile(filePath: string): Promise<unknown>;
	getSessionStore(): SessionStore | undefined;
}

export interface PreparedSemanticCommandService {
	service: SemanticCommandService;
	session: SessionStore;
}

export interface SemanticPipelineStatus {
	semanticStatus: 'ok' | 'partial';
	semanticWarning?: string;
}

const INCOMPLETE_PROPAGATION_WARNING =
	'Prototype persistence succeeded, but typed caller propagation is not yet proven. ' +
	'The R33 Reference Graph must recompute every materialized consumer before this result can be complete.';

function pathIdentity(filePath: string): string {
	const resolved = path.resolve(filePath);
	return process.platform === 'win32' ? resolved.toLowerCase() : resolved;
}

/**
 * Bind semantic commands to the requested binary before opening HXDB. A pipeline
 * step always supplies `file`; interactive calls may use the already-loaded target.
 */
export async function prepareSemanticCommandService(
	host: SemanticCommandHost,
	filePath: string | undefined,
	options: SemanticCommandServiceOptions | ((session: SessionStore) => SemanticCommandServiceOptions) = {},
): Promise<PreparedSemanticCommandService> {
	if (filePath !== undefined) {
		const requested = filePath.trim();
		if (!requested) {
			throw new Error('Semantic command target path must not be empty.');
		}
		const current = host.getFilePath();
		if (!host.isFileLoaded() || !current || pathIdentity(current) !== pathIdentity(requested)) {
			await host.loadFile(requested);
		}
		const loadedPath = host.getFilePath();
		if (!host.isFileLoaded() || !loadedPath || pathIdentity(loadedPath) !== pathIdentity(requested)) {
			throw new Error(`Semantic command failed to load the requested target: ${requested}`);
		}
	}
	if (!host.isFileLoaded()) {
		throw new Error('Load a binary or provide the pipeline file before running a semantic command.');
	}
	const session = host.getSessionStore();
	if (!session) {
		throw new Error('HXDB semantic persistence is unavailable for the active binary.');
	}
	const resolvedOptions = typeof options === 'function' ? options(session) : options;
	return { service: new SemanticCommandService(session, resolvedOptions), session };
}

/**
 * Preserve the service payload while exposing semantic completeness to the
 * automation runner. Transport success is not caller-propagation success.
 */
export function decorateSemanticCommandResult<T extends Record<string, unknown>>(result: T): T & SemanticPipelineStatus {
	const propagationComplete = result.propagationComplete;
	const changed = result.changed === true ||
		(typeof result.changedPrototypeCount === 'number' && result.changedPrototypeCount > 0);
	if (changed && propagationComplete === false) {
		return {
			...result,
			semanticStatus: 'partial',
			semanticWarning: INCOMPLETE_PROPAGATION_WARNING,
		};
	}
	return { ...result, semanticStatus: 'ok' };
}

export function resolveSemanticOutputPath(output: SemanticCommandOutput | undefined): string | undefined {
	if (typeof output === 'string') {
		const trimmed = output.trim();
		return trimmed || undefined;
	}
	if (output && typeof output.path === 'string') {
		const trimmed = output.path.trim();
		return trimmed || undefined;
	}
	return undefined;
}

/** Read an import envelope without guessing between a file path and inline JSON. */
export function readSemanticImportInput(options: {
	input?: unknown;
	inputPath?: unknown;
}): string | Record<string, unknown> {
	if (options.input !== undefined) {
		if (typeof options.input === 'string' || (options.input !== null && typeof options.input === 'object')) {
			return options.input as string | Record<string, unknown>;
		}
		throw new Error('Semantic import input must be canonical JSON text or an export object.');
	}
	if (typeof options.inputPath !== 'string' || options.inputPath.trim().length === 0) {
		throw new Error('Semantic import requires input or inputPath.');
	}
	const inputPath = path.resolve(options.inputPath);
	const stat = fs.statSync(inputPath);
	if (!stat.isFile()) {
		throw new Error(`Semantic import input is not a file: ${inputPath}`);
	}
	return fs.readFileSync(inputPath, 'utf8');
}

export function semanticCommandCallbacks(
	session: SessionStore,
	engine?: DisassemblerEngine,
): NonNullable<SemanticCommandServiceOptions['callbacks']> {
	return {
		onGeneration: event => {
			if (engine) {
				engine.advanceSemanticGeneration(`semantic-${event.command}`, event.functionIdentity);
				return;
			}
			const target = session.getAnalysisTarget();
			if (!target) {
				throw new Error('The semantic edit was stored, but no bound AnalysisTarget exists for generation tracking.');
			}
			session.advanceAnalysisGeneration(
				`semantic-${event.command}`,
				event.functionIdentity,
				session.getAnalysisUniverseManifest()?.universeSha256,
			);
		},
		onInvalidate: event => {
			const prototype = session.getSemanticStore().getPrototype(event.functionIdentity);
			const address = prototype?.functionAddress ?? event.functionIdentity.replace(/^function:/i, '');
			session.invalidateFunction(address);
		},
		...(engine ? {
			onPropagateConsumers: (event: SemanticCommandChangeEvent) => {
				const { syncWholeProgramPropagation } = require('./wholeProgramPropagationProducer') as typeof import('./wholeProgramPropagationProducer');
				const prototype = session.getSemanticStore().getPrototype(event.functionIdentity);
				const address = prototype?.functionAddress ?? event.functionIdentity;
				const changedFunction = /^function:/i.test(address)
					? address.toLowerCase()
					: /^0x[0-9a-f]+$/i.test(address) ? `function:${address.toLowerCase()}` : undefined;
				if (!changedFunction) {
					throw new Error(`Cannot map semantic identity ${event.functionIdentity} to a materialized function.`);
				}
				const result = syncWholeProgramPropagation(engine, { changedFunctions: [changedFunction] });
				if (result.references.status !== 'ok' || result.collection.status !== 'ok' || !result.run.committed
					|| !result.run.recomputedFunctions.includes(changedFunction)) {
					throw new Error(`Typed consumer closure is incomplete for ${changedFunction}.`);
				}
			},
		} : {}),
	};
}
