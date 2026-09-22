/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';

export type PipelineArtifactKind = 'llvm-ir' | 'c-source' | 'json' | 'text' | 'binary' | 'failed-output';
export interface PipelineArtifactProducer {
	outputPath?: string;
	status?: 'ok' | 'partial' | 'error' | 'skipped';
	artifactKind?: PipelineArtifactKind;
	executionOrdinal?: number;
}

export interface PipelineArtifactBinding extends PipelineArtifactProducer {
	path: string;
	sha256: string;
	targetIdentity?: string;
	sessionId?: string;
	generation?: number;
	universeSha256?: string;
	producerCommand?: string;
}
const trustedBindingSets = new WeakSet<object>();

export function isTrustedPipelineArtifactBindings(value: unknown): value is readonly PipelineArtifactBinding[] {
	return Array.isArray(value) && trustedBindingSets.has(value);
}

/** Only a downgrade is consumed from the runner's input-quality envelope. */
export function pipelineInputPartialReasons(value: unknown): string[] {
	if (!value || typeof value !== 'object' || (value as { status?: unknown }).status !== 'partial') { return []; }
	const raw = (value as { reasons?: unknown }).reasons;
	const reasons = Array.isArray(raw) ? raw.filter((reason): reason is string => typeof reason === 'string' && reason.length > 0) : [];
	return reasons.length ? [...new Set(reasons)] : ['Partial input artifact'];
}

export function producerArtifactKind(command: string, captureKind: 'json' | 'text' | 'binary' | undefined, status: string): PipelineArtifactKind {
	if (status !== 'ok' && status !== 'partial') { return 'failed-output'; }
	if (['hexcore.disasm.liftToIR', 'hexcore.disasm.liftMemoryHeadless', 'hexcore.souper.optimize'].includes(command)) { return 'llvm-ir'; }
	if (['hexcore.helix.decompile', 'hexcore.helix.decompileIR', 'hexcore.rellic.decompile', 'hexcore.rellic.decompileIR'].includes(command)) { return 'c-source'; }
	return captureKind ?? 'text';
}

export function assertProducerUsable(producer: PipelineArtifactProducer, label: string, allowPartial: boolean): boolean {
	if (producer.status === 'error' || producer.status === 'skipped' || producer.artifactKind === 'failed-output') {
		throw new Error(`upstream-artifact-unavailable: ${label} producer is ${producer.status ?? 'failed'}`);
	}
	if (producer.status === 'partial' && !allowPartial) {
		throw new Error(`upstream-artifact-partial: ${label} requires allowPartial: true on the consumer`);
	}
	return producer.status === 'partial';
}

function pathKey(value: string): string {
	const resolved = path.resolve(value);
	return process.platform === 'win32' ? resolved.toLowerCase() : resolved;
}

/** Validate explicit inputs, including literal paths that bypass $step interpolation. */
export async function validatePipelineArtifactInputs(
	options: Record<string, unknown>, producers: readonly (PipelineArtifactProducer | undefined)[], allowPartial: boolean,
	baseDirectory = process.cwd(),
): Promise<string[]> {
	const byPath = new Map<string, PipelineArtifactProducer>();
	for (const producer of producers) {
		if (producer?.outputPath) {
			const key = pathKey(producer.outputPath);
			const prior = byPath.get(key);
			if (!prior || (producer.executionOrdinal ?? 0) >= (prior.executionOrdinal ?? 0)) { byPath.set(key, producer); }
		}
	}
	const reasons: string[] = [];
	const files = new Map<string, boolean>();
	const visit = (value: unknown, key: string): void => {
		if (typeof value === 'string' && value.length <= 32767 && !/[\r\n\0]/.test(value)) {
			const producer = byPath.get(pathKey(value)) ?? byPath.get(pathKey(path.resolve(baseDirectory, value)));
			if (producer && assertProducerUsable(producer, value, allowPartial)) { reasons.push(`Partial input: ${value}`); }
			const resolved = key === 'irPath' ? path.resolve(baseDirectory, value) : path.resolve(value);
			if (fs.existsSync(resolved) && fs.statSync(resolved).isFile()) {
				files.set(resolved, files.get(resolved) === true || key === 'irPath');
			}
		} else if (Array.isArray(value)) {
			for (const item of value) { visit(item, key); }
		} else if (value && typeof value === 'object') {
			for (const [childKey, item] of Object.entries(value)) { visit(item, childKey); }
		}
	};
	// Output and target identity are not consumer artifact inputs.
	for (const [key, value] of Object.entries(options)) {
		if (!['file', 'output', 'quiet', 'irText'].includes(key)) { visit(value, key); }
	}
	if (typeof options.irText === 'string') { inspectTextInput(options.irText, '<inline IR>', true, allowPartial, reasons); }
	for (const [value, expectedIr] of files) {
		const producer = byPath.get(pathKey(value));
		if (expectedIr && producer?.artifactKind && producer.artifactKind !== 'llvm-ir') {
			throw new Error(`upstream-artifact-kind: ${value} is ${producer.artifactKind}, expected llvm-ir`);
		}
		const fd = fs.openSync(value, 'r');
		try {
			const prefix = Buffer.alloc(64 * 1024);
			const count = fs.readSync(fd, prefix, 0, prefix.length, 0);
			inspectTextInput(prefix.subarray(0, count).toString('utf8'), value, expectedIr, allowPartial, reasons);
		} finally { fs.closeSync(fd); }
		const persisted = await persistedProducer(value, baseDirectory);
		if (persisted) {
			if (assertProducerUsable(persisted, value, allowPartial)) { reasons.push(`Partial persisted input: ${value}`); }
			if (expectedIr && persisted.artifactKind && persisted.artifactKind !== 'llvm-ir') {
				throw new Error(`upstream-artifact-kind: ${value} is ${persisted.artifactKind}, expected llvm-ir`);
			}
		}
	}
	return [...new Set(reasons)];
}

async function persistedProducer(inputPath: string, root: string): Promise<PipelineArtifactBinding | undefined> {
	let directory = path.dirname(inputPath);
	for (let depth = 0; depth < 16; depth++) {
		const manifestPath = path.join(directory, '.hexcore-meta', 'provenance.json');
		if (fs.existsSync(manifestPath)) {
			if (fs.statSync(manifestPath).size > 16 * 1024 * 1024) { throw new Error('upstream-artifact-provenance: manifest budget exceeded'); }
			let manifest: any;
			try { manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8')); }
			catch { throw new Error(`upstream-artifact-provenance: unreadable ${manifestPath}`); }
			if (!manifest || typeof manifest !== 'object' || !Array.isArray(manifest.artifacts)) { throw new Error(`upstream-artifact-provenance: invalid ${manifestPath}`); }
			const entries = manifest.artifacts.filter((entry: any) => typeof entry?.artifact?.path === 'string' && pathKey(entry.artifact.path) === pathKey(inputPath));
			if (entries.length > 1) { throw new Error(`upstream-artifact-provenance: ambiguous producer for ${inputPath}`); }
			if (entries.length === 1) {
				const entry = entries[0];
				const hash = crypto.createHash('sha256');
				for await (const chunk of fs.createReadStream(inputPath)) { hash.update(chunk); }
				if (hash.digest('hex') !== String(entry.artifact.sha256).toLowerCase()) { throw new Error(`upstream-artifact-hash-mismatch: ${inputPath}`); }
				const statuses = [entry.step?.semanticStatus, entry.analysisContract?.status].filter(value => value !== undefined);
				if (statuses.some(value => !['ok', 'partial', 'error', 'failed', 'skipped'].includes(value))) {
					throw new Error(`upstream-artifact-provenance: unsupported producer state for ${inputPath}`);
				}
				const status = statuses.some(value => value === 'error' || value === 'failed' || value === 'skipped') ? 'error'
					: statuses.includes('partial') ? 'partial' : statuses.includes('ok') ? 'ok' : undefined;
				if (!status) { throw new Error(`upstream-artifact-provenance: unknown producer state for ${inputPath}`); }
				return {
					outputPath: inputPath, status,
					artifactKind: entry.step?.artifactKind ?? (typeof entry.step?.resolvedCmd === 'string'
						? producerArtifactKind(entry.step.resolvedCmd, undefined, status) : undefined),
					path: inputPath,
					sha256: String(entry.artifact.sha256).toLowerCase(),
					targetIdentity: typeof entry.analysisContract?.target?.id === 'string' ? entry.analysisContract.target.id : undefined,
					sessionId: typeof entry.analysisContract?.session?.id === 'string' ? entry.analysisContract.session.id : undefined,
					generation: Number.isSafeInteger(entry.analysisContract?.session?.generation) ? entry.analysisContract.session.generation : undefined,
					universeSha256: typeof entry.analysisUniverse?.universeSha256 === 'string' ? entry.analysisUniverse.universeSha256 : undefined,
					producerCommand: typeof entry.step?.resolvedCmd === 'string' ? entry.step.resolvedCmd : undefined,
				};
			}
		}
		const parent = path.dirname(directory);
		const relative = path.relative(path.resolve(root), parent);
		if (parent === directory || relative === '..' || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) { break; }
		directory = parent;
	}
	return undefined;
}

/** Mint runner-only ancestry objects after the normal artifact validation gate. */
export async function collectPipelineArtifactBindings(
	options: Record<string, unknown>, root = process.cwd(),
): Promise<readonly PipelineArtifactBinding[]> {
	const bindings: PipelineArtifactBinding[] = [];
	if (typeof options.irPath === 'string') {
		const inputPath = path.resolve(root, options.irPath);
		const producer = await persistedProducer(inputPath, root) as PipelineArtifactBinding | undefined;
		if (!producer?.sha256) { throw new Error(`upstream-artifact-provenance: bound producer unavailable for ${inputPath}`); }
		bindings.push(Object.freeze({ ...producer, path: inputPath }));
	}
	const result = Object.freeze(bindings);
	trustedBindingSets.add(result);
	return result;
}

function inspectTextInput(text: string, label: string, expectedIr: boolean, allowPartial: boolean, reasons: string[]): void {
	if (/^[\s\uFEFF]*[\[{]/.test(text)) {
		let record: Record<string, unknown> | undefined;
		try { record = JSON.parse(text); } catch { /* A bounded prefix is not necessarily complete JSON. */ }
		const isContract = expectedIr || record?.stub === true || record?.artifactKind === 'failed-output' ||
			(typeof record?.cmd === 'string' && record.cmd.startsWith('hexcore.')) ||
			(typeof record?.command === 'string' && record.command.startsWith('hexcore.'));
		if (isContract && record && (record.stub === true || record.ok === false || record.success === false || record.status === 'error' || record.status === 'failed')) {
			throw new Error(`upstream-artifact-error-contract: ${label} contains a producer failure`);
		}
		if (isContract && record?.status === 'partial') {
			if (!allowPartial) { throw new Error(`upstream-artifact-partial: ${label} requires allowPartial: true on the consumer`); }
			reasons.push(`Partial input artifact: ${label}`);
		}
		if (expectedIr) { throw new Error(`upstream-artifact-kind: ${label} contains JSON, expected llvm-ir`); }
	}
	if (expectedIr) {
		const state = /^; SemanticStatus:\s*(?<status>\S+)/m.exec(text)?.groups?.status;
		if (state && state !== 'ok') {
			if (state !== 'partial') { throw new Error(`upstream-artifact-unavailable: ${label} lift status is ${state}`); }
			if (!allowPartial) { throw new Error(`upstream-artifact-partial: ${label} requires allowPartial: true on the consumer`); }
			reasons.push(`Partial input lift: ${label}`);
		}
	}
}
