/*---------------------------------------------------------------------------------------------
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';

export interface AuditInputQuality {
	schemaVersion: 1;
	status: 'ok' | 'partial';
	negativeEvidenceUsable: boolean;
	scope: 'patterns-in-provided-source';
	inputSha256: string;
	producerStatus: string;
	provenancePath?: string;
	provenanceSha256?: string;
	provenanceSnapshot?: { path: string; sha256: string };
	reasons: string[];
}

function record(value: unknown): Record<string, any> | undefined {
	return value !== null && typeof value === 'object' && !Array.isArray(value)
		? value as Record<string, any> : undefined;
}

/** Check the exact input and its recorded ancestry, without executing the target. */
export function assessAuditInputQuality(
	inputPath: string, bytes: Buffer, manifest: unknown, provenancePath?: string,
): AuditInputQuality {
	const inputSha256 = crypto.createHash('sha256').update(bytes).digest('hex');
	const reasons: string[] = [];
	const entries = record(manifest)?.artifacts;
	const normalizedPath = (value: string) => process.platform === 'win32'
		? path.resolve(value).toLowerCase() : path.resolve(value);
	const artifacts: Record<string, any>[] = Array.isArray(entries)
		? entries.map(record).filter((entry): entry is Record<string, any> => Boolean(entry)) : [];
	const matches = artifacts.filter(entry => typeof entry.artifact?.path === 'string' &&
		normalizedPath(entry.artifact.path) === normalizedPath(inputPath));
	let producerStatus = 'unknown';
	if (matches.length !== 1) {
		reasons.push(matches.length ? 'ambiguous-input-provenance' : 'input-provenance-unavailable');
	} else {
		const entry = matches[0];
		if (String(entry.artifact.sha256).toLowerCase() !== inputSha256) reasons.push('input-hash-mismatch');
		producerStatus = String(entry.step?.semanticStatus ?? entry.analysisContract?.status ?? 'unknown');
		const visiting = new Set<Record<string, any>>();
		const visited = new Set<Record<string, any>>();
		const visit = (current: Record<string, any>): void => {
			if (visiting.has(current)) { reasons.push('provenance-cycle'); return; }
			if (visited.has(current)) return;
			if (visited.size >= 256) { reasons.push('provenance-budget-exceeded'); return; }
			visited.add(current);
			visiting.add(current);
			const statuses = [current.step?.semanticStatus, current.analysisContract?.status].filter(value => value !== undefined);
			if (!statuses.length || statuses.some(value => value !== 'ok')) reasons.push('upstream-not-ok');
			const target = current.analysisContract?.target?.id;
			if (target && entry.analysisContract?.target?.id && target !== entry.analysisContract.target.id) reasons.push('upstream-target-mismatch');
			for (const input of current.inputs ?? current.analysisContract?.inputs ?? []) {
				const parents = artifacts.filter(parent =>
					(typeof input.id === 'string' && parent.analysisContract?.artifact?.id === input.id) ||
					(typeof input.sha256 === 'string' && parent.artifact?.sha256 === input.sha256));
				if (parents.length !== 1) reasons.push('upstream-provenance-unresolved');
				else visit(parents[0]);
			}
			visiting.delete(current);
		};
		visit(entry);
	}
	const header = bytes.toString('utf8').slice(0, 16_384);
	if (/^\s*\/\/\s*(?:Issues:|.*\bUNDERLIFT\b)|__helix_unknown\s*\(/m.test(header)) reasons.push('decompiler-quality-warning');
	const uniqueReasons = [...new Set(reasons)].sort();
	return {
		schemaVersion: 1, status: uniqueReasons.length ? 'partial' : 'ok',
		negativeEvidenceUsable: uniqueReasons.length === 0,
		scope: 'patterns-in-provided-source', inputSha256, producerStatus,
		...(provenancePath ? { provenancePath } : {}), reasons: uniqueReasons,
	};
}

/** Search only ancestor manifests inside the permitted workspace roots. */
export function readAuditInputQuality(inputPath: string, bytes: Buffer, roots: readonly string[], snapshotDirectory?: string): AuditInputQuality {
	let directory = path.dirname(path.resolve(inputPath));
	const contained = (candidate: string) => roots.some(root => {
		const relative = path.relative(path.resolve(root), candidate);
		return relative === '' || (!path.isAbsolute(relative) && relative !== '..' && !relative.startsWith(`..${path.sep}`));
	});
	for (let depth = 0; depth < 16 && contained(directory); depth++) {
		const manifestPath = path.join(directory, '.hexcore-meta', 'provenance.json');
		if (fs.existsSync(manifestPath)) {
			try {
				if (fs.statSync(manifestPath).size > 16 * 1024 * 1024) throw new Error('manifest budget');
				const manifestBytes = fs.readFileSync(manifestPath);
				const digest = crypto.createHash('sha256').update(manifestBytes).digest('hex');
				let manifest: unknown;
				try { manifest = JSON.parse(manifestBytes.toString('utf8')); } catch { /* retain the consumed invalid revision */ }
				const result = assessAuditInputQuality(inputPath, bytes, manifest, manifestPath);
				result.provenanceSha256 = digest;
				if (manifest === undefined) result.reasons.push('provenance-unreadable');
				if (snapshotDirectory) {
					try {
						fs.mkdirSync(snapshotDirectory, { recursive: true });
						const snapshotPath = path.join(snapshotDirectory, `${digest}.json`);
						try { fs.writeFileSync(snapshotPath, manifestBytes, { flag: 'wx' }); }
						catch (error) { if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error; }
						if (crypto.createHash('sha256').update(fs.readFileSync(snapshotPath)).digest('hex') !== digest) {
							throw new Error('snapshot digest mismatch');
						}
						result.provenanceSnapshot = { path: snapshotPath, sha256: digest };
					} catch {
						result.status = 'partial'; result.negativeEvidenceUsable = false;
						result.reasons.push('provenance-snapshot-unavailable');
					}
				}
				return result;
			} catch {
				const result = assessAuditInputQuality(inputPath, bytes, undefined, manifestPath);
				result.reasons.push('provenance-unreadable');
				return result;
			}
		}
		const parent = path.dirname(directory);
		if (parent === directory) break;
		directory = parent;
	}
	return assessAuditInputQuality(inputPath, bytes, undefined);
}
