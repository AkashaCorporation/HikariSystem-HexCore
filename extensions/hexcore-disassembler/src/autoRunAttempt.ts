/*---------------------------------------------------------------------------------------------
 *  Copyright (c) HikariSystem. All rights reserved.
 *--------------------------------------------------------------------------------------------*/

import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import { analysisPathIdentity } from './analysisContextOwnership';

export interface RecordedAutoRunAttempt {
	status: string;
	startedAt: string;
	statusPath: string;
	ageMs: number;
	stale: boolean;
}

export interface StaleAttemptRecovery {
	recovered: boolean;
	archivePath?: string;
	reason?: string;
}

function isRecord(value: unknown): value is Record<string, unknown> {
	return value !== null && typeof value === 'object' && !Array.isArray(value);
}

/**
 * Finds a pipeline status proving that the current on-disk job revision was
 * already attempted. Manual runs bypass this check; it exists only to stop the
 * startup watcher from replaying an unchanged root job after Extension Host reload.
 */
export function findRecordedAutoRunAttempt(
	jobFilePath: string,
	nowMs = Date.now(),
	staleRunningMs = 15 * 60_000,
): RecordedAutoRunAttempt | undefined {
	try {
		const absoluteJobPath = path.resolve(jobFilePath);
		const jobStat = fs.statSync(absoluteJobPath);
		const definition = JSON.parse(fs.readFileSync(absoluteJobPath, 'utf8')) as unknown;
		if (!isRecord(definition) || typeof definition.outDir !== 'string') { return undefined; }
		const outDir = path.isAbsolute(definition.outDir)
			? definition.outDir
			: path.resolve(path.dirname(absoluteJobPath), definition.outDir);
		const statusPath = path.join(outDir, 'hexcore-pipeline.status.json');
		if (!fs.existsSync(statusPath)) { return undefined; }
		const status = JSON.parse(fs.readFileSync(statusPath, 'utf8')) as unknown;
		if (!isRecord(status) || typeof status.jobFile !== 'string' || typeof status.startedAt !== 'string') {
			return undefined;
		}
		if (analysisPathIdentity(status.jobFile) !== analysisPathIdentity(absoluteJobPath)) {
			return undefined;
		}
		if (typeof status.jobFileSha256 === 'string') {
			const currentHash = crypto.createHash('sha256')
				.update(fs.readFileSync(absoluteJobPath))
				.digest('hex');
			if (status.jobFileSha256.toLowerCase() !== currentHash) {
				return undefined;
			}
		}
		const startedAtMs = Date.parse(status.startedAt);
		if (!Number.isFinite(startedAtMs) || startedAtMs < jobStat.mtimeMs) {
			return undefined;
		}
		const statusValue = typeof status.status === 'string' ? status.status : 'unknown';
		const ageMs = Math.max(0, nowMs - startedAtMs);
		return {
			status: statusValue,
			startedAt: status.startedAt,
			statusPath,
			ageMs,
			stale: statusValue === 'running' && ageMs >= Math.max(60_000, staleRunningMs),
		};
	} catch {
		return undefined;
	}
}

export function recoverStaleAutoRunAttempt(attempt: RecordedAutoRunAttempt): StaleAttemptRecovery {
	if (!attempt.stale || attempt.status !== 'running') {
		return { recovered: false, reason: 'attempt is not stale-running' };
	}
	try {
		const current = JSON.parse(fs.readFileSync(attempt.statusPath, 'utf8')) as unknown;
		if (!isRecord(current) || current.status !== 'running' || current.startedAt !== attempt.startedAt) {
			return { recovered: false, reason: 'status changed before recovery' };
		}
		const metaDir = path.join(path.dirname(attempt.statusPath), '.hexcore-meta');
		fs.mkdirSync(metaDir, { recursive: true });
		const stamp = attempt.startedAt.replace(/[^0-9A-Za-z.-]/g, '_');
		const archivePath = path.join(metaDir, `recovered-stale-running-${stamp}.json`);
		const recoveredAt = new Date().toISOString();
		let jobFileSha256 = typeof current.jobFileSha256 === 'string' ? current.jobFileSha256 : undefined;
		if (!jobFileSha256 && typeof current.jobFile === 'string' && fs.existsSync(current.jobFile)) {
			jobFileSha256 = crypto.createHash('sha256').update(fs.readFileSync(current.jobFile)).digest('hex');
		}
		const recoveryReason = `Recovered stale running attempt after ${attempt.ageMs}ms; prior Extension Host/process did not publish a terminal state.`;
		const archived = {
			...current,
			...(jobFileSha256 ? { jobFileSha256 } : {}),
			recoveryArchive: {
				kind: 'stale-running', archivedAt: recoveredAt, ageMs: attempt.ageMs,
				reason: recoveryReason,
				...(jobFileSha256 ? { jobFileSha256 } : {}),
			},
		};
		fs.writeFileSync(archivePath, JSON.stringify(archived, null, 2), 'utf8');
		const updated = {
			...current,
			...(jobFileSha256 ? { jobFileSha256 } : {}),
			status: 'error',
			finishedAt: recoveredAt,
			error: recoveryReason,
			recovery: {
				kind: 'stale-running', recoveredAt, ageMs: attempt.ageMs, archivedStatusPath: archivePath,
			},
		};
		const temporary = `${attempt.statusPath}.recover-${process.pid}`;
		fs.writeFileSync(temporary, JSON.stringify(updated, null, 2), 'utf8');
		fs.renameSync(temporary, attempt.statusPath);
		fs.appendFileSync(
			path.join(path.dirname(attempt.statusPath), 'hexcore-pipeline.log'),
			`[${recoveredAt}] [Recovery] Marked stale running attempt terminal; archived=${archivePath}\n`,
			'utf8',
		);
		return { recovered: true, archivePath };
	} catch (error: unknown) {
		return { recovered: false, reason: error instanceof Error ? error.message : String(error) };
	}
}
