/*---------------------------------------------------------------------------------------------
 *  Copyright (c) HikariSystem. All rights reserved.
 *--------------------------------------------------------------------------------------------*/

import * as assert from 'assert';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { findRecordedAutoRunAttempt, recoverStaleAutoRunAttempt } from './autoRunAttempt';

suite('persistent watcher attempt deduplication', () => {
	test('skips an unchanged job already represented by running status', () => {
		const root = fs.mkdtempSync(path.join(os.tmpdir(), 'hexcore-autorun-'));
		try {
			const jobPath = path.join(root, '.hexcore_job.json');
			const outDir = path.join(root, 'reports');
			fs.mkdirSync(outDir);
			fs.writeFileSync(jobPath, JSON.stringify({ file: 'target.exe', outDir: './reports', steps: [{}] }));
			const jobTime = new Date('2026-08-09T12:00:00.000Z');
			fs.utimesSync(jobPath, jobTime, jobTime);
			fs.writeFileSync(path.join(outDir, 'hexcore-pipeline.status.json'), JSON.stringify({
				jobFile: jobPath,
				status: 'running',
				startedAt: '2026-08-09T12:00:01.000Z',
			}));
			const attempt = findRecordedAutoRunAttempt(jobPath, Date.parse('2026-08-09T12:01:00.000Z'));
			assert.strictEqual(attempt?.status, 'running');
			assert.strictEqual(attempt?.stale, false);
		} finally {
			fs.rmSync(root, { recursive: true, force: true });
		}
	});

	test('archives and terminates a stale running status so startup can retry', () => {
		const root = fs.mkdtempSync(path.join(os.tmpdir(), 'hexcore-autorun-'));
		try {
			const jobPath = path.join(root, '.hexcore_job.json');
			const outDir = path.join(root, 'reports');
			fs.mkdirSync(outDir);
			fs.writeFileSync(jobPath, JSON.stringify({ file: 'target.exe', outDir: './reports', steps: [{}] }));
			const jobTime = new Date('2026-08-09T12:00:00.000Z');
			fs.utimesSync(jobPath, jobTime, jobTime);
			const statusPath = path.join(outDir, 'hexcore-pipeline.status.json');
			fs.writeFileSync(statusPath, JSON.stringify({
				jobFile: jobPath, status: 'running', startedAt: '2026-08-09T12:00:01.000Z',
			}));
			const attempt = findRecordedAutoRunAttempt(jobPath, Date.parse('2026-08-09T12:20:01.000Z'), 15 * 60_000);
			assert.strictEqual(attempt?.stale, true);
			const recovered = recoverStaleAutoRunAttempt(attempt!);
			assert.strictEqual(recovered.recovered, true);
			assert.ok(recovered.archivePath && fs.existsSync(recovered.archivePath));
			const archived = JSON.parse(fs.readFileSync(recovered.archivePath!, 'utf8'));
			const expectedJobHash = crypto.createHash('sha256').update(fs.readFileSync(jobPath)).digest('hex');
			assert.strictEqual(archived.jobFileSha256, expectedJobHash);
			assert.strictEqual(archived.recoveryArchive.jobFileSha256, expectedJobHash);
			assert.strictEqual(archived.recoveryArchive.kind, 'stale-running');
			assert.match(archived.recoveryArchive.reason, /prior Extension Host/);
			const status = JSON.parse(fs.readFileSync(statusPath, 'utf8'));
			assert.strictEqual(status.status, 'error');
			assert.strictEqual(status.jobFileSha256, expectedJobHash);
			assert.strictEqual(status.recovery.kind, 'stale-running');
		} finally {
			fs.rmSync(root, { recursive: true, force: true });
		}
	});

	test('allows auto-run after the job file is edited', () => {
		const root = fs.mkdtempSync(path.join(os.tmpdir(), 'hexcore-autorun-'));
		try {
			const jobPath = path.join(root, '.hexcore_job.json');
			const outDir = path.join(root, 'reports');
			fs.mkdirSync(outDir);
			fs.writeFileSync(jobPath, JSON.stringify({ file: 'target.exe', outDir: './reports', steps: [{}] }));
			fs.writeFileSync(path.join(outDir, 'hexcore-pipeline.status.json'), JSON.stringify({
				jobFile: jobPath,
				status: 'error',
				startedAt: '2026-08-09T12:00:00.000Z',
			}));
			const edited = new Date('2026-08-09T12:00:01.000Z');
			fs.utimesSync(jobPath, edited, edited);
			assert.strictEqual(findRecordedAutoRunAttempt(jobPath), undefined);
		} finally {
			fs.rmSync(root, { recursive: true, force: true });
		}
	});

	test('does not suppress a different job body when a hash is recorded', () => {
		const root = fs.mkdtempSync(path.join(os.tmpdir(), 'hexcore-autorun-'));
		try {
			const jobPath = path.join(root, '.hexcore_job.json');
			const outDir = path.join(root, 'reports');
			fs.mkdirSync(outDir);
			fs.writeFileSync(jobPath, JSON.stringify({ file: 'target.exe', outDir: './reports', steps: [{ cmd: 'new' }] }));
			const old = new Date('2026-08-09T12:00:00.000Z');
			fs.utimesSync(jobPath, old, old);
			fs.writeFileSync(path.join(outDir, 'hexcore-pipeline.status.json'), JSON.stringify({
				jobFile: jobPath,
				jobFileSha256: '0'.repeat(64),
				status: 'running',
				startedAt: '2026-08-09T12:00:01.000Z',
			}));
			assert.strictEqual(findRecordedAutoRunAttempt(jobPath), undefined);
		} finally {
			fs.rmSync(root, { recursive: true, force: true });
		}
	});
});
