/*---------------------------------------------------------------------------------------------
 *  Copyright (c) HikariSystem. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import * as fs from 'fs';
import * as path from 'path';

/**
 * A single annotation entry tied to an assembly address.
 */
export interface AnnotationEntry {
	address: string;    // hex string "0x00401000"
	comment: string;
	createdAt: string;  // ISO 8601
	updatedAt: string;  // ISO 8601
}

/**
 * The on-disk JSON format for the annotation file.
 */
export interface AnnotationFile {
	version: 1;
	binaryPath: string;
	annotations: Record<string, AnnotationEntry>; // key = address hex
}

const ANNOTATION_FILENAME = '.hexcore-annotations.json';
const GITIGNORE_ENTRIES = ['.hexcore-annotations.json', '.hexcore_job.json'];

/**
 * Manages persistent annotations (comments) for a disassembled binary.
 * Annotations are stored in a `.hexcore-annotations.json` file in the same
 * directory as the analysed binary.
 */
export class AnnotationStore {
	private data: AnnotationFile;
	private dirty: boolean = false;
	private gitignoreEnsured: boolean = false;

	constructor(private binaryPath: string) {
		this.data = {
			version: 1,
			binaryPath,
			annotations: {}
		};
	}

	/**
	 * Resolves the path to the `.hexcore-annotations.json` file.
	 */
	getStorePath(): string {
		const dir = path.dirname(this.binaryPath);
		return path.join(dir, ANNOTATION_FILENAME);
	}

	/**
	 * Loads annotations from disk. If the file is corrupted, creates a `.bak`
	 * backup and returns an empty annotation set. If the file does not exist,
	 * returns an empty set silently.
	 */
	load(): AnnotationFile {
		const storePath = this.getStorePath();
		try {
			if (!fs.existsSync(storePath)) {
				return this.data;
			}
			const raw = fs.readFileSync(storePath, 'utf-8');
			const parsed = JSON.parse(raw);
			if (parsed && typeof parsed === 'object' && parsed.version === 1 && parsed.annotations) {
				this.data = parsed as AnnotationFile;
			} else {
				// Invalid structure — treat as corrupted
				this.backupCorruptedFile(storePath);
				this.data = this.createEmptyFile();
			}
		} catch {
			// JSON parse error or read error — treat as corrupted if file exists
			try {
				if (fs.existsSync(storePath)) {
					this.backupCorruptedFile(storePath);
				}
			} catch {
				// Ignore backup errors
			}
			this.data = this.createEmptyFile();
		}
		return this.data;
	}

	/**
	 * Saves the current annotation data to disk.
	 * @throws Error if the file system write fails.
	 */
	save(data?: AnnotationFile): void {
		if (data) {
			this.data = data;
		}
		const storePath = this.getStorePath();
		try {
			fs.writeFileSync(storePath, JSON.stringify(this.data, null, '\t'), 'utf-8');
			this.dirty = false;
		} catch (err: any) {
			throw new Error(`Failed to save annotations to ${storePath}: ${err?.message || err}`);
		}
	}

	/**
	 * Adds or updates a comment at the given address.
	 */
	setComment(address: string, comment: string): void {
		const now = new Date().toISOString();
		const existing = this.data.annotations[address];
		this.data.annotations[address] = {
			address,
			comment,
			createdAt: existing?.createdAt ?? now,
			updatedAt: now
		};
		this.dirty = true;
		this.save();
	}

	/**
	 * Removes the comment at the given address.
	 * No-op if the address has no annotation.
	 */
	deleteComment(address: string): void {
		if (address in this.data.annotations) {
			delete this.data.annotations[address];
			this.dirty = true;
			this.save();
		}
	}

	/**
	 * Returns all annotations keyed by address.
	 */
	getAll(): Record<string, AnnotationEntry> {
		return this.data.annotations;
	}

	/**
	 * Ensures the nearest `.gitignore` contains entries for
	 * `.hexcore-annotations.json` and `.hexcore_job.json`.
	 * Idempotent — will not modify the file if entries already exist.
	 */
	ensureGitignore(): void {
		if (this.gitignoreEnsured) {
			return;
		}
		const dir = path.dirname(this.binaryPath);
		const gitignorePath = this.findNearestGitignore(dir);
		const targetPath = gitignorePath ?? path.join(dir, '.gitignore');

		try {
			let content = '';
			if (fs.existsSync(targetPath)) {
				content = fs.readFileSync(targetPath, 'utf-8');
			}

			const lines = content.split(/\r?\n/);
			const entriesToAdd: string[] = [];

			for (const entry of GITIGNORE_ENTRIES) {
				const alreadyPresent = lines.some(line => line.trim() === entry);
				if (!alreadyPresent) {
					entriesToAdd.push(entry);
				}
			}

			if (entriesToAdd.length > 0) {
				const needsNewline = content.length > 0 && !content.endsWith('\n');
				const addition = (needsNewline ? '\n' : '') +
					'# HexCore analysis files\n' +
					entriesToAdd.join('\n') + '\n';
				fs.writeFileSync(targetPath, content + addition, 'utf-8');
			}

			this.gitignoreEnsured = true;
		} catch {
			// Silently ignore gitignore errors — not critical
		}
	}

	// ── Private helpers ──────────────────────────────────────────────

	private createEmptyFile(): AnnotationFile {
		return {
			version: 1,
			binaryPath: this.binaryPath,
			annotations: {}
		};
	}

	private backupCorruptedFile(storePath: string): void {
		try {
			const bakPath = storePath + '.bak';
			fs.copyFileSync(storePath, bakPath);
		} catch {
			// Ignore backup errors
		}
	}

	/**
	 * Walks up from `startDir` looking for an existing `.gitignore`.
	 * Returns the path if found, or `undefined` if none exists.
	 */
	private findNearestGitignore(startDir: string): string | undefined {
		let current = path.resolve(startDir);
		const root = path.parse(current).root;

		while (current !== root) {
			const candidate = path.join(current, '.gitignore');
			if (fs.existsSync(candidate)) {
				return candidate;
			}
			const parent = path.dirname(current);
			if (parent === current) {
				break;
			}
			current = parent;
		}
		return undefined;
	}
}
