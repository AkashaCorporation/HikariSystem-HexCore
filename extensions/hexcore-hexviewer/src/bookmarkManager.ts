/*---------------------------------------------------------------------------------------------
 *  HexCore Hex Viewer - Bookmark Manager
 *  Manages file bookmarks with persistence
 *  Copyright (c) HikariSystem. All rights reserved.
 *--------------------------------------------------------------------------------------------*/

import * as vscode from 'vscode';

export interface Bookmark {
	offset: number;
	name: string;
	color: string;
	timestamp: number;
}

export class BookmarkManager {
	private bookmarks: Map<string, Bookmark[]> = new Map();
	private context: vscode.ExtensionContext;

	constructor(context: vscode.ExtensionContext) {
		this.context = context;
		this.loadBookmarks();
	}

	getBookmarks(filePath: string): Bookmark[] {
		return this.bookmarks.get(filePath) || [];
	}

	addBookmark(filePath: string, offset: number, name: string, color: string): Bookmark {
		const fileBookmarks = this.getBookmarks(filePath);
		
		// Check if bookmark already exists at this offset
		const existingIndex = fileBookmarks.findIndex(b => b.offset === offset);
		
		const bookmark: Bookmark = {
			offset,
			name,
			color,
			timestamp: Date.now()
		};

		if (existingIndex >= 0) {
			fileBookmarks[existingIndex] = bookmark;
		} else {
			fileBookmarks.push(bookmark);
		}

		// Sort by offset
		fileBookmarks.sort((a, b) => a.offset - b.offset);
		
		this.bookmarks.set(filePath, fileBookmarks);
		this.saveBookmarks();
		
		return bookmark;
	}

	removeBookmark(filePath: string, offset: number): void {
		const fileBookmarks = this.getBookmarks(filePath);
		const filtered = fileBookmarks.filter(b => b.offset !== offset);
		
		if (filtered.length === 0) {
			this.bookmarks.delete(filePath);
		} else {
			this.bookmarks.set(filePath, filtered);
		}
		
		this.saveBookmarks();
	}

	updateBookmark(filePath: string, offset: number, updates: Partial<Bookmark>): void {
		const fileBookmarks = this.getBookmarks(filePath);
		const bookmark = fileBookmarks.find(b => b.offset === offset);
		
		if (bookmark) {
			Object.assign(bookmark, updates);
			this.saveBookmarks();
		}
	}

	clearFileBookmarks(filePath: string): void {
		this.bookmarks.delete(filePath);
		this.saveBookmarks();
	}

	getAllBookmarkedFiles(): string[] {
		return Array.from(this.bookmarks.keys());
	}

	exportBookmarks(): string {
		const data: Record<string, Bookmark[]> = {};
		this.bookmarks.forEach((bookmarks, filePath) => {
			data[filePath] = bookmarks;
		});
		return JSON.stringify(data, null, 2);
	}

	importBookmarks(jsonData: string): void {
		try {
			const data = JSON.parse(jsonData);
			this.bookmarks.clear();
			
			for (const [filePath, bookmarks] of Object.entries(data)) {
				if (Array.isArray(bookmarks)) {
					this.bookmarks.set(filePath, bookmarks as Bookmark[]);
				}
			}
			
			this.saveBookmarks();
		} catch (e) {
			vscode.window.showErrorMessage('Failed to import bookmarks: ' + e);
		}
	}

	private loadBookmarks(): void {
		const stored = this.context.globalState.get<Record<string, Bookmark[]>>('hexcore.bookmarks');
		if (stored) {
			this.bookmarks.clear();
			for (const [filePath, bookmarks] of Object.entries(stored)) {
				this.bookmarks.set(filePath, bookmarks);
			}
		}
	}

	private saveBookmarks(): void {
		const data: Record<string, Bookmark[]> = {};
		this.bookmarks.forEach((bookmarks, filePath) => {
			data[filePath] = bookmarks;
		});
		this.context.globalState.update('hexcore.bookmarks', data);
	}
}
