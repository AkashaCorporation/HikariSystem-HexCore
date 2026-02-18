/*---------------------------------------------------------------------------------------------
 *  HexCore Hex Viewer Extension
 *  Copyright (c) HikariSystem. All rights reserved.
 *  Licensed under the MIT License.
 *--------------------------------------------------------------------------------------------*/

import * as vscode from 'vscode';
import * as fs from 'fs';
import * as path from 'path';
import { HexEditorProvider } from './hexEditorProvider';
import { hexDumpRange } from './hexDump';
import { hexSearchPattern } from './hexSearch';

export function activate(context: vscode.ExtensionContext): void {
	// Register internal commands FIRST - before any other extension might need them
	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.internal.goToOffset', (offset: number) => {
			const sent = HexEditorProvider.postToActiveWebview({
				type: 'jumpToOffset',
				offset: offset
			});
			if (!sent) {
				console.log('HexCore: No active hex editor to navigate');
			}
		})
	);

	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.internal.searchHex', (pattern: string) => {
			const sent = HexEditorProvider.postToActiveWebview({
				type: 'search',
				pattern: pattern
			});
			if (!sent) {
				console.log('HexCore: No active hex editor for search');
			}
		})
	);

	// Cross-extension sync command: navigate to a specific offset (called by Disassembler, Entropy, etc.)
	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.hexview.goToOffset', (offset: number) => {
			const sent = HexEditorProvider.postToActiveWebview({
				type: 'jumpToOffset',
				offset: offset
			});
			if (!sent) {
				console.log('HexCore: hexview.goToOffset — no active hex editor to navigate');
			}
		})
	);

	// Register the custom editor provider
	context.subscriptions.push(
		HexEditorProvider.register(context)
	);


	// Register commands
	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.openHexView', async (uri?: vscode.Uri) => {
			if (!uri) {
				const uris = await vscode.window.showOpenDialog({
					canSelectMany: false,
					openLabel: 'Open in Hex View',
					filters: {
						'All Files': ['*'],
						'Binary Files': ['bin', 'exe', 'dll', 'so', 'dylib'],
						'Data Files': ['dat', 'raw']
					}
				});
				if (uris && uris.length > 0) {
					uri = uris[0];
				}
			}
			if (uri) {
				await vscode.commands.executeCommand('vscode.openWith', uri, 'hexcore.hexEditor');
			}
		})
	);

	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.goToOffset', async () => {
			const input = await vscode.window.showInputBox({
				prompt: 'Enter offset (hex or decimal)',
				placeHolder: '0x1000 or 4096',
				validateInput: (value) => {
					const num = value.startsWith('0x')
						? parseInt(value, 16)
						: parseInt(value, 10);
					if (isNaN(num) || num < 0) {
						return 'Please enter a valid positive number';
					}
					return null;
				}
			});
			if (input) {
				const offset = input.startsWith('0x')
					? parseInt(input, 16)
					: parseInt(input, 10);
				// Send message to webview
				vscode.commands.executeCommand('hexcore.internal.goToOffset', offset);
			}
		})
	);

	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.searchHex', async () => {
			const input = await vscode.window.showInputBox({
				prompt: 'Enter hex pattern to search',
				placeHolder: '4D 5A 90 00 or 4D5A9000',
				validateInput: (value) => {
					const cleaned = value.replace(/\s/g, '');
					if (!/^[0-9A-Fa-f]*$/.test(cleaned)) {
						return 'Please enter valid hex characters only';
					}
					if (cleaned.length % 2 !== 0) {
						return 'Hex string must have even length';
					}
					return null;
				}
			});
			if (input) {
				vscode.commands.executeCommand('hexcore.internal.searchHex', input);
			}
		})
	);

	// Command to open file at specific offset (used by YARA, PE Analyzer, etc.)
	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.openHexViewAtOffset', async (uri: vscode.Uri, offset: number) => {
			if (!uri) {
				vscode.window.showErrorMessage('No file specified');
				return;
			}
			// Open with hex editor
			await vscode.commands.executeCommand('vscode.openWith', uri, 'hexcore.hexEditor');
			// Navigate to offset after a short delay to allow webview to load
			setTimeout(() => {
				vscode.commands.executeCommand('hexcore.internal.goToOffset', offset);
			}, 500);
		})
	);

	// Headless command: hex dump
	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.hexview.dumpHeadless', async (arg?: Record<string, unknown>) => {
			const filePath = typeof arg?.file === 'string' ? arg.file : undefined;
			if (!filePath) {
				throw new Error('dumpHeadless requires a "file" argument.');
			}

			const offset = typeof arg?.offset === 'number' ? arg.offset : 0;
			const size = typeof arg?.size === 'number' ? arg.size : 256;
			const quietMode = arg?.quiet === true;
			const outputOptions = arg?.output as { path?: string } | undefined;

			const result = hexDumpRange(filePath, offset, size);

			if (outputOptions?.path) {
				fs.mkdirSync(path.dirname(outputOptions.path), { recursive: true });
				fs.writeFileSync(outputOptions.path, JSON.stringify(result, null, 2), 'utf8');
			}

			if (!quietMode) {
				vscode.window.showInformationMessage(
					`HexCore Hex Dump: ${result.size} bytes from offset 0x${offset.toString(16).toUpperCase()}`
				);
			}

			return result;
		})
	);

	// Headless command: hex search
	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.hexview.searchHeadless', async (arg?: Record<string, unknown>) => {
			const filePath = typeof arg?.file === 'string' ? arg.file : undefined;
			if (!filePath) {
				throw new Error('searchHeadless requires a "file" argument.');
			}

			const pattern = typeof arg?.pattern === 'string' ? arg.pattern : undefined;
			if (!pattern) {
				throw new Error('searchHeadless requires a "pattern" argument.');
			}

			const maxResults = typeof arg?.maxResults === 'number' ? arg.maxResults : 1000;
			const quietMode = arg?.quiet === true;
			const outputOptions = arg?.output as { path?: string } | undefined;

			const result = hexSearchPattern(filePath, pattern, maxResults);

			if (outputOptions?.path) {
				fs.mkdirSync(path.dirname(outputOptions.path), { recursive: true });
				fs.writeFileSync(outputOptions.path, JSON.stringify(result, null, 2), 'utf8');
			}

			if (!quietMode) {
				vscode.window.showInformationMessage(
					`HexCore Hex Search: Found ${result.totalMatches} match(es) for pattern ${result.pattern}`
				);
			}

			return result;
		})
	);

	console.log('HexCore Hex Viewer extension activated');
}

export function deactivate(): void {
	// Cleanup if needed
}
