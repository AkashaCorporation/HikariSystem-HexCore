/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import * as crypto from 'crypto';

/** Canonical content identity shared by watcher, Agent Bridge and pipeline status. */
export function jobRevisionSha256(content: string | Buffer): string {
	return crypto.createHash('sha256').update(content).digest('hex');
}
