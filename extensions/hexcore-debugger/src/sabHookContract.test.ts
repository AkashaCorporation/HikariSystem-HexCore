/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as assert from 'assert';
import { createNativeSabHookView } from './unicornWrapper';

suite('SAB native hook contract', () => {
	test('passes a typed view while retaining the shared backing store', () => {
		const shared = new SharedArrayBuffer(4096);
		const view = createNativeSabHookView(shared);

		assert.ok(view instanceof Uint8Array);
		assert.strictEqual(view.buffer, shared);
		assert.strictEqual(view.byteOffset, 0);
		assert.strictEqual(view.byteLength, shared.byteLength);
		assert.strictEqual(ArrayBuffer.isView(view), true);
	});
});
