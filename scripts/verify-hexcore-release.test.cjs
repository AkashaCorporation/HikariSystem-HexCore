/*---------------------------------------------------------------------------------------------
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License. See License.txt in the project root.
 *--------------------------------------------------------------------------------------------*/
'use strict';
const assert = require('node:assert/strict');
const { verifyReleaseIdentity } = require('./verify-hexcore-release.cjs');
assert.equal(verifyReleaseIdentity({ hexcoreVersion: '3.8.4-rc.1' }, 'v3.8.4-rc.1').channel, 'release-candidate');
assert.equal(verifyReleaseIdentity({ hexcoreVersion: '3.8.4' }, 'v3.8.4').channel, 'stable');
assert.throws(() => verifyReleaseIdentity({ hexcoreVersion: '3.8.4-rc.1' }, 'v3.8.3-rc'), /does not match/);
for (const version of ['3.8.4.1', '3.8.4.rc', '3.08.4', '3.8.4-rc.01', undefined]) {
	assert.throws(() => verifyReleaseIdentity({ hexcoreVersion: version }, `v${version}`), /must use/);
}
console.log('Release identity: 8 assertions passed.');
