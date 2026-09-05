/*---------------------------------------------------------------------------------------------
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License. See License.txt in the project root.
 *--------------------------------------------------------------------------------------------*/
'use strict';
const fs = require('node:fs');
const path = require('node:path');

function verifyReleaseIdentity(product, tag) {
	const version = product.hexcoreVersion;
	// Deliberately restricted release policy, not a general SemVer parser.
	if (typeof version !== 'string' || !/^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-rc\.(0|[1-9]\d*))?$/.test(version)) {
		throw new Error('hexcoreVersion must use X.Y.Z or X.Y.Z-rc.N; four-part versions are not npm SemVer');
	}
	if (tag !== `v${version}`) throw new Error(`Release tag ${tag} does not match product v${version}`);
	return { version, tag, channel: version.includes('-rc.') ? 'release-candidate' : 'stable' };
}

if (require.main === module) {
	try {
		const product = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'product.json'), 'utf8'));
		const identity = verifyReleaseIdentity(product, process.env.HEXCORE_RELEASE_TAG);
		console.log(JSON.stringify(identity));
	} catch (error) { console.error(error.message); process.exitCode = 1; }
}
module.exports = { verifyReleaseIdentity };
