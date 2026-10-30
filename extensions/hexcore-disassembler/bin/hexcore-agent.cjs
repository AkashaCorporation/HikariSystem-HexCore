/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
'use strict';

const cli = require('../out/agentCli.js');

void cli.main(process.argv.slice(2)).then(code => {
	process.exitCode = code;
});
