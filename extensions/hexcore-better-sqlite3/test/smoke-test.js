/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
'use strict';

const path = require('path');
const Database = require(path.resolve(__dirname, '..', 'index.js'));

const db = Database.openDatabase(':memory:');

try {
	db.exec('CREATE TABLE kv (id INTEGER PRIMARY KEY, value TEXT NOT NULL);');
	const insert = db.prepare('INSERT INTO kv(value) VALUES (?)');
	insert.run('hexcore');

	const row = db.prepare('SELECT value FROM kv WHERE id = 1').get();
	if (!row || row.value !== 'hexcore') {
		throw new Error('Unexpected query result from sqlite smoke test.');
	}

	console.log('hexcore-better-sqlite3 smoke test passed');
} finally {
	db.close();
}

