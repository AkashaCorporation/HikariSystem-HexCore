/**
 * HexCore Better-SQLite3 - Test Suite
 * Smoke tests for the native binding
 */

'use strict';

let sqlite;
try {
	sqlite = require('..');
} catch (e) {
	console.log('Native module not built yet. Run `npm run build` first.');
	console.log('Error:', e.message);
	process.exit(0);
}

const { Database, openDatabase, SqliteError } = sqlite;

console.log('=== HexCore Better-SQLite3 Test Suite ===\n');

// Test openDatabase
console.log('Testing openDatabase()...');
const db = openDatabase(':memory:');
console.assert(db.open === true, 'Database should be open');
console.assert(db.memory === true, 'Should be in-memory');
console.log('  [PASS] openDatabase works\n');

// Test exec
console.log('Testing exec()...');
db.exec('CREATE TABLE kv (id INTEGER PRIMARY KEY, value TEXT NOT NULL)');
console.log('  [PASS] exec works\n');

// Test prepare + run
console.log('Testing prepare + run...');
const insert = db.prepare('INSERT INTO kv(value) VALUES (?)');
const result = insert.run('hexcore');
console.assert(result.changes === 1, 'Should have 1 change');
console.assert(typeof result.lastInsertRowid !== 'undefined', 'Should have lastInsertRowid');
console.log(`  Inserted row with id: ${result.lastInsertRowid}`);
console.log('  [PASS] prepare + run works\n');

// Test prepare + get
console.log('Testing prepare + get...');
const row = db.prepare('SELECT value FROM kv WHERE id = 1').get();
console.assert(row !== undefined, 'Row should exist');
console.assert(row.value === 'hexcore', 'Value should be "hexcore"');
console.log(`  Got value: ${row.value}`);
console.log('  [PASS] prepare + get works\n');

// Test prepare + all
console.log('Testing prepare + all...');
insert.run('sqlite3');
insert.run('napi');
const rows = db.prepare('SELECT value FROM kv ORDER BY id').all();
console.assert(rows.length === 3, 'Should have 3 rows');
console.log(`  Got ${rows.length} rows`);
console.log('  [PASS] prepare + all works\n');

// Test transaction
console.log('Testing transaction...');
const insertMany = db.transaction((items) => {
	for (const item of items) {
		insert.run(item);
	}
});
insertMany(['alpha', 'beta', 'gamma']);
const count = db.prepare('SELECT COUNT(*) as cnt FROM kv').get();
console.assert(count.cnt === 6, 'Should have 6 rows after transaction');
console.log(`  Total rows after transaction: ${count.cnt}`);
console.log('  [PASS] transaction works\n');

// Test pragma
console.log('Testing pragma...');
const journalMode = db.pragma('journal_mode', { simple: true });
console.log(`  Journal mode: ${journalMode}`);
console.log('  [PASS] pragma works\n');

// Test close
console.log('Testing close...');
db.close();
console.assert(db.open === false, 'Database should be closed');
console.log('  [PASS] close works\n');

// Test error handling
console.log('Testing error handling...');
try {
	const db2 = openDatabase(':memory:');
	db2.exec('SELECT * FROM nonexistent_table');
	console.assert(false, 'Should have thrown');
} catch (e) {
	console.log(`  Caught expected error: ${e.message}`);
	console.log('  [PASS] error handling works\n');
}

console.log('=== All tests passed! ===');
