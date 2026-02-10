# hexcore-better-sqlite3

HexCore wrapper for `better-sqlite3` with deterministic native prebuild packaging.

This module is intended for HexCore engines that need a local SQLite store with a stable
N-API runtime surface.

## Features

- Uses upstream `better-sqlite3` API directly.
- Adds convenience helpers:
  - `openDatabase(filename, options)`
  - `resolveNativeBinaryPath()`
- Provides `prebuild` script that:
  - rebuilds `better-sqlite3` from source
  - exports `.node` binaries to `prebuilds/<platform>-<arch>/`
  - writes `metadata.json`

## Install

```bash
npm install
```

## Build Native Binary

```bash
npm run build
```

## Generate Prebuild Payload

```bash
npm run prebuild
```

This creates:

- `prebuilds/<platform>-<arch>/node.napi.node`
- `prebuilds/<platform>-<arch>/metadata.json`

## Usage (CommonJS)

```js
const Database = require('hexcore-better-sqlite3');

const db = Database.openDatabase(':memory:');
db.exec('CREATE TABLE kv (id INTEGER PRIMARY KEY, value TEXT)');
db.prepare('INSERT INTO kv(value) VALUES (?)').run('ok');
console.log(db.prepare('SELECT * FROM kv').all());
db.close();
```

## Usage (ESM)

```js
import Database, { openDatabase } from 'hexcore-better-sqlite3';

const db = openDatabase(':memory:');
db.exec('SELECT 1');
db.close();
```

