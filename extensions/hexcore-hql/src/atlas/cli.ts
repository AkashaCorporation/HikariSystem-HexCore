import * as fs from 'fs';
import * as path from 'path';
import sqliteModule = require('hexcore-better-sqlite3');
import {
  assertAtlasDatabase,
  buildAtlasDatabase,
  exportAtlasDatabaseJson,
} from './database.js';
import type { AtlasSqliteModule } from './types.js';

const sqlite = sqliteModule as unknown as AtlasSqliteModule;
const packageRoot = path.resolve(__dirname, '..', '..');
const outputPath = path.resolve(process.argv[3] ?? path.join(packageRoot, 'dist', 'hql-atlas.sqlite'));
const command = process.argv[2] ?? 'build';

if (command === 'build') {
  fs.mkdirSync(path.dirname(outputPath), { recursive: true });
  const manifest = buildAtlasDatabase({
    sourceRoot: packageRoot,
    outputPath,
    sqliteModule: sqlite,
    replaceExisting: true,
  });
  const canonical = exportAtlasDatabaseJson(outputPath, sqlite);
  fs.writeFileSync(`${outputPath}.manifest.json`, `${JSON.stringify(manifest, null, 2)}\n`, 'utf8');
  fs.writeFileSync(`${outputPath}.canonical.json`, `${canonical}\n`, 'utf8');
  console.log(`HQL Atlas built: ${outputPath}`);
  console.log(`logicalSha256=${manifest.logicalSha256} rules=${manifest.rowCounts.rules} fixtures=${manifest.rowCounts.fixtures}`);
} else if (command === 'verify') {
  const report = assertAtlasDatabase(outputPath, sqlite);
  console.log(`HQL Atlas verified: ${outputPath}`);
  console.log(`logicalSha256=${report.logicalSha256} rules=${report.rowCounts.rules} fixtures=${report.rowCounts.fixtures}`);
} else if (command === 'export') {
  process.stdout.write(`${exportAtlasDatabaseJson(outputPath, sqlite)}\n`);
} else {
  throw new Error(`Unknown Atlas command ${command}; expected build, verify, or export`);
}
