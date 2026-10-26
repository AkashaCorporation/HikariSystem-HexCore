import sqliteModule = require('hexcore-better-sqlite3');
import { assertValidSignature } from '../signatures/schema.js';
import type { HQLSignature } from '../types/hql.js';
import { assertAtlasDatabase } from './database.js';
import type { AtlasRuleRecord, AtlasSqliteModule } from './types.js';

const sqlite = sqliteModule as unknown as AtlasSqliteModule;

export function loadReleasedAtlasSignatures(databasePath: string, sqliteOverride: AtlasSqliteModule = sqlite): HQLSignature[] {
  assertAtlasDatabase(databasePath, sqliteOverride);
  const db = sqliteOverride.openDatabase(databasePath, { readonly: true, fileMustExist: true });
  try {
    const rows = db.prepare(`
      SELECT canonical_json FROM rules
      WHERE status = 'released'
      ORDER BY rule_id, version
    `).all() as Array<{ canonical_json: string }>;
    const signatures: HQLSignature[] = [];
    const ids = new Set<string>();
    for (const [index, row] of rows.entries()) {
      const record = JSON.parse(row.canonical_json) as AtlasRuleRecord;
      const signature = record.signature as HQLSignature;
      assertValidSignature(signature, `${databasePath}:rules[${index}]`);
      if (signature.id !== record.id || signature.version !== record.version || signature.status !== 'released') {
        throw new Error(`${databasePath}: indexed rule identity disagrees with its signature`);
      }
      if (ids.has(signature.id)) throw new Error(`${databasePath}: multiple released versions for ${signature.id}`);
      ids.add(signature.id);
      if (signature.calibration) {
        const benchmark = db.prepare(`
          SELECT 1 AS present FROM benchmarks
          WHERE rule_id = ? AND rule_version = ? AND corpus = ? AND corpus_sha256 = ?
          LIMIT 1
        `).get(signature.id, signature.version, signature.calibration.corpus, signature.calibration.corpusSha256) as { present?: number } | undefined;
        if (benchmark?.present !== 1) throw new Error(`${databasePath}: ${signature.id} calibration has no matching Atlas benchmark`);
      }
      signatures.push(signature);
    }
    if (signatures.length === 0) throw new Error(`${databasePath}: Atlas has no released rules`);
    return signatures;
  } finally {
    db.close();
  }
}
