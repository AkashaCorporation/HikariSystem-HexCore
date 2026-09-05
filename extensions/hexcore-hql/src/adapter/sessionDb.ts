// ─── Session DB Reader for HQL ───
// Opens the disassembler's .hexcore_session.db in read-only mode to
// enrich HAST hydration with analyst-defined renames and retypes.
// WAL mode allows concurrent reads while the disassembler writes.

/** Function rename/retype from the session database. */
export interface SessionFunctionEntry {
  address: string;
  name: string | null;
  return_type: string | null;
}

/** Variable rename/retype from the session database. */
export interface SessionVariableRename {
  original_name: string;
  new_name: string | null;
  new_type: string | null;
}

// ── SQLite type interfaces (minimal, matches hexcore-better-sqlite3 API) ──

interface SqlitePreparedStatement {
  get(...params: unknown[]): unknown;
  all(...params: unknown[]): unknown[];
}

interface SqliteDatabase {
  prepare(sql: string): SqlitePreparedStatement;
  close(): void;
  readonly open: boolean;
}

export interface HexcoreBetterSqlite3Module {
  openDatabase(filename: string, options?: { readonly?: boolean; fileMustExist?: boolean }): SqliteDatabase;
}

import type { HQLSemanticFact, HQLSemanticFactKind } from '../types/hql.js';

function asRecord(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : undefined;
}

function proofStatus(strength: string): HQLSemanticFact['proofStatus'] {
  return strength === 'definitive' || strength === 'debug' ? 'proven' : strength === 'signature' || strength === 'derived' ? 'candidate' : 'signal';
}

/**
 * Read-only accessor for the disassembler's session database.
 * Use this to enrich HAST hydration with analyst renames/retypes.
 *
 * @example
 * ```ts
 * const reader = new SessionDbReader('/path/to/.hexcore_session.db');
 * const name = reader.getFunctionName('0x14003EDD0');
 * reader.dispose();
 * ```
 */
export class SessionDbReader {
  private db: SqliteDatabase;
  private semanticReadErrors: string[] = [];
  private readonly getFuncStmt: SqlitePreparedStatement;
  private readonly getVarsStmt: SqlitePreparedStatement;
  private readonly getRetypeStmt: SqlitePreparedStatement;

  constructor(
    private readonly dbPath: string,
    private readonly sqliteModule: HexcoreBetterSqlite3Module,
  ) {
    this.db = sqliteModule.openDatabase(dbPath, { readonly: true, fileMustExist: true });

    this.getFuncStmt = this.db.prepare(
      `SELECT name, return_type FROM functions WHERE address = ?`
    );
    this.getVarsStmt = this.db.prepare(
      `SELECT original_name, new_name, new_type FROM variables WHERE func_address = ?`
    );
    this.getRetypeStmt = this.db.prepare(
      `SELECT return_type FROM functions WHERE address = ?`
    );
  }

  /**
   * Get the analyst-defined name for a function, or undefined if not renamed.
   */
  getFunctionName(address: string): string | undefined {
    const row = this.getFuncStmt.get(address) as { name: string | null; return_type: string | null } | undefined;
    return row?.name ?? undefined;
  }

  /**
   * Get the analyst-defined return type for a function.
   */
  getFunctionReturnType(address: string): string | undefined {
    const row = this.getRetypeStmt.get(address) as { return_type: string | null } | undefined;
    return row?.return_type ?? undefined;
  }

  /**
   * Get all variable renames/retypes for a given function.
   */
  getVariableRenames(funcAddress: string): SessionVariableRename[] {
    return this.getVarsStmt.all(funcAddress) as SessionVariableRename[];
  }

  /** Exact HXDB target identity used to bind this read-only view to a binary. */
  getTargetIdentity(): string | undefined {
    try {
      const row = this.db.prepare(`SELECT value FROM hxdb_meta WHERE key = 'target_identity'`).get() as { value?: unknown } | undefined;
      return typeof row?.value === 'string' ? row.value : undefined;
    } catch {
      return undefined;
    }
  }

  /** Read typed HXDB facts for one exact function generation. */
  getSemanticFacts(funcAddress: string): HQLSemanticFact[] {
    this.semanticReadErrors = [];
    const address = funcAddress.toLowerCase();
    const functionIdentity = `function:${address}`;
    const facts: HQLSemanticFact[] = [];
    const readSnapshot = (): Record<string, unknown[]> => {
      let semanticDb: SqliteDatabase | undefined;
      try {
        semanticDb = this.sqliteModule.openDatabase(this.dbPath, { readonly: true, fileMustExist: true });
        const statement = semanticDb.prepare(`
          SELECT
            (SELECT json_group_array(record_json) FROM function_prototypes
              WHERE target_identity = (SELECT value FROM hxdb_meta WHERE key='target_identity')
                AND (function_identity = ? OR function_address = ?)) AS prototypes_json,
            (SELECT json_group_array(record_json) FROM type_bindings
              WHERE target_identity = (SELECT value FROM hxdb_meta WHERE key='target_identity')
                AND function_identity = ?) AS bindings_json,
            (SELECT json_group_array(record_json) FROM reference_edges
              WHERE analysis_target_identity = (SELECT value FROM hxdb_meta WHERE key='target_identity')
                AND active = 1 AND (owner_function_identity = ? OR target_identity_value = ?)) AS references_json,
            (SELECT json_group_array(record_json) FROM propagation_summaries
              WHERE analysis_target_identity = (SELECT value FROM hxdb_meta WHERE key='target_identity')
                AND function_identity = ?) AS summaries_json,
            (SELECT json_group_array(json_object(
                'fact_kind', fact_kind, 'fact_key', fact_key, 'reason', reason,
                'winner_hash', winner_hash, 'loser_hash', loser_hash))
              FROM fact_conflicts
              WHERE target_identity = (SELECT value FROM hxdb_meta WHERE key='target_identity')
                AND fact_key IN (?, ?)) AS conflicts_json
        `);
        if (!statement || typeof statement.get !== 'function') {
          throw new Error('native SQLite wrapper did not return a readable statement');
        }
        const row = asRecord(statement.get(
          functionIdentity, address, functionIdentity, functionIdentity,
          functionIdentity, functionIdentity, functionIdentity, address,
        )) ?? {};
        const records = (field: string): unknown[] => {
          const raw = row[field];
          if (typeof raw !== 'string') return [];
          try {
            const parsed = JSON.parse(raw);
            return Array.isArray(parsed) ? parsed.map(record_json => ({ record_json })) : [];
          } catch { return []; }
        };
        const conflicts = (() => {
          const raw = row.conflicts_json;
          if (typeof raw !== 'string') return [];
          try { const parsed = JSON.parse(raw); return Array.isArray(parsed) ? parsed : []; } catch { return []; }
        })();
        return {
          'function-prototype': records('prototypes_json'),
          'type-binding': records('bindings_json'),
          'reference-edge': records('references_json'),
          'propagation-summary': records('summaries_json'),
          'semantic-conflict': conflicts,
        };
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        this.semanticReadErrors.push(`semantic-snapshot: ${message}`);
        return {};
      } finally {
        try { semanticDb?.close(); } catch { /* best-effort read connection */ }
      }
    };
    const parse = (row: unknown): Record<string, unknown> | undefined => {
      const raw = asRecord(row)?.record_json;
      if (typeof raw !== 'string') return undefined;
      try { return asRecord(JSON.parse(raw)); } catch { return undefined; }
    };
    const append = (kind: HQLSemanticFactKind, attributes: Record<string, string | number | boolean>, record: Record<string, unknown>, fallbackProof: HQLSemanticFact['proofStatus'] = 'candidate'): void => {
      const evidenceSet = Array.isArray(record.evidenceSet) ? record.evidenceSet.map(asRecord).filter((item): item is Record<string, unknown> => Boolean(item)) : [];
      const evidence = asRecord(record.evidence);
      const allEvidence = evidenceSet.length > 0 ? evidenceSet : evidence ? [evidence] : [];
      const provenance = allEvidence.map(item => ({
        producer: String(item.producer ?? 'unknown'), source: String(item.source ?? 'unknown'), strength: String(item.strength ?? 'unknown'), generation: Number(item.generation ?? 0),
      }));
      const strongest = provenance[0]?.strength;
      facts.push({ kind, attributes, proofStatus: strongest ? proofStatus(strongest) : fallbackProof, provenance });
    };
    // One statement produces the complete semantic snapshot. This avoids the
    // Electron addon's transient-statement lifetime limit and makes zero facts
    // distinguishable from a failed read.
    const snapshot = readSnapshot();
    const from = (kind: string): unknown[] => snapshot[kind] ?? [];
    for (const row of from('function-prototype')) {
      const record = parse(row); if (!record) continue;
      append('function-prototype', {
        functionIdentity: String(record.functionIdentity ?? functionIdentity), callingConventionId: String(record.callingConventionId ?? 'unknown'),
        returnTypeId: String(record.returnTypeId ?? 'unknown'), variadic: record.variadic === true, noreturn: record.noreturn === true, method: record.method === true,
        provider: String(asRecord(record.evidence)?.producer ?? 'unknown'), evidenceStrength: String(asRecord(record.evidence)?.strength ?? 'unknown'), generation: Number(asRecord(record.evidence)?.generation ?? 0),
      }, record);
    }
    for (const row of from('type-binding')) {
      const record = parse(row); if (!record) continue;
      append('type-binding', {
        bindingId: String(record.bindingId ?? ''), scope: String(record.scope ?? ''), valueIdentity: String(record.valueIdentity ?? ''), typeId: String(record.typeId ?? ''),
        functionIdentity, provider: String(asRecord(record.evidence)?.producer ?? 'unknown'), evidenceStrength: String(asRecord(record.evidence)?.strength ?? 'unknown'), generation: Number(asRecord(record.evidence)?.generation ?? 0),
      }, record);
    }
    for (const row of from('reference-edge')) {
      const record = parse(row); if (!record) continue;
      const source = asRecord(record.source) ?? {}; const target = asRecord(record.target) ?? {};
      const relation = String(record.relation ?? 'unknown');
      append('xref', {
        relation, family: String(record.family ?? 'unknown'), sourceAddress: String(source.address ?? ''), targetKind: String(target.kind ?? ''), targetIdentity: String(target.identity ?? ''),
        ...(target.address ? { targetAddress: String(target.address) } : {}), ...(record.accessWidthBits !== null && record.accessWidthBits !== undefined ? { accessWidthBits: Number(record.accessWidthBits) } : {}),
        provider: String(asRecord(record.evidence)?.producer ?? 'unknown'), evidenceStrength: String(asRecord(record.evidence)?.strength ?? 'unknown'), generation: Number(record.generation ?? 0),
      }, record);
      const resolutions = Array.isArray(record.indirectResolutionSet) ? record.indirectResolutionSet.map(asRecord).filter((item): item is Record<string, unknown> => Boolean(item)) : [];
      for (const resolution of resolutions) append('indirect-target', {
        relation, sourceAddress: String(source.address ?? ''), targetIdentity: String(target.identity ?? ''), status: String(resolution.status ?? ''),
        resolutionSource: String(resolution.source ?? ''), candidateSetId: String(resolution.candidateSetId ?? ''), provider: String(asRecord(record.evidence)?.producer ?? 'unknown'), generation: Number(record.generation ?? 0),
      }, record, resolution.status === 'resolved' ? 'proven' : 'candidate');
    }
    for (const row of from('propagation-summary')) {
      const record = parse(row); if (!record) continue;
      const generation = Number(record.generation ?? 0);
      for (const call of Array.isArray(record.calls) ? record.calls.map(asRecord).filter(Boolean) as Record<string, unknown>[] : []) append('summary-call', {
        callsiteIdentity: String(call.callsiteIdentity ?? ''), calleeIdentity: String(call.calleeIdentity ?? ''), argumentCount: Array.isArray(call.arguments) ? call.arguments.length : 0,
        indirectCandidateCount: Array.isArray(call.indirectCandidates) ? call.indirectCandidates.length : 0, generation,
      }, record);
      for (const global of Array.isArray(record.globalEffects) ? record.globalEffects.map(asRecord).filter(Boolean) as Record<string, unknown>[] : []) append('summary-global', { globalIdentity: String(global.globalIdentity ?? ''), access: String(global.access ?? ''), generation }, record);
      for (const ownership of Array.isArray(record.ownershipEffects) ? record.ownershipEffects.map(asRecord).filter(Boolean) as Record<string, unknown>[] : []) append('summary-ownership', { ownershipKind: String(ownership.kind ?? ''), valueIdentity: String(asRecord(ownership.value)?.identity ?? ''), ...(ownership.objectIdentity ? { objectIdentity: String(ownership.objectIdentity) } : {}), generation }, record);
      for (const field of Array.isArray(record.fieldAccesses) ? record.fieldAccesses.map(asRecord).filter(Boolean) as Record<string, unknown>[] : []) append('summary-field', { fieldIdentity: String(field.fieldIdentity ?? ''), baseIdentity: String(asRecord(field.base)?.identity ?? ''), offsetBytes: Number(field.offsetBytes ?? 0), access: String(field.access ?? ''), ...(field.typeId ? { typeId: String(field.typeId) } : {}), generation }, record);
      for (const barrier of Array.isArray(record.barriers) ? record.barriers.map(asRecord).filter(Boolean) as Record<string, unknown>[] : []) append('summary-barrier', { barrierIdentity: String(barrier.identity ?? ''), reason: String(barrier.reason ?? ''), lossy: barrier.lossy === true, generation }, record, 'signal');
    }
    for (const row of from('semantic-conflict')) {
      const record = asRecord(row); if (!record) continue;
      facts.push({ kind: 'semantic-conflict', attributes: { factKind: String(record.fact_kind ?? ''), factKey: String(record.fact_key ?? ''), reason: String(record.reason ?? ''), winnerHash: String(record.winner_hash ?? ''), loserHash: String(record.loser_hash ?? '') }, proofStatus: 'signal', provenance: [] });
    }
    return facts.sort((left, right) => JSON.stringify(left).localeCompare(JSON.stringify(right)));
  }

  getSemanticReadErrors(): string[] {
    return [...this.semanticReadErrors];
  }

  /**
   * Close the read-only database connection.
   */
  dispose(): void {
    try {
      if (this.db.open) {
        this.db.close();
      }
    } catch {
      // best-effort
    }
  }
}
