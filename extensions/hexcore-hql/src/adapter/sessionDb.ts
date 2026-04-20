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
  private readonly getFuncStmt: SqlitePreparedStatement;
  private readonly getVarsStmt: SqlitePreparedStatement;
  private readonly getRetypeStmt: SqlitePreparedStatement;

  constructor(dbPath: string, sqliteModule: HexcoreBetterSqlite3Module) {
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
