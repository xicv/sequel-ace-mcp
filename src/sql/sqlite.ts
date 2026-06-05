import os from 'node:os';
import path from 'node:path';
import Database from 'better-sqlite3';
import type { Policy, SqlCategory, SqliteConnection } from '../types.js';
import { extractBackupSpec, isBackupRequired } from '../backup/extractor.js';
import {
  BackupOverflowError,
  captureBackupSqlite,
  captureInsertHint,
} from '../backup/capture.js';
import type { ExecuteResult } from './executor.js';

export type SqliteDatabase = Database.Database;

export interface ExecuteSqliteParams {
  connection: SqliteConnection;
  sql: string;
  category: SqlCategory;
  astType?: string;
  policy: Policy;
  database?: string;
}

const READ_ONLY_CATEGORIES: ReadonlySet<SqlCategory> = new Set(['read']);

function log(msg: string): void {
  process.stderr.write(`[sequel-mcp] ${msg}\n`);
}

export function expandSqlitePath(file: string): string {
  if (file === ':memory:') return file;
  if (file === '~') return os.homedir();
  if (file.startsWith('~/')) return path.join(os.homedir(), file.slice(2));
  return path.resolve(file);
}

export function openSqliteDatabase(args: {
  connection: SqliteConnection;
  readonly?: boolean;
  timeoutMs?: number;
}): SqliteDatabase {
  const filename = expandSqlitePath(args.connection.path);
  const db = new Database(filename, {
    readonly: args.readonly ?? false,
    fileMustExist: args.readonly ?? false,
    timeout: args.timeoutMs ?? 5000,
  });
  db.pragma(`busy_timeout = ${Math.max(args.timeoutMs ?? 5000, 1)}`);
  db.pragma('foreign_keys = ON');
  return db;
}

function fieldsFor(stmt: Database.Statement): { name: string; type?: number }[] {
  try {
    return stmt.columns().map((c) => ({ name: c.name }));
  } catch {
    return [];
  }
}

function getChangeStats(db: SqliteDatabase): { affectedRows: number; insertId: number | null } {
  const row = db
    .prepare('SELECT changes() AS affectedRows, last_insert_rowid() AS insertId')
    .get() as { affectedRows?: unknown; insertId?: unknown } | undefined;
  const affectedRows = Number(row?.affectedRows ?? 0);
  const insertIdRaw = Number(row?.insertId ?? 0);
  return {
    affectedRows: Number.isFinite(affectedRows) ? affectedRows : 0,
    insertId: Number.isFinite(insertIdRaw) && insertIdRaw > 0 ? insertIdRaw : null,
  };
}

function runPreparedStatement(args: {
  db: SqliteDatabase;
  sql: string;
  rowCap: number;
  category: SqlCategory;
}): {
  rows: Record<string, unknown>[];
  fields: { name: string; type?: number }[];
  affectedRows: number;
  truncated: boolean;
  insertId: number | null;
} {
  const stmt = args.db.prepare(args.sql);
  const fields = stmt.reader ? fieldsFor(stmt) : [];
  let rows: Record<string, unknown>[] = [];
  let affectedRows = 0;
  let insertId: number | null = null;
  let truncated = false;

  if (stmt.reader) {
    const rowsRaw = stmt.all() as Record<string, unknown>[];
    if (rowsRaw.length > args.rowCap) {
      rows = rowsRaw.slice(0, args.rowCap);
      truncated = true;
    } else {
      rows = rowsRaw;
    }
    if (args.category !== 'read') {
      const stats = getChangeStats(args.db);
      affectedRows = stats.affectedRows;
      insertId = stats.insertId;
    }
  } else {
    const result = stmt.run();
    affectedRows = result.changes;
    const id = Number(result.lastInsertRowid);
    insertId = Number.isFinite(id) && id > 0 ? id : null;
  }

  return { rows, fields, affectedRows, truncated, insertId };
}

export async function executeSqliteStatement(params: ExecuteSqliteParams): Promise<ExecuteResult> {
  const start = Date.now();
  const tag = `${params.connection.name}/${params.category}`;
  const isRead = READ_ONLY_CATEGORIES.has(params.category);
  let db: SqliteDatabase | null = null;
  let inTransaction = false;

  try {
    db = openSqliteDatabase({
      connection: params.connection,
      readonly: isRead,
      timeoutMs: params.policy.stmtTimeoutMs,
    });
    log(`${tag} opened sqlite db=${expandSqlitePath(params.connection.path)} readonly=${isRead}`);

    if (params.category !== 'txCtrl' && !isRead) {
      db.exec('BEGIN IMMEDIATE');
      inTransaction = true;
    }

    let backupId: number | null = null;
    let backupRowCount = 0;
    let pendingInsertSpec: ReturnType<typeof extractBackupSpec> | null = null;

    if (params.astType && isBackupRequired(params.astType) && db) {
      const spec = extractBackupSpec(params.sql, params.astType, { dialect: 'sqlite' });
      if (spec.kind === 'insert-hint') {
        pendingInsertSpec = spec;
        log(`${tag} INSERT detected; will capture rollback hint after execution`);
      } else if (spec.kind !== 'none') {
        try {
          log(`${tag} capturing sqlite backup for ${params.astType}...`);
          const captured = captureBackupSqlite({
            db,
            spec,
            connectionName: params.connection.name,
            database: params.database ?? params.connection.database,
            policy: params.policy,
          });
          if (captured) {
            backupId = captured.backupId;
            backupRowCount = captured.totalRows;
            log(
              `${tag} backup #${backupId}: ${captured.totalRows} rows, ${captured.totalBytes}B${captured.truncated ? ' (truncated)' : ''}`,
            );
          }
        } catch (e) {
          if (e instanceof BackupOverflowError) {
            log(`${tag} backup overflow: ${e.message}; aborting per policy`);
            throw e;
          }
          log(`${tag} backup capture failed: ${(e as Error).message}; continuing without backup`);
        }
      } else if (spec.reason) {
        log(`${tag} no backup taken: ${spec.reason}`);
      }
    }

    log(`${tag} executing sqlite: ${params.sql.slice(0, 120).replace(/\s+/g, ' ')}`);
    const result = runPreparedStatement({
      db,
      sql: params.sql,
      rowCap: params.policy.rowCap,
      category: params.category,
    });

    if (pendingInsertSpec) {
      try {
        const id = captureInsertHint({
          spec: pendingInsertSpec,
          connectionName: params.connection.name,
          database: params.database ?? params.connection.database,
          result: { insertId: result.insertId, affectedRows: result.affectedRows },
        });
        if (id) {
          backupId = id;
          backupRowCount = result.affectedRows;
          log(`${tag} insert-hint backup #${id}: ${result.affectedRows} row(s)`);
        }
      } catch (e) {
        log(`${tag} insert-hint capture failed: ${(e as Error).message}`);
      }
    }

    if (inTransaction) {
      db.exec('COMMIT');
      inTransaction = false;
    }

    return {
      rows: result.rows,
      fields: result.fields,
      affectedRows: result.affectedRows,
      truncated: result.truncated,
      durationMs: Date.now() - start,
      backupId,
      backupRowCount,
    };
  } catch (e) {
    log(`${tag} FAILED at t=${Date.now() - start}ms: ${(e as Error).message}`);
    if (db && inTransaction) {
      try {
        db.exec('ROLLBACK');
      } catch {
        /* ignore */
      }
    }
    throw e;
  } finally {
    if (db) {
      try {
        db.close();
      } catch {
        /* ignore */
      }
    }
  }
}
