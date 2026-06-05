import type mysql from 'mysql2/promise';
import type Database from 'better-sqlite3';
import { openAuditDb } from '../audit/db.js';
import type { BackupSpec } from './extractor.js';
import type { Policy } from '../types.js';

export interface CapturedBackup {
  backupId: number;
  totalRows: number;
  truncated: boolean;
  totalBytes: number;
  perTable: { db: string | null; table: string; rowCount: number; truncated: boolean }[];
}

export class BackupOverflowError extends Error {
  constructor(public readonly limit: { kind: 'rows' | 'bytes'; cap: number }, public readonly observed: number) {
    super(`backup ${limit.kind} cap exceeded (${observed} > ${limit.cap})`);
    this.name = 'BackupOverflowError';
  }
}

type SqliteDb = Database.Database;

async function showCreateTable(conn: mysql.Connection, db: string | null, table: string): Promise<string | null> {
  const target = db ? `\`${db}\`.\`${table}\`` : `\`${table}\``;
  try {
    const [rowsRaw] = await conn.query(`SHOW CREATE TABLE ${target}`);
    const r = Array.isArray(rowsRaw) && rowsRaw.length > 0 ? (rowsRaw[0] as Record<string, unknown>) : null;
    if (!r) return null;
    const create = r['Create Table'] ?? r['Create View'];
    return typeof create === 'string' ? create : null;
  } catch {
    return null;
  }
}

function quoteId(id: string): string {
  return '`' + id.replace(/`/g, '``') + '`';
}

function showCreateTableSqlite(db: SqliteDb, database: string | null, table: string): string | null {
  const schemaTable = database ? `${quoteId(database)}.sqlite_schema` : 'sqlite_schema';
  try {
    const row = db
      .prepare(
        `SELECT sql
           FROM ${schemaTable}
          WHERE name = ?
            AND type IN ('table', 'view')
          ORDER BY CASE type WHEN 'table' THEN 0 ELSE 1 END
          LIMIT 1`,
      )
      .get(table) as { sql?: unknown } | undefined;
    return typeof row?.sql === 'string' ? row.sql : null;
  } catch {
    return null;
  }
}

async function fetchRows(args: {
  conn: mysql.Connection;
  selectSql: string;
  rowCap: number;
  byteCap: number;
}): Promise<{ rows: unknown[]; totalBytes: number; truncated: boolean }> {
  const cappedSql = `${args.selectSql} LIMIT ${Math.max(args.rowCap + 1, 1)}`;
  const [rowsRaw] = await args.conn.query(cappedSql);
  if (!Array.isArray(rowsRaw)) return { rows: [], totalBytes: 0, truncated: false };
  const truncatedRows = rowsRaw.length > args.rowCap;
  const usable = truncatedRows ? rowsRaw.slice(0, args.rowCap) : rowsRaw;
  const json = JSON.stringify(usable);
  const bytes = Buffer.byteLength(json, 'utf8');
  return {
    rows: usable as unknown[],
    totalBytes: bytes,
    truncated: truncatedRows,
  };
}

function fetchRowsSqlite(args: {
  db: SqliteDb;
  selectSql: string;
  rowCap: number;
  byteCap: number;
}): { rows: unknown[]; totalBytes: number; truncated: boolean } {
  const cappedSql = `${args.selectSql.replace(/;\s*$/, '')} LIMIT ${Math.max(args.rowCap + 1, 1)}`;
  const rowsRaw = args.db.prepare(cappedSql).all();
  const truncatedRows = rowsRaw.length > args.rowCap;
  const usable = truncatedRows ? rowsRaw.slice(0, args.rowCap) : rowsRaw;
  const json = JSON.stringify(usable);
  const bytes = Buffer.byteLength(json, 'utf8');
  void args.byteCap;
  return {
    rows: usable as unknown[],
    totalBytes: bytes,
    truncated: truncatedRows,
  };
}

export async function captureBackup(args: {
  conn: mysql.Connection;
  spec: BackupSpec;
  connectionName: string;
  database: string | undefined;
  policy: Policy;
  pathOverride?: string;
}): Promise<CapturedBackup | null> {
  if (args.spec.kind === 'none') return null;
  if (args.spec.kind === 'insert-hint') return null;

  const db = openAuditDb({ pathOverride: args.pathOverride });
  const ts = new Date().toISOString();
  const stmt = db.prepare(
    `INSERT INTO backup
       (ts, connection, database, table_name, backup_kind, rows_json, schema_sql, primary_key, row_count, truncated, size_bytes)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  );

  const rowCap = args.policy.maxBackupRows;
  const byteCap = args.policy.maxBackupBytes;
  const onOverflow = args.policy.onBackupOverflow;
  const perTable: CapturedBackup['perTable'] = [];
  let totalRows = 0;
  let totalBytes = 0;
  let truncatedAny = false;
  let firstId: number | null = null;

  const tables = args.spec.tables;

  for (const t of tables) {
    let rowsJson: string | null = null;
    let schemaSql: string | null = null;
    let rowCount = 0;
    let truncated = false;
    let bytes = 0;

    if (args.spec.kind === 'schema' || args.spec.kind === 'combined') {
      schemaSql = await showCreateTable(args.conn, t.db, t.table);
    }
    if (args.spec.kind === 'rows' || args.spec.kind === 'combined') {
      const tt = t as { db: string | null; table: string; selectSql: string; locking: 'FOR UPDATE' | 'NONE' };
      const fetch = await fetchRows({
        conn: args.conn,
        selectSql: tt.selectSql,
        rowCap,
        byteCap,
      });
      if (fetch.truncated && onOverflow === 'abort') {
        throw new BackupOverflowError({ kind: 'rows', cap: rowCap }, rowCap + 1);
      }
      if (fetch.totalBytes > byteCap && onOverflow === 'abort') {
        throw new BackupOverflowError({ kind: 'bytes', cap: byteCap }, fetch.totalBytes);
      }
      rowsJson = JSON.stringify(fetch.rows);
      rowCount = fetch.rows.length;
      truncated = fetch.truncated;
      bytes = fetch.totalBytes;
    }

    const ins = stmt.run(
      ts,
      args.connectionName,
      args.database ?? t.db ?? null,
      t.table,
      args.spec.kind,
      rowsJson,
      schemaSql,
      null,
      rowCount,
      truncated ? 1 : 0,
      bytes,
    );

    if (firstId === null) firstId = Number(ins.lastInsertRowid);
    perTable.push({ db: t.db, table: t.table, rowCount, truncated });
    totalRows += rowCount;
    totalBytes += bytes;
    truncatedAny = truncatedAny || truncated;
  }

  if (firstId === null) return null;
  return { backupId: firstId, totalRows, totalBytes, truncated: truncatedAny, perTable };
}

export function captureBackupSqlite(args: {
  db: SqliteDb;
  spec: BackupSpec;
  connectionName: string;
  database: string | undefined;
  policy: Policy;
  pathOverride?: string;
}): CapturedBackup | null {
  if (args.spec.kind === 'none') return null;
  if (args.spec.kind === 'insert-hint') return null;

  const auditDb = openAuditDb({ pathOverride: args.pathOverride });
  const ts = new Date().toISOString();
  const stmt = auditDb.prepare(
    `INSERT INTO backup
       (ts, connection, database, table_name, backup_kind, rows_json, schema_sql, primary_key, row_count, truncated, size_bytes)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  );

  const rowCap = args.policy.maxBackupRows;
  const byteCap = args.policy.maxBackupBytes;
  const onOverflow = args.policy.onBackupOverflow;
  const perTable: CapturedBackup['perTable'] = [];
  let totalRows = 0;
  let totalBytes = 0;
  let truncatedAny = false;
  let firstId: number | null = null;

  for (const t of args.spec.tables) {
    let rowsJson: string | null = null;
    let schemaSql: string | null = null;
    let rowCount = 0;
    let truncated = false;
    let bytes = 0;

    const database = t.db ?? args.database ?? null;
    if (args.spec.kind === 'schema' || args.spec.kind === 'combined') {
      schemaSql = showCreateTableSqlite(args.db, database, t.table);
    }
    if (args.spec.kind === 'rows' || args.spec.kind === 'combined') {
      const tt = t as { db: string | null; table: string; selectSql: string; locking: 'FOR UPDATE' | 'NONE' };
      const fetch = fetchRowsSqlite({
        db: args.db,
        selectSql: tt.selectSql,
        rowCap,
        byteCap,
      });
      if (fetch.truncated && onOverflow === 'abort') {
        throw new BackupOverflowError({ kind: 'rows', cap: rowCap }, rowCap + 1);
      }
      if (fetch.totalBytes > byteCap && onOverflow === 'abort') {
        throw new BackupOverflowError({ kind: 'bytes', cap: byteCap }, fetch.totalBytes);
      }
      rowsJson = JSON.stringify(fetch.rows);
      rowCount = fetch.rows.length;
      truncated = fetch.truncated;
      bytes = fetch.totalBytes;
    }

    const ins = stmt.run(
      ts,
      args.connectionName,
      database,
      t.table,
      args.spec.kind,
      rowsJson,
      schemaSql,
      null,
      rowCount,
      truncated ? 1 : 0,
      bytes,
    );

    if (firstId === null) firstId = Number(ins.lastInsertRowid);
    perTable.push({ db: t.db, table: t.table, rowCount, truncated });
    totalRows += rowCount;
    totalBytes += bytes;
    truncatedAny = truncatedAny || truncated;
  }

  if (firstId === null) return null;
  return { backupId: firstId, totalRows, totalBytes, truncated: truncatedAny, perTable };
}

export interface InsertResult {
  insertId: number | null;
  affectedRows: number;
}

export function captureInsertHint(args: {
  spec: BackupSpec;
  connectionName: string;
  database: string | undefined;
  result: InsertResult;
  pathOverride?: string;
}): number | null {
  if (args.spec.kind !== 'insert-hint') return null;
  const { table, columns, explicitPkValues } = args.spec;
  const db = openAuditDb({ pathOverride: args.pathOverride });
  const ts = new Date().toISOString();

  let primaryKey: string | null = null;
  let rowsJson: string | null = null;
  let rowCount = args.result.affectedRows;

  if (explicitPkValues && explicitPkValues.length > 0) {
    primaryKey = JSON.stringify({ kind: 'explicit', columns: ['id'], values: explicitPkValues });
    rowsJson = JSON.stringify(explicitPkValues);
  } else if (
    typeof args.result.insertId === 'number' &&
    args.result.insertId > 0 &&
    args.result.affectedRows > 0
  ) {
    const start = args.result.insertId;
    const end = start + args.result.affectedRows - 1;
    primaryKey = JSON.stringify({ kind: 'range', column: 'id', start, end });
    rowCount = args.result.affectedRows;
  } else {
    return null;
  }

  const ins = db
    .prepare(
      `INSERT INTO backup
         (ts, connection, database, table_name, backup_kind, rows_json, schema_sql, primary_key, row_count, truncated, size_bytes)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .run(
      ts,
      args.connectionName,
      args.database ?? table.db ?? null,
      table.table,
      'insert-hint',
      rowsJson,
      null,
      primaryKey,
      rowCount,
      0,
      rowsJson ? Buffer.byteLength(rowsJson, 'utf8') : 0,
    );
  void columns;
  return Number(ins.lastInsertRowid);
}

export interface BackupRow {
  id: number;
  ts: string;
  connection: string;
  database: string | null;
  table_name: string;
  backup_kind: string;
  row_count: number;
  truncated: boolean;
  size_bytes: number;
}

export function listBackups(filters: { connection?: string; limit?: number }, opts?: { pathOverride?: string }): BackupRow[] {
  const db = openAuditDb({ pathOverride: opts?.pathOverride });
  const conds: string[] = [];
  const params: (string | number)[] = [];
  if (filters.connection) {
    conds.push('connection = ?');
    params.push(filters.connection);
  }
  const where = conds.length > 0 ? `WHERE ${conds.join(' AND ')}` : '';
  const limit = Math.min(filters.limit ?? 50, 1000);
  const rows = db
    .prepare(
      `SELECT id, ts, connection, database, table_name, backup_kind, row_count, truncated, size_bytes
       FROM backup ${where} ORDER BY id DESC LIMIT ?`,
    )
    .all(...params, limit) as Record<string, unknown>[];
  return rows.map((r) => ({
    id: Number(r.id),
    ts: String(r.ts),
    connection: String(r.connection),
    database: r.database == null ? null : String(r.database),
    table_name: String(r.table_name),
    backup_kind: String(r.backup_kind),
    row_count: Number(r.row_count),
    truncated: Boolean(r.truncated),
    size_bytes: Number(r.size_bytes),
  }));
}

export interface BackupDetail extends BackupRow {
  rows: unknown[] | null;
  schema_sql: string | null;
  primary_key: string | null;
}

export function getBackup(id: number, opts?: { pathOverride?: string }): BackupDetail | null {
  const db = openAuditDb({ pathOverride: opts?.pathOverride });
  const r = db
    .prepare(
      `SELECT id, ts, connection, database, table_name, backup_kind, rows_json, schema_sql, primary_key, row_count, truncated, size_bytes
       FROM backup WHERE id = ?`,
    )
    .get(id) as Record<string, unknown> | undefined;
  if (!r) return null;
  return {
    id: Number(r.id),
    ts: String(r.ts),
    connection: String(r.connection),
    database: r.database == null ? null : String(r.database),
    table_name: String(r.table_name),
    backup_kind: String(r.backup_kind),
    row_count: Number(r.row_count),
    truncated: Boolean(r.truncated),
    size_bytes: Number(r.size_bytes),
    rows: r.rows_json == null ? null : (JSON.parse(String(r.rows_json)) as unknown[]),
    schema_sql: r.schema_sql == null ? null : String(r.schema_sql),
    primary_key: r.primary_key == null ? null : String(r.primary_key),
  };
}
