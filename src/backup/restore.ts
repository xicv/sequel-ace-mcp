import type mysql from 'mysql2/promise';
import type Database from 'better-sqlite3';
import { getBackup } from './capture.js';

type RestoreDialect = 'mysql' | 'sqlite';

function quoteId(id: string): string {
  return '`' + id.replace(/`/g, '``') + '`';
}

function tableRefSql(db: string | null, table: string): string {
  return db ? `${quoteId(db)}.${quoteId(table)}` : quoteId(table);
}

function escapeValue(v: unknown, dialect: RestoreDialect): string {
  if (v === null || v === undefined) return 'NULL';
  if (typeof v === 'number' || typeof v === 'bigint') return String(v);
  if (typeof v === 'boolean') return v ? '1' : '0';
  if (v instanceof Date) return `'${v.toISOString().slice(0, 19).replace('T', ' ')}'`;
  if (Buffer.isBuffer(v)) return dialect === 'sqlite' ? `X'${v.toString('hex')}'` : `0x${v.toString('hex')}`;
  if (typeof v === 'object') return `'${JSON.stringify(v).replace(/'/g, "''").replace(/\\/g, '\\\\')}'`;
  return `'${String(v).replace(/'/g, "''").replace(/\\/g, '\\\\')}'`;
}

export interface RestorePlan {
  backupId: number;
  statements: string[];
  rowCount: number;
  warnings: string[];
}

export function planRestore(
  backupId: number,
  opts?: { pathOverride?: string; dialect?: RestoreDialect },
): RestorePlan {
  const backup = getBackup(backupId, opts);
  if (!backup) throw new Error(`backup #${backupId} not found`);
  const dialect = opts?.dialect ?? 'mysql';

  const statements: string[] = [];
  const warnings: string[] = [];

  if (backup.truncated) {
    warnings.push('backup was truncated; restore will not be complete');
  }

  if (backup.backup_kind === 'schema' && backup.schema_sql) {
    warnings.push('schema-only backup; running this will fail unless the table was dropped first');
    statements.push(backup.schema_sql + ';');
    return { backupId, statements, rowCount: 0, warnings };
  }

  if (backup.backup_kind === 'combined') {
    if (backup.schema_sql) statements.push(backup.schema_sql + ';');
  }

  if (backup.backup_kind === 'insert-hint') {
    if (!backup.primary_key) {
      warnings.push('insert-hint backup has no recoverable PK metadata; nothing to restore');
      return { backupId, statements, rowCount: 0, warnings };
    }
    const meta = JSON.parse(backup.primary_key) as
      | { kind: 'range'; column: string; start: number; end: number }
      | { kind: 'explicit'; columns: string[]; values: unknown[][] };
    const tref = tableRefSql(backup.database, backup.table_name);
    if (meta.kind === 'range') {
      statements.push(
        `DELETE FROM ${tref} WHERE ${quoteId(meta.column)} BETWEEN ${meta.start} AND ${meta.end};`,
      );
    } else {
      const colExpr = meta.columns.map(quoteId).join(', ');
      const valueRows = meta.values
        .map((row) => `(${row.map((v) => escapeValue(v, dialect)).join(', ')})`)
        .join(', ');
      statements.push(`DELETE FROM ${tref} WHERE (${colExpr}) IN (${valueRows});`);
    }
    warnings.push('insert-hint restore deletes the rows the INSERT created — verify before running');
    return { backupId, statements, rowCount: backup.row_count, warnings };
  }

  if (backup.rows && Array.isArray(backup.rows) && backup.rows.length > 0) {
    const tref = tableRefSql(backup.database, backup.table_name);
    const sample = backup.rows[0] as Record<string, unknown>;
    const cols = Object.keys(sample);
    const colList = cols.map(quoteId).join(', ');
    const updateClause =
      dialect === 'sqlite'
        ? cols.map((c) => `${quoteId(c)} = excluded.${quoteId(c)}`).join(', ')
        : cols.map((c) => `${quoteId(c)} = VALUES(${quoteId(c)})`).join(', ');

    for (const row of backup.rows as Record<string, unknown>[]) {
      const values = cols.map((c) => escapeValue(row[c], dialect)).join(', ');
      if (dialect === 'sqlite') {
        statements.push(
          `INSERT INTO ${tref} (${colList}) VALUES (${values}) ON CONFLICT DO UPDATE SET ${updateClause};`,
        );
      } else {
        statements.push(
          `INSERT INTO ${tref} (${colList}) VALUES (${values}) ON DUPLICATE KEY UPDATE ${updateClause};`,
        );
      }
    }
  }

  return { backupId, statements, rowCount: backup.row_count, warnings };
}

export async function executeRestore(args: {
  conn: mysql.Connection;
  plan: RestorePlan;
}): Promise<{ statementsRun: number; affected: number }> {
  let affected = 0;
  for (const stmt of args.plan.statements) {
    const [r] = await args.conn.query(stmt);
    if (r && typeof r === 'object' && 'affectedRows' in r) {
      affected += Number((r as { affectedRows: number }).affectedRows ?? 0);
    }
  }
  return { statementsRun: args.plan.statements.length, affected };
}

export function executeRestoreSqlite(args: {
  db: Database.Database;
  plan: RestorePlan;
}): { statementsRun: number; affected: number } {
  let affected = 0;
  for (const stmtRaw of args.plan.statements) {
    const stmtText = stmtRaw.replace(/;\s*$/, '');
    const stmt = args.db.prepare(stmtText);
    if (stmt.reader) {
      stmt.all();
    } else {
      const r = stmt.run();
      affected += r.changes;
    }
  }
  return { statementsRun: args.plan.statements.length, affected };
}
