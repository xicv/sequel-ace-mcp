import crypto from 'node:crypto';
import { openAuditDb } from './db.js';
import { redactSql } from './redactor.js';
import type { PolicyAction, SqlCategory } from '../types.js';

export type AuditOutcome = 'success' | 'error' | 'denied' | 'declined';

export interface AuditEntryInput {
  ts?: Date;
  requestId: string;
  connection: string;
  databases: string[];
  category: SqlCategory;
  astType?: string | null;
  sql: string;
  decision: PolicyAction;
  confirmed: boolean;
  outcome: AuditOutcome;
  affectedRows?: number | null;
  durationMs?: number | null;
  error?: string | null;
  backupId?: number | null;
}

export interface WriteAuditOptions {
  redactSqlInLog: boolean;
  tamperEvidentChain: boolean;
  pathOverride?: string;
}

function hashRow(prev: Buffer | null, payload: string): Buffer {
  const h = crypto.createHash('sha256');
  if (prev) h.update(prev);
  h.update(payload);
  return h.digest();
}

export function writeAuditEntry(entry: AuditEntryInput, opts: WriteAuditOptions): number {
  const db = openAuditDb({ pathOverride: opts.pathOverride });
  const ts = (entry.ts ?? new Date()).toISOString();
  const sqlRedacted = redactSql(entry.sql);
  const sqlRaw = opts.redactSqlInLog ? sqlRedacted : entry.sql;
  const databases = JSON.stringify(entry.databases);

  const insertStmt = db.prepare(
    `INSERT INTO audit_log
        (ts, request_id, connection, databases, category, ast_type,
         sql_raw, sql_redacted, decision, confirmed, outcome,
         affected_rows, duration_ms, error_msg, backup_id, prev_hash, row_hash)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  );
  const tailStmt = db.prepare('SELECT row_hash FROM audit_log ORDER BY id DESC LIMIT 1');

  const writeTxn = db.transaction((): number => {
    let prevHash: Buffer | null = null;
    let rowHash: Buffer | null = null;

    if (opts.tamperEvidentChain) {
      const last = tailStmt.get() as { row_hash: Buffer | null } | undefined;
      prevHash = last?.row_hash ?? null;
      const canonical = JSON.stringify({
        ts,
        requestId: entry.requestId,
        connection: entry.connection,
        databases,
        category: entry.category,
        astType: entry.astType ?? null,
        sqlRedacted,
        decision: entry.decision,
        confirmed: entry.confirmed ? 1 : 0,
        outcome: entry.outcome,
        affectedRows: entry.affectedRows ?? null,
        durationMs: entry.durationMs ?? null,
        error: entry.error ?? null,
        backupId: entry.backupId ?? null,
      });
      rowHash = hashRow(prevHash, canonical);
    }

    const result = insertStmt.run(
      ts,
      entry.requestId,
      entry.connection,
      databases,
      entry.category,
      entry.astType ?? null,
      sqlRaw,
      sqlRedacted,
      entry.decision,
      entry.confirmed ? 1 : 0,
      entry.outcome,
      entry.affectedRows ?? null,
      entry.durationMs ?? null,
      entry.error ?? null,
      entry.backupId ?? null,
      prevHash,
      rowHash,
    );
    return Number(result.lastInsertRowid);
  });

  return writeTxn.immediate();
}

export interface AuditSearchFilters {
  since?: Date;
  until?: Date;
  connection?: string;
  category?: SqlCategory;
  outcome?: AuditOutcome;
  limit?: number;
}

export interface AuditRow {
  id: number;
  ts: string;
  request_id: string;
  connection: string;
  databases: string[];
  category: string;
  ast_type: string | null;
  sql_redacted: string;
  decision: string;
  confirmed: boolean;
  outcome: string;
  affected_rows: number | null;
  duration_ms: number | null;
  error_msg: string | null;
  backup_id: number | null;
}

export function searchAuditLog(filters: AuditSearchFilters, opts?: { pathOverride?: string }): AuditRow[] {
  const db = openAuditDb({ pathOverride: opts?.pathOverride });
  const conds: string[] = [];
  const params: (string | number)[] = [];
  if (filters.since) {
    conds.push('ts >= ?');
    params.push(filters.since.toISOString());
  }
  if (filters.until) {
    conds.push('ts < ?');
    params.push(filters.until.toISOString());
  }
  if (filters.connection) {
    conds.push('connection = ?');
    params.push(filters.connection);
  }
  if (filters.category) {
    conds.push('category = ?');
    params.push(filters.category);
  }
  if (filters.outcome) {
    conds.push('outcome = ?');
    params.push(filters.outcome);
  }
  const where = conds.length > 0 ? `WHERE ${conds.join(' AND ')}` : '';
  const limit = Math.min(filters.limit ?? 200, 5000);
  const rows = db
    .prepare(
      `SELECT id, ts, request_id, connection, databases, category, ast_type,
              sql_redacted, decision, confirmed, outcome, affected_rows,
              duration_ms, error_msg, backup_id
         FROM audit_log
         ${where}
         ORDER BY id DESC
         LIMIT ?`,
    )
    .all(...params, limit) as Record<string, unknown>[];
  return rows.map((r) => ({
    id: Number(r.id),
    ts: String(r.ts),
    request_id: String(r.request_id),
    connection: String(r.connection),
    databases: JSON.parse(String(r.databases ?? '[]')) as string[],
    category: String(r.category),
    ast_type: r.ast_type == null ? null : String(r.ast_type),
    sql_redacted: String(r.sql_redacted),
    decision: String(r.decision),
    confirmed: Boolean(r.confirmed),
    outcome: String(r.outcome),
    affected_rows: r.affected_rows == null ? null : Number(r.affected_rows),
    duration_ms: r.duration_ms == null ? null : Number(r.duration_ms),
    error_msg: r.error_msg == null ? null : String(r.error_msg),
    backup_id: r.backup_id == null ? null : Number(r.backup_id),
  }));
}
