import path from 'node:path';
import os from 'node:os';
import fs from 'node:fs';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { writeAuditEntry, searchAuditLog } from '../src/audit/logger.js';
import { closeAuditDb, openAuditDb } from '../src/audit/db.js';

let dbFile: string;

beforeEach(() => {
  dbFile = path.join(os.tmpdir(), `sequel-mcp-test-${Date.now()}-${Math.random().toString(36).slice(2)}.sqlite`);
});

afterEach(() => {
  closeAuditDb();
  for (const ext of ['', '-wal', '-shm']) {
    try {
      fs.unlinkSync(dbFile + ext);
    } catch {
      /* ignore */
    }
  }
});

describe('audit logger', () => {
  it('writes and reads back an entry with redacted SQL', () => {
    writeAuditEntry(
      {
        requestId: 'req-1',
        connection: 'c',
        databases: ['app'],
        category: 'read',
        astType: 'select',
        sql: "SELECT * FROM users WHERE email = 'a@b.c'",
        decision: 'allow',
        confirmed: false,
        outcome: 'success',
        affectedRows: 0,
        durationMs: 5,
      },
      { redactSqlInLog: false, tamperEvidentChain: false, pathOverride: dbFile },
    );

    const rows = searchAuditLog({ connection: 'c' }, { pathOverride: dbFile });
    expect(rows).toHaveLength(1);
    expect(rows[0]?.connection).toBe('c');
    expect(rows[0]?.databases).toEqual(['app']);
    expect(rows[0]?.sql_redacted).not.toContain('a@b.c');
    expect(rows[0]?.outcome).toBe('success');
  });

  it('chains row hashes when tamperEvidentChain is enabled', () => {
    const common = { connection: 'c', databases: ['app'], category: 'read' as const, decision: 'allow' as const, confirmed: false, outcome: 'success' as const };
    writeAuditEntry({ ...common, requestId: 'r1', sql: 'SELECT 1' }, { redactSqlInLog: false, tamperEvidentChain: true, pathOverride: dbFile });
    writeAuditEntry({ ...common, requestId: 'r2', sql: 'SELECT 2' }, { redactSqlInLog: false, tamperEvidentChain: true, pathOverride: dbFile });

    // Verify the hash chain itself: row 1's row_hash must equal row 2's prev_hash.
    const db = openAuditDb({ pathOverride: dbFile });
    const raw = db
      .prepare('SELECT id, prev_hash, row_hash FROM audit_log ORDER BY id ASC')
      .all() as { id: number; prev_hash: Buffer | null; row_hash: Buffer | null }[];
    expect(raw).toHaveLength(2);
    expect(raw[0]?.prev_hash).toBeNull();
    expect(raw[0]?.row_hash).toBeInstanceOf(Buffer);
    expect(raw[1]?.prev_hash).toBeInstanceOf(Buffer);
    expect(raw[1]?.row_hash).toBeInstanceOf(Buffer);
    expect(raw[1]?.prev_hash?.equals(raw[0]!.row_hash!)).toBe(true);
  });

  it('writes the row inside a single transaction (no chain corruption across rapid writes)', () => {
    const common = { connection: 'c', databases: [], category: 'read' as const, decision: 'allow' as const, confirmed: false, outcome: 'success' as const };
    for (let i = 0; i < 20; i++) {
      writeAuditEntry(
        { ...common, requestId: `r${i}`, sql: `SELECT ${i}` },
        { redactSqlInLog: false, tamperEvidentChain: true, pathOverride: dbFile },
      );
    }
    const db = openAuditDb({ pathOverride: dbFile });
    const raw = db
      .prepare('SELECT id, prev_hash, row_hash FROM audit_log ORDER BY id ASC')
      .all() as { id: number; prev_hash: Buffer | null; row_hash: Buffer | null }[];
    expect(raw).toHaveLength(20);
    for (let i = 1; i < raw.length; i++) {
      expect(raw[i]?.prev_hash?.equals(raw[i - 1]!.row_hash!)).toBe(true);
    }
  });

  it('filter by outcome', () => {
    writeAuditEntry(
      { requestId: 'r1', connection: 'c', databases: [], category: 'write', sql: 'UPDATE x SET y=1', decision: 'allow', confirmed: false, outcome: 'success' },
      { redactSqlInLog: false, tamperEvidentChain: false, pathOverride: dbFile },
    );
    writeAuditEntry(
      { requestId: 'r2', connection: 'c', databases: [], category: 'write', sql: 'UPDATE x SET y=2', decision: 'deny', confirmed: false, outcome: 'denied' },
      { redactSqlInLog: false, tamperEvidentChain: false, pathOverride: dbFile },
    );
    const denied = searchAuditLog({ outcome: 'denied' }, { pathOverride: dbFile });
    expect(denied).toHaveLength(1);
    expect(denied[0]?.request_id).toBe('r2');
  });
});
