import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import Database from 'better-sqlite3';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { captureBackupSqlite } from '../src/backup/capture.js';
import { extractBackupSpec } from '../src/backup/extractor.js';
import { planRestore } from '../src/backup/restore.js';
import { classifyStatement } from '../src/policy/classifier.js';
import { executeStatement } from '../src/sql/executor.js';
import { ConnectionSchema, PolicySchema } from '../src/types.js';

describe('SQLite connection schema', () => {
  it('parses SQLite connections with main as the default schema', () => {
    const conn = ConnectionSchema.parse({
      driver: 'sqlite',
      name: 'local-file',
      path: '~/app.sqlite',
      policy: PolicySchema.parse({}),
    });

    expect(conn.driver).toBe('sqlite');
    if (conn.driver === 'sqlite') {
      expect(conn.path).toBe('~/app.sqlite');
      expect(conn.database).toBe('main');
    }
  });

  it('keeps legacy driver-less configs as MySQL', () => {
    const conn = ConnectionSchema.parse({
      name: 'legacy',
      host: '127.0.0.1',
      user: 'root',
      policy: PolicySchema.parse({}),
    });

    expect(conn.driver).toBe('mysql');
  });
});

describe('SQLite classifier behavior', () => {
  it('classifies read-only PRAGMA statements as read', () => {
    const result = classifyStatement('PRAGMA table_info(users)', { dialect: 'sqlite' });
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.category).toBe('read');
  });

  it('classifies mutating PRAGMA statements as admin', () => {
    const result = classifyStatement('PRAGMA user_version = 2', { dialect: 'sqlite' });
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.category).toBe('admin');
  });
});

describe('SQLite backup extraction', () => {
  it('omits MySQL FOR UPDATE locking syntax', () => {
    const spec = extractBackupSpec('UPDATE users SET name = "x" WHERE id = 1', 'update', {
      dialect: 'sqlite',
    });

    expect(spec.kind).toBe('rows');
    if (spec.kind === 'rows') {
      expect(spec.tables[0]?.selectSql).not.toContain('FOR UPDATE');
      expect(spec.tables[0]?.locking).toBe('NONE');
    }
  });
});

describe('SQLite execution and backup capture', () => {
  let tmpDir: string;

  beforeEach(async () => {
    tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'sequel-mcp-sqlite-'));
  });

  afterEach(async () => {
    await fs.rm(tmpDir, { recursive: true, force: true });
  });

  it('executes read statements without a password', async () => {
    const dbPath = path.join(tmpDir, 'app.sqlite');
    const policy = PolicySchema.parse({ ddl: 'allow', rowCap: 10 });
    const conn = ConnectionSchema.parse({
      driver: 'sqlite',
      name: 'local-sqlite',
      path: dbPath,
      policy,
    });

    await executeStatement({
      connection: conn,
      sql: 'CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT)',
      category: 'ddl',
      astType: 'create',
      policy,
    });

    const db = new Database(dbPath);
    db.prepare('INSERT INTO users (name) VALUES (?)').run('Ada');
    db.close();

    const result = await executeStatement({
      connection: conn,
      sql: 'SELECT id, name FROM users',
      category: 'read',
      astType: 'select',
      policy,
    });

    expect(result.rows).toEqual([{ id: 1, name: 'Ada' }]);
    expect(result.fields.map((f) => f.name)).toEqual(['id', 'name']);
  });

  it('captures SQLite row backups and plans SQLite upserts for restore', () => {
    const dbPath = path.join(tmpDir, 'backup.sqlite');
    const auditPath = path.join(tmpDir, 'audit.sqlite');
    const db = new Database(dbPath);
    db.exec("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT); INSERT INTO users (id, name) VALUES (1, 'Ada');");

    const spec = extractBackupSpec("UPDATE users SET name = 'Grace' WHERE id = 1", 'update', {
      dialect: 'sqlite',
    });
    const captured = captureBackupSqlite({
      db,
      spec,
      connectionName: 'local-sqlite',
      database: 'main',
      policy: PolicySchema.parse({ maxBackupRows: 10 }),
      pathOverride: auditPath,
    });
    db.close();

    expect(captured?.backupId).toBeGreaterThan(0);
    expect(captured?.totalRows).toBe(1);

    const plan = planRestore(captured!.backupId, {
      pathOverride: auditPath,
      dialect: 'sqlite',
    });

    expect(plan.statements[0]).toContain('ON CONFLICT DO UPDATE');
    expect(plan.statements[0]).toContain('excluded.');
  });
});
