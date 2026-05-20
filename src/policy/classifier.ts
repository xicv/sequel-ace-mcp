import { createRequire } from 'node:module';
import type { SqlCategory } from '../types.js';

const require = createRequire(import.meta.url);
const { Parser } = require('node-sql-parser') as typeof import('node-sql-parser');

export type ClassifierResult =
  | {
      ok: true;
      category: SqlCategory;
      astType: string;
      statement: string;
      targetDatabases: string[];
    }
  | { ok: false; error: string };

interface TableRef {
  op: string;
  db: string | null;
  table: string;
}

function parseTableList(sql: string): TableRef[] {
  try {
    const list = parser.tableList(sql, { database: 'mysql' });
    if (!Array.isArray(list)) return [];
    return list.flatMap((entry) => {
      if (typeof entry !== 'string') return [];
      const parts = entry.split('::');
      if (parts.length < 3) return [];
      const op = parts[0] ?? '';
      const dbRaw = parts[1] ?? '';
      const table = parts.slice(2).join('::');
      return [{ op, db: dbRaw && dbRaw !== 'null' ? dbRaw : null, table }];
    });
  } catch {
    return [];
  }
}

export function extractTargetDatabases(sql: string): string[] {
  const refs = parseTableList(sql);
  const out = new Set<string>();
  for (const r of refs) {
    if (r.db) out.add(r.db);
  }
  return [...out].sort();
}

const READ_TYPES = new Set(['select', 'show', 'describe', 'desc', 'explain', 'pragma']);
const WRITE_TYPES = new Set(['insert', 'update', 'delete', 'replace']);
const DDL_TYPES = new Set([
  'create',
  'drop',
  'alter',
  'truncate',
  'rename',
]);
const ADMIN_TYPES = new Set([
  'grant',
  'revoke',
  'set',
  'kill',
  'flush',
  'lock',
  'unlock',
  'reset',
  'load',
  'analyze',
  'optimize',
  'repair',
  'check',
  'handler',
  'do',
]);
const TX_TYPES = new Set([
  'transaction',
  'begin',
  'start',
  'commit',
  'rollback',
  'savepoint',
  'release',
]);

const parser = new Parser();

function categorize(astType: string): SqlCategory | null {
  const t = astType.toLowerCase();
  if (READ_TYPES.has(t)) return 'read';
  if (WRITE_TYPES.has(t)) return 'write';
  if (DDL_TYPES.has(t)) return 'ddl';
  if (ADMIN_TYPES.has(t)) return 'admin';
  if (TX_TYPES.has(t)) return 'txCtrl';
  return null;
}

function stripComments(sql: string): string {
  return sql
    .replace(/\/\*[\s\S]*?\*\//g, ' ')
    .replace(/--[^\n]*/g, ' ')
    .replace(/^#[^\n]*$/gm, ' ');
}

function looksLikeMultipleStatements(sql: string): boolean {
  const stripped = stripComments(sql);
  const trimmed = stripped.replace(/;\s*$/, '').trim();
  if (trimmed.length === 0) return false;
  let q: '\'' | '"' | '`' | null = null;
  let depth = 0;
  for (let i = 0; i < trimmed.length; i++) {
    const c = trimmed[i];
    const prev = i > 0 ? trimmed[i - 1] : '';
    if (q) {
      if (c === q && prev !== '\\') q = null;
      continue;
    }
    if (c === '\'' || c === '"' || c === '`') {
      q = c;
      continue;
    }
    if (c === '(') depth++;
    else if (c === ')') depth--;
    else if (c === ';' && depth === 0) return true;
  }
  return false;
}

const TX_KEYWORD_REGEX =
  /^\s*(begin|commit|rollback|start\s+transaction|savepoint\b|release\s+savepoint)\b/i;

const ADMIN_KEYWORD_REGEX =
  /^\s*(grant|revoke|set\s+(global|persist|persist_only|@@global|@@persist)|kill|flush|reset(\s+master|\s+slave|\s+replica)?|lock\s+tables|unlock\s+tables|load\s+data|handler\b|do\s+|change\s+master|change\s+replication|start\s+slave|stop\s+slave|start\s+replica|stop\s+replica|optimize\s+table|repair\s+table|analyze\s+table|check\s+table|create\s+user|alter\s+user|drop\s+user|rename\s+user|set\s+password)\b/i;

function classifyTxKeyword(sql: string): SqlCategory | null {
  return TX_KEYWORD_REGEX.test(sql) ? 'txCtrl' : null;
}

function classifyAdminKeyword(sql: string): SqlCategory | null {
  return ADMIN_KEYWORD_REGEX.test(sql) ? 'admin' : null;
}

export function classifyStatement(sql: string): ClassifierResult {
  if (typeof sql !== 'string' || sql.trim().length === 0) {
    return { ok: false, error: 'empty input' };
  }

  const stripped = stripComments(sql).trim();
  if (stripped.length === 0) {
    return { ok: false, error: 'input contains only comments' };
  }

  if (looksLikeMultipleStatements(sql)) {
    return { ok: false, error: 'multiple statements not allowed (single statement only)' };
  }

  const txCategory = classifyTxKeyword(stripped);
  if (txCategory) {
    return {
      ok: true,
      category: txCategory,
      astType: 'transaction',
      statement: sql,
      targetDatabases: [],
    };
  }

  const adminCategory = classifyAdminKeyword(stripped);
  if (adminCategory) {
    return {
      ok: true,
      category: adminCategory,
      astType: 'admin-keyword',
      statement: sql,
      targetDatabases: extractTargetDatabases(sql),
    };
  }

  let ast;
  try {
    ast = parser.astify(sql, { database: 'mysql' });
  } catch (e) {
    return { ok: false, error: `parser error: ${(e as Error).message}` };
  }

  const node = Array.isArray(ast) ? ast[0] : ast;
  if (!node || typeof node !== 'object' || !('type' in node) || typeof node.type !== 'string') {
    return { ok: false, error: 'parser returned no AST type' };
  }

  const category = categorize(node.type);
  if (!category) {
    return { ok: false, error: `unknown statement type "${node.type}"` };
  }

  return {
    ok: true,
    category,
    astType: node.type,
    statement: sql,
    targetDatabases: extractTargetDatabases(sql),
  };
}
