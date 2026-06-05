import { createRequire } from 'node:module';
import type { SqlCategory } from '../types.js';

const require = createRequire(import.meta.url);
const { Parser } = require('node-sql-parser') as typeof import('node-sql-parser');
type ParserDialect = 'mysql' | 'sqlite';

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

function parseTableList(sql: string, dialect: ParserDialect): TableRef[] {
  try {
    const list = parser.tableList(sql, { database: dialect });
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

export function extractTargetDatabases(
  sql: string,
  opts: { dialect?: ParserDialect } = {},
): string[] {
  const refs = parseTableList(sql, opts.dialect ?? 'mysql');
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
  /^\s*(grant|revoke|set\s+(global|persist|persist_only|@@global|@@persist)|kill|flush|reset(\s+master|\s+slave|\s+replica)?|lock\s+tables|unlock\s+tables|load\s+data|handler\b|do\s+|change\s+master|change\s+replication|start\s+slave|stop\s+slave|start\s+replica|stop\s+replica|optimize\s+table|repair\s+table|analyze\s+table|check\s+table|create\s+user|alter\s+user|drop\s+user|rename\s+user|set\s+password|attach\s+database|detach\s+database|vacuum|reindex)\b/i;

const READ_ONLY_PRAGMAS = new Set([
  'application_id',
  'collation_list',
  'compile_options',
  'database_list',
  'foreign_key_check',
  'foreign_key_list',
  'freelist_count',
  'function_list',
  'index_info',
  'index_list',
  'index_xinfo',
  'integrity_check',
  'module_list',
  'page_count',
  'page_size',
  'quick_check',
  'schema_version',
  'table_info',
  'table_list',
  'table_xinfo',
  'user_version',
]);

function classifySqlitePragma(sql: string): SqlCategory | null {
  const match = /^\s*pragma\s+(?:(?:`[^`]+`|"[^"]+"|\[[^\]]+\]|[A-Za-z_][\w]*)\.)?([A-Za-z_][\w]*)\b/i.exec(sql);
  if (!match) return null;
  const name = match[1]!.toLowerCase();
  if (sql.includes('=') || !READ_ONLY_PRAGMAS.has(name)) return 'admin';
  return 'read';
}

function classifyTxKeyword(sql: string): SqlCategory | null {
  return TX_KEYWORD_REGEX.test(sql) ? 'txCtrl' : null;
}

function classifyAdminKeyword(sql: string): SqlCategory | null {
  return ADMIN_KEYWORD_REGEX.test(sql) ? 'admin' : null;
}

export function classifyStatement(
  sql: string,
  opts: { dialect?: ParserDialect } = {},
): ClassifierResult {
  const dialect = opts.dialect ?? 'mysql';
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

  if (dialect === 'sqlite') {
    const pragmaCategory = classifySqlitePragma(stripped);
    if (pragmaCategory) {
      return {
        ok: true,
        category: pragmaCategory,
        astType: 'pragma',
        statement: sql,
        targetDatabases: [],
      };
    }
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
      targetDatabases: extractTargetDatabases(sql, { dialect }),
    };
  }

  let ast;
  try {
    ast = parser.astify(sql, { database: dialect });
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
    targetDatabases: extractTargetDatabases(sql, { dialect }),
  };
}
