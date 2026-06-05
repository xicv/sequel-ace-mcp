import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const { Parser } = require('node-sql-parser') as typeof import('node-sql-parser');

const parser = new Parser();
export type SqlDialect = 'mysql' | 'sqlite';

export type BackupSpec =
  | { kind: 'none'; reason?: string }
  | {
      kind: 'rows';
      tables: { db: string | null; table: string; selectSql: string; locking: 'FOR UPDATE' | 'NONE' }[];
    }
  | { kind: 'schema'; tables: { db: string | null; table: string }[] }
  | {
      kind: 'combined';
      tables: { db: string | null; table: string; selectSql: string; locking: 'FOR UPDATE' | 'NONE' }[];
    }
  | {
      kind: 'insert-hint';
      table: { db: string | null; table: string };
      columns: string[];
      explicitPkValues: unknown[][] | null;
    };

interface UpdateLikeAst {
  type: string;
  table?: TableRef[];
  from?: TableRef[];
  name?: TableRef[];
  set?: SetEntry[];
  where?: unknown;
  with?: unknown;
  columns?: string[];
  values?: { values?: { value?: unknown[] }[] };
}

interface SetEntry {
  column: string;
  value: unknown;
  table?: string | null;
}

interface TableRef {
  db?: string | null;
  table?: string;
  as?: string | null;
  join?: string;
  on?: unknown;
}

function quoteId(id: string): string {
  return '`' + id.replace(/`/g, '``') + '`';
}

function tableRefSql(db: string | null | undefined, table: string): string {
  return db ? `${quoteId(db)}.${quoteId(table)}` : quoteId(table);
}

function findRefForName(tables: TableRef[], name: string): TableRef | null {
  for (const t of tables) {
    if (t.as === name || t.table === name) return t;
  }
  return null;
}

function buildSelectFor(args: {
  selectColumns: string;
  fromTables: TableRef[];
  where: unknown;
  forUpdate: boolean;
  dialect: SqlDialect;
}): string | null {
  const lockSuffix = args.forUpdate && args.dialect === 'mysql' ? ' FOR UPDATE' : '';
  if (args.fromTables.length === 0) return null;
  if (args.fromTables.length === 1) {
    const t = args.fromTables[0]!;
    if (!t.table) return null;
    if (!args.where) {
      const base = `SELECT ${args.selectColumns} FROM ${tableRefSql(t.db ?? null, t.table)}`;
      return `${base}${lockSuffix}`;
    }
  }

  if (args.where) {
    try {
      const tmpAst = {
        type: 'select',
        with: null,
        options: null,
        distinct: null,
        columns: [
          { expr: { type: 'column_ref', table: null, column: args.selectColumns === '*' ? '*' : args.selectColumns }, as: null },
        ],
        from: args.fromTables,
        where: args.where,
        groupby: null,
        having: null,
        orderby: null,
        limit: null,
      };
      const sql = parser.sqlify(tmpAst as unknown as Parameters<typeof parser.sqlify>[0], { database: args.dialect });
      if (typeof sql !== 'string') return null;
      return `${sql}${lockSuffix}`;
    } catch {
      return null;
    }
  }

  return null;
}

function inferMutatedTables(setEntries: SetEntry[], fromTables: TableRef[]): TableRef[] {
  const fallback = fromTables[0];
  const namesSeen = new Set<string>();
  const out: TableRef[] = [];
  for (const e of setEntries) {
    const name = e.table ?? null;
    const ref = name ? findRefForName(fromTables, name) : fallback;
    if (!ref?.table) continue;
    const key = `${ref.db ?? ''}.${ref.table}`;
    if (namesSeen.has(key)) continue;
    namesSeen.add(key);
    out.push(ref);
  }
  if (out.length === 0 && fallback?.table) out.push(fallback);
  return out;
}

function buildPerTableSelect(args: {
  target: TableRef;
  fullFrom: TableRef[];
  where: unknown;
  dialect: SqlDialect;
}): string | null {
  const lockSuffix = args.dialect === 'mysql' ? ' FOR UPDATE' : '';
  const targetName = args.target.as ?? args.target.table;
  const colExpr = `${quoteId(targetName!)}.*`;
  if (args.fullFrom.length === 1 && !args.where) {
    return `SELECT ${colExpr} FROM ${tableRefSql(args.target.db ?? null, args.target.table!)}${lockSuffix}`;
  }
  try {
    const tmpAst = {
      type: 'select',
      with: null,
      options: null,
      distinct: null,
      columns: [{ expr: { type: 'column_ref', table: targetName, column: '*' }, as: null }],
      from: args.fullFrom,
      where: args.where ?? null,
      groupby: null,
      having: null,
      orderby: null,
      limit: null,
    };
    const sql = parser.sqlify(tmpAst as unknown as Parameters<typeof parser.sqlify>[0], { database: args.dialect });
    if (typeof sql !== 'string') return null;
    return `${sql}${lockSuffix}`;
  } catch {
    return null;
  }
}

function extractAllRowValues(ast: UpdateLikeAst): unknown[][] | null {
  const values = ast.values?.values;
  if (!Array.isArray(values) || values.length === 0) return null;
  const out: unknown[][] = [];
  for (const row of values) {
    if (!Array.isArray(row.value)) return null;
    out.push(
      row.value.map((v) => {
        if (v && typeof v === 'object' && 'value' in (v as Record<string, unknown>)) {
          return (v as { value: unknown }).value;
        }
        return v;
      }),
    );
  }
  return out;
}

const PK_GUESS_NAMES = ['id', 'uuid', 'pk'];

function guessPkColumn(columns: string[]): { name: string; index: number } | null {
  for (const guess of PK_GUESS_NAMES) {
    const idx = columns.findIndex((c) => c.toLowerCase() === guess);
    if (idx >= 0) return { name: columns[idx]!, index: idx };
  }
  return null;
}

export function extractBackupSpec(
  sql: string,
  astType: string,
  opts: { dialect?: SqlDialect } = {},
): BackupSpec {
  const dialect = opts.dialect ?? 'mysql';
  let ast: UpdateLikeAst | null = null;
  try {
    const parsed = parser.astify(sql, { database: dialect });
    ast = (Array.isArray(parsed) ? parsed[0] : parsed) as UpdateLikeAst | null;
  } catch (e) {
    return { kind: 'none', reason: `parse error: ${(e as Error).message}` };
  }
  if (!ast) return { kind: 'none', reason: 'no AST' };

  const t = astType.toLowerCase();

  if (t === 'update') {
    const fromTables = ast.table ?? [];
    if (fromTables.length === 0) return { kind: 'none', reason: 'UPDATE has no target table' };

    if (fromTables.length === 1) {
      const target = fromTables[0]!;
      if (!target.table) return { kind: 'none', reason: 'UPDATE missing table name' };
      const selectSql = buildSelectFor({
        selectColumns: '*',
        fromTables,
        where: ast.where,
        forUpdate: true,
        dialect,
      });
      if (!selectSql) return { kind: 'none', reason: 'failed to construct backup SELECT' };
      return {
        kind: 'rows',
        tables: [
          {
            db: target.db ?? null,
            table: target.table,
            selectSql,
            locking: dialect === 'mysql' ? 'FOR UPDATE' : 'NONE',
          },
        ],
      };
    }

    const setEntries = ast.set ?? [];
    if (setEntries.length === 0) return { kind: 'none', reason: 'multi-table UPDATE has no SET' };
    const mutated = inferMutatedTables(setEntries, fromTables);
    const tables: { db: string | null; table: string; selectSql: string; locking: 'FOR UPDATE' | 'NONE' }[] = [];
    for (const target of mutated) {
      if (!target.table) continue;
      const selectSql = buildPerTableSelect({ target, fullFrom: fromTables, where: ast.where, dialect });
      if (!selectSql) {
        return { kind: 'none', reason: `failed to construct backup SELECT for table "${target.table}"` };
      }
      tables.push({
        db: target.db ?? null,
        table: target.table,
        selectSql,
        locking: dialect === 'mysql' ? 'FOR UPDATE' : 'NONE',
      });
    }
    if (tables.length === 0) return { kind: 'none', reason: 'no mutated tables identified in multi-table UPDATE' };
    return { kind: 'rows', tables };
  }

  if (t === 'delete') {
    const fromTables = ast.from ?? ast.table ?? [];
    const deleteTargets = ast.from ? ast.table ?? [] : [];
    if (fromTables.length === 0) return { kind: 'none', reason: 'DELETE has no source table' };

    if (fromTables.length === 1) {
      const target = fromTables[0]!;
      if (!target.table) return { kind: 'none', reason: 'DELETE missing table name' };
      const selectSql = buildSelectFor({
        selectColumns: '*',
        fromTables,
        where: ast.where,
        forUpdate: true,
        dialect,
      });
      if (!selectSql) return { kind: 'none', reason: 'failed to construct backup SELECT' };
      return {
        kind: 'rows',
        tables: [
          {
            db: target.db ?? null,
            table: target.table,
            selectSql,
            locking: dialect === 'mysql' ? 'FOR UPDATE' : 'NONE',
          },
        ],
      };
    }

    const targets = deleteTargets.length > 0 ? deleteTargets : fromTables;
    const tables: { db: string | null; table: string; selectSql: string; locking: 'FOR UPDATE' | 'NONE' }[] = [];
    for (const target of targets) {
      const ref = target.table ? findRefForName(fromTables, target.table) : null;
      const actual = ref ?? target;
      if (!actual?.table) continue;
      const selectSql = buildPerTableSelect({ target: actual, fullFrom: fromTables, where: ast.where, dialect });
      if (!selectSql) {
        return { kind: 'none', reason: `failed to construct backup SELECT for table "${actual.table}"` };
      }
      tables.push({
        db: actual.db ?? null,
        table: actual.table,
        selectSql,
        locking: dialect === 'mysql' ? 'FOR UPDATE' : 'NONE',
      });
    }
    if (tables.length === 0) return { kind: 'none', reason: 'no DELETE targets identified' };
    return { kind: 'rows', tables };
  }

  if (t === 'replace') {
    const tables = ast.table ?? [];
    const target = tables[0];
    if (tables.length !== 1 || !target?.table) return { kind: 'none', reason: 'REPLACE target unclear' };
    const cols = ast.columns ?? [];
    const allRows = extractAllRowValues(ast);
    const pk = cols.length > 0 ? guessPkColumn(cols) : null;
    if (cols.length > 0 && pk && allRows && allRows.length > 0) {
      const pkValues = allRows.map((row) => row[pk.index]);
      const placeholders = pkValues.map(() => '?').join(', ');
      const lockSuffix = dialect === 'mysql' ? ' FOR UPDATE' : '';
      const selectSql = `SELECT * FROM ${tableRefSql(target.db ?? null, target.table)} WHERE ${quoteId(pk.name)} IN (${placeholders})${lockSuffix}`;
      const bound = bindLiterals(selectSql, pkValues);
      return {
        kind: 'rows',
        tables: [
          {
            db: target.db ?? null,
            table: target.table,
            selectSql: bound,
            locking: dialect === 'mysql' ? 'FOR UPDATE' : 'NONE',
          },
        ],
      };
    }
    return { kind: 'none', reason: 'REPLACE without identifiable PK column; no backup taken' };
  }

  if (t === 'insert') {
    const tables = ast.table ?? [];
    const target = tables[0];
    if (!target?.table) return { kind: 'none', reason: 'INSERT target unclear' };
    const cols = ast.columns ?? [];
    const allRows = extractAllRowValues(ast);
    let explicitPk: unknown[][] | null = null;
    if (cols.length > 0 && allRows) {
      const pk = guessPkColumn(cols);
      if (pk) {
        explicitPk = allRows.map((row) => [row[pk.index]]);
      }
    }
    return {
      kind: 'insert-hint',
      table: { db: target.db ?? null, table: target.table },
      columns: cols,
      explicitPkValues: explicitPk,
    };
  }

  if (t === 'truncate') {
    const tables = ast.name ?? ast.table ?? ast.from ?? [];
    const t0 = tables[0];
    if (!t0?.table) return { kind: 'none', reason: 'TRUNCATE target unclear' };
    return {
      kind: 'combined',
      tables: [
        {
          db: t0.db ?? null,
          table: t0.table,
          selectSql: `SELECT * FROM ${tableRefSql(t0.db ?? null, t0.table)}`,
          locking: 'NONE',
        },
      ],
    };
  }

  if (t === 'drop') {
    const tables = ast.name ?? ast.table ?? ast.from ?? [];
    const t0 = tables[0];
    if (!t0?.table) return { kind: 'none', reason: 'DROP target unclear' };
    return {
      kind: 'combined',
      tables: [
        {
          db: t0.db ?? null,
          table: t0.table,
          selectSql: `SELECT * FROM ${tableRefSql(t0.db ?? null, t0.table)}`,
          locking: 'NONE',
        },
      ],
    };
  }

  if (t === 'alter' || t === 'rename') {
    const tables = ast.table ?? ast.from ?? ast.name ?? [];
    const refs = tables.filter((tr) => !!tr?.table);
    if (refs.length === 0) return { kind: 'none', reason: 'ALTER/RENAME target unclear' };
    return { kind: 'schema', tables: refs.map((r) => ({ db: r.db ?? null, table: r.table! })) };
  }

  return { kind: 'none', reason: `no backup strategy for AST type "${astType}"` };
}

function bindLiterals(template: string, values: unknown[]): string {
  let i = 0;
  return template.replace(/\?/g, () => formatLiteral(values[i++]));
}

function formatLiteral(v: unknown): string {
  if (v === null || v === undefined) return 'NULL';
  if (typeof v === 'number' || typeof v === 'bigint') return String(v);
  if (typeof v === 'boolean') return v ? '1' : '0';
  return `'${String(v).replace(/\\/g, '\\\\').replace(/'/g, "''")}'`;
}

export function isBackupRequired(astType: string): boolean {
  const t = astType.toLowerCase();
  return ['update', 'delete', 'replace', 'insert', 'truncate', 'drop', 'alter', 'rename'].includes(t);
}
