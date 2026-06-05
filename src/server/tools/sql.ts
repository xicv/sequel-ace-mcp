import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { runSqlTool } from '../run-sql.js';
import { noConnectionMessage, toolError, type ToolDeps } from '../shared.js';
import { resolveConnection } from '../../vault/config.js';

function quoteId(id: string): string {
  return '`' + id.replace(/`/g, '``') + '`';
}

function quoteString(value: string): string {
  return `'${value.replace(/'/g, "''")}'`;
}

export function registerSqlTools(mcp: McpServer, deps: ToolDeps): void {
  const queryShape = {
    connection: z
      .string()
      .min(1)
      .optional()
      .describe('Configured connection name. Omit to use the default connection set via set_default_connection.'),
    sql: z.string().min(1).describe('Single SQL statement (multi-statement input rejected)'),
    database: z.string().optional().describe('Override default database/schema'),
  };

  mcp.registerTool(
    'query',
    {
      title: 'Run a read-only SQL query',
      description:
        'Run a single read-only SQL statement (SELECT/SHOW/DESCRIBE/EXPLAIN, plus read-only SQLite PRAGMA). MySQL/MariaDB uses START TRANSACTION READ ONLY; SQLite opens a read-only file handle.',
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false,
      },
      inputSchema: queryShape,
    },
    async (args) => runSqlTool({ deps, args, expectReadOnly: true }),
  );

  mcp.registerTool(
    'execute',
    {
      title: 'Execute a write/DDL/admin SQL statement',
      description:
        'Run a non-read SQL statement (INSERT/UPDATE/DELETE/DDL/admin). Subject to the connection policy: write/ddl/admin may be allow|confirm|deny. Confirm triggers a user elicitation.',
      annotations: {
        readOnlyHint: false,
        destructiveHint: true,
        idempotentHint: false,
        openWorldHint: false,
      },
      inputSchema: queryShape,
    },
    async (args) => runSqlTool({ deps, args, expectReadOnly: false }),
  );

  mcp.registerTool(
    'describe_table',
    {
      title: 'Describe a table',
      description: 'Describe a table. Uses DESCRIBE on MySQL/MariaDB and PRAGMA table_info on SQLite. Always read-only.',
      annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: false },
      inputSchema: {
        connection: z.string().min(1).optional(),
        database: z.string().optional(),
        table: z.string().min(1).regex(/^[A-Za-z0-9_]+$/, 'identifier-safe table name'),
      },
    },
    async (args) => {
      const conn = await resolveConnection(args.connection);
      if (!conn) return toolError(noConnectionMessage(args.connection));
      const sql =
        conn.driver === 'sqlite'
          ? `PRAGMA ${quoteId(args.database ?? conn.database ?? 'main')}.table_info(${quoteString(args.table)})`
          : args.database
            ? `DESCRIBE ${quoteId(args.database)}.${quoteId(args.table)}`
            : `DESCRIBE ${quoteId(args.table)}`;
      return runSqlTool({
        deps,
        args: { connection: args.connection, sql, database: args.database },
        expectReadOnly: true,
      });
    },
  );

  mcp.registerTool(
    'list_databases',
    {
      title: 'List databases',
      description: 'SHOW DATABASES on MySQL/MariaDB or PRAGMA database_list on SQLite.',
      annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: false },
      inputSchema: { connection: z.string().min(1).optional() },
    },
    async (args) => {
      const conn = await resolveConnection(args.connection);
      if (!conn) return toolError(noConnectionMessage(args.connection));
      return runSqlTool({
        deps,
        args: {
          connection: args.connection,
          sql: conn.driver === 'sqlite' ? 'PRAGMA database_list' : 'SHOW DATABASES',
        },
        expectReadOnly: true,
      });
    },
  );
}
