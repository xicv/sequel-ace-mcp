import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { runSqlTool } from '../run-sql.js';
import type { ToolDeps } from '../shared.js';

export function registerSqlTools(mcp: McpServer, deps: ToolDeps): void {
  const queryShape = {
    connection: z
      .string()
      .min(1)
      .optional()
      .describe('Configured connection name. Omit to use the default connection set via set_default_connection.'),
    sql: z.string().min(1).describe('Single SQL statement (multi-statement input rejected)'),
    database: z.string().optional().describe('Override default database'),
  };

  mcp.registerTool(
    'query',
    {
      title: 'Run a read-only SQL query',
      description:
        'Run a single read-only SQL statement (SELECT/SHOW/DESCRIBE/EXPLAIN). Wrapped in START TRANSACTION READ ONLY. Server-side enforced even if the connection user has write privileges.',
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
      description: 'Run DESCRIBE <table>. Always read-only.',
      annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: false },
      inputSchema: {
        connection: z.string().min(1).optional(),
        database: z.string().optional(),
        table: z.string().min(1).regex(/^[A-Za-z0-9_]+$/, 'identifier-safe table name'),
      },
    },
    async (args) => {
      const sql = args.database
        ? `DESCRIBE \`${args.database}\`.\`${args.table}\``
        : `DESCRIBE \`${args.table}\``;
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
      description: 'SHOW DATABASES on the given connection.',
      annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: false },
      inputSchema: { connection: z.string().min(1).optional() },
    },
    async (args) =>
      runSqlTool({
        deps,
        args: { connection: args.connection, sql: 'SHOW DATABASES' },
        expectReadOnly: true,
      }),
  );
}
