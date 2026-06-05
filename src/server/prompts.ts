import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';

export function registerPrompts(mcp: McpServer): void {
  mcp.registerPrompt(
    'setup-connection',
    {
      title: 'Set up a new database connection',
      description:
        'Walks through adding either a MySQL/MariaDB connection with Keychain password capture or a SQLite file connection with no password.',
      argsSchema: {
        suggestedName: z.string().optional(),
      },
    },
    (args) => ({
      messages: [
        {
          role: 'user',
          content: {
            type: 'text',
            text:
              `I want to add a new database connection${args.suggestedName ? ` called "${args.suggestedName}"` : ''}.\n\n` +
              `First ask whether it is MySQL/MariaDB or SQLite. For MySQL/MariaDB, use "add_connection" and ask for: name, host, port (default 3306), user, database (optional), ssl (default false), policy preset (read-only | dev | admin), and optional SSH tunnel (host/port/user/keyPath). The tool will then prompt me for the password via elicitation. Do NOT include the password in the tool arguments. For SQLite, use "add_sqlite_connection" and ask for name, path, database/schema (usually main), and policy preset; no password is used.`,
          },
        },
      ],
    }),
  );

  mcp.registerPrompt(
    'analyze-table',
    {
      title: 'Analyze a table',
      description: 'Read-only investigation: schema, row count, indexes, sample rows.',
      argsSchema: { connection: z.string(), database: z.string().optional(), table: z.string() },
    },
    (args) => ({
      messages: [
        {
          role: 'user',
          content: {
            type: 'text',
            text:
              `Analyze table \`${args.table}\`${args.database ? ` in database \`${args.database}\`` : ''} on connection "${args.connection}". ` +
              `Use only read-only tools: describe_table, list_databases, and query (SELECT/SHOW or read-only SQLite PRAGMA only). Specifically: ` +
              `1) describe schema, 2) inspect indexes (SHOW INDEX for MySQL/MariaDB; PRAGMA index_list/index_info for SQLite), 3) SELECT COUNT(*), 4) SELECT * LIMIT 5. Summarize findings.`,
          },
        },
      ],
    }),
  );
}
