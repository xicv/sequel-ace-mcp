import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';

export function registerPrompts(mcp: McpServer): void {
  mcp.registerPrompt(
    'setup-connection',
    {
      title: 'Set up a new database connection',
      description:
        'Walks through host, port, user, database, then asks for a password via elicitation and stores it in the macOS Keychain.',
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
              `I want to add a new MySQL/MariaDB connection${args.suggestedName ? ` called "${args.suggestedName}"` : ''}.\n\n` +
              `Use the "add_connection" tool. Ask me for: name, host, port (default 3306), user, database (optional), ssl (default false), policy preset (read-only | dev | admin), and optional SSH tunnel (host/port/user/keyPath). The tool will then prompt me for the password via elicitation. Do NOT include the password in the tool arguments — the tool collects it through the secure elicitation channel.`,
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
              `Use only read-only tools: describe_table, list_databases, and query (SELECT/SHOW only). Specifically: ` +
              `1) describe schema, 2) SHOW INDEX FROM the table, 3) SELECT COUNT(*), 4) SELECT * LIMIT 5. Summarize findings.`,
          },
        },
      ],
    }),
  );
}
