import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { SqlCategory } from '../types.js';

type ServerHandle = McpServer['server'];

export type GrantChoice = 'once' | 'session' | 'always' | 'decline';

const CATEGORY_LABEL: Record<SqlCategory, string> = {
  read: 'read',
  write: 'WRITE',
  ddl: 'DDL (schema-changing)',
  admin: 'ADMIN',
  txCtrl: 'transaction control',
};

const GRANT_CHOICES: readonly GrantChoice[] = ['once', 'session', 'always', 'decline'];

function isGrantChoice(value: unknown): value is GrantChoice {
  return typeof value === 'string' && (GRANT_CHOICES as readonly string[]).includes(value);
}

export function makeConfirmFn(server: ServerHandle) {
  return async (args: {
    category: SqlCategory;
    statement: string;
    connectionName: string;
  }): Promise<GrantChoice> => {
    const snippet =
      args.statement.length > 800
        ? `${args.statement.slice(0, 800)}…`
        : args.statement;

    const label = CATEGORY_LABEL[args.category];

    try {
      const result = await server.elicitInput({
        message:
          `About to run a ${label} statement on connection "${args.connectionName}".\n\n` +
          `--- SQL ---\n${snippet}\n--- end ---\n\n` +
          `Pick an authorization scope. "Allow for session" skips the prompt for further ${label} ` +
          `statements on this connection until the MCP server restarts. "Allow always" persists the ` +
          `policy as "allow" in your saved config.`,
        requestedSchema: {
          type: 'object',
          properties: {
            choice: {
              type: 'string',
              title: 'Authorization',
              description: 'How should this statement be authorized?',
              enum: ['once', 'session', 'always', 'decline'],
              enumNames: [
                'Allow once (this statement only)',
                `Allow for session (all ${label} statements until restart)`,
                'Allow always (persist policy as allow)',
                'Decline',
              ],
            },
          },
          required: ['choice'],
        },
      });

      if (result.action !== 'accept') return 'decline';
      const value = result.content?.['choice'];
      return isGrantChoice(value) ? value : 'decline';
    } catch {
      return 'decline';
    }
  };
}
