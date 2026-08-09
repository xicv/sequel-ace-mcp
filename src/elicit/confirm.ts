import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { SqlCategory } from '../types.js';

type ServerHandle = McpServer['server'];

export type GrantChoice = 'once' | 'session' | 'decline';

/**
 * Outcome of asking the user to authorize a statement.
 *
 * `unavailable` means the question was never put to them - the client does not
 * support elicitation, or the request failed. It is deliberately not folded
 * into `decline`, so callers can say what actually happened.
 */
export type ConfirmOutcome =
  | { choice: GrantChoice }
  | { choice: 'unavailable'; reason: string };

const CATEGORY_LABEL: Record<SqlCategory, string> = {
  read: 'read',
  write: 'WRITE',
  ddl: 'DDL (schema-changing)',
  admin: 'ADMIN',
  txCtrl: 'transaction control',
};

const GRANT_CHOICES: readonly GrantChoice[] = ['once', 'session', 'decline'];

function isGrantChoice(value: unknown): value is GrantChoice {
  return typeof value === 'string' && (GRANT_CHOICES as readonly string[]).includes(value);
}

function describeError(error: unknown): string {
  if (error instanceof Error) {
    return error.message;
  }
  return typeof error === 'string' ? error : 'unknown error';
}

export function makeConfirmFn(server: ServerHandle) {
  return async (args: {
    category: SqlCategory;
    statement: string;
    connectionName: string;
    database?: string | null;
  }): Promise<ConfirmOutcome> => {
    const snippet =
      args.statement.length > 800
        ? `${args.statement.slice(0, 800)}…`
        : args.statement;

    const label = CATEGORY_LABEL[args.category];

    const target = args.database
      ? `${args.connectionName} · ${args.database}`
      : args.connectionName;
    const sessionScope = args.database
      ? `all ${label} statements on ${args.database} until the MCP server restarts`
      : `all ${label} statements on this connection until the MCP server restarts`;

    // Elicitation is an optional MCP capability. Asking a client that never
    // declared it produces a "method not found" error that is indistinguishable
    // from a refusal, so check first and report the real reason.
    let capabilities;
    try {
      capabilities = server.getClientCapabilities();
    } catch (error) {
      return { choice: 'unavailable', reason: describeError(error) };
    }

    if (!capabilities?.elicitation) {
      return {
        choice: 'unavailable',
        reason: 'this MCP client does not support elicitation (no prompt can be shown)',
      };
    }

    try {
      const result = await server.elicitInput({
        message:
          `About to run a ${label} statement on ${target}.\n\n` +
          `--- SQL ---\n${snippet}\n--- end ---\n\n` +
          `Pick an authorization scope. "Allow for session" skips the prompt for ${sessionScope} ` +
          `To make this permanent, use the set_database_policy tool.`,
        requestedSchema: {
          type: 'object',
          properties: {
            choice: {
              type: 'string',
              title: 'Authorization',
              description: 'How should this statement be authorized?',
              enum: ['once', 'session', 'decline'],
              enumNames: [
                'Allow once (this statement only)',
                `Allow for session (${sessionScope})`,
                'Decline',
              ],
            },
          },
          required: ['choice'],
        },
      });

      // Per the MCP spec, "cancel" means the client dismissed the request
      // *without* an explicit choice - a timeout, no UI to show it in, the
      // user closing a dialog unanswered. That is not the same thing as
      // "decline" (an explicit no) and must not be reported as one: a client
      // that can never get a real answer (e.g. running in an unattended
      // mode with no interactive surface) will legitimately resolve every
      // elicitation this way, and folding it into "decline" fabricates a
      // refusal nobody made.
      if (result.action === 'cancel') {
        return {
          choice: 'unavailable',
          reason:
            'the client dismissed the prompt without an explicit choice - no UI to show it in, a timeout, or it was closed unanswered',
        };
      }

      // Only "decline" left as a non-accept action; it is a real answer.
      if (result.action !== 'accept') return { choice: 'decline' };

      const value = result.content?.['choice'];
      return { choice: isGrantChoice(value) ? value : 'decline' };
    } catch (error) {
      return { choice: 'unavailable', reason: describeError(error) };
    }
  };
}
