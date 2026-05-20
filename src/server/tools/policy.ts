import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import {
  PartialPolicySchema,
  PolicySchema,
  type Connection,
} from '../../types.js';
import {
  getConnection,
  resolveConnection,
  upsertConnection,
} from '../../vault/config.js';
import { jsonResult, noConnectionMessage, textResult, toolError } from '../shared.js';

const policyOverrideShape = z.object({
  read: z.enum(['allow', 'confirm', 'deny']).optional(),
  write: z.enum(['allow', 'confirm', 'deny']).optional(),
  ddl: z.enum(['allow', 'confirm', 'deny']).optional(),
  admin: z.enum(['allow', 'confirm', 'deny']).optional(),
  txCtrl: z.enum(['allow', 'confirm', 'deny']).optional(),
  rowCap: z.number().int().positive().optional(),
  stmtTimeoutMs: z.number().int().positive().optional(),
  maxBackupRows: z.number().int().positive().optional(),
  maxBackupBytes: z.number().int().positive().optional(),
  onBackupOverflow: z.enum(['abort', 'truncate']).optional(),
  requireTouchID: z.boolean().optional(),
});

export function registerPolicyTools(mcp: McpServer): void {
  mcp.registerTool(
    'set_policy',
    {
      title: 'Update a connection policy',
      description:
        'Change the action set (read|write|ddl|admin|txCtrl → allow|confirm|deny) and limits for an existing connection.',
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false,
      },
      inputSchema: {
        name: z.string().min(1),
        policy: policyOverrideShape,
      },
    },
    async (args) => {
      const c = await getConnection(args.name);
      if (!c) return toolError(`Connection "${args.name}" not found`);
      const merged = PolicySchema.parse({ ...c.policy, ...args.policy });
      await upsertConnection({ ...c, policy: merged });
      return jsonResult({ name: c.name, policy: merged });
    },
  );

  mcp.registerTool(
    'set_database_policy',
    {
      title: 'Set per-database policy override',
      description:
        'Override the connection policy for a specific database. Per-DB override takes precedence over the connection baseline. When a single statement touches multiple DBs, the strictest action wins.',
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false },
      inputSchema: {
        connection: z.string().min(1).optional(),
        database: z.string().min(1).max(64),
        policy: policyOverrideShape,
      },
    },
    async (args) => {
      const conn = await resolveConnection(args.connection);
      if (!conn) return toolError(noConnectionMessage(args.connection));
      const partial = PartialPolicySchema.parse(args.policy);
      const next: Connection = {
        ...conn,
        databasePolicies: { ...(conn.databasePolicies ?? {}), [args.database]: partial },
      };
      await upsertConnection(next);
      return jsonResult({
        connection: conn.name,
        database: args.database,
        policy: partial,
      });
    },
  );

  mcp.registerTool(
    'clear_database_policy',
    {
      title: 'Clear per-database policy override',
      description: 'Remove the override for a specific database; the connection baseline cascades again.',
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false },
      inputSchema: { connection: z.string().min(1).optional(), database: z.string().min(1) },
    },
    async (args) => {
      const conn = await resolveConnection(args.connection);
      if (!conn) return toolError(noConnectionMessage(args.connection));
      if (!conn.databasePolicies?.[args.database]) {
        return textResult(`No override exists for ${conn.name}/${args.database}.`);
      }
      const remaining = { ...conn.databasePolicies };
      delete remaining[args.database];
      const next: Connection = {
        ...conn,
        databasePolicies: Object.keys(remaining).length > 0 ? remaining : undefined,
      };
      await upsertConnection(next);
      return textResult(`Cleared override for ${conn.name}/${args.database}.`);
    },
  );

  mcp.registerTool(
    'list_database_policies',
    {
      title: 'List per-database policy overrides',
      description: 'Show baseline + every per-DB override for a connection.',
      annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: false },
      inputSchema: { connection: z.string().min(1).optional() },
    },
    async (args) => {
      const conn = await resolveConnection(args.connection);
      if (!conn) return toolError(noConnectionMessage(args.connection));
      return jsonResult({
        connection: conn.name,
        baseline: conn.policy,
        overrides: conn.databasePolicies ?? {},
      });
    },
  );
}
