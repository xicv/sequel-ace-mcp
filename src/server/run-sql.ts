import { randomUUID } from 'node:crypto';
import type { CallToolResult } from '@modelcontextprotocol/sdk/types.js';
import {
  PolicyConfirmationDeclinedError,
  PolicyDeniedError,
  PolicySchema,
} from '../types.js';
import { classifyStatement } from '../policy/classifier.js';
import { evaluatePolicy } from '../policy/gate.js';
import { resolveEffectivePolicy } from '../policy/resolver.js';
import { writeAuditEntry } from '../audit/logger.js';
import { getConnection, loadConfig, resolveConnection, upsertConnection } from '../vault/config.js';
import { executeStatement } from '../sql/executor.js';
import { jsonResult, loadCredentials, noConnectionMessage, toolError, type ToolDeps } from './shared.js';

export interface RunSqlArgs {
  connection?: string;
  sql: string;
  database?: string;
}

export async function runSqlTool(params: {
  deps: ToolDeps;
  args: RunSqlArgs;
  expectReadOnly: boolean;
}): Promise<CallToolResult> {
  const { args, deps, expectReadOnly } = params;
  const { secretStore, confirmFn, auth, grants } = deps;
  const conn = await resolveConnection(args.connection);
  if (!conn) return toolError(noConnectionMessage(args.connection));

  const classified = classifyStatement(args.sql);
  if (!classified.ok) return toolError(`Cannot run statement: ${classified.error}`);

  if (expectReadOnly && classified.category !== 'read') {
    return toolError(
      `query tool only accepts read statements (got ${classified.category}). Use the "execute" tool for non-read statements.`,
    );
  }

  const cfg = await loadConfig();
  const retention = cfg.retention;

  const resolved = resolveEffectivePolicy({
    connection: conn,
    category: classified.category,
    targetDatabases: classified.targetDatabases,
    fallbackDatabase: args.database,
  });

  if (resolved.effective.requireTouchID) {
    const ok = await auth.ensureAuthenticated(
      `Authenticate to run ${classified.category} on ${conn.name}`,
    );
    if (!ok) return toolError('Touch ID authentication failed.');
  }

  const requestId = randomUUID();
  const databasesForLog =
    classified.targetDatabases.length > 0
      ? classified.targetDatabases
      : args.database
        ? [args.database]
        : conn.database
          ? [conn.database]
          : [];

  const grantDatabase =
    resolved.contributingDatabase ??
    (databasesForLog.length > 0 ? databasesForLog[0] : null) ??
    null;

  try {
    await evaluatePolicy({
      policy: resolved.effective,
      category: classified.category,
      statement: args.sql,
      connectionName: conn.name,
      elicitConfirm: confirmFn,
      grants,
      grantDatabase,
      onAlwaysGrant: async (category) => {
        const fresh = await getConnection(conn.name);
        if (!fresh) return;
        const nextPolicy = PolicySchema.parse({ ...fresh.policy, [category]: 'allow' });
        await upsertConnection({ ...fresh, policy: nextPolicy });
      },
    });
  } catch (e) {
    const declined = e instanceof PolicyConfirmationDeclinedError;
    const denied = e instanceof PolicyDeniedError;
    if (declined || denied) {
      writeAuditEntry(
        {
          requestId,
          connection: conn.name,
          databases: databasesForLog,
          category: classified.category,
          astType: classified.astType,
          sql: args.sql,
          decision: denied ? 'deny' : 'confirm',
          confirmed: false,
          outcome: denied ? 'denied' : 'declined',
        },
        { redactSqlInLog: retention.redactSqlInLog, tamperEvidentChain: retention.tamperEvidentChain },
      );
      if (denied) {
        const dbHint = resolved.contributingDatabase ? ` (${resolved.contributingDatabase})` : '';
        return toolError(`Denied by policy: ${classified.category} statements not allowed on "${conn.name}"${dbHint}.`);
      }
      return toolError('User declined confirmation. Statement not executed.');
    }
    throw e;
  }

  const creds = await loadCredentials({ store: secretStore, connection: conn });
  if (!creds) {
    return toolError(
      `No password stored for connection "${conn.name}". Run add_connection or import_from_sequel_ace first.`,
    );
  }

  try {
    const result = await executeStatement({
      connection: conn,
      password: creds.password,
      sshPassword: creds.sshPassword,
      sql: args.sql,
      category: classified.category,
      astType: classified.astType,
      policy: resolved.effective,
      database: args.database,
    });
    writeAuditEntry(
      {
        requestId,
        connection: conn.name,
        databases: databasesForLog,
        category: classified.category,
        astType: classified.astType,
        sql: args.sql,
        decision: resolved.action,
        confirmed: resolved.action === 'confirm',
        outcome: 'success',
        affectedRows: result.affectedRows ?? null,
        durationMs: result.durationMs,
        backupId: result.backupId ?? null,
      },
      { redactSqlInLog: retention.redactSqlInLog, tamperEvidentChain: retention.tamperEvidentChain },
    );
    return jsonResult({
      connection: conn.name,
      category: classified.category,
      contributingDatabase: resolved.contributingDatabase,
      contributingDatabases: resolved.contributingDatabases,
      rows: result.rows,
      fields: result.fields,
      affectedRows: result.affectedRows,
      truncated: result.truncated,
      rowCap: resolved.effective.rowCap,
      durationMs: result.durationMs,
      backupId: result.backupId ?? null,
      backupRowCount: result.backupRowCount ?? 0,
      requestId,
    });
  } catch (e) {
    writeAuditEntry(
      {
        requestId,
        connection: conn.name,
        databases: databasesForLog,
        category: classified.category,
        astType: classified.astType,
        sql: args.sql,
        decision: resolved.action,
        confirmed: resolved.action === 'confirm',
        outcome: 'error',
        error: (e as Error).message,
      },
      { redactSqlInLog: retention.redactSqlInLog, tamperEvidentChain: retention.tamperEvidentChain },
    );
    return toolError(`SQL execution failed: ${(e as Error).message}`);
  }
}
