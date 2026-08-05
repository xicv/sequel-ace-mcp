import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import mysql from 'mysql2/promise';
import { z } from 'zod';
import { getBackup, listBackups } from '../../backup/capture.js';
import { executeRestore, executeRestoreSqlite, planRestore } from '../../backup/restore.js';
import { isMySqlConnection } from '../../types.js';
import { getConnection } from '../../vault/config.js';
import { jsonResult, loadCredentials, toolError, type ToolDeps } from '../shared.js';
import { openSqliteDatabase, type SqliteDatabase } from '../../sql/sqlite.js';

export function registerBackupTools(mcp: McpServer, deps: ToolDeps): void {
  mcp.registerTool(
    'list_backups',
    {
      title: 'List recent row/schema backups',
      description: 'Show recent pre-mutation backups taken before UPDATE/DELETE/TRUNCATE/DROP/ALTER. Each row links to a backup_id.',
      annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: false },
      inputSchema: { connection: z.string().optional(), limit: z.number().int().min(1).max(1000).default(50) },
    },
    async (args) => {
      const rows = listBackups({ connection: args.connection, limit: args.limit });
      return jsonResult({ count: rows.length, rows });
    },
  );

  mcp.registerTool(
    'restore_backup',
    {
      title: 'Restore from a pre-mutation backup',
      description:
        'Replay backup #N into the originating connection. Generates dialect-specific upserts for row backups and CREATE TABLE for schema backups. Subject to the same policy gate (counts as a write). Pass dryRun=true to inspect the plan first.',
      annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: false },
      inputSchema: {
        backupId: z.number().int().positive(),
        dryRun: z.boolean().default(true),
      },
    },
    async (args) => {
      const backup = getBackup(args.backupId);
      if (!backup) return toolError(`Backup #${args.backupId} not found.`);

      const conn = await getConnection(backup.connection);
      if (!conn) return toolError(`Connection "${backup.connection}" referenced by backup no longer exists.`);

      let plan;
      try {
        plan = planRestore(args.backupId, {
          dialect: conn.driver === 'sqlite' ? 'sqlite' : 'mysql',
        });
      } catch (e) {
        return toolError(`Cannot plan restore: ${(e as Error).message}`);
      }

      if (args.dryRun) {
        return jsonResult({
          backupId: args.backupId,
          connection: backup.connection,
          rowCount: plan.rowCount,
          statementCount: plan.statements.length,
          warnings: plan.warnings,
          firstStatementPreview: plan.statements[0]?.slice(0, 240) ?? null,
          note: 'dry-run; pass dryRun=false to actually execute',
        });
      }

      const ok = await deps.confirmFn({
        category: 'write',
        statement: `RESTORE backup #${args.backupId}: ${plan.statements.length} statement(s) into ${backup.connection}.${backup.database ?? '<default>'}.${backup.table_name}`,
        connectionName: backup.connection,
        database: backup.database ?? null,
      });
      if (ok.choice === 'unavailable') {
        return toolError(
          `Restore needs confirmation, but no prompt could be shown: ${ok.reason}. ` +
            `Nothing was restored. This is not a refusal - set an explicit write policy for ` +
            `"${backup.connection}" with set_database_policy, or restore outside this tool.`,
        );
      }
      if (ok.choice === 'decline') return toolError('Restore declined.');

      if (!isMySqlConnection(conn)) {
        let sqliteDb: SqliteDatabase | null = null;
        try {
          sqliteDb = openSqliteDatabase({
            connection: conn,
            readonly: false,
            timeoutMs: conn.policy.stmtTimeoutMs,
          });
          sqliteDb.exec('BEGIN IMMEDIATE');
          const r = executeRestoreSqlite({ db: sqliteDb, plan });
          sqliteDb.exec('COMMIT');
          return jsonResult({ backupId: args.backupId, ...r, warnings: plan.warnings });
        } catch (e) {
          try {
            sqliteDb?.exec('ROLLBACK');
          } catch {
            /* ignore */
          }
          return toolError(`Restore failed: ${(e as Error).message}`);
        } finally {
          try {
            sqliteDb?.close();
          } catch {
            /* ignore */
          }
        }
      }

      const creds = await loadCredentials({ store: deps.secretStore, connection: conn });
      if (!creds) return toolError(`No password for "${backup.connection}".`);

      let mysqlConn: mysql.Connection | null = null;
      try {
        mysqlConn = await mysql.createConnection({
          host: conn.host,
          port: conn.port,
          user: conn.user,
          password: creds.password,
          database: backup.database ?? conn.database,
          multipleStatements: false,
          connectTimeout: 15000,
        });
        await mysqlConn.query('START TRANSACTION READ WRITE');
        const r = await executeRestore({ conn: mysqlConn, plan });
        await mysqlConn.query('COMMIT');
        return jsonResult({ backupId: args.backupId, ...r, warnings: plan.warnings });
      } catch (e) {
        try {
          await mysqlConn?.query('ROLLBACK');
        } catch {
          /* ignore */
        }
        return toolError(`Restore failed: ${(e as Error).message}`);
      } finally {
        try {
          await mysqlConn?.end();
        } catch {
          /* ignore */
        }
      }
    },
  );
}
