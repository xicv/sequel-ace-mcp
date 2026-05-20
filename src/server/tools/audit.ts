import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { RetentionConfigSchema } from '../../types.js';
import { searchAuditLog } from '../../audit/logger.js';
import { cleanupAudit } from '../../audit/retention.js';
import { searchUnifiedHistory } from '../../audit/history-search.js';
import { loadConfig, saveConfig } from '../../vault/config.js';
import {
  readSequelAceHistory,
  statSequelAceHistory,
} from '../../importer/sequelAceHistory.js';
import { jsonResult, toolError } from '../shared.js';

export function registerAuditTools(mcp: McpServer): void {
  mcp.registerTool(
    'audit_search',
    {
      title: 'Search audit log',
      description:
        'Query the local audit-log SQLite. Returns redacted SQL by default. Includes connection, decision, outcome, duration, and backup_id.',
      annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: false },
      inputSchema: {
        connection: z.string().optional(),
        category: z.enum(['read', 'write', 'ddl', 'admin', 'txCtrl']).optional(),
        outcome: z.enum(['success', 'error', 'denied', 'declined']).optional(),
        sinceIso: z.string().optional(),
        untilIso: z.string().optional(),
        limit: z.number().int().min(1).max(5000).default(200),
      },
    },
    async (args) => {
      const rows = searchAuditLog({
        connection: args.connection,
        category: args.category,
        outcome: args.outcome,
        since: args.sinceIso ? new Date(args.sinceIso) : undefined,
        until: args.untilIso ? new Date(args.untilIso) : undefined,
        limit: args.limit,
      });
      return jsonResult({ count: rows.length, rows });
    },
  );

  mcp.registerTool(
    'audit_cleanup',
    {
      title: 'Clean up audit log + old backups',
      description:
        'Prune audit entries older than retention.auditDays and backups older than retention.backupDays. Hard size caps trigger an additional 20% trim. VACUUMs the file. Pass dryRun=true to preview.',
      annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: false },
      inputSchema: { dryRun: z.boolean().default(false) },
    },
    async (args) => {
      const cfg = await loadConfig();
      const r = cleanupAudit(cfg.retention, { dryRun: args.dryRun });
      return jsonResult(r);
    },
  );

  mcp.registerTool(
    'set_retention',
    {
      title: 'Update retention / cleanup config',
      description:
        'Configure per-category retention (read=7, write=30, ddl=90, admin=180, txCtrl=7 by default), backup retention, hard size caps, and how often auto-cleanup runs on server boot. Pass any subset; missing fields keep current values.',
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false },
      inputSchema: {
        retentionDaysByCategory: z
          .object({
            read: z.number().int().min(1).max(3650).optional(),
            write: z.number().int().min(1).max(3650).optional(),
            ddl: z.number().int().min(1).max(3650).optional(),
            admin: z.number().int().min(1).max(3650).optional(),
            txCtrl: z.number().int().min(1).max(3650).optional(),
          })
          .optional(),
        backupDays: z.number().int().min(1).max(3650).optional(),
        auditMaxMB: z.number().int().min(10).max(100000).optional(),
        backupMaxMB: z.number().int().min(10).max(100000).optional(),
        autoCleanupHours: z.number().int().min(0).max(720).optional(),
        redactSqlInLog: z.boolean().optional(),
        tamperEvidentChain: z.boolean().optional(),
      },
    },
    async (args) => {
      const cfg = await loadConfig();
      const merged = {
        ...cfg.retention,
        ...args,
        retentionDaysByCategory: {
          ...cfg.retention.retentionDaysByCategory,
          ...(args.retentionDaysByCategory ?? {}),
        },
      };
      const next = RetentionConfigSchema.parse(merged);
      await saveConfig({ ...cfg, retention: next });
      return jsonResult(next);
    },
  );

  mcp.registerTool(
    'history_search',
    {
      title: 'Unified history (MCP audit + Sequel Ace)',
      description:
        'Merge our audit_log with Sequel Ace queryHistory.db, sorted by timestamp DESC. Each row has a source field (mcp | sequel-ace). Use source=mcp or source=sequel-ace to filter to one. Useful when you want a single timeline regardless of where a query was run.',
      annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: false },
      inputSchema: {
        sinceIso: z.string().optional(),
        untilIso: z.string().optional(),
        search: z.string().optional(),
        connection: z.string().optional(),
        source: z.enum(['mcp', 'sequel-ace', 'both']).default('both'),
        limit: z.number().int().min(1).max(5000).default(200),
      },
    },
    async (args) => {
      const rows = searchUnifiedHistory({
        sinceIso: args.sinceIso,
        untilIso: args.untilIso,
        search: args.search,
        connection: args.connection,
        source: args.source,
        limit: args.limit,
      });
      return jsonResult({ count: rows.length, rows });
    },
  );

  mcp.registerTool(
    'sequel_ace_history',
    {
      title: 'Read Sequel Ace query history',
      description:
        'Read the queryHistory.db that Sequel Ace maintains in its sandbox. Returns distinct queries the user has run in the GUI (deduplicated by Sequel Ace, with latest createdTime). Read-only — no modification. Optional sinceIso, search (LIKE %text%), limit (default 200, max 5000).',
      annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: false },
      inputSchema: {
        sinceIso: z.string().optional(),
        search: z.string().optional(),
        limit: z.number().int().min(1).max(5000).default(200),
      },
    },
    async (args) => {
      const stat = statSequelAceHistory();
      if (!stat.exists) {
        return toolError(
          `Sequel Ace queryHistory.db not found at ${stat.path}. Open Sequel Ace and run at least one query first, or check that Sequel Ace is installed.`,
        );
      }
      const rows = readSequelAceHistory({
        sinceIso: args.sinceIso,
        search: args.search,
        limit: args.limit,
      });
      return jsonResult({
        source: 'sequel-ace',
        path: stat.path,
        totalAvailable: stat.entryCount,
        returned: rows.length,
        note: 'Sequel Ace dedupes by query text — only the latest createdTime is kept per distinct query.',
        rows,
      });
    },
  );
}
