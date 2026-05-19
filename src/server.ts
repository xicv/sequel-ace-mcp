import { randomUUID } from 'node:crypto';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { CallToolResult } from '@modelcontextprotocol/sdk/types.js';
import { z } from 'zod';
import {
  ConnectionSchema,
  POLICY_PRESETS,
  PartialPolicySchema,
  PolicySchema,
  RetentionConfigSchema,
  PolicyConfirmationDeclinedError,
  PolicyDeniedError,
  type Connection,
  type PolicyPresetName,
} from './types.js';
import { classifyStatement } from './policy/classifier.js';
import { evaluatePolicy } from './policy/gate.js';
import { resolveEffectivePolicy } from './policy/resolver.js';
import { writeAuditEntry, searchAuditLog } from './audit/logger.js';
import { cleanupAudit, maybeAutoCleanup } from './audit/retention.js';
import { listBackups, getBackup } from './backup/capture.js';
import { planRestore, executeRestore } from './backup/restore.js';
import mysql from 'mysql2/promise';
import {
  getConnection,
  getDefaultConnectionName,
  loadConfig,
  policyFromPreset,
  removeConnectionByName,
  resolveConnection,
  saveConfig,
  setDefaultConnection,
  upsertConnection,
} from './vault/config.js';
import { KeychainSecretStore, type SecretStore } from './vault/keyring.js';
import { SessionAuthenticator, getTouchID } from './vault/touchid.js';
import { executeStatement } from './sql/executor.js';
import { importFromSequelAce } from './importer/sequelAcePlist.js';
import { readSequelAceHistory, statSequelAceHistory } from './importer/sequelAceHistory.js';
import { searchUnifiedHistory } from './audit/history-search.js';
import { makeConfirmFn } from './elicit/confirm.js';
import { createGrantStore, type GrantStore } from './policy/grants.js';

const PACKAGE_NAME = 'sequel-mcp';
const PACKAGE_VERSION = '0.6.0';

function toolError(text: string): CallToolResult {
  return { isError: true, content: [{ type: 'text', text }] };
}

function jsonResult(value: unknown): CallToolResult {
  return { content: [{ type: 'text', text: JSON.stringify(value, null, 2) }] };
}

function textResult(text: string): CallToolResult {
  return { content: [{ type: 'text', text }] };
}

async function loadCredentials(args: {
  store: SecretStore;
  connection: Connection;
}): Promise<{ password: string; sshPassword?: string } | null> {
  const password = await args.store.getPassword(args.connection.name, args.connection.user);
  if (!password) return null;
  let sshPassword: string | undefined;
  if (args.connection.ssh) {
    const got = await args.store.getPassword(
      `${args.connection.name}::ssh`,
      args.connection.ssh.user,
    );
    if (got) sshPassword = got;
  }
  return { password, sshPassword };
}

export interface AppOptions {
  secretStore?: SecretStore;
}

export function buildServer(opts: AppOptions = {}): McpServer {
  const mcp = new McpServer(
    { name: PACKAGE_NAME, version: PACKAGE_VERSION },
    {
      capabilities: {
        tools: {},
        prompts: {},
        resources: {},
        logging: {},
      },
    },
  );

  const secretStore: SecretStore = opts.secretStore ?? new KeychainSecretStore();
  const confirmFn = makeConfirmFn(mcp.server);
  const grants = createGrantStore();
  const auth = new SessionAuthenticator({ available: false, prompt: async () => false });
  void getTouchID().then((tid) => {
    Object.assign(auth, new SessionAuthenticator(tid));
  });

  void loadConfig()
    .then((cfg) => maybeAutoCleanup(cfg.retention))
    .catch(() => undefined);

  registerTools(mcp, { secretStore, confirmFn, auth, grants });
  registerPrompts(mcp);
  registerResources(mcp, { secretStore });

  return mcp;
}

interface ToolDeps {
  secretStore: SecretStore;
  confirmFn: ReturnType<typeof makeConfirmFn>;
  auth: SessionAuthenticator;
  grants: GrantStore;
}

function registerTools(mcp: McpServer, deps: ToolDeps): void {
  mcp.registerTool(
    'list_connections',
    {
      title: 'List configured connections',
      description: 'Return all connections configured in the local config (no passwords).',
      annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: false },
      inputSchema: {},
    },
    async () => {
      const cfg = await loadConfig();
      const sanitized = cfg.connections.map((c) => ({
        name: c.name,
        host: c.host,
        port: c.port,
        user: c.user,
        database: c.database,
        ssl: c.ssl,
        ssh: c.ssh
          ? {
              host: c.ssh.host,
              user: c.ssh.user,
              port: c.ssh.port,
              docker: c.ssh.docker
                ? {
                    container: c.ssh.docker.container,
                    bridgeTool: c.ssh.docker.bridgeTool,
                  }
                : null,
            }
          : null,
        policy: c.policy,
        isDefault: c.name === cfg.defaultConnection,
        hasStoredPassword: undefined as boolean | undefined,
      }));
      for (const item of sanitized) {
        item.hasStoredPassword = await deps.secretStore.hasPassword(item.name, item.user);
      }
      return jsonResult({ defaultConnection: cfg.defaultConnection ?? null, connections: sanitized });
    },
  );

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
    async (args) => {
      return runSqlTool({ ...deps, args, expectReadOnly: true });
    },
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
    async (args) => {
      return runSqlTool({ ...deps, args, expectReadOnly: false });
    },
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
        ...deps,
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
    async (args) => {
      return runSqlTool({
        ...deps,
        args: { connection: args.connection, sql: 'SHOW DATABASES' },
        expectReadOnly: true,
      });
    },
  );

  // OWASP MCP Top 10 (2026) input hardening note:
  // MCP SDK v1.29 constrains `inputSchema` to ZodRawShape; we cannot pass
  // `z.object({...}).strict()` directly. Zod's default object behavior (strip)
  // discards unknown keys before the handler sees them, so extra LLM-supplied
  // fields cannot influence handler behavior. ConnectionSchema.parse() at the
  // end provides defense-in-depth for the persisted shape.
  mcp.registerTool(
    'add_connection',
    {
      title: 'Add or update a connection',
      description:
        'Persist a connection. The password is captured via elicitation and stored in the macOS Keychain; it never appears in tool arguments or logs.',
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false,
      },
      inputSchema: {
        name: z.string().min(1).max(128),
        host: z.string().min(1),
        port: z.number().int().min(1).max(65535).default(3306),
        user: z.string().min(1),
        database: z.string().optional(),
        ssl: z.boolean().default(false),
        policyPreset: z.enum(['read-only', 'dev', 'admin']).default('read-only'),
        sshHost: z.string().optional(),
        sshPort: z.number().int().min(1).max(65535).optional(),
        sshUser: z.string().optional(),
        sshKeyPath: z.string().optional(),
        sshDockerContainer: z
          .string()
          .regex(
            /^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/,
            'docker container name must be alphanumeric/_.- and start with alnum',
          )
          .optional(),
        sshDockerBridgeTool: z.enum(['socat', 'nc', 'ncat']).optional(),
        sshHostKeyPolicy: z.enum(['lenient', 'strict']).optional(),
        sshKnownHostsPath: z.string().min(1).max(1024).optional(),
        sslServerName: z.string().min(1).max(253).optional(),
      },
    },
    async (args) => {
      const passwordReply = await mcp.server.elicitInput({
        mode: 'form',
        message: `Enter MySQL/MariaDB password for ${args.user}@${args.host}:${args.port}. Stored in macOS Keychain (service "${PACKAGE_NAME} : ${args.name}").`,
        requestedSchema: {
          type: 'object',
          properties: {
            password: {
              type: 'string',
              title: 'Password',
              description: 'Stored locally in macOS Keychain',
            },
          },
          required: ['password'],
        },
      });
      if (passwordReply.action !== 'accept' || typeof passwordReply.content?.['password'] !== 'string') {
        return toolError('Password capture cancelled. Connection not saved.');
      }
      const password = passwordReply.content['password'];

      const ssh =
        args.sshHost && args.sshUser
          ? {
              host: args.sshHost,
              port: args.sshPort ?? 22,
              user: args.sshUser,
              authMethod: args.sshKeyPath ? ('key' as const) : ('password' as const),
              privateKeyPath: args.sshKeyPath,
              docker: args.sshDockerContainer
                ? {
                    container: args.sshDockerContainer,
                    bridgeTool: args.sshDockerBridgeTool ?? ('nc' as const),
                  }
                : undefined,
              hostKeyPolicy: args.sshHostKeyPolicy,
              knownHostsPath: args.sshKnownHostsPath,
            }
          : undefined;

      const connection = ConnectionSchema.parse({
        name: args.name,
        host: args.host,
        port: args.port,
        user: args.user,
        database: args.database,
        ssl: args.ssl,
        sslServerName: args.sslServerName,
        ssh,
        policy: policyFromPreset(args.policyPreset as PolicyPresetName),
      });

      await upsertConnection(connection);
      await deps.secretStore.setPassword(connection.name, connection.user, password);

      return textResult(
        `Saved connection "${connection.name}" with policy preset "${args.policyPreset}". Password stored in macOS Keychain.`,
      );
    },
  );

  mcp.registerTool(
    'remove_connection',
    {
      title: 'Remove a connection',
      description: 'Delete the connection from config and its Keychain password.',
      annotations: {
        readOnlyHint: false,
        destructiveHint: true,
        idempotentHint: true,
        openWorldHint: false,
      },
      inputSchema: { name: z.string().min(1) },
    },
    async (args) => {
      const c = await getConnection(args.name);
      if (!c) return toolError(`Connection "${args.name}" not found`);
      await deps.secretStore.deletePassword(c.name, c.user);
      if (c.ssh) {
        await deps.secretStore.deletePassword(`${c.name}::ssh`, c.ssh.user);
      }
      await removeConnectionByName(args.name);
      return textResult(`Removed connection "${args.name}".`);
    },
  );

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
        policy: z.object({
          read: z.enum(['allow', 'confirm', 'deny']).optional(),
          write: z.enum(['allow', 'confirm', 'deny']).optional(),
          ddl: z.enum(['allow', 'confirm', 'deny']).optional(),
          admin: z.enum(['allow', 'confirm', 'deny']).optional(),
          txCtrl: z.enum(['allow', 'confirm', 'deny']).optional(),
          rowCap: z.number().int().positive().optional(),
          stmtTimeoutMs: z.number().int().positive().optional(),
          requireTouchID: z.boolean().optional(),
        }),
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
    'doctor',
    {
      title: 'Diagnostic report',
      description:
        'Print a sanitized JSON diagnostic of the MCP install: runtime versions, config file presence, Touch ID availability, every configured connection (host/user/db, password presence, SSH key file presence, policy). Contains zero passwords and zero secrets — safe to paste into a bug report.',
      annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: false },
      inputSchema: {},
    },
    async () => {
      const cfg = await loadConfig();
      const def = cfg.defaultConnection ?? null;
      const tid = await getTouchID();
      const conns = await Promise.all(
        cfg.connections.map(async (c) => ({
          name: c.name,
          host: c.host,
          port: c.port,
          user: c.user,
          database: c.database ?? null,
          ssl: c.ssl,
          isDefault: c.name === def,
          hasStoredPassword: await deps.secretStore.hasPassword(c.name, c.user),
          ssh: c.ssh
            ? {
                host: c.ssh.host,
                port: c.ssh.port,
                user: c.ssh.user,
                authMethod: c.ssh.authMethod,
                privateKeyPath: c.ssh.privateKeyPath ?? null,
                docker: c.ssh.docker
                  ? {
                      container: c.ssh.docker.container,
                      bridgeTool: c.ssh.docker.bridgeTool,
                    }
                  : null,
              }
            : null,
          policy: c.policy,
        })),
      );
      const sequelAceHistory = statSequelAceHistory();
      return jsonResult({
        app: 'sequel-mcp',
        version: PACKAGE_VERSION,
        runtime: {
          node: process.versions.node,
          platform: process.platform,
          arch: process.arch,
        },
        touchID: { available: tid.available },
        defaultConnection: def,
        connections: conns,
        sequelAceHistory: {
          available: sequelAceHistory.exists,
          path: sequelAceHistory.path,
          entryCount: sequelAceHistory.entryCount,
          sizeBytes: sequelAceHistory.sizeBytes,
        },
        retention: cfg.retention,
        note: 'no passwords or Keychain secrets included; hostnames/usernames/key paths ARE included — redact before posting publicly.',
      });
    },
  );

  mcp.registerTool(
    'set_default_connection',
    {
      title: 'Set the default connection',
      description:
        'Mark a saved connection as the default. Subsequent query/execute/list_databases/describe_table calls without an explicit "connection" arg will use it. Pass an empty string to clear.',
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false,
      },
      inputSchema: {
        name: z.string().describe('Connection name, or empty string to clear the default.'),
      },
    },
    async (args) => {
      try {
        if (args.name === '') {
          await setDefaultConnection(null);
          return textResult('Default connection cleared.');
        }
        await setDefaultConnection(args.name);
        return textResult(`Default connection is now "${args.name}".`);
      } catch (e) {
        return toolError((e as Error).message);
      }
    },
  );

  mcp.registerTool(
    'get_default_connection',
    {
      title: 'Get the default connection',
      description: 'Return the connection name currently used when "connection" arg is omitted.',
      annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: false },
      inputSchema: {},
    },
    async () => {
      const name = await getDefaultConnectionName();
      return jsonResult({ defaultConnection: name });
    },
  );

  mcp.registerTool(
    'select_database',
    {
      title: 'Set the default database on a connection',
      description:
        'Update a saved connection so that subsequent query/execute calls default to this database when no per-call override is supplied. Does not require the password.',
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false,
      },
      inputSchema: {
        connection: z.string().min(1).optional(),
        database: z
          .string()
          .min(1)
          .max(64)
          .regex(/^[A-Za-z0-9_$]+$/, 'identifier-safe database name'),
      },
    },
    async (args) => {
      const c = await resolveConnection(args.connection);
      if (!c) return toolError(noConnectionMessage(args.connection));
      await upsertConnection({ ...c, database: args.database });
      return textResult(
        `Default database for "${c.name}" set to "${args.database}". Per-call database overrides still take precedence.`,
      );
    },
  );

  mcp.registerTool(
    'import_from_sequel_ace',
    {
      title: 'Import connections from Sequel Ace',
      description:
        'Read Sequel Ace Favorites.plist, copy connections (and optionally passwords via /usr/bin/security; macOS will prompt user to allow access) into our config + keychain. Sequel Ace data is never modified.',
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false,
      },
      inputSchema: { copyPasswords: z.boolean().default(true) },
    },
    async (args) => {
      const result = await importFromSequelAce({
        copyPasswords: args.copyPasswords,
        secretStore: deps.secretStore,
      });
      return jsonResult(result);
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
        policy: z.object({
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
        }),
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
        'Replay backup #N into the originating connection. Generates INSERT … ON DUPLICATE KEY UPDATE for row backups, CREATE TABLE for schema backups. Subject to the same policy gate (counts as a write). Pass dryRun=true to inspect the plan first.',
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
        plan = planRestore(args.backupId);
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
      });
      if (!ok) return toolError('Restore declined.');

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

function noConnectionMessage(explicit: string | undefined): string {
  return explicit
    ? `Unknown connection "${explicit}". Use list_connections to see available names.`
    : 'No connection specified and no default set. Pass "connection" or call set_default_connection first.';
}

async function runSqlTool(params: {
  secretStore: SecretStore;
  confirmFn: ReturnType<typeof makeConfirmFn>;
  auth: SessionAuthenticator;
  grants: GrantStore;
  args: { connection?: string; sql: string; database?: string };
  expectReadOnly: boolean;
}): Promise<CallToolResult> {
  const { args, secretStore, confirmFn, auth, grants, expectReadOnly } = params;
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

function registerPrompts(mcp: McpServer): void {
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

function registerResources(
  mcp: McpServer,
  deps: { secretStore: SecretStore },
): void {
  mcp.registerResource(
    'connections',
    'sequel-mcp://connections',
    {
      title: 'Configured connections',
      description: 'JSON listing of saved connections (no secrets).',
      mimeType: 'application/json',
    },
    async () => {
      const cfg = await loadConfig();
      const items = await Promise.all(
        cfg.connections.map(async (c) => ({
          name: c.name,
          host: c.host,
          port: c.port,
          user: c.user,
          database: c.database,
          ssh: c.ssh
            ? {
                host: c.ssh.host,
                user: c.ssh.user,
                docker: c.ssh.docker
                  ? {
                      container: c.ssh.docker.container,
                      bridgeTool: c.ssh.docker.bridgeTool,
                    }
                  : null,
              }
            : null,
          policy: c.policy,
          presets: Object.keys(POLICY_PRESETS),
          hasPassword: await deps.secretStore.hasPassword(c.name, c.user),
        })),
      );
      return {
        contents: [
          {
            uri: 'sequel-mcp://connections',
            mimeType: 'application/json',
            text: JSON.stringify({ connections: items }, null, 2),
          },
        ],
      };
    },
  );
}
