import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import {
  MySqlConnectionSchema,
  SqliteConnectionSchema,
  isMySqlConnection,
  type PolicyPresetName,
} from '../../types.js';
import {
  getConnection,
  getDefaultConnectionName,
  loadConfig,
  policyFromPreset,
  removeConnectionByName,
  resolveConnection,
  setDefaultConnection,
  upsertConnection,
} from '../../vault/config.js';
import { importFromSequelAce } from '../../importer/sequelAcePlist.js';
import { jsonResult, noConnectionMessage, PACKAGE_NAME, textResult, toolError, type ToolDeps } from '../shared.js';

export function registerConnectionTools(mcp: McpServer, deps: ToolDeps): void {
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
      const sanitized = await Promise.all(
        cfg.connections.map(async (c) => ({
          name: c.name,
          driver: c.driver,
          host: isMySqlConnection(c) ? c.host : undefined,
          port: isMySqlConnection(c) ? c.port : undefined,
          user: isMySqlConnection(c) ? c.user : undefined,
          path: isMySqlConnection(c) ? undefined : c.path,
          database: c.database,
          ssl: isMySqlConnection(c) ? c.ssl : undefined,
          ssh: isMySqlConnection(c) && c.ssh
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
          hasStoredPassword: isMySqlConnection(c)
            ? await deps.secretStore.hasPassword(c.name, c.user)
            : false,
        })),
      );
      return jsonResult({ defaultConnection: cfg.defaultConnection ?? null, connections: sanitized });
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
      title: 'Add or update a MySQL/MariaDB connection',
      description:
        'Persist a MySQL/MariaDB connection. The password is captured via elicitation and stored in the macOS Keychain; it never appears in tool arguments or logs.',
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

      const connection = MySqlConnectionSchema.parse({
        driver: 'mysql',
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
    'add_sqlite_connection',
    {
      title: 'Add or update a SQLite connection',
      description:
        'Persist a SQLite database file connection. Stores only the local file path and policy; no password or Keychain entry is used.',
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false,
      },
      inputSchema: {
        name: z.string().min(1).max(128),
        path: z.string().min(1).max(4096).describe('SQLite database file path. "~/" is expanded at execution time.'),
        database: z
          .string()
          .min(1)
          .max(64)
          .default('main')
          .describe('SQLite schema name used for policy scope and metadata lookups. Usually "main".'),
        policyPreset: z.enum(['read-only', 'dev', 'admin']).default('read-only'),
      },
    },
    async (args) => {
      const connection = SqliteConnectionSchema.parse({
        driver: 'sqlite',
        name: args.name,
        path: args.path,
        database: args.database,
        policy: policyFromPreset(args.policyPreset as PolicyPresetName),
      });

      await upsertConnection(connection);

      return textResult(
        `Saved SQLite connection "${connection.name}" with policy preset "${args.policyPreset}". No password was stored.`,
      );
    },
  );

  mcp.registerTool(
    'remove_connection',
    {
      title: 'Remove a connection',
      description: 'Delete the connection from config and delete any associated MySQL/MariaDB Keychain password.',
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
      if (isMySqlConnection(c)) {
        await deps.secretStore.deletePassword(c.name, c.user);
      }
      if (isMySqlConnection(c) && c.ssh) {
        await deps.secretStore.deletePassword(`${c.name}::ssh`, c.ssh.user);
      }
      await removeConnectionByName(args.name);
      return textResult(`Removed connection "${args.name}".`);
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
}
