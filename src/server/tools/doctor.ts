import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { loadConfig } from '../../vault/config.js';
import { getTouchID } from '../../vault/touchid.js';
import { statSequelAceHistory } from '../../importer/sequelAceHistory.js';
import { jsonResult, PACKAGE_VERSION, type ToolDeps } from '../shared.js';
import { isMySqlConnection } from '../../types.js';

export function registerDoctorTool(mcp: McpServer, deps: ToolDeps): void {
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
          driver: c.driver,
          host: isMySqlConnection(c) ? c.host : null,
          port: isMySqlConnection(c) ? c.port : null,
          user: isMySqlConnection(c) ? c.user : null,
          path: isMySqlConnection(c) ? null : c.path,
          database: c.database ?? null,
          ssl: isMySqlConnection(c) ? c.ssl : null,
          isDefault: c.name === def,
          hasStoredPassword: isMySqlConnection(c)
            ? await deps.secretStore.hasPassword(c.name, c.user)
            : false,
          ssh: isMySqlConnection(c) && c.ssh
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

      // Without elicitation there is no way to answer a "confirm" policy, so
      // every confirm-gated statement fails closed. Surfaced here because that
      // is otherwise only discoverable by attempting a write and being refused.
      let elicitationSupported: boolean | null = null;
      try {
        elicitationSupported = Boolean(mcp.server.getClientCapabilities()?.elicitation);
      } catch {
        elicitationSupported = null;
      }

      return jsonResult({
        app: 'sequel-mcp',
        version: PACKAGE_VERSION,
        runtime: {
          node: process.versions.node,
          platform: process.platform,
          arch: process.arch,
        },
        touchID: { available: tid.available },
        elicitation: {
          supported: elicitationSupported,
          note:
            elicitationSupported === false
              ? 'This client cannot show confirmation prompts, so any policy set to "confirm" will always fail closed. Use "allow" or "deny" explicitly.'
              : elicitationSupported === null
                ? 'Could not determine client elicitation support.'
                : 'Client can show confirmation prompts.',
        },
        defaultConnection: def,
        connections: conns,
        sequelAceHistory: {
          available: sequelAceHistory.exists,
          path: sequelAceHistory.path,
          entryCount: sequelAceHistory.entryCount,
          sizeBytes: sequelAceHistory.sizeBytes,
        },
        retention: cfg.retention,
        note: 'no passwords or Keychain secrets included; hostnames/usernames/SQLite paths/key paths ARE included — redact before posting publicly.',
      });
    },
  );
}
