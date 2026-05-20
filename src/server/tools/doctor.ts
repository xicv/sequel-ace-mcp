import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { loadConfig } from '../../vault/config.js';
import { getTouchID } from '../../vault/touchid.js';
import { statSequelAceHistory } from '../../importer/sequelAceHistory.js';
import { jsonResult, PACKAGE_VERSION, type ToolDeps } from '../shared.js';

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
}
