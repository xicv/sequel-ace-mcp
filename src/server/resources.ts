import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { isMySqlConnection, POLICY_PRESETS } from '../types.js';
import { loadConfig } from '../vault/config.js';
import type { SecretStore } from '../vault/keyring.js';

export function registerResources(
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
          driver: c.driver,
          host: isMySqlConnection(c) ? c.host : undefined,
          port: isMySqlConnection(c) ? c.port : undefined,
          user: isMySqlConnection(c) ? c.user : undefined,
          path: isMySqlConnection(c) ? undefined : c.path,
          database: c.database,
          ssh: isMySqlConnection(c) && c.ssh
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
          hasPassword: isMySqlConnection(c)
            ? await deps.secretStore.hasPassword(c.name, c.user)
            : false,
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
