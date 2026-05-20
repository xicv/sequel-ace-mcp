import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { POLICY_PRESETS } from '../types.js';
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
