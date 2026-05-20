import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { maybeAutoCleanup } from './audit/retention.js';
import { makeConfirmFn } from './elicit/confirm.js';
import { createGrantStore } from './policy/grants.js';
import { loadConfig } from './vault/config.js';
import { KeychainSecretStore, type SecretStore } from './vault/keyring.js';
import {
  createLazyAuth,
  PACKAGE_NAME,
  PACKAGE_VERSION,
  type ToolDeps,
} from './server/shared.js';
import { registerSqlTools } from './server/tools/sql.js';
import { registerConnectionTools } from './server/tools/connections.js';
import { registerPolicyTools } from './server/tools/policy.js';
import { registerAuditTools } from './server/tools/audit.js';
import { registerBackupTools } from './server/tools/backup.js';
import { registerDoctorTool } from './server/tools/doctor.js';
import { registerPrompts } from './server/prompts.js';
import { registerResources } from './server/resources.js';

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
  const deps: ToolDeps = {
    secretStore,
    confirmFn: makeConfirmFn(mcp.server),
    auth: createLazyAuth(),
    grants: createGrantStore(),
  };

  void loadConfig()
    .then((cfg) => maybeAutoCleanup(cfg.retention))
    .catch(() => undefined);

  registerSqlTools(mcp, deps);
  registerConnectionTools(mcp, deps);
  registerPolicyTools(mcp);
  registerAuditTools(mcp);
  registerBackupTools(mcp, deps);
  registerDoctorTool(mcp, deps);
  registerPrompts(mcp);
  registerResources(mcp, { secretStore });

  return mcp;
}
