import type { CallToolResult } from '@modelcontextprotocol/sdk/types.js';
import { SessionAuthenticator, getTouchID, type TouchIDPrompt } from '../vault/touchid.js';
import type { SecretStore } from '../vault/keyring.js';
import type { MySqlConnection } from '../types.js';
import type { makeConfirmFn } from '../elicit/confirm.js';
import type { GrantStore } from '../policy/grants.js';

export const PACKAGE_NAME = 'sequel-mcp';
export const PACKAGE_VERSION = '0.9.1';

export function toolError(text: string): CallToolResult {
  return { isError: true, content: [{ type: 'text', text }] };
}

export function jsonResult(value: unknown): CallToolResult {
  const text = JSON.stringify(value, null, 2);
  // Per MCP spec: tools that return structuredContent SHOULD also serialize
  // the same payload as a TextContent block for backward-compatible clients.
  // structuredContent must be a JSON object; wrap non-object payloads under a `value` key.
  const structuredContent =
    value !== null && typeof value === 'object' && !Array.isArray(value)
      ? (value as Record<string, unknown>)
      : { value };
  return { content: [{ type: 'text', text }], structuredContent };
}

export function textResult(text: string): CallToolResult {
  return { content: [{ type: 'text', text }] };
}

export async function loadCredentials(args: {
  store: SecretStore;
  connection: MySqlConnection;
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

export function noConnectionMessage(explicit: string | undefined): string {
  return explicit
    ? `Unknown connection "${explicit}". Use list_connections to see available names.`
    : 'No connection specified and no default set. Pass "connection" or call set_default_connection first.';
}

export interface LazyAuth {
  ensureAuthenticated(reason: string): Promise<boolean>;
}

export function createLazyAuth(
  provider: () => Promise<TouchIDPrompt> = getTouchID,
): LazyAuth {
  let resolver: Promise<TouchIDPrompt> | null = null;
  let inner: SessionAuthenticator | null = null;
  return {
    async ensureAuthenticated(reason) {
      if (!inner) {
        resolver ??= provider();
        inner = new SessionAuthenticator(await resolver);
      }
      return inner.ensureAuthenticated(reason);
    },
  };
}

export interface ToolDeps {
  secretStore: SecretStore;
  confirmFn: ReturnType<typeof makeConfirmFn>;
  auth: LazyAuth;
  grants: GrantStore;
}
