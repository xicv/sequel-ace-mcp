#!/usr/bin/env node
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { buildServer } from './server.js';
import { closeAuditDb } from './audit/db.js';

function registerShutdownHooks(): void {
  let shuttingDown = false;
  const shutdown = (): void => {
    if (shuttingDown) return;
    shuttingDown = true;
    closeAuditDb();
  };
  process.once('beforeExit', shutdown);
  process.once('SIGINT', () => {
    shutdown();
    process.exit(130);
  });
  process.once('SIGTERM', () => {
    shutdown();
    process.exit(143);
  });
}

async function main(): Promise<void> {
  registerShutdownHooks();
  const server = buildServer();
  const transport = new StdioServerTransport();
  await server.connect(transport);
  process.stderr.write('sequel-mcp ready\n');
}

main().catch((err) => {
  process.stderr.write(`fatal: ${(err as Error).stack ?? String(err)}\n`);
  process.exit(1);
});
