#!/usr/bin/env node
/**
 * sequel-mcp migrate — copy config + Keychain entries from sequel-ace-mcp <= 0.1.0
 * into the new sequel-mcp namespace. Reads the legacy entries; writes the new ones;
 * does NOT delete the legacy entries unless --purge is passed.
 */
import fs from 'node:fs/promises';
import path from 'node:path';
import { Entry } from '@napi-rs/keyring';
import {
  ConfigSchema,
  isMySqlConnection,
  type Config,
  type MySqlConnection,
} from './types.js';
import {
  configDir,
  configPath,
  keychainServiceName,
  legacyConfigPath,
  legacyKeychainServiceName,
} from './vault/paths.js';

interface MigrationResult {
  configCopied: boolean;
  configSourceMissing: boolean;
  configDestExisted: boolean;
  passwords: { connection: string; account: string; copied: boolean; reason?: string }[];
  sshSecrets: { connection: string; account: string; copied: boolean; reason?: string }[];
  legacyPurged: boolean;
}

async function fileExists(p: string): Promise<boolean> {
  try {
    await fs.access(p);
    return true;
  } catch {
    return false;
  }
}

async function ensureDir(d: string): Promise<void> {
  await fs.mkdir(d, { recursive: true, mode: 0o700 });
}

async function copyConfig(force: boolean): Promise<{
  copied: boolean;
  sourceMissing: boolean;
  destExisted: boolean;
  parsed: Config | null;
}> {
  const src = legacyConfigPath();
  const dst = configPath();
  const sourceMissing = !(await fileExists(src));
  const destExisted = await fileExists(dst);

  if (sourceMissing) return { copied: false, sourceMissing: true, destExisted, parsed: null };
  if (destExisted && !force) {
    const raw = await fs.readFile(src, 'utf8');
    return {
      copied: false,
      sourceMissing: false,
      destExisted: true,
      parsed: ConfigSchema.parse(JSON.parse(raw)),
    };
  }

  const raw = await fs.readFile(src, 'utf8');
  const parsed = ConfigSchema.parse(JSON.parse(raw));

  await ensureDir(configDir());
  const tmp = path.join(configDir(), `.config.${process.pid}.tmp`);
  await fs.writeFile(tmp, `${JSON.stringify(parsed, null, 2)}\n`, { encoding: 'utf8', mode: 0o600 });
  await fs.rename(tmp, dst);

  return { copied: true, sourceMissing: false, destExisted, parsed };
}

function legacyEntry(name: string, account: string): Entry {
  return new Entry(legacyKeychainServiceName(name), account);
}

function newEntry(name: string, account: string): Entry {
  return new Entry(keychainServiceName(name), account);
}

function readLegacy(name: string, account: string): string | null {
  try {
    return legacyEntry(name, account).getPassword();
  } catch {
    return null;
  }
}

function writeNew(name: string, account: string, password: string): void {
  newEntry(name, account).setPassword(password);
}

function deleteLegacy(name: string, account: string): boolean {
  try {
    return legacyEntry(name, account).deletePassword();
  } catch {
    return false;
  }
}

async function migrateConnection(c: MySqlConnection, purge: boolean): Promise<{
  password: { copied: boolean; reason?: string };
  ssh: { copied: boolean; reason?: string } | null;
}> {
  const result: Awaited<ReturnType<typeof migrateConnection>> = { password: { copied: false }, ssh: null };

  const legacyPwd = readLegacy(c.name, c.user);
  if (legacyPwd) {
    try {
      writeNew(c.name, c.user, legacyPwd);
      result.password = { copied: true };
      if (purge) deleteLegacy(c.name, c.user);
    } catch (e) {
      result.password = { copied: false, reason: (e as Error).message };
    }
  } else {
    result.password = { copied: false, reason: 'no legacy entry found (or denied by Keychain ACL)' };
  }

  if (c.ssh) {
    const sshAccount = c.ssh.user;
    const sshLegacyName = `${c.name}::ssh`;
    const sshPwd = readLegacy(sshLegacyName, sshAccount);
    if (sshPwd) {
      try {
        writeNew(sshLegacyName, sshAccount, sshPwd);
        result.ssh = { copied: true };
        if (purge) deleteLegacy(sshLegacyName, sshAccount);
      } catch (e) {
        result.ssh = { copied: false, reason: (e as Error).message };
      }
    } else {
      result.ssh = { copied: false, reason: 'no legacy ssh entry (or not required)' };
    }
  }

  return result;
}

export async function migrate(opts: { force: boolean; purge: boolean }): Promise<MigrationResult> {
  const result: MigrationResult = {
    configCopied: false,
    configSourceMissing: false,
    configDestExisted: false,
    passwords: [],
    sshSecrets: [],
    legacyPurged: opts.purge,
  };

  const cfg = await copyConfig(opts.force);
  result.configCopied = cfg.copied;
  result.configSourceMissing = cfg.sourceMissing;
  result.configDestExisted = cfg.destExisted;

  if (!cfg.parsed) return result;

  for (const c of cfg.parsed.connections) {
    if (!isMySqlConnection(c)) continue;
    const m = await migrateConnection(c, opts.purge);
    result.passwords.push({ connection: c.name, account: c.user, ...m.password });
    if (m.ssh && c.ssh) {
      result.sshSecrets.push({ connection: c.name, account: c.ssh.user, ...m.ssh });
    }
  }

  return result;
}

function renderText(r: MigrationResult): string {
  const lines: string[] = [];
  lines.push('sequel-mcp migration report');
  lines.push('=' .repeat(40));
  if (r.configSourceMissing) {
    lines.push('legacy config: NOT FOUND — nothing to migrate. (Was sequel-ace-mcp <= 0.1.0 ever installed?)');
    return lines.join('\n');
  }
  lines.push(`legacy config copied: ${r.configCopied ? 'YES' : (r.configDestExisted ? 'NO (new config already exists; pass --force to overwrite)' : 'NO')}`);
  lines.push('');
  lines.push('passwords:');
  for (const p of r.passwords) {
    lines.push(`  - ${p.connection} (${p.account}): ${p.copied ? 'copied' : `skipped — ${p.reason ?? '?'}`}`);
  }
  if (r.sshSecrets.length > 0) {
    lines.push('');
    lines.push('ssh secrets:');
    for (const s of r.sshSecrets) {
      lines.push(`  - ${s.connection} (${s.account}): ${s.copied ? 'copied' : `skipped — ${s.reason ?? '?'}`}`);
    }
  }
  if (r.legacyPurged) {
    lines.push('');
    lines.push('legacy keychain entries: DELETED (--purge was used)');
  } else {
    lines.push('');
    lines.push('legacy keychain entries: kept (run again with --purge to remove)');
  }
  return lines.join('\n');
}

async function main(): Promise<void> {
  const argv = new Set(process.argv.slice(2));
  const force = argv.has('--force');
  const purge = argv.has('--purge');
  const json = argv.has('--json');

  const result = await migrate({ force, purge });
  if (json) process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  else process.stdout.write(`${renderText(result)}\n`);
}

main().catch((err) => {
  process.stderr.write(`migrate failed: ${(err as Error).stack ?? String(err)}\n`);
  process.exit(1);
});
