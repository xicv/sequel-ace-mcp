import { spawn } from 'node:child_process';
import fs from 'node:fs/promises';
import plist from 'plist';
import {
  policyFromPreset,
  upsertConnection,
} from '../vault/config.js';
import {
  sequelAceFavoritesPlistPath,
  sequelAceLegacyKeychainServiceName,
  sequelAceLegacySshKeychainServiceName,
} from '../vault/paths.js';
import type { SecretStore } from '../vault/keyring.js';
import type { MySqlConnection, SshTunnel } from '../types.js';

interface RawFavorite {
  id?: number | string;
  name?: string;
  host?: string;
  port?: number | string;
  user?: string;
  database?: string;
  type?: number;
  useSSL?: number | boolean;
  sshHost?: string;
  sshPort?: number | string;
  sshUser?: string;
  sshKeyLocation?: string;
  sshKeyLocationEnabled?: number | boolean;
  Children?: RawFavorite[];
}

export interface ImportedFavorite {
  connection: MySqlConnection;
  legacyKeychainService: string;
  legacySshKeychainService: string | null;
  legacyAccount: string;
  legacySshAccount: string | null;
}

export async function readFavoritesPlist(plistPath = sequelAceFavoritesPlistPath()): Promise<ImportedFavorite[]> {
  const data = await fs.readFile(plistPath, 'utf8');
  const parsed = plist.parse(data) as { 'Favorites Root'?: { Children?: RawFavorite[] } };
  const root = parsed['Favorites Root'];
  const out: ImportedFavorite[] = [];
  if (!root?.Children) return out;
  walk(root.Children, out);
  return out;
}

function walk(nodes: RawFavorite[], out: ImportedFavorite[]): void {
  for (const node of nodes) {
    if (Array.isArray(node.Children)) {
      walk(node.Children, out);
    }
    if (!node.host || !node.user || node.id === undefined || !node.name) continue;
    const c = toConnection(node);
    if (c) out.push(c);
  }
}

function asInt(v: number | string | undefined, fallback: number): number {
  if (typeof v === 'number') return v;
  if (typeof v === 'string') {
    const n = parseInt(v, 10);
    return Number.isFinite(n) ? n : fallback;
  }
  return fallback;
}

function toConnection(fav: RawFavorite): ImportedFavorite | null {
  if (!fav.name || !fav.host || !fav.user || fav.id === undefined) return null;
  const usesSsh = fav.type === 1 || (fav.sshHost?.length ?? 0) > 0;
  const ssh: SshTunnel | undefined = usesSsh
    ? {
        host: fav.sshHost ?? '',
        port: asInt(fav.sshPort, 22),
        user: fav.sshUser ?? '',
        authMethod:
          fav.sshKeyLocationEnabled && fav.sshKeyLocation ? 'key' : 'password',
        privateKeyPath: fav.sshKeyLocation,
      }
    : undefined;

  const connection: MySqlConnection = {
    driver: 'mysql',
    name: fav.name,
    host: fav.host,
    port: asInt(fav.port, 3306),
    user: fav.user,
    database: fav.database,
    ssl: Boolean(fav.useSSL),
    ssh,
    policy: policyFromPreset('read-only'),
  };

  return {
    connection,
    legacyKeychainService: sequelAceLegacyKeychainServiceName(fav.name, fav.id),
    legacySshKeychainService: usesSsh
      ? sequelAceLegacySshKeychainServiceName(fav.name, fav.id)
      : null,
    legacyAccount: fav.user,
    legacySshAccount: usesSsh ? fav.sshUser ?? null : null,
  };
}

function runSecurity(args: string[]): Promise<{ code: number; stdout: string; stderr: string }> {
  return new Promise((resolve) => {
    const child = spawn('/usr/bin/security', args, { stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (b: Buffer) => (stdout += b.toString('utf8')));
    child.stderr.on('data', (b: Buffer) => (stderr += b.toString('utf8')));
    child.on('error', () => resolve({ code: -1, stdout, stderr }));
    child.on('exit', (code) => resolve({ code: code ?? -1, stdout, stderr }));
  });
}

export async function readLegacyPassword(service: string, account: string): Promise<string | null> {
  const r = await runSecurity([
    'find-generic-password',
    '-s',
    service,
    '-a',
    account,
    '-w',
  ]);
  if (r.code !== 0) return null;
  return r.stdout.trim();
}

export interface ImportOptions {
  copyPasswords: boolean;
  secretStore: SecretStore;
  onItem?: (event: {
    name: string;
    status: 'imported' | 'skipped' | 'password-missing';
    reason?: string;
  }) => void;
}

export interface ImportResult {
  total: number;
  imported: number;
  withPasswords: number;
  skipped: { name: string; reason: string }[];
}

export async function importFromSequelAce(opts: ImportOptions): Promise<ImportResult> {
  const items = await readFavoritesPlist();
  let imported = 0;
  let withPasswords = 0;
  const skipped: ImportResult['skipped'] = [];

  for (const item of items) {
    try {
      await upsertConnection(item.connection);
      imported++;
      if (opts.copyPasswords) {
        const pwd = await readLegacyPassword(item.legacyKeychainService, item.legacyAccount);
        if (pwd) {
          await opts.secretStore.setPassword(
            item.connection.name,
            item.connection.user,
            pwd,
          );
          withPasswords++;
          opts.onItem?.({ name: item.connection.name, status: 'imported' });
        } else {
          opts.onItem?.({ name: item.connection.name, status: 'password-missing' });
        }
        if (item.legacySshKeychainService && item.legacySshAccount && item.connection.ssh) {
          const sshPwd = await readLegacyPassword(
            item.legacySshKeychainService,
            item.legacySshAccount,
          );
          if (sshPwd) {
            await opts.secretStore.setPassword(
              `${item.connection.name}::ssh`,
              item.legacySshAccount,
              sshPwd,
            );
          }
        }
      } else {
        opts.onItem?.({ name: item.connection.name, status: 'imported' });
      }
    } catch (e) {
      skipped.push({ name: item.connection.name, reason: (e as Error).message });
      opts.onItem?.({
        name: item.connection.name,
        status: 'skipped',
        reason: (e as Error).message,
      });
    }
  }

  return { total: items.length, imported, withPasswords, skipped };
}
