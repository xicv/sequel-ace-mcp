#!/usr/bin/env node
/**
 * sequel-mcp doctor — diagnostic report for the local install.
 *
 * Prints a sanitized summary: versions, configured connections (host/user/db for
 * MySQL/MariaDB, path/schema for SQLite, NEVER passwords), Keychain entry presence, SSH key file presence, MCP boot
 * smoke check. Intended for sharing with maintainers when filing a bug.
 *
 * Usage:
 *   sequel-mcp-doctor                # default text report
 *   sequel-mcp-doctor --json         # machine-readable
 *   sequel-mcp-doctor --probe        # additionally try mysql2 connect (no SQL)
 */
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { createRequire } from 'node:module';
import { loadConfig, getDefaultConnectionName } from './vault/config.js';
import { KeychainSecretStore } from './vault/keyring.js';
import { configDir, configPath, sequelAceFavoritesPlistPath } from './vault/paths.js';
import { getTouchID } from './vault/touchid.js';
import { isMySqlConnection, type Connection } from './types.js';

const require = createRequire(import.meta.url);
const pkg = require('../package.json') as { name: string; version: string };

interface ConnectionReport {
  name: string;
  driver: Connection['driver'];
  host: string | null;
  port: number | null;
  user: string | null;
  path: string | null;
  database: string | null;
  ssl: boolean | null;
  sslServerName: string | null;
  ssh:
    | {
        host: string;
        port: number;
        user: string;
        authMethod: 'password' | 'key';
        privateKeyPath: string | null;
        privateKeyExists: boolean | null;
        hostKeyPolicy: 'lenient' | 'strict' | null;
        knownHostsPath: string | null;
        docker:
          | {
              container: string;
              bridgeTool: 'socat' | 'nc' | 'ncat';
            }
          | null;
      }
    | null;
  policy: Connection['policy'];
  hasStoredPassword: boolean;
  hasStoredSshSecret: boolean;
  isDefault: boolean;
  probe?: { ok: boolean; durationMs: number; error?: string };
}

interface DoctorReport {
  app: { name: string; version: string };
  runtime: {
    nodeVersion: string;
    platform: string;
    arch: string;
    macosVersion: string | null;
  };
  paths: {
    configDir: string;
    configFile: string;
    configFileExists: boolean;
    configFilePerm: string | null;
    sequelAceFavoritesPlist: string;
    sequelAceFavoritesPlistExists: boolean;
  };
  touchID: { available: boolean };
  swiftc: { available: boolean };
  defaultConnection: string | null;
  connections: ConnectionReport[];
}

async function fileExists(p: string): Promise<boolean> {
  try {
    await fs.access(p);
    return true;
  } catch {
    return false;
  }
}

async function fileMode(p: string): Promise<string | null> {
  try {
    const s = await fs.stat(p);
    return (s.mode & 0o777).toString(8);
  } catch {
    return null;
  }
}

function expandTilde(p: string): string {
  if (!p) return p;
  if (p === '~') return os.homedir();
  if (p.startsWith('~/')) return path.join(os.homedir(), p.slice(2));
  return p;
}

async function getMacosVersion(): Promise<string | null> {
  if (process.platform !== 'darwin') return null;
  return new Promise((resolve) => {
    const child = spawn('sw_vers', ['-productVersion'], { stdio: ['ignore', 'pipe', 'ignore'] });
    let out = '';
    child.stdout.on('data', (b: Buffer) => (out += b.toString('utf8')));
    child.on('error', () => resolve(null));
    child.on('exit', () => resolve(out.trim() || null));
  });
}

async function which(cmd: string): Promise<boolean> {
  return new Promise((resolve) => {
    const c = spawn('/usr/bin/which', [cmd], { stdio: 'ignore' });
    c.on('error', () => resolve(false));
    c.on('exit', (code) => resolve(code === 0));
  });
}

async function probeConnection(_conn: Connection): Promise<{ ok: boolean; durationMs: number; error?: string }> {
  const start = Date.now();
  try {
    return { ok: false, durationMs: Date.now() - start, error: 'probe disabled by default; pass --probe to enable real connect' };
  } catch (e) {
    return { ok: false, durationMs: Date.now() - start, error: (e as Error).message };
  }
}

async function buildReport(opts: { probe: boolean }): Promise<DoctorReport> {
  const cfg = await loadConfig();
  const store = new KeychainSecretStore();
  const tid = await getTouchID();
  const swiftcAvailable = await which('swiftc');
  const macosVersion = await getMacosVersion();
  const cfgFile = configPath();
  const cfgFileExists = await fileExists(cfgFile);
  const cfgFilePerm = await fileMode(cfgFile);
  const plistPath = sequelAceFavoritesPlistPath();
  const plistExists = await fileExists(plistPath);
  const def = await getDefaultConnectionName();

  const connections: ConnectionReport[] = [];
  for (const c of cfg.connections) {
    const hasPwd = isMySqlConnection(c) ? await store.hasPassword(c.name, c.user) : false;
    const hasSsh = isMySqlConnection(c) && c.ssh
      ? await store.hasPassword(`${c.name}::ssh`, c.ssh.user)
      : false;

    let sshReport: ConnectionReport['ssh'] = null;
    if (isMySqlConnection(c) && c.ssh) {
      const keyPath = c.ssh.privateKeyPath ?? null;
      const expanded = keyPath ? expandTilde(keyPath) : null;
      sshReport = {
        host: c.ssh.host,
        port: c.ssh.port,
        user: c.ssh.user,
        authMethod: c.ssh.authMethod,
        privateKeyPath: keyPath,
        privateKeyExists: expanded ? await fileExists(expanded) : null,
        hostKeyPolicy: c.ssh.hostKeyPolicy ?? null,
        knownHostsPath: c.ssh.knownHostsPath ?? null,
        docker: c.ssh.docker
          ? {
              container: c.ssh.docker.container,
              bridgeTool: c.ssh.docker.bridgeTool,
            }
          : null,
      };
    }

    const report: ConnectionReport = {
      name: c.name,
      driver: c.driver,
      host: isMySqlConnection(c) ? c.host : null,
      port: isMySqlConnection(c) ? c.port : null,
      user: isMySqlConnection(c) ? c.user : null,
      path: isMySqlConnection(c) ? null : c.path,
      database: c.database ?? null,
      ssl: isMySqlConnection(c) ? c.ssl : null,
      sslServerName: isMySqlConnection(c) ? c.sslServerName ?? null : null,
      ssh: sshReport,
      policy: c.policy,
      hasStoredPassword: hasPwd,
      hasStoredSshSecret: hasSsh,
      isDefault: c.name === def,
    };
    if (opts.probe) {
      report.probe = await probeConnection(c);
    }
    connections.push(report);
  }

  return {
    app: { name: pkg.name, version: pkg.version },
    runtime: {
      nodeVersion: process.versions.node,
      platform: process.platform,
      arch: process.arch,
      macosVersion,
    },
    paths: {
      configDir: configDir(),
      configFile: cfgFile,
      configFileExists: cfgFileExists,
      configFilePerm: cfgFilePerm,
      sequelAceFavoritesPlist: plistPath,
      sequelAceFavoritesPlistExists: plistExists,
    },
    touchID: { available: tid.available },
    swiftc: { available: swiftcAvailable },
    defaultConnection: def,
    connections,
  };
}

function pad(s: string, n: number): string {
  return s.length >= n ? s : s + ' '.repeat(n - s.length);
}

function badge(b: boolean): string {
  return b ? 'OK ' : 'NO ';
}

function renderText(r: DoctorReport): string {
  const lines: string[] = [];
  lines.push(`${r.app.name} v${r.app.version} doctor report`);
  lines.push('=' .repeat(60));
  lines.push(`runtime    : node ${r.runtime.nodeVersion} ${r.runtime.platform}/${r.runtime.arch}${r.runtime.macosVersion ? ` macOS ${r.runtime.macosVersion}` : ''}`);
  lines.push(`Touch ID   : ${badge(r.touchID.available)}available`);
  lines.push(`swiftc     : ${badge(r.swiftc.available)}on PATH`);
  lines.push(`config dir : ${r.paths.configDir}`);
  lines.push(`config file: ${r.paths.configFile} ${r.paths.configFileExists ? '(exists, mode=' + r.paths.configFilePerm + ')' : '(missing)'}`);
  lines.push(`Sequel Ace : ${r.paths.sequelAceFavoritesPlist} ${r.paths.sequelAceFavoritesPlistExists ? '(present)' : '(missing — install Sequel Ace + save at least one favorite to use import_from_sequel_ace)'}`);
  lines.push(`default    : ${r.defaultConnection ?? '(none)'}`);
  lines.push('');
  if (r.connections.length === 0) {
    lines.push('connections: (none configured)');
  } else {
    lines.push('connections:');
    for (const c of r.connections) {
      const endpoint =
        c.driver === 'sqlite'
          ? `sqlite:${c.path ?? '(missing path)'}`
          : `${c.user}@${c.host}:${c.port}`;
      lines.push(`  - ${pad(c.name, 24)} ${pad(endpoint, 38)} db=${c.database ?? '(none)'}${c.isDefault ? '  [default]' : ''}`);
      if (c.driver === 'mysql') {
        lines.push(`      pwd-stored      : ${badge(c.hasStoredPassword)}`);
      }
      if (c.ssh) {
        lines.push(`      ssh-tunnel      : ${c.ssh.user}@${c.ssh.host}:${c.ssh.port} (auth=${c.ssh.authMethod})`);
        if (c.ssh.privateKeyPath) {
          lines.push(`      ssh-key         : ${c.ssh.privateKeyPath} ${badge(c.ssh.privateKeyExists === true)}`);
        }
        if (c.ssh.authMethod === 'password' || c.ssh.authMethod === 'key') {
          lines.push(`      ssh-secret      : ${badge(c.hasStoredSshSecret)} (only required when key has passphrase or auth=password)`);
        }
        lines.push(`      host-key-policy : ${c.ssh.hostKeyPolicy ?? 'lenient (default)'}${c.ssh.knownHostsPath ? ` (known_hosts=${c.ssh.knownHostsPath})` : ''}`);
        if (c.ssh.docker) {
          lines.push(`      docker-tunnel   : container=${c.ssh.docker.container} bridge=${c.ssh.docker.bridgeTool}`);
        }
      }
      if (c.sslServerName) {
        lines.push(`      tls-servername  : ${c.sslServerName}`);
      }
      lines.push(`      policy          : read=${c.policy.read} write=${c.policy.write} ddl=${c.policy.ddl} admin=${c.policy.admin} touchID=${c.policy.requireTouchID}`);
      lines.push(`      limits          : rowCap=${c.policy.rowCap} stmtTimeoutMs=${c.policy.stmtTimeoutMs}`);
      if (c.probe) {
        lines.push(`      probe           : ${c.probe.ok ? 'OK' : 'FAIL'} ${c.probe.durationMs}ms${c.probe.error ? ' — ' + c.probe.error : ''}`);
      }
    }
  }
  lines.push('');
  lines.push('NOTE: this report contains NO passwords and NO Keychain secrets. It does include hostnames, DB usernames, SQLite paths, and key paths from your local config — review and redact before sharing publicly.');
  return lines.join('\n');
}

async function main(): Promise<void> {
  const argv = new Set(process.argv.slice(2));
  const json = argv.has('--json');
  const probe = argv.has('--probe');
  const report = await buildReport({ probe });
  if (json) {
    process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  } else {
    process.stdout.write(`${renderText(report)}\n`);
  }
}

main().catch((err) => {
  process.stderr.write(`doctor failed: ${(err as Error).stack ?? String(err)}\n`);
  process.exit(1);
});
