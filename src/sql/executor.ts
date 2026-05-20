import mysql, { type ConnectionOptions } from 'mysql2/promise';
import type { Connection, Policy, SqlCategory } from '../types.js';
import { openSshTunnel, type TunnelHandle } from './tunnel.js';
import { openSshDockerTunnel } from './dockerTunnel.js';
import { injectMaxExecutionTime } from './hints.js';
import { extractBackupSpec, isBackupRequired } from '../backup/extractor.js';
import { captureBackup, captureInsertHint, BackupOverflowError } from '../backup/capture.js';

export interface ExecuteParams {
  connection: Connection;
  password: string;
  sshPassword?: string;
  sql: string;
  category: SqlCategory;
  astType?: string;
  policy: Policy;
  database?: string;
}

export interface ExecuteResult {
  rows: Record<string, unknown>[];
  fields: { name: string; type?: number }[];
  affectedRows: number;
  truncated: boolean;
  durationMs: number;
  backupId?: number | null;
  backupRowCount?: number;
}

const READ_ONLY_CATEGORIES: ReadonlySet<SqlCategory> = new Set(['read']);

export function buildBaseOptions(args: {
  connection: Connection;
  password: string;
  database?: string;
}): ConnectionOptions {
  let ssl: ConnectionOptions['ssl'];
  if (args.connection.ssl) {
    // mysql2 forwards the ssl object to tls.connect, so `servername` is honored at
    // runtime even though mysql2's SslOptions type doesn't list it.
    ssl = args.connection.sslServerName
      ? ({ servername: args.connection.sslServerName } as ConnectionOptions['ssl'])
      : {};
  }
  return {
    host: args.connection.host,
    port: args.connection.port,
    user: args.connection.user,
    password: args.password,
    database: args.database ?? args.connection.database,
    multipleStatements: false,
    ssl,
    dateStrings: true,
    decimalNumbers: false,
    supportBigNumbers: true,
    bigNumberStrings: true,
    connectTimeout: 15000,
    enableKeepAlive: true,
  };
}

function log(msg: string): void {
  process.stderr.write(`[sequel-mcp] ${msg}\n`);
}

export async function executeStatement(params: ExecuteParams): Promise<ExecuteResult> {
  let tunnel: TunnelHandle | null = null;
  let conn: mysql.Connection | null = null;
  const start = Date.now();
  const tag = `${params.connection.name}/${params.category}`;
  try {
    let host = params.connection.host;
    let port = params.connection.port;
    if (params.connection.ssh) {
      if (params.connection.ssh.docker) {
        log(
          `${tag} opening SSH+docker tunnel via ${params.connection.ssh.host}:${params.connection.ssh.port} → container ${params.connection.ssh.docker.container} (bridge=${params.connection.ssh.docker.bridgeTool})`,
        );
        const dt = await openSshDockerTunnel({
          ssh: params.connection.ssh,
          sshPassword: params.sshPassword,
          docker: params.connection.ssh.docker,
          remoteHost: params.connection.host,
          remotePort: params.connection.port,
        });
        tunnel = dt;
        log(
          `${tag} container=${dt.containerImage} started=${dt.containerStartedAt}`,
        );
      } else {
        log(`${tag} opening SSH tunnel to ${params.connection.ssh.host}:${params.connection.ssh.port}`);
        tunnel = await openSshTunnel({
          ssh: params.connection.ssh,
          sshPassword: params.sshPassword,
          remoteHost: params.connection.host,
          remotePort: params.connection.port,
        });
      }
      host = tunnel.localHost;
      port = tunnel.localPort;
      log(`${tag} tunnel ready on ${host}:${port}`);
    }

    const opts = buildBaseOptions({
      connection: { ...params.connection, host, port },
      password: params.password,
      database: params.database,
    });

    log(`${tag} connecting mysql2 to ${host}:${port} db=${opts.database ?? '<none>'}`);
    conn = await mysql.createConnection(opts);
    log(`${tag} connected, t=${Date.now() - start}ms`);

    const isRead = READ_ONLY_CATEGORIES.has(params.category);
    if (params.category !== 'txCtrl') {
      try {
        await conn.query(
          isRead ? 'START TRANSACTION READ ONLY' : 'START TRANSACTION READ WRITE',
        );
      } catch (e) {
        log(`${tag} START TRANSACTION failed: ${(e as Error).message}; continuing without explicit tx`);
      }
    }

    let backupId: number | null = null;
    let backupRowCount = 0;
    let pendingInsertSpec: ReturnType<typeof extractBackupSpec> | null = null;
    if (params.astType && isBackupRequired(params.astType) && conn) {
      const spec = extractBackupSpec(params.sql, params.astType);
      if (spec.kind === 'insert-hint') {
        pendingInsertSpec = spec;
        log(`${tag} INSERT detected; will capture rollback hint after execution`);
      } else if (spec.kind !== 'none') {
        try {
          log(`${tag} capturing backup for ${params.astType}…`);
          const captured = await captureBackup({
            conn,
            spec,
            connectionName: params.connection.name,
            database: params.database ?? params.connection.database,
            policy: params.policy,
          });
          if (captured) {
            backupId = captured.backupId;
            backupRowCount = captured.totalRows;
            log(
              `${tag} backup #${backupId}: ${captured.totalRows} rows, ${captured.totalBytes}B${captured.truncated ? ' (truncated)' : ''}`,
            );
          }
        } catch (e) {
          if (e instanceof BackupOverflowError) {
            log(`${tag} backup overflow: ${e.message}; aborting per policy`);
            throw e;
          }
          log(`${tag} backup capture failed: ${(e as Error).message}; continuing without backup`);
        }
      } else if (spec.reason) {
        log(`${tag} no backup taken: ${spec.reason}`);
      }
    }

    const sql =
      isRead && params.policy.stmtTimeoutMs > 0
        ? injectMaxExecutionTime(params.sql, params.policy.stmtTimeoutMs)
        : params.sql;

    log(`${tag} executing: ${sql.slice(0, 120).replace(/\s+/g, ' ')}`);
    const [rowsRaw, fieldsRaw] = await conn.query(sql);
    log(`${tag} executed, t=${Date.now() - start}ms`);

    let rows: Record<string, unknown>[] = [];
    let truncated = false;
    let affectedRows = 0;

    if (Array.isArray(rowsRaw)) {
      const cap = params.policy.rowCap;
      if (rowsRaw.length > cap) {
        rows = rowsRaw.slice(0, cap) as Record<string, unknown>[];
        truncated = true;
      } else {
        rows = rowsRaw as Record<string, unknown>[];
      }
    } else if (rowsRaw && typeof rowsRaw === 'object' && 'affectedRows' in rowsRaw) {
      affectedRows = Number((rowsRaw as { affectedRows: number }).affectedRows ?? 0);
    }

    if (pendingInsertSpec) {
      const insertId =
        rowsRaw && typeof rowsRaw === 'object' && 'insertId' in rowsRaw
          ? Number((rowsRaw as { insertId: number }).insertId ?? 0)
          : null;
      try {
        const id = captureInsertHint({
          spec: pendingInsertSpec,
          connectionName: params.connection.name,
          database: params.database ?? params.connection.database,
          result: { insertId, affectedRows },
        });
        if (id) {
          backupId = id;
          backupRowCount = affectedRows;
          log(`${tag} insert-hint backup #${id}: ${affectedRows} row(s)`);
        }
      } catch (e) {
        log(`${tag} insert-hint capture failed: ${(e as Error).message}`);
      }
    }

    const fields = Array.isArray(fieldsRaw)
      ? fieldsRaw.map((f) => ({ name: f.name, type: f.type }))
      : [];

    if (params.category !== 'txCtrl') {
      await conn.query('COMMIT');
    }

    return {
      rows,
      fields,
      affectedRows,
      truncated,
      durationMs: Date.now() - start,
      backupId,
      backupRowCount,
    };
  } catch (e) {
    log(`${tag} FAILED at t=${Date.now() - start}ms: ${(e as Error).message}`);
    if (conn && params.category !== 'txCtrl') {
      try {
        await conn.query('ROLLBACK');
      } catch {
        /* ignore */
      }
    }
    throw e;
  } finally {
    if (conn) {
      try {
        await conn.end();
      } catch {
        /* ignore */
      }
    }
    if (tunnel) {
      try {
        await tunnel.close();
      } catch {
        /* ignore */
      }
    }
  }
}
