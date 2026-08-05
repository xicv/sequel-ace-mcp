import { z } from 'zod';

export const SQL_CATEGORIES = ['read', 'write', 'ddl', 'admin', 'txCtrl'] as const;
export type SqlCategory = (typeof SQL_CATEGORIES)[number];

export const POLICY_ACTIONS = ['allow', 'confirm', 'deny'] as const;
export type PolicyAction = (typeof POLICY_ACTIONS)[number];

export const PolicySchema = z.object({
  read: z.enum(POLICY_ACTIONS).default('allow'),
  write: z.enum(POLICY_ACTIONS).default('confirm'),
  ddl: z.enum(POLICY_ACTIONS).default('deny'),
  admin: z.enum(POLICY_ACTIONS).default('deny'),
  txCtrl: z.enum(POLICY_ACTIONS).default('allow'),
  rowCap: z.number().int().positive().max(100000).default(1000),
  stmtTimeoutMs: z.number().int().positive().max(600000).default(10000),
  requireTouchID: z.boolean().default(false),
  maxBackupRows: z.number().int().positive().max(1_000_000).default(10000),
  maxBackupBytes: z.number().int().positive().default(50 * 1024 * 1024),
  onBackupOverflow: z.enum(['abort', 'truncate']).default('abort'),
});

export type Policy = z.infer<typeof PolicySchema>;

export const PartialPolicySchema = PolicySchema.partial();
export type PartialPolicy = z.infer<typeof PartialPolicySchema>;

export const SshDockerSchema = z.object({
  container: z
    .string()
    .min(1)
    .max(128)
    .regex(
      /^[A-Za-z0-9][A-Za-z0-9_.-]*$/,
      'container must match Docker naming rules (alnum, _, ., -)',
    ),
  bridgeTool: z.enum(['socat', 'nc', 'ncat']).default('nc'),
});

export type SshDocker = z.infer<typeof SshDockerSchema>;

export const SshHostKeyPolicySchema = z.enum(['lenient', 'strict']);
export type SshHostKeyPolicy = z.infer<typeof SshHostKeyPolicySchema>;

export const SshTunnelSchema = z.object({
  host: z.string().min(1),
  port: z.number().int().positive().max(65535).default(22),
  user: z.string().min(1),
  authMethod: z.enum(['password', 'key']).default('key'),
  privateKeyPath: z.string().optional(),
  docker: SshDockerSchema.optional(),
  hostKeyPolicy: SshHostKeyPolicySchema.optional(),
  knownHostsPath: z.string().optional(),
});

export type SshTunnel = z.infer<typeof SshTunnelSchema>;

const ConnectionCommonSchema = z.object({
  name: z.string().min(1).max(128).regex(/^[A-Za-z0-9 _\-:.]+$/),
  policy: PolicySchema,
  databasePolicies: z.record(z.string().min(1).max(64), PartialPolicySchema).optional(),
});

export const MySqlConnectionSchema = ConnectionCommonSchema.extend({
  driver: z.literal('mysql'),
  host: z.string().min(1),
  port: z.number().int().positive().max(65535).default(3306),
  user: z.string().min(1),
  database: z.string().optional(),
  ssl: z.boolean().default(false),
  sslServerName: z.string().min(1).max(253).optional(),
  ssh: SshTunnelSchema.optional(),
});

export type MySqlConnection = z.infer<typeof MySqlConnectionSchema>;

export const SqliteConnectionSchema = ConnectionCommonSchema.extend({
  driver: z.literal('sqlite'),
  path: z.string().min(1).max(4096),
  database: z.string().min(1).max(64).default('main'),
});

export type SqliteConnection = z.infer<typeof SqliteConnectionSchema>;

const ConnectionUnionSchema = z.discriminatedUnion('driver', [
  MySqlConnectionSchema,
  SqliteConnectionSchema,
]);

export const ConnectionSchema = z.preprocess((raw) => {
  if (raw && typeof raw === 'object') {
    const r = raw as Record<string, unknown>;
    if (r.driver === undefined) {
      return { ...r, driver: 'mysql' };
    }
  }
  return raw;
}, ConnectionUnionSchema);

export type Connection = z.infer<typeof ConnectionSchema>;
export type ConnectionDriver = Connection['driver'];

export function isMySqlConnection(connection: Connection): connection is MySqlConnection {
  return connection.driver === 'mysql';
}

export function isSqliteConnection(connection: Connection): connection is SqliteConnection {
  return connection.driver === 'sqlite';
}

export const DEFAULT_RETENTION_BY_CATEGORY = {
  read: 7,
  write: 30,
  ddl: 90,
  admin: 180,
  txCtrl: 7,
} as const satisfies Record<SqlCategory, number>;

export const RetentionByCategorySchema = z.object({
  read: z.number().int().min(1).max(3650).default(DEFAULT_RETENTION_BY_CATEGORY.read),
  write: z.number().int().min(1).max(3650).default(DEFAULT_RETENTION_BY_CATEGORY.write),
  ddl: z.number().int().min(1).max(3650).default(DEFAULT_RETENTION_BY_CATEGORY.ddl),
  admin: z.number().int().min(1).max(3650).default(DEFAULT_RETENTION_BY_CATEGORY.admin),
  txCtrl: z.number().int().min(1).max(3650).default(DEFAULT_RETENTION_BY_CATEGORY.txCtrl),
});

export type RetentionByCategory = z.infer<typeof RetentionByCategorySchema>;

const RetentionInnerSchema = z.object({
  retentionDaysByCategory: RetentionByCategorySchema.default(DEFAULT_RETENTION_BY_CATEGORY),
  backupDays: z.number().int().min(1).max(3650).default(30),
  auditMaxMB: z.number().int().min(10).max(100000).default(500),
  backupMaxMB: z.number().int().min(10).max(100000).default(1000),
  autoCleanupHours: z.number().int().min(0).max(720).default(24),
  redactSqlInLog: z.boolean().default(false),
  tamperEvidentChain: z.boolean().default(false),
});

export const RetentionConfigSchema = z.preprocess((raw) => {
  if (raw && typeof raw === 'object') {
    const r = raw as Record<string, unknown>;
    if (typeof r.auditDays === 'number' && r.retentionDaysByCategory === undefined) {
      const d = r.auditDays;
      r.retentionDaysByCategory = { read: d, write: d, ddl: d, admin: d, txCtrl: d };
    }
    delete r.auditDays;
  }
  return raw;
}, RetentionInnerSchema);

export type RetentionConfig = z.infer<typeof RetentionConfigSchema>;

const RETENTION_DEFAULT: RetentionConfig = {
  retentionDaysByCategory: { ...DEFAULT_RETENTION_BY_CATEGORY },
  backupDays: 30,
  auditMaxMB: 500,
  backupMaxMB: 1000,
  autoCleanupHours: 24,
  redactSqlInLog: false,
  tamperEvidentChain: false,
};

export const ConfigSchema = z.object({
  version: z.literal(1).default(1),
  connections: z.array(ConnectionSchema).default([]),
  defaultConnection: z.string().optional(),
  retention: RetentionConfigSchema.default(RETENTION_DEFAULT),
});

export type Config = z.infer<typeof ConfigSchema>;

export const POLICY_PRESETS = {
  'read-only': {
    read: 'allow',
    write: 'deny',
    ddl: 'deny',
    admin: 'deny',
    txCtrl: 'allow',
    rowCap: 1000,
    stmtTimeoutMs: 10000,
    requireTouchID: false,
    maxBackupRows: 10000,
    maxBackupBytes: 50 * 1024 * 1024,
    onBackupOverflow: 'abort',
  },
  dev: {
    read: 'allow',
    write: 'confirm',
    ddl: 'confirm',
    admin: 'deny',
    txCtrl: 'allow',
    rowCap: 5000,
    stmtTimeoutMs: 30000,
    requireTouchID: false,
    maxBackupRows: 10000,
    maxBackupBytes: 50 * 1024 * 1024,
    onBackupOverflow: 'abort',
  },
  admin: {
    read: 'allow',
    write: 'confirm',
    ddl: 'confirm',
    admin: 'confirm',
    txCtrl: 'allow',
    rowCap: 5000,
    stmtTimeoutMs: 60000,
    requireTouchID: true,
    maxBackupRows: 10000,
    maxBackupBytes: 50 * 1024 * 1024,
    onBackupOverflow: 'abort',
  },
} as const satisfies Record<string, Policy>;

export type PolicyPresetName = keyof typeof POLICY_PRESETS;

export class PolicyDeniedError extends Error {
  constructor(
    public readonly category: SqlCategory,
    public readonly statementSnippet: string,
  ) {
    super(`Policy denies ${category} statements on this connection: ${statementSnippet}`);
    this.name = 'PolicyDeniedError';
  }
}

export class PolicyConfirmationDeclinedError extends Error {
  constructor(public readonly category: SqlCategory) {
    super(`User declined confirmation for ${category} statement`);
    this.name = 'PolicyConfirmationDeclinedError';
  }
}

/**
 * The confirmation prompt could not be shown at all - the client does not
 * implement MCP elicitation, or the request failed in transport.
 *
 * Distinct from PolicyConfirmationDeclinedError on purpose: reporting this as a
 * decline tells the user they rejected something they were never asked about,
 * and hides a broken confirmation channel behind a plausible-looking refusal.
 */
export class PolicyConfirmationUnavailableError extends Error {
  constructor(
    public readonly category: SqlCategory,
    public readonly reason: string,
  ) {
    super(`Confirmation required for ${category} statement, but no prompt could be shown: ${reason}`);
    this.name = 'PolicyConfirmationUnavailableError';
  }
}

export class ClassifierError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ClassifierError';
  }
}
