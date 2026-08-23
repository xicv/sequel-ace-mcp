# Policy reference

## Contents
- Categories
- Actions
- Presets
- Per-database overrides + strictest-wins
- Numeric caps

## Categories

Every classified statement maps to exactly one category. Misclassification is fail-closed: if the parser cannot determine a category, the statement is rejected.

| Category | Examples |
|----------|----------|
| `read` | `SELECT`, `SHOW`, `DESCRIBE`, `EXPLAIN`, `PRAGMA` |
| `write` | `INSERT`, `UPDATE`, `DELETE`, `REPLACE` |
| `ddl` | `CREATE`, `DROP`, `ALTER`, `TRUNCATE`, `RENAME` |
| `admin` | `GRANT`, `REVOKE`, `FLUSH`, `KILL`, `LOCK/UNLOCK TABLES`, `SET GLOBAL`, replica control, `CREATE/ALTER/DROP USER` |
| `txCtrl` | `BEGIN`, `START TRANSACTION`, `COMMIT`, `ROLLBACK`, `SAVEPOINT`, `RELEASE SAVEPOINT` |

## Actions

- `allow` — execute without prompting.
- `confirm` — elicit a 3-choice prompt: once / session / decline. Durable allowances go through
  `set_table_policy`, not the prompt.
- `deny` — reject with a `Policy denies …` error; audit row stored with `outcome=denied`.

`confirm` prefers a client that implements MCP elicitation. Where it does not, the server asks the
local approval companions instead (`sequel-mcp approve` CLI or the native GUI window, authenticated
same-user IPC, 60 s deadline) and only then fails closed — audited as `outcome=error` (not
`declined`) with the reason.

## Presets

`sequel-mcp:add_sqlite_connection` (and `import_from_sequel_ace`) accept `policyPreset` ∈ `{ read-only, dev, admin }` (`development` / `administration` are accepted long forms).

| Preset | read | write | ddl | admin | txCtrl | rowCap | stmtTimeoutMs | requireTouchID |
|--------|------|-------|-----|-------|--------|--------|---------------|----------------|
| `read-only` | allow | deny | deny | deny | allow | 1000 | 10000 | false |
| `dev` | allow | confirm | confirm | deny | allow | 5000 | 30000 | false |
| `admin` | allow | confirm | confirm | confirm | allow | 5000 | 60000 | true |

After creation, `sequel-mcp:set_policy` overrides individual fields.

## Table rules + strictest-wins

`tablePolicies` on a connection holds exact (`db.table`) or wildcard (`db.*`) rules — migrated v1
`databasePolicies` appear as `db.*` wildcards:

```jsonc
{
  "policy": { "write": "allow", "ddl": "confirm", "admin": "deny", ... },
  "tablePolicies": {
    "prod_payments.*": { "write": "confirm", "ddl": "deny" },
    "audit_archive.events": { "write": "deny" }
  }
}
```

Exact rules beat wildcards; wildcards beat the baseline. When a single statement touches multiple
tables or databases (e.g. a cross-DB `UPDATE`), the **strictest action wins** (`deny` > `confirm` >
`allow`). A rule may elevate a denied category, but elevated statements always confirm. Use
`explain_policy` to preview the resolution for any statement without executing it.

Tools:
- `sequel-mcp:set_table_policy connection=<n> table=<db.table|db.*> policy={...}`
- `sequel-mcp:clear_table_policy connection=<n> table=<db.table|db.*>`
- `sequel-mcp:list_table_policies connection=<n>`
- `sequel-mcp:set_database_policy` / `clear_database_policy` / `list_database_policies` — the legacy per-DB view (backed by `db.*` wildcards)

## Numeric caps

Per-policy fields (set via `sequel-mcp:set_policy`):

| Field | Meaning | Bounds |
|-------|---------|--------|
| `rowCap` | Truncates `SELECT` result rows; `truncated:true` flag set in response | 1–100000 |
| `stmtTimeoutMs` | `MAX_EXECUTION_TIME` hint injected for reads | 1–600000 |
| `requireTouchID` | Touch ID required (15-min idle window cached) | bool |
| `maxBackupRows` | Cap on rows captured before mutation | 1–1000000 |
| `maxBackupBytes` | Cap on backup JSON size | bytes |
| `onBackupOverflow` | `abort` (default) or `truncate` if rows/bytes exceed cap | enum |

If `onBackupOverflow=abort` and the cap is exceeded, the mutation is **not executed** — the safer default. Switch to `truncate` only when the user explicitly accepts a partial rollback window.
