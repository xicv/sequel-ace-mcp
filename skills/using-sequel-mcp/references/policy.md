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
- `confirm` — elicit a 4-choice prompt: once / session / always / decline.
- `deny` — reject with a `Policy denies …` error; audit row stored with `outcome=denied`.

## Presets

`sequel-mcp:add_connection` accepts `policyPreset` ∈ `{ read-only, dev, admin }`.

| Preset | read | write | ddl | admin | txCtrl | rowCap | stmtTimeoutMs | requireTouchID |
|--------|------|-------|-----|-------|--------|--------|---------------|----------------|
| `read-only` | allow | deny | deny | deny | allow | 1000 | 10000 | false |
| `dev` | allow | confirm | confirm | deny | allow | 5000 | 30000 | false |
| `admin` | allow | confirm | confirm | confirm | allow | 5000 | 60000 | true |

After creation, `sequel-mcp:set_policy` overrides individual fields.

## Per-database overrides + strictest-wins

`databasePolicies` on a connection lets you tighten policy for sensitive DBs:

```jsonc
{
  "policy": { "write": "allow", "ddl": "confirm", "admin": "deny", ... },
  "databasePolicies": {
    "prod_payments": { "write": "confirm", "ddl": "deny" },
    "audit_archive": { "write": "deny" }
  }
}
```

When a single statement touches multiple databases (e.g. a cross-DB `UPDATE`), the **strictest action wins** (`deny` > `confirm` > `allow`). The response reports `contributingDatabase` (the DB that forced the strictest action) and `contributingDatabases` (all DBs in scope).

Tools:
- `sequel-mcp:set_database_policy connection=<n> database=<d> policy={...}`
- `sequel-mcp:clear_database_policy connection=<n> database=<d>`
- `sequel-mcp:list_database_policies connection=<n>`

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
