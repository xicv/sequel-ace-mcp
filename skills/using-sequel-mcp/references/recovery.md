# Recovery + backup reference

## Contents
- When backups are captured
- Backup kinds
- Insert-hint backups
- Restore plan + execution
- Multi-table UPDATE / DELETE
- Limits + overflow behavior

## When backups are captured

Before executing one of these `write` / `ddl` statements, the server captures a backup row and links the resulting `backup_id` to the audit entry:

| AST type | Backup kind |
|----------|-------------|
| `update`, `delete`, `replace` | `rows` (PRE-image of targeted rows; MySQL uses `SELECT … FOR UPDATE`, SQLite captures inside `BEGIN IMMEDIATE`) |
| `truncate`, `drop_table` | `combined` (rows + schema SQL where supported) |
| `alter_table` | `schema` (schema SQL where supported) |
| `insert` | `insert-hint` (POST-execution; uses `LAST_INSERT_ID()` or explicit `id` values) |

If backup capture fails (overflow + `onBackupOverflow=abort`), the mutation is **not run**. The audit row reflects an error outcome.

## Backup kinds

Stored in the `backup` table of `audit.sqlite`:

```text
id | ts | connection | database | table_name | backup_kind |
rows_json | schema_sql | primary_key | row_count | truncated | size_bytes
```

`rows_json` is a JSON array of the pre-image rows. `schema_sql` is the `CREATE TABLE` statement (rebuild on `DROP`). `primary_key` holds insert-hint metadata.

## Insert-hint backups

`INSERT` does not need pre-images (no rows existed). The server captures one of:

- **`explicit` PK values** — if the INSERT statement supplies primary key values explicitly, those values are recorded. Restore re-issues `DELETE FROM <t> WHERE id IN (...)`.
- **`range`** — auto-increment range derived from `LAST_INSERT_ID()` + `affectedRows`. Restore re-issues `DELETE FROM <t> WHERE id BETWEEN <start> AND <end>`.

If neither is available (e.g. INSERT…SELECT into a table with non-auto-increment PK), no insert-hint is stored. Surface this to the user explicitly when planning a restore.

## Restore plan + execution

```text
sequel-mcp:restore_backup backupId=<n> dryRun=true
  → returns { rowCount, statementCount, warnings, firstStatementPreview }
sequel-mcp:restore_backup backupId=<n> dryRun=false
  → elicits confirm (counts as a write), executes inside a transaction,
    rolls back on failure
```

Restore strategy by backup kind:

| Kind | Restore SQL |
|------|-------------|
| `rows` | MySQL/MariaDB: `INSERT … ON DUPLICATE KEY UPDATE col=VALUES(col)` per captured row. SQLite: `INSERT … ON CONFLICT DO UPDATE SET col=excluded.col` |
| `schema` | Re-issues the captured `CREATE TABLE` |
| `combined` | `CREATE TABLE` then row inserts |
| `insert-hint` | `DELETE FROM <t> WHERE id IN/BETWEEN …` |

Restores are themselves audited (`outcome=success`) and gated. A failed restore rolls back inside its transaction; the original backup row is **not** consumed.

## Multi-table UPDATE / DELETE

The extractor walks the AST and rewrites the WHERE clause per target table to fetch a per-table pre-image. Each touched table gets its own backup row; the audit `backup_id` points to the first one, and the rest are linked by their shared `ts`. Restore picks all rows with the same `ts + connection + database` to replay the multi-table mutation cleanly.

## Limits + overflow

Policy fields gate every capture:

- `maxBackupRows` — hard cap; if exceeded, behavior depends on `onBackupOverflow`.
- `maxBackupBytes` — hard cap on JSON size.
- `onBackupOverflow=abort` (default) — mutation **not** executed.
- `onBackupOverflow=truncate` — mutation executed, but only the first N rows are recoverable. The audit row's `backup_id` will have `truncated=1`.

Recommendation: keep `abort` for `prod`. Use `truncate` for bulk dev cleanup tasks where partial rollback is acceptable.

## Listing + searching

- `sequel-mcp:list_backups connection=<name> limit=<n>` — recent backups.
- `sequel-mcp:audit_search outcome=success category=write` — audit rows; each carries `backup_id` you can feed to restore.
- Backup retention is governed by `retention.backupDays` (default 30 days) + hard size cap; `sequel-mcp:audit_cleanup` prunes both audit and backup rows.
