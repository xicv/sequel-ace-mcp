//! Two-layer policy resolution (connection baseline + table rules) with
//! strictest-wins and elevation-requires-confirmation semantics.

use crate::config::Connection;
use crate::policy::classifier::{ClassifiedStatement, TableRef};
use crate::policy::model::{
    PartialPolicy, Policy, PolicyAction, SqlCategory, TableId, TableRuleKey,
};
use std::collections::BTreeMap;

/// Why a resolution denied the statement (audit/explain surface).
#[derive(Debug, Clone, PartialEq)]
pub enum DenyReason {
    FileIo,
    UnresolvedTarget { table: String },
    NoTargetsEstablished,
    Policy,
}

#[derive(Debug, Clone, PartialEq)]
pub struct TableContribution {
    pub table: TableId,
    pub kind: &'static str, // "read" | "mutated" | "locking-read"
    pub category: SqlCategory,
    pub action: PolicyAction,
    pub baseline_action: PolicyAction,
    pub rule: Option<String>, // governing rule rendered
    pub elevated: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Resolution {
    pub action: PolicyAction,
    pub effective: Policy,
    pub contributions: Vec<TableContribution>,
    pub elevated: bool,
    pub deny_reason: Option<DenyReason>,
    /// Legacy-compat: distinct target databases considered.
    pub contributing_databases: Vec<String>,
}

fn resolve_table_action(
    baseline: PolicyAction,
    rule: Option<PolicyAction>,
) -> (PolicyAction, bool) {
    match rule {
        None => (baseline, false),
        Some(a) => {
            if a == PolicyAction::Allow && baseline != PolicyAction::Allow {
                // A table rule elevates what the baseline denies (or gates):
                // eligible, but never silent — confirmation required.
                (PolicyAction::Confirm, true)
            } else {
                (a, false)
            }
        }
    }
}

/// Find the governing partial rule for a table: exact beats wildcard.
fn governing_rule<'a>(
    table_policies: &'a BTreeMap<TableRuleKey, PartialPolicy>,
    table: &TableId,
) -> Option<(&'a PartialPolicy, String)> {
    if let Some(p) = table_policies.get(&TableRuleKey::Exact(table.clone())) {
        return Some((p, TableRuleKey::Exact(table.clone()).render()));
    }
    if let Some(p) = table_policies.get(&TableRuleKey::Wildcard {
        database: table.database.clone(),
    }) {
        return Some((
            p,
            TableRuleKey::Wildcard {
                database: table.database.clone(),
            }
            .render(),
        ));
    }
    None
}

#[allow(clippy::too_many_arguments)]
fn resolve_object(
    _conn: &Connection,
    baseline: &Policy,
    table_policies: &BTreeMap<TableRuleKey, PartialPolicy>,
    category: SqlCategory,
    table: &TableRef,
    fallback_db: Option<&str>,
    kind: &'static str,
    contributions: &mut Vec<TableContribution>,
    strictest: &mut Option<(PolicyAction, Policy, TableContribution)>,
) -> Result<(), DenyReason> {
    let database = match &table.database {
        Some(db) => db.clone(),
        None => match fallback_db {
            Some(db) => db.to_string(),
            // Unqualified table without an established database: fail closed.
            None => {
                return Err(DenyReason::UnresolvedTarget {
                    table: table.table.clone(),
                });
            }
        },
    };
    let id = TableId {
        database,
        table: table.table.clone(),
    };
    let base_action = baseline.action_for(category);
    let (partial, rule_name) = match governing_rule(table_policies, &id) {
        Some((p, name)) => (Some(p), Some(name)),
        None => (None, None),
    };
    let rule_action = partial.and_then(|p| p.action_for(category));
    let (action, elevated) = resolve_table_action(base_action, rule_action);
    // Effective limits come from the baseline merged with the governing
    // rule's overrides (legacy merge semantics).
    let effective = match partial {
        Some(p) => baseline.merged_with(p),
        None => baseline.clone(),
    };
    let contribution = TableContribution {
        table: id,
        kind,
        category,
        action,
        baseline_action: base_action,
        rule: rule_name,
        elevated,
    };
    let better = match strictest {
        None => true,
        Some((a, _, _)) => action.rank() > a.rank(),
    };
    if better {
        *strictest = Some((action, effective, contribution.clone()));
    }
    contributions.push(contribution);
    Ok(())
}

/// Resolve a classified statement against a connection's two-layer policy.
///
/// Rules (normative):
/// - every read table is authorized for `read`; every mutated table for the
///   statement's mutation category (`write`/`ddl`/`admin`);
/// - locking reads additionally require `write` authorization on their
///   tables;
/// - file I/O is denied regardless of grants;
/// - strictest action across all contributions wins;
/// - unresolved (unqualified, no database) targets deny;
/// - table-rule elevation of a stricter baseline always downgrades to
///   `confirm`.
pub fn resolve(
    conn: &Connection,
    classified: &ClassifiedStatement,
    fallback_database: Option<&str>,
) -> Resolution {
    let baseline = conn.policy();
    let table_policies = conn.table_policies();
    let fallback = fallback_database.or_else(|| conn.database());

    if classified.file_io {
        return Resolution {
            action: PolicyAction::Deny,
            effective: baseline.clone(),
            contributions: Vec::new(),
            elevated: false,
            deny_reason: Some(DenyReason::FileIo),
            contributing_databases: Vec::new(),
        };
    }

    let mut contributions = Vec::new();
    let mut strictest: Option<(PolicyAction, Policy, TableContribution)> = None;
    let mut elevated_any = false;
    let mut dbs: Vec<String> = Vec::new();

    let consider = |category: SqlCategory,
                    table: &TableRef,
                    kind: &'static str,
                    contributions: &mut Vec<TableContribution>,
                    strictest: &mut Option<(PolicyAction, Policy, TableContribution)>,
                    elevated_any: &mut bool,
                    dbs: &mut Vec<String>|
     -> Result<(), DenyReason> {
        let res = resolve_object(
            conn,
            baseline,
            table_policies,
            category,
            table,
            fallback,
            kind,
            contributions,
            strictest,
        );
        if let Ok(c) = res.as_ref() {
            let _ = c;
        }
        if res.is_ok()
            && let Some(c) = contributions.last()
        {
            if c.elevated {
                *elevated_any = true;
            }
            if !dbs.contains(&c.table.database) {
                dbs.push(c.table.database.clone());
            }
        }
        res
    };

    let mutation_category = classified.category;
    let mut denied: Option<DenyReason> = None;

    for t in &classified.read_tables {
        if let Err(e) = consider(
            SqlCategory::Read,
            t,
            "read",
            &mut contributions,
            &mut strictest,
            &mut elevated_any,
            &mut dbs,
        ) {
            denied = denied.or(Some(e));
        }
        if classified.locking_read
            && let Err(e) = consider(
                SqlCategory::Write,
                t,
                "locking-read",
                &mut contributions,
                &mut strictest,
                &mut elevated_any,
                &mut dbs,
            )
        {
            denied = denied.or(Some(e));
        }
    }
    for t in &classified.mutated_tables {
        if mutation_category == SqlCategory::Read {
            // Defensive: mutated tables under a read classification cannot
            // happen via the classifier; deny if it ever does.
            denied = denied.or(Some(DenyReason::Policy));
            continue;
        }
        if let Err(e) = consider(
            mutation_category,
            t,
            "mutated",
            &mut contributions,
            &mut strictest,
            &mut elevated_any,
            &mut dbs,
        ) {
            denied = denied.or(Some(e));
        }
    }

    if let Some(reason) = denied {
        return Resolution {
            action: PolicyAction::Deny,
            effective: baseline.clone(),
            contributions,
            elevated: elevated_any,
            deny_reason: Some(reason),
            contributing_databases: dbs,
        };
    }

    match strictest {
        Some((action, effective, _)) => Resolution {
            action,
            effective,
            contributions,
            elevated: elevated_any,
            deny_reason: None,
            contributing_databases: dbs,
        },
        None => {
            // Table-free statements (txCtrl, admin fast paths, bare SELECT 1):
            // fall back to the baseline, matching the legacy resolver.
            let action = baseline.action_for(mutation_category);
            let mut dbs = Vec::new();
            if classified.target_databases.is_empty() {
                if let Some(f) = fallback {
                    dbs.push(f.to_string());
                }
            } else {
                dbs.extend(classified.target_databases.iter().cloned());
            }
            Resolution {
                action,
                effective: baseline.clone(),
                contributions: Vec::new(),
                elevated: false,
                deny_reason: None,
                contributing_databases: dbs,
            }
        }
    }
}

/// Legacy-compat helper used by the database-policy wrapper tools and
/// explain surfaces: strictest action across explicit databases with
/// wildcard-table-rule overrides standing in for per-database policies.
pub fn resolve_databases_legacy(
    conn: &Connection,
    category: SqlCategory,
    target_databases: &[String],
    fallback_database: Option<&str>,
) -> Resolution {
    let baseline = conn.policy();
    let table_policies = conn.table_policies();
    let mut dbs: Vec<String> = if target_databases.is_empty() {
        match fallback_database.or_else(|| conn.database()) {
            Some(db) => vec![db.to_string()],
            None => Vec::new(),
        }
    } else {
        target_databases.to_vec()
    };
    dbs.sort();
    dbs.dedup();

    if dbs.is_empty() {
        return Resolution {
            action: baseline.action_for(category),
            effective: baseline.clone(),
            contributions: Vec::new(),
            elevated: false,
            deny_reason: None,
            contributing_databases: Vec::new(),
        };
    }

    let mut contributions = Vec::new();
    let mut strictest: Option<(PolicyAction, Policy)> = None;
    for db in &dbs {
        let id = TableId {
            database: db.clone(),
            table: "*".to_string(),
        };
        let base_action = baseline.action_for(category);
        let (partial, rule_name) = match governing_rule(table_policies, &id) {
            Some((p, name)) => (Some(p), Some(name)),
            None => (None, None),
        };
        let rule_action = partial.and_then(|p| p.action_for(category));
        let (action, elevated) = resolve_table_action(base_action, rule_action);
        let effective = match partial {
            Some(p) => baseline.merged_with(p),
            None => baseline.clone(),
        };
        contributions.push(TableContribution {
            table: id,
            kind: "database",
            category,
            action,
            baseline_action: base_action,
            rule: rule_name,
            elevated,
        });
        let better = match &strictest {
            None => true,
            Some((a, _)) => action.rank() > a.rank(),
        };
        if better {
            strictest = Some((action, effective));
        }
    }

    let (action, effective) =
        strictest.unwrap_or_else(|| (baseline.action_for(category), baseline.clone()));
    let elevated = contributions.iter().any(|c| c.elevated);
    Resolution {
        action,
        effective,
        contributions,
        elevated,
        deny_reason: None,
        contributing_databases: dbs,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{MySqlConnection, SqliteConnection};
    use crate::policy::classifier::classify_statement;
    use crate::policy::model::{PolicyPresetName, policy_from_preset};

    fn mysql_conn(policy: Policy, rules: Vec<(TableRuleKey, PartialPolicy)>) -> Connection {
        let mut c = MySqlConnection {
            name: "c1".into(),
            host: "db.example.invalid".into(),
            user: "u".into(),
            ..MySqlConnection::default()
        };
        c.policy = policy;
        for (k, v) in rules {
            c.table_policies.insert(k, v);
        }
        Connection::Mysql(c)
    }

    fn sqlite_conn(rules: Vec<(TableRuleKey, PartialPolicy)>) -> Connection {
        let mut c = SqliteConnection {
            name: "s1".into(),
            path: "/tmp/app.sqlite".into(),
            ..SqliteConnection::default()
        };
        c.policy = policy_from_preset(PolicyPresetName::ReadOnly);
        for (k, v) in rules {
            c.table_policies.insert(k, v);
        }
        Connection::Sqlite(c)
    }

    fn write_allow() -> PartialPolicy {
        PartialPolicy {
            write: Some(PolicyAction::Allow),
            ..PartialPolicy::default()
        }
    }

    fn resolve_sql(conn: &Connection, sql: &str) -> Resolution {
        let c = classify_statement(sql, crate::policy::classifier::Dialect::MySql).unwrap();
        resolve(conn, &c, None)
    }

    #[test]
    fn read_only_baseline_allows_reads_denies_writes() {
        let conn = mysql_conn(policy_from_preset(PolicyPresetName::ReadOnly), vec![]);
        assert_eq!(
            resolve_sql(&conn, "SELECT * FROM app.users").action,
            PolicyAction::Allow
        );
        let r = resolve_sql(&conn, "UPDATE app.jobs SET state = 'x' WHERE id = 1");
        assert_eq!(r.action, PolicyAction::Deny);
    }

    #[test]
    fn table_elevation_requires_confirmation() {
        let conn = mysql_conn(
            policy_from_preset(PolicyPresetName::ReadOnly),
            vec![(TableRuleKey::parse("app.jobs").unwrap(), write_allow())],
        );
        let r = resolve_sql(&conn, "UPDATE app.jobs SET state = 'x' WHERE id = 1");
        assert_eq!(r.action, PolicyAction::Confirm);
        assert!(r.elevated);
        assert_eq!(r.contributions.len(), 1);
        assert_eq!(r.contributions[0].rule.as_deref(), Some("app.jobs"));
    }

    #[test]
    fn cross_table_strictest_wins() {
        let conn = mysql_conn(
            policy_from_preset(PolicyPresetName::ReadOnly),
            vec![
                (TableRuleKey::parse("app.jobs").unwrap(), write_allow()),
                (TableRuleKey::parse("app.users").unwrap(), {
                    PartialPolicy {
                        write: Some(PolicyAction::Deny),
                        ..PartialPolicy::default()
                    }
                }),
            ],
        );
        let r = resolve_sql(
            &conn,
            "UPDATE app.jobs JOIN app.users ON app.users.id = app.jobs.user_id SET app.jobs.state = 'ok'",
        );
        assert_eq!(r.action, PolicyAction::Deny);
        assert_eq!(r.contributions.len(), 2);
    }

    #[test]
    fn insert_select_authorizes_source_as_read() {
        let conn = mysql_conn(
            policy_from_preset(PolicyPresetName::ReadOnly),
            vec![(
                TableRuleKey::parse("app.jobs").unwrap(),
                PartialPolicy {
                    write: Some(PolicyAction::Allow),
                    read: Some(PolicyAction::Deny),
                    ..PartialPolicy::default()
                },
            )],
        );
        // Write elevated to confirm on app.jobs; read of app.jobs denied.
        let r = resolve_sql(&conn, "INSERT INTO app.jobs (id) SELECT id FROM app.jobs");
        assert_eq!(r.action, PolicyAction::Deny);
    }

    #[test]
    fn exact_rule_beats_wildcard() {
        let conn = mysql_conn(
            policy_from_preset(PolicyPresetName::ReadOnly),
            vec![
                (TableRuleKey::parse("app.*").unwrap(), write_allow()),
                (
                    TableRuleKey::parse("app.audit").unwrap(),
                    PartialPolicy {
                        write: Some(PolicyAction::Deny),
                        ..PartialPolicy::default()
                    },
                ),
            ],
        );
        let elevated = resolve_sql(&conn, "UPDATE app.jobs SET x = 1");
        assert_eq!(elevated.action, PolicyAction::Confirm);
        let blocked = resolve_sql(&conn, "UPDATE app.audit SET x = 1");
        assert_eq!(blocked.action, PolicyAction::Deny);
    }

    #[test]
    fn unqualified_without_fallback_denies() {
        let conn = mysql_conn(policy_from_preset(PolicyPresetName::ReadOnly), vec![]);
        let r = resolve_sql(&conn, "UPDATE jobs SET x = 1");
        assert_eq!(r.action, PolicyAction::Deny);
        assert!(matches!(
            r.deny_reason,
            Some(DenyReason::UnresolvedTarget { .. })
        ));
    }

    #[test]
    fn unqualified_uses_connection_database() {
        let mut c = MySqlConnection {
            name: "c1".into(),
            host: "db.example.invalid".into(),
            user: "u".into(),
            database: Some("app".into()),
            ..MySqlConnection::default()
        };
        c.policy = policy_from_preset(PolicyPresetName::ReadOnly);
        {
            let (k, v) = (TableRuleKey::parse("app.jobs").unwrap(), write_allow());
            c.table_policies.insert(k, v);
        }
        let conn = Connection::Mysql(c);
        let r = resolve_sql(&conn, "UPDATE jobs SET x = 1");
        assert_eq!(r.action, PolicyAction::Confirm);
    }

    #[test]
    fn locking_reads_need_write_authorization() {
        let conn = mysql_conn(policy_from_preset(PolicyPresetName::ReadOnly), vec![]);
        let r = resolve_sql(&conn, "SELECT * FROM app.users FOR UPDATE");
        // Read allow + write deny ⇒ deny.
        assert_eq!(r.action, PolicyAction::Deny);
    }

    #[test]
    fn file_io_always_denied() {
        let mut conn = mysql_conn(Policy::default(), vec![]);
        if let Connection::Mysql(ref mut m) = conn {
            m.policy.admin = PolicyAction::Allow;
            m.policy.write = PolicyAction::Allow;
        }
        let r = resolve_sql(&conn, "SELECT * FROM users INTO OUTFILE '/tmp/x'");
        assert_eq!(r.action, PolicyAction::Deny);
        assert_eq!(r.deny_reason, Some(DenyReason::FileIo));
    }

    #[test]
    fn table_free_statements_use_baseline() {
        let conn = mysql_conn(policy_from_preset(PolicyPresetName::ReadOnly), vec![]);
        assert_eq!(resolve_sql(&conn, "BEGIN").action, PolicyAction::Allow);
        let mut dev = policy_from_preset(PolicyPresetName::Development);
        dev.admin = PolicyAction::Deny;
        let conn2 = mysql_conn(dev, vec![]);
        assert_eq!(resolve_sql(&conn2, "KILL 42").action, PolicyAction::Deny);
    }

    #[test]
    fn sqlite_read_confirm_rule_prompts_reads() {
        let conn = sqlite_conn(vec![(
            TableRuleKey::parse("main.secrets").unwrap(),
            PartialPolicy {
                read: Some(PolicyAction::Confirm),
                ..PartialPolicy::default()
            },
        )]);
        let c = classify_statement(
            "SELECT * FROM secrets",
            crate::policy::classifier::Dialect::SQLite,
        )
        .unwrap();
        let r = resolve(&conn, &c, None);
        assert_eq!(r.action, PolicyAction::Confirm);
        // Ordinary reads on other tables stay prompt-free.
        let c2 = classify_statement(
            "SELECT * FROM main.users",
            crate::policy::classifier::Dialect::SQLite,
        )
        .unwrap();
        assert_eq!(resolve(&conn, &c2, None).action, PolicyAction::Allow);
    }

    #[test]
    fn legacy_database_resolution_via_wildcards() {
        let conn = mysql_conn(
            policy_from_preset(PolicyPresetName::ReadOnly),
            vec![(
                TableRuleKey::parse("app.*").unwrap(),
                PartialPolicy {
                    write: Some(PolicyAction::Confirm),
                    ..PartialPolicy::default()
                },
            )],
        );
        let r = resolve_databases_legacy(&conn, SqlCategory::Write, &["app".into()], None);
        assert_eq!(r.action, PolicyAction::Confirm);
        // Strictest across two databases.
        let r2 = resolve_databases_legacy(
            &conn,
            SqlCategory::Write,
            &["app".into(), "analytics".into()],
            None,
        );
        assert_eq!(r2.action, PolicyAction::Deny);
    }

    /// Differential check against the legacy resolver fixtures (database
    /// granularity, via wildcard rules standing in for databasePolicies).
    #[test]
    fn matches_legacy_resolver_fixtures() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/legacy/resolver.json"
        );
        // Untracked corpus generated from the legacy checkout; skip on
        // fresh CI checkouts where it is absent.
        let Ok(data) = std::fs::read_to_string(path) else {
            eprintln!("skipping: legacy fixture corpus not present ({path})");
            return;
        };
        let cases: Vec<serde_json::Value> = serde_json::from_str(&data).unwrap();
        for case in cases {
            let label = case["label"].as_str().unwrap();
            let args = &case["args"];
            let conn_json = &args["connection"];
            let mut rules = Vec::new();
            if let Some(dbs) = conn_json["databasePolicies"].as_object() {
                for (db, partial) in dbs {
                    let p: PartialPolicy = serde_json::from_value(partial.clone()).unwrap();
                    rules.push((
                        TableRuleKey::Wildcard {
                            database: db.clone(),
                        },
                        p,
                    ));
                }
            }
            let mut m = MySqlConnection {
                name: "c1".into(),
                host: "db.example.invalid".into(),
                user: "u".into(),
                database: conn_json["database"].as_str().map(str::to_string),
                ..MySqlConnection::default()
            };
            m.policy = serde_json::from_value(conn_json["policy"].clone()).unwrap();
            for (k, v) in rules {
                m.table_policies.insert(k, v);
            }
            let conn = Connection::Mysql(m);
            let category = SqlCategory::parse(args["category"].as_str().unwrap()).unwrap();
            let targets: Vec<String> = args["targetDatabases"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_str().unwrap().to_string())
                .collect();
            let fallback = args["fallbackDatabase"].as_str();
            let r = resolve_databases_legacy(&conn, category, &targets, fallback);
            let want = case["result"]["action"].as_str().unwrap();
            assert_eq!(r.action.as_str(), want, "case {label}");
        }
    }
}
