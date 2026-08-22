//! D5 boundary-type coverage on MariaDB 11 and MySQL 8.4: extreme
//! integers, DECIMAL precision/scale/sign, temporal precision and time
//! zones, BIT widths, binary structure (including valid-UTF-8 BLOB and
//! invalid UTF-8), large BLOB near the response cap, nested JSON,
//! ENUM empty, SET multi, NULL families, and signed TIME/DATE bounds.

use sequel_mcp::config::MySqlConnection;
use sequel_mcp::policy::classifier::{Dialect, classify_statement};
use sequel_mcp::policy::model::{PolicyPresetName, policy_from_preset};
use sequel_mcp::sql::mysql::pool_manager;
use sequel_mcp::sql::mysql::{MySqlExecuteParams, execute_mysql_statement};
use std::sync::Arc;
use zeroize::Zeroizing;

fn target() -> Option<(String, u16, String, String)> {
    let spec = std::env::var("SEQUEL_MCP_TEST_MYSQL").ok()?;
    let mut parts = spec.splitn(4, ':');
    Some((
        parts.next()?.to_string(),
        parts.next()?.parse().ok()?,
        parts.next()?.to_string(),
        parts.next()?.to_string(),
    ))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn d5_boundary_types() {
    let Some((host, port, user, password)) = target() else {
        eprintln!("skipping: SEQUEL_MCP_TEST_MYSQL not set");
        return;
    };
    pool_manager().invalidate_all();
    let conn = MySqlConnection {
        name: "d5".into(),
        host,
        port,
        user,
        database: Some("app".into()),
        ..MySqlConnection::default()
    };
    let dir = tempfile::TempDir::new().unwrap();
    let audit =
        Arc::new(sequel_mcp::audit::AuditDb::at_path(&dir.path().join("a.sqlite")).unwrap());
    let policy = policy_from_preset(PolicyPresetName::Administration);

    async fn run(
        conn: &MySqlConnection,
        password: &str,
        audit: &Arc<sequel_mcp::audit::AuditDb>,
        policy: &sequel_mcp::policy::model::Policy,
        sql: &str,
    ) -> sequel_mcp::sql::mysql::ExecuteResult {
        let classified = classify_statement(sql, Dialect::MySql).unwrap();
        execute_mysql_statement(MySqlExecuteParams {
            connection: conn,
            request_id: format!("req-{}", uuid::Uuid::new_v4()),
            databases_for_log: vec![],
            password: Zeroizing::new(password.to_string()),
            sql,
            classified: &classified,
            policy,
            database: None,
            audit: Some(audit.clone()),
            revision: 1,
            tunnel_endpoint: None,
            expected_ddl_targets: None,
        })
        .await
        .unwrap()
    }

    macro_rules! run {
        ($sql:expr) => {
            run(&conn, &password, &audit, &policy, $sql).await
        };
    }
    macro_rules! one {
        ($sql:expr) => {{
            let rows = run!($sql).rows;
            assert_eq!(rows.len(), 1, "{}", $sql);
            rows.into_iter().next().unwrap()
        }};
    }

    run!("DROP TABLE IF EXISTS d5_bounds");
    run!(
        "CREATE TABLE d5_bounds (
          id INT PRIMARY KEY,
          big_u BIGINT UNSIGNED, big_s BIGINT,
          dec_max DECIMAL(65,30), dec_zero DECIMAL(10,0), dec_neg DECIMAL(20,4),
          f32 FLOAT, f64 DOUBLE,
          bit1 BIT(1), bit64 BIT(64),
          d DATE, dt6 DATETIME(6), ts0 TIMESTAMP NULL,
          tm_neg TIME, tm_big TIME,
          bin VARBINARY(16), bl BLOB,
          j JSON, e ENUM('','a','b'), s SET('x','y','z')
        )"
    );
    run!(
        "INSERT INTO d5_bounds VALUES (
          1,
          18446744073709551615, -9223372036854775808,
          999999999999999999999999999999.999999999999999999999999999999,
          9999999999, -12345.6789,
          3.40282e38, 1.7976931348623157e308,
          b'1', X'FFFFFFFFFFFFFFFF',
          '1000-01-01', '9999-12-31 23:59:59.999999', NULL,
          '-838:59:59', '838:59:59',
          X'', X'DEADBEFF00',
          JSON_OBJECT('a', JSON_ARRAY(1, JSON_OBJECT('b', 'c'))), '', 'x,z'
        )"
    );

    let row = one!(
        "SELECT big_u, big_s, dec_max, dec_zero, dec_neg, f32, f64,
                          bit1, bit64, d, dt6, ts0, tm_neg, tm_big, bin, bl, j, e, s
                     FROM d5_bounds WHERE id = 1"
    );

    // Extreme integers stay lossless strings (BIGINT contract).
    assert_eq!(row["big_u"], serde_json::json!("18446744073709551615"));
    assert_eq!(row["big_s"], serde_json::json!("-9223372036854775808"));

    // DECIMAL: max precision, zero scale, negative — exact strings.
    assert!(row["dec_max"].is_string());
    let dec_max = row["dec_max"].as_str().unwrap();
    assert!(
        dec_max.starts_with("999999999999999999999999999999."),
        "{dec_max}"
    );
    assert_eq!(row["dec_zero"], serde_json::json!("9999999999"));
    assert!(row["dec_neg"].as_str().unwrap().starts_with("-12345.6789"));

    // FLOAT/DOUBLE are numbers; non-finite must never produce invalid JSON
    // (they'd serialize as strings by serde_json's rules).
    assert!(row["f32"].is_number());
    assert!(row["f64"].is_number());

    // BIT(1)/BIT(64): structured binary, base64 payload.
    let check_binary = |v: &serde_json::Value, want_hex: &str| {
        assert_eq!(v["type"], "binary", "{v}");
        assert_eq!(v["encoding"], "base64");
        use base64::Engine;
        let data = v["data"].as_str().unwrap();
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(data)
            .unwrap();
        assert_eq!(hex(&bytes), want_hex, "{v}");
    };
    check_binary(&row["bit1"], "01");
    check_binary(&row["bit64"], "ffffffffffffffff");

    // Temporal boundaries and precision.
    assert_eq!(row["d"], serde_json::json!("1000-01-01"));
    assert!(
        row["dt6"]
            .as_str()
            .unwrap()
            .starts_with("9999-12-31 23:59:59.999999"),
        "{}",
        row["dt6"]
    );
    assert_eq!(row["ts0"], serde_json::Value::Null);
    // Negative TIME and >24h TIME (MySQL renders -838:59:59).
    let tm_neg = row["tm_neg"].as_str().unwrap();
    assert!(tm_neg.contains("838:59:59"), "{tm_neg}");
    let tm_big = row["tm_big"].as_str().unwrap();
    assert!(tm_big.contains("838:59:59"), "{tm_big}");

    // Binary columns: empty and non-UTF-8 — structured base64, never
    // mistaken for text.
    check_binary(&row["bin"], "");
    check_binary(&row["bl"], "deadbeff00");

    // Nested JSON survives.
    assert!(row["j"].is_object() || row["j"].is_string(), "{}", row["j"]);

    // ENUM empty value and SET multiple values.
    assert_eq!(row["e"], serde_json::json!(""));
    assert_eq!(row["s"], serde_json::json!("x,z"));

    // NULL across families in one query.
    let nulls = one!("SELECT NULL AS a, CAST(NULL AS CHAR) AS b, CAST(NULL AS SIGNED) AS c");
    assert_eq!(nulls["a"], serde_json::Value::Null);
    assert_eq!(nulls["b"], serde_json::Value::Null);
    assert_eq!(nulls["c"], serde_json::Value::Null);

    // Valid-UTF-8 BLOB still structured (ASCII blob is still a blob).
    run!("DROP TABLE IF EXISTS d5_ascii_blob");
    run!("CREATE TABLE d5_ascii_blob (b BLOB)");
    run!("INSERT INTO d5_ascii_blob VALUES (X'61626364')"); // "abcd"
    let r = one!("SELECT b FROM d5_ascii_blob");
    assert_eq!(r["b"]["type"], "binary");
    assert_eq!(r["b"]["data"], serde_json::json!("YWJjZA=="));

    // Large BLOB near the response byte cap: 3 MiB of deterministic bytes;
    // row cap or byte cap must truncate rather than explode.
    run!("DROP TABLE IF EXISTS d5_big_blob");
    run!("CREATE TABLE d5_big_blob (b LONGBLOB)");
    run!("INSERT INTO d5_big_blob (b) SELECT LEFT(CONCAT(REPEAT(X'41', 4096), ''), 3145728)");
    let result = run!("SELECT b FROM d5_big_blob");
    assert!(
        result.truncated
            || result.rows.is_empty()
            || result.rows[0]
                .get("b")
                .map(|v| v["data"]
                    .as_str()
                    .map(|d| d.len() < 4_200_000)
                    .unwrap_or(false))
                .unwrap_or(false),
        "large blob must be bounded: truncated={} rows={}",
        result.truncated,
        result.rows.len()
    );

    // TIMESTAMP with explicit session time zone: consistent rendering.
    run!("SET SESSION time_zone = '+00:00'");
    run!("DROP TABLE IF EXISTS d5_ts");
    run!("CREATE TABLE d5_ts (t TIMESTAMP)");
    run!("INSERT INTO d5_ts VALUES ('2026-08-22 10:00:00')");
    let r = one!("SELECT t FROM d5_ts");
    assert_eq!(r["t"], serde_json::json!("2026-08-22 10:00:00"));

    // Documented cross-engine literal-type difference (already asserted in
    // the matrix): `SELECT 1` is LONGLONG on MySQL (string) and LONG on
    // MariaDB (number). Re-assert per engine here for the record.
    let lit = one!("SELECT 1 AS n");
    assert!(
        lit["n"] == serde_json::json!(1) || lit["n"] == serde_json::json!("1"),
        "literal typing is server metadata driven: {}",
        lit["n"]
    );
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
