//! Reproduction for the MCP-server MySQL hang: gate called from
//! spawn_blocking with block_in_place + Handle::block_on.

use sequel_mcp::config::MySqlConnection;
use sequel_mcp::policy::classifier::{Dialect, classify_statement};
use sequel_mcp::policy::model::{PolicyPresetName, policy_from_preset};
use sequel_mcp::sql::mysql::{MySqlExecuteParams, execute_mysql_statement};
use zeroize::Zeroizing;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mysql_via_blocking_gate_like_server() {
    let Ok(spec) = std::env::var("SEQUEL_MCP_TEST_MYSQL") else {
        eprintln!("skipping: SEQUEL_MCP_TEST_MYSQL not set");
        return;
    };
    let mut parts = spec.splitn(4, ':');
    let host = parts.next().unwrap().to_string();
    let port: u16 = parts.next().unwrap().parse().unwrap();
    let user = parts.next().unwrap().to_string();
    let password = parts.next().unwrap().to_string();

    let out = tokio::task::spawn_blocking(move || {
        let conn = MySqlConnection {
            name: "db".into(),
            host,
            port,
            user,
            database: Some("app".into()),
            ..MySqlConnection::default()
        };
        let policy = policy_from_preset(PolicyPresetName::ReadOnly);
        let classified =
            classify_statement("SELECT COUNT(*) AS n FROM jobs", Dialect::MySql).unwrap();
        let res = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                execute_mysql_statement(MySqlExecuteParams {
                    connection: &conn,
                    password: Zeroizing::new(password),
                    sql: "SELECT COUNT(*) AS n FROM jobs",
                    classified: &classified,
                    policy: &policy,
                    database: None,
                    audit: None,
                    revision: 1,
                    tunnel_endpoint: None,
                })
                .await
            })
        });
        format!("{res:?}")
    })
    .await
    .expect("join");
    eprintln!("result: {out}");
    assert!(out.contains("Ok(ExecuteResult"), "{out}");
}
