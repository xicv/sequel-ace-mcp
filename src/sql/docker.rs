//! Docker bridge validation and command construction (no shell strings).

/// Container names: alnum start, then alnum/`_`/`.`/`-`, ≤128 total.
pub fn validate_container_name(container: &str) -> Result<(), String> {
    let ok = matches!(container.chars().next(), Some(c) if c.is_ascii_alphanumeric())
        && container.len() <= 128
        && container
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'));
    if ok {
        Ok(())
    } else {
        Err(format!(
            "invalid container name: {container:?} (must match Docker naming rules)"
        ))
    }
}

/// Remote hosts reachable through the bridge: alnum/`.`/`-`, ≤253.
pub fn validate_remote_host(host: &str) -> Result<(), String> {
    let ok = !host.is_empty()
        && host.len() <= 253
        && host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-'));
    if ok {
        Ok(())
    } else {
        Err(format!("invalid remote host: {host:?}"))
    }
}

pub fn validate_remote_port(port: u16) -> Result<(), String> {
    if (1..=65535).contains(&port) {
        Ok(())
    } else {
        Err(format!("invalid remote port: {port}"))
    }
}

/// The argv for the remote `docker exec` bridge — a structured argument
/// vector, never a shell string. Executed over an SSH exec channel.
/// Per-tool forms match the legacy bridge commands:
/// `socat - TCP:h:p` and `nc|ncat h p`.
pub fn bridge_argv(
    container: &str,
    tool: crate::config::BridgeTool,
    remote_host: &str,
    remote_port: u16,
) -> Result<Vec<String>, String> {
    validate_container_name(container)?;
    validate_remote_host(remote_host)?;
    validate_remote_port(remote_port)?;
    let mut argv = vec![
        "docker".to_string(),
        "exec".to_string(),
        "-i".to_string(),
        container.to_string(),
        tool.as_str().to_string(),
    ];
    match tool {
        crate::config::BridgeTool::Socat => {
            argv.push("-".into());
            argv.push(format!("TCP:{remote_host}:{remote_port}"));
        }
        crate::config::BridgeTool::Nc | crate::config::BridgeTool::Ncat => {
            argv.push(remote_host.to_string());
            argv.push(remote_port.to_string());
        }
    }
    Ok(argv)
}

/// Argv probing the bridge tool's presence inside the container. `which` is
/// executed directly (an exec argv, no `sh -c` string).
pub fn tool_probe_argv(
    container: &str,
    tool: crate::config::BridgeTool,
) -> Result<Vec<String>, String> {
    validate_container_name(container)?;
    Ok(vec![
        "docker".into(),
        "exec".into(),
        container.to_string(),
        "which".into(),
        tool.as_str().to_string(),
    ])
}

/// Argv for `docker inspect` with a structured output format.
pub fn inspect_argv(container: &str) -> Result<Vec<String>, String> {
    validate_container_name(container)?;
    Ok(vec![
        "docker".into(),
        "inspect".into(),
        "--format".into(),
        "{{.Config.Image}}|{{.State.StartedAt}}|{{.State.Running}}".into(),
        container.to_string(),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn container_rules() {
        assert!(validate_container_name("db-1.x_y").is_ok());
        assert!(validate_container_name("-bad").is_err());
        assert!(validate_container_name("bad;rm").is_err());
        assert!(validate_container_name("$(x)").is_err());
        assert!(validate_container_name("").is_err());
        assert!(validate_container_name(&"a".repeat(129)).is_err());
    }

    #[test]
    fn host_rules() {
        assert!(validate_remote_host("db.internal-1.example.invalid").is_ok());
        assert!(validate_remote_host("10.0.0.5").is_ok());
        assert!(validate_remote_host("h; rm -rf").is_err());
        assert!(validate_remote_host("").is_err());
    }

    #[test]
    fn bridge_argv_forms() {
        let nc = bridge_argv("c1", crate::config::BridgeTool::Nc, "h", 3306).unwrap();
        assert_eq!(nc, vec!["docker", "exec", "-i", "c1", "nc", "h", "3306"]);
        let socat = bridge_argv("c1", crate::config::BridgeTool::Socat, "h", 3306).unwrap();
        assert_eq!(
            socat,
            vec!["docker", "exec", "-i", "c1", "socat", "-", "TCP:h:3306"]
        );
        let ncat = bridge_argv("c1", crate::config::BridgeTool::Ncat, "h", 3306).unwrap();
        assert_eq!(
            ncat,
            vec!["docker", "exec", "-i", "c1", "ncat", "h", "3306"]
        );
        assert!(bridge_argv("c;1", crate::config::BridgeTool::Nc, "h", 3306).is_err());
        assert!(bridge_argv("c1", crate::config::BridgeTool::Nc, "h", 0).is_err());
    }

    #[test]
    fn probe_uses_which_without_shell() {
        let probe = tool_probe_argv("c1", crate::config::BridgeTool::Socat).unwrap();
        assert_eq!(probe, vec!["docker", "exec", "c1", "which", "socat"]);
        assert!(!probe.iter().any(|a| a.contains("sh -c")));
    }
}
