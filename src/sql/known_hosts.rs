//! SSH known_hosts parsing, matching and verification (`sshHostKey.ts`
//! port): plain, wildcard, `[host]:port`, hashed `|1|` entries,
//! `@cert-authority`/`@revoked` markers, SHA-256 fingerprints.

use base64::Engine;
use hmac;
use sha1;
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KnownHostEntry {
    pub host_patterns: Vec<String>,
    pub key_type: String,
    pub key_base64: String,
    pub marker: Option<&'static str>, // "@cert-authority" | "@revoked"
    pub hashed: Option<(Vec<u8>, Vec<u8>)>, // (salt, expected hmac)
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct VerifyResult {
    pub fingerprint: String,
    pub matched: bool,
    pub had_matching_host_entry: bool,
    pub revoked: bool,
}

pub fn parse_known_hosts(content: &str) -> Vec<KnownHostEntry> {
    let mut entries = Vec::new();
    for raw_line in content.split('\n') {
        let line = raw_line.trim_end_matches('\r').trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        let mut cursor = 0usize;
        let mut marker = None;
        if parts[0] == "@cert-authority" || parts[0] == "@revoked" {
            marker = Some(match parts[0] {
                "@cert-authority" => "@cert-authority",
                _ => "@revoked",
            });
            cursor = 1;
        }
        if parts.len() < cursor + 3 {
            continue;
        }
        let host_field = parts[cursor];
        let key_type = parts[cursor + 1].to_string();
        let key_base64 = parts[cursor + 2].to_string();

        let mut hashed = None;
        let mut host_patterns = Vec::new();
        if let Some(rest) = host_field.strip_prefix("|1|") {
            let segments: Vec<&str> = rest.split('|').collect();
            if segments.len() >= 2 {
                let salt = b64_decode(segments[0]);
                let hash = b64_decode(segments[1]);
                if let (Some(salt), Some(hash)) = (salt, hash) {
                    hashed = Some((salt, hash));
                }
            }
        } else {
            host_patterns = host_field
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect();
        }
        entries.push(KnownHostEntry {
            host_patterns,
            key_type,
            key_base64,
            marker,
            hashed,
        });
    }
    entries
}

fn b64_decode(s: &str) -> Option<Vec<u8>> {
    base64::engine::general_purpose::STANDARD.decode(s).ok()
}

fn matches_pattern(pattern: &str, host: &str, port: u16) -> bool {
    let mut p = pattern.to_string();
    let mut port_match = true;
    if p.starts_with('[') {
        if let Some(close) = p.find("]:") {
            let port_part = p[close + 2..].to_string();
            p = p[1..close].to_string();
            port_match = port_part == port.to_string();
        }
    } else if port != 22 {
        port_match = false;
    }
    if !port_match {
        return false;
    }
    if p == host {
        return true;
    }
    if p.contains('*') || p.contains('?') {
        let mut re = String::from("^");
        for c in p.chars() {
            match c {
                '*' => re.push_str(".*"),
                '?' => re.push('.'),
                '.' | '+' | '^' | '$' | '(' | ')' | '[' | ']' | '{' | '}' | '\\' => {
                    re.push('\\');
                    re.push(c);
                }
                other => re.push(other),
            }
        }
        re.push('$');
        // Shell-style glob patterns are ASCII; use a manual match to avoid
        // pulling a regex dependency.
        glob_match(&re[1..re.len() - 1], host)
    } else {
        false
    }
}

/// Tiny glob matcher for the wildcard translation (`.*` / `.`).
fn glob_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    fn rec(p: &[char], t: &[char]) -> bool {
        if p.is_empty() {
            return t.is_empty();
        }
        if p[0] == '.' && p.len() > 1 && p[1] == '*' {
            for i in 0..=t.len() {
                if rec(&p[2..], &t[i..]) {
                    return true;
                }
            }
            return false;
        }
        if t.is_empty() {
            return false;
        }
        if p[0] == '.' && p.len() > 1 && p[1] == '\\' {
            return p.len() > 2 && t[0] == p[2] && rec(&p[2..], &t[1..]);
        }
        if p[0] == '\\' && p.len() > 1 {
            return t[0] == p[1] && rec(&p[2..], &t[1..]);
        }
        (p[0] == t[0]) && rec(&p[1..], &t[1..])
    }
    rec(&p, &t)
}

fn hashed_host_matches(entry: &KnownHostEntry, host: &str, port: u16) -> bool {
    let Some((salt, expected)) = &entry.hashed else {
        return false;
    };
    let probes: Vec<String> = if port == 22 {
        vec![host.to_string()]
    } else {
        vec![format!("[{host}]:{port}")]
    };
    for probe in probes {
        // OpenSSH hashed known_hosts format: HMAC-SHA1(salt, hostname).
        // Retained deliberately — it is the file format's definition, used
        // only for hostname matching (not secret protection).
        let tag = hmac_sha1(salt, probe.as_bytes());
        if tag.as_slice() == expected.as_slice() {
            return true;
        }
    }
    false
}

pub fn match_host<'a>(
    entries: &'a [KnownHostEntry],
    host: &str,
    port: u16,
) -> Vec<&'a KnownHostEntry> {
    entries
        .iter()
        .filter(|e| {
            if e.hashed.is_some() {
                hashed_host_matches(e, host, port)
            } else {
                e.host_patterns
                    .iter()
                    .any(|p| matches_pattern(p, host, port))
            }
        })
        .collect()
}

pub fn fingerprint_sha256(raw_key: &[u8]) -> String {
    let digest = Sha256::digest(raw_key);
    let b64 = base64::engine::general_purpose::STANDARD.encode(digest);
    format!("SHA256:{}", b64.trim_end_matches('='))
}

pub fn key_matches_entry(raw_key: &[u8], entry: &KnownHostEntry) -> bool {
    let Some(entry_key) = b64_decode(&entry.key_base64) else {
        return false;
    };
    if entry_key.len() != raw_key.len() {
        // Length mismatch resisted without an early-content oracle.
        let mut diff: u8 = 1;
        for (a, b) in entry_key.iter().zip(raw_key.iter()) {
            diff |= a ^ b;
        }
        let _ = diff;
        return false;
    }
    let mut diff: u8 = 0;
    for (a, b) in entry_key.iter().zip(raw_key.iter()) {
        diff |= a ^ b;
    }
    diff == 0
}

pub fn verify_host_key(
    raw_key: &[u8],
    host: &str,
    port: u16,
    entries: &[KnownHostEntry],
) -> VerifyResult {
    let fingerprint = fingerprint_sha256(raw_key);
    let candidates = match_host(entries, host, port);
    let mut matched = false;
    let mut revoked = false;
    for e in &candidates {
        if key_matches_entry(raw_key, e) {
            if e.marker == Some("@revoked") {
                revoked = true;
            } else {
                matched = true;
            }
        }
    }
    VerifyResult {
        fingerprint,
        matched,
        had_matching_host_entry: !candidates.is_empty(),
        revoked,
    }
}

pub fn load_known_hosts(file_path: Option<&std::path::Path>) -> Vec<KnownHostEntry> {
    let target = file_path
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| crate::app::paths::expand_tilde("~/.ssh/known_hosts"));
    match std::fs::read_to_string(target) {
        Ok(content) => parse_known_hosts(&content),
        Err(_) => Vec::new(),
    }
}

/// Fail-closed loader: an EXPLICITLY configured known_hosts file that
/// cannot be read, or that contains no parseable entry at all, is a
/// deny (in every policy mode) rather than a silently-empty host set.
/// An absent DEFAULT path (~/.ssh/known_hosts) stays an empty set —
/// strict then rejects unknown hosts anyway, lenient TOFU-accepts.
pub fn load_known_hosts_checked(
    file_path: Option<&std::path::Path>,
) -> Result<Vec<KnownHostEntry>, String> {
    let explicit = file_path.is_some();
    let target = file_path
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| crate::app::paths::expand_tilde("~/.ssh/known_hosts"));
    match std::fs::read_to_string(&target) {
        Err(e) if explicit => Err(format!(
            "known_hosts file {} is unreadable: {e}",
            target.display()
        )),
        Err(_) => Ok(Vec::new()),
        Ok(content) => {
            if content.trim().is_empty() {
                return Ok(Vec::new());
            }
            let entries = parse_known_hosts(&content);
            if entries.is_empty() {
                Err(format!(
                    "known_hosts file {} is malformed: no parseable entries",
                    target.display()
                ))
            } else {
                Ok(entries)
            }
        }
    }
}

/// Decision for `check_server_key` in the SSH client handler.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostKeyDecision {
    Accept,
    Reject,
}

pub fn decide_host_key(
    policy: crate::config::SshHostKeyPolicy,
    host: &str,
    port: u16,
    entries: &[KnownHostEntry],
    raw_key: &[u8],
    log: &mut impl FnMut(String),
) -> HostKeyDecision {
    let r = verify_host_key(raw_key, host, port, entries);
    log(format!(
        "SSH host {host}:{port} fingerprint={}",
        r.fingerprint
    ));
    if r.revoked {
        log(format!(
            "SSH host key REVOKED for {host}:{port} — rejecting"
        ));
        return HostKeyDecision::Reject;
    }
    if policy == crate::config::SshHostKeyPolicy::Strict {
        if !r.had_matching_host_entry {
            log(format!(
                "SSH host {host}:{port} not in known_hosts (strict mode — rejecting). Fingerprint={}",
                r.fingerprint
            ));
            return HostKeyDecision::Reject;
        }
        if !r.matched {
            log(format!(
                "SSH host key MISMATCH for {host}:{port} (strict mode — rejecting). Got={}",
                r.fingerprint
            ));
            return HostKeyDecision::Reject;
        }
        return HostKeyDecision::Accept;
    }
    // lenient (migration compatibility ONLY, warned loudly). A MISMATCH
    // means the server identity changed or is being impersonated — that
    // is rejected in EVERY mode. Only a genuinely unknown host may be
    // accepted under lenient, with a high-visibility warning.
    if r.had_matching_host_entry && !r.matched {
        log(format!(
            "SSH host key MISMATCH for {host}:{port} (lenient mode — REJECTING). Got={}",
            r.fingerprint
        ));
        return HostKeyDecision::Reject;
    }
    if !r.had_matching_host_entry {
        log(format!(
            "SSH host {host}:{port} not in known_hosts (lenient mode — accepting, migration compatibility only). Add {} to enable strict mode.",
            r.fingerprint
        ));
    }
    HostKeyDecision::Accept
}

/// HMAC-SHA1 over `data` with key `salt`, used ONLY to match OpenSSH's
/// hashed known_hosts entry format (`|1|salt|hash`). SHA-1 here is a
/// file-format compatibility requirement, not a chosen cryptographic
/// primitive — it is never used for signatures, password hashing, or any
/// secret-protection purpose.
fn hmac_sha1(key: &[u8], data: &[u8]) -> [u8; 20] {
    use hmac::Mac;
    type HmacSha1 = hmac::Hmac<sha1::Sha1>;
    let mut mac = HmacSha1::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    const PUB: &[u8] = b"AAAAC3NzaC1lZDI1NTE5AAAAIExampleKeyMaterial0123456789abcdefghijklm";
    const OTHER: &[u8] = b"AAAAC3NzaC1lZDI1NTE5AAAAIDifferentKeyMaterial9876543210mlkjihgfe";

    fn hosts() -> Vec<KnownHostEntry> {
        let b64 = |b: &[u8]| base64::engine::general_purpose::STANDARD.encode(b);
        parse_known_hosts(&format!(
            "# comment\n\
             \n\
             host-a.example.invalid ssh-ed25519 {}\n\
             host-a.example.invalid,alias ssh-ed25519 {}\n\
             [host-a.example.invalid]:2222 ssh-ed25519 {}\n\
             *.wild.example.invalid ssh-ed25519 {}\n\
             @revoked host-a.example.invalid ssh-ed25519 {}\n\
             @cert-authority *.ca.example.invalid ssh-ed25519 {}\n\
             host-b.example.invalid ssh-ed25519 {}\n\
             garbage-line\n\
             host-c.example.invalid\n",
            b64(PUB),
            b64(PUB),
            b64(PUB),
            b64(PUB),
            b64(PUB),
            b64(PUB),
            b64(OTHER),
        ))
    }

    #[test]
    fn parses_entries() {
        let h = hosts();
        // malformed + comment + blank lines skipped
        assert_eq!(h.len(), 7);
        assert_eq!(
            h[0].host_patterns,
            vec!["host-a.example.invalid".to_string()]
        );
        assert_eq!(h[1].host_patterns.len(), 2);
        assert_eq!(h[4].marker, Some("@revoked"));
        assert_eq!(h[5].marker, Some("@cert-authority"));
    }

    #[test]
    fn matches_hostnames() {
        let h = hosts();
        assert_eq!(match_host(&h, "host-a.example.invalid", 22).len(), 3); // plain, alias list, revoked
        assert_eq!(match_host(&h, "host-a.example.invalid", 2222).len(), 1);
        assert_eq!(match_host(&h, "anything.wild.example.invalid", 22).len(), 1);
        assert_eq!(match_host(&h, "nope.example.invalid", 22).len(), 0);
        assert_eq!(match_host(&h, "sub.ca.example.invalid", 22).len(), 1);
    }

    #[test]
    fn fingerprints() {
        let f = fingerprint_sha256(PUB);
        assert!(f.starts_with("SHA256:"));
        assert!(!f.ends_with('='));
        assert_ne!(f, fingerprint_sha256(OTHER));
    }

    #[test]
    fn verify_outcomes() {
        let h = hosts();
        // matched known host
        let r = verify_host_key(PUB, "host-a.example.invalid", 22, &h);
        assert!(r.matched && r.had_matching_host_entry);
        // changed key on known host (MitM signal)
        let r = verify_host_key(OTHER, "host-a.example.invalid", 22, &h);
        assert!(!r.matched && r.had_matching_host_entry);
        // unknown host
        let r = verify_host_key(PUB, "nope.example.invalid", 22, &h);
        assert!(!r.had_matching_host_entry);
        // revoked key
        let r = verify_host_key(PUB, "host-a.example.invalid", 22, &h);
        // revoked entry also matches the same key
        assert!(r.revoked);
    }

    #[test]
    fn length_mismatch_resists_oracle() {
        let h = hosts();
        assert!(!key_matches_entry(b"short", &h[0]));
    }

    #[test]
    fn strict_and_lenient_decisions() {
        use crate::config::SshHostKeyPolicy;
        let h = hosts();
        let mut logs = Vec::new();
        let mut log = |m: String| logs.push(m);

        // strict: unknown host rejected
        assert_eq!(
            decide_host_key(
                SshHostKeyPolicy::Strict,
                "nope.example.invalid",
                22,
                &h,
                PUB,
                &mut log
            ),
            HostKeyDecision::Reject
        );
        // strict: matching host accepted
        let h_no_revoke: Vec<KnownHostEntry> =
            h.iter().filter(|e| e.marker.is_none()).cloned().collect();
        assert_eq!(
            decide_host_key(
                SshHostKeyPolicy::Strict,
                "host-a.example.invalid",
                22,
                &h_no_revoke,
                PUB,
                &mut log
            ),
            HostKeyDecision::Accept
        );
        // strict: mismatch rejected
        assert_eq!(
            decide_host_key(
                SshHostKeyPolicy::Strict,
                "host-a.example.invalid",
                22,
                &h_no_revoke,
                OTHER,
                &mut log
            ),
            HostKeyDecision::Reject
        );
        // lenient: unknown accepted (warned)
        assert_eq!(
            decide_host_key(
                SshHostKeyPolicy::Lenient,
                "nope.example.invalid",
                22,
                &h,
                PUB,
                &mut log
            ),
            HostKeyDecision::Accept
        );
        // lenient: MISMATCH REJECTED (server identity change is never
        // acceptable, even in migration-compatibility mode)
        assert_eq!(
            decide_host_key(
                SshHostKeyPolicy::Lenient,
                "host-a.example.invalid",
                22,
                &h_no_revoke,
                OTHER,
                &mut log
            ),
            HostKeyDecision::Reject
        );
        // revoked rejected even lenient
        assert_eq!(
            decide_host_key(
                SshHostKeyPolicy::Lenient,
                "host-a.example.invalid",
                22,
                &h,
                PUB,
                &mut log
            ),
            HostKeyDecision::Reject
        );
        assert!(!logs.is_empty());
    }

    #[test]
    fn hashed_entries_self_consistent() {
        // Build a hashed entry like OpenSSH would, then match it.
        let salt = vec![0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
        let probe = "hashed.example.invalid";
        let tag = hmac_sha1(&salt, probe.as_bytes());
        let b64 = base64::engine::general_purpose::STANDARD;
        let line = format!(
            "|1|{}|{} ssh-ed25519 {}",
            b64.encode(&salt),
            b64.encode(tag),
            b64.encode(PUB)
        );
        let entries = parse_known_hosts(&line);
        assert_eq!(entries.len(), 1);
        assert!(entries[0].hashed.is_some());
        assert_eq!(match_host(&entries, probe, 22).len(), 1);
        assert_eq!(match_host(&entries, "other.example.invalid", 22).len(), 0);
        assert!(key_matches_entry(PUB, &entries[0]));
    }

    #[test]
    fn hmac_sha1_matches_reference_vectors() {
        // RFC 2202 test vectors.
        assert_eq!(
            hmac_sha1(&[0x0b; 20], b"Hi There").to_vec(),
            hex_decode("b617318655057264e28bc0b6fb378c8ef146be00")
        );
        assert_eq!(
            hmac_sha1(b"Jefe", b"what do ya want for nothing?").to_vec(),
            hex_decode("effcdf6ae5eb2fa2d27416d5f184df9c259a7c79")
        );
    }

    fn hex_decode(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn multiple_algorithms_for_same_host() {
        // Two entries for one host with different key types: either key
        // is acceptable; a third, unseen key is a mismatch.
        let b64 = |b: &[u8]| base64::engine::general_purpose::STANDARD.encode(b);
        let entries = parse_known_hosts(&format!(
            "multi.example.invalid ssh-ed25519 {}\n             multi.example.invalid ssh-rsa {}",
            b64(PUB),
            b64(OTHER)
        ));
        assert_eq!(entries.len(), 2);
        let mut log = |_: String| {};
        assert_eq!(
            decide_host_key(
                crate::config::SshHostKeyPolicy::Strict,
                "multi.example.invalid",
                22,
                &entries,
                OTHER,
                &mut log
            ),
            HostKeyDecision::Accept
        );
        let third = b"AAAAC3NzaC1lZDI1NTE5AAAAIThirdKeyNeverSeenBefore0000000000000";
        assert_eq!(
            decide_host_key(
                crate::config::SshHostKeyPolicy::Strict,
                "multi.example.invalid",
                22,
                &entries,
                third,
                &mut log
            ),
            HostKeyDecision::Reject
        );
    }

    #[test]
    fn checked_loader_fail_closed() {
        let dir = tempfile::TempDir::new().unwrap();
        let good = dir.path().join("good");
        std::fs::write(
            &good,
            "h.example.invalid ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFixture
",
        )
        .unwrap();
        assert!(load_known_hosts_checked(Some(&good)).is_ok());

        // Explicit path that does not exist: deny.
        let missing = dir.path().join("missing");
        let err = load_known_hosts_checked(Some(&missing)).unwrap_err();
        assert!(err.contains("unreadable"), "{err}");

        // Non-empty file with zero parseable entries: deny. (A 3-part
        // garbage line still parses, mirroring OpenSSH's tolerant
        // reader — such lines simply never match; only lines with no
        // key field at all are structurally unparseable.)
        let malformed = dir.path().join("garbage");
        std::fs::write(&malformed, "two-parts-only\n???\nno-key-here either-way\n").unwrap();
        let err = load_known_hosts_checked(Some(&malformed)).unwrap_err();
        assert!(err.contains("malformed"), "{err}");

        // Empty file is an empty set (not an error).
        let empty = dir.path().join("empty");
        std::fs::write(&empty, "\n").unwrap();
        assert!(load_known_hosts_checked(Some(&empty)).unwrap().is_empty());
    }

    /// Differential check against the legacy fixtures.
    #[test]
    fn matches_legacy_known_hosts_fixtures() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/legacy/known-hosts.json"
        );
        // Untracked corpus generated from the legacy checkout; skip on
        // fresh CI checkouts where it is absent.
        let Ok(raw) = std::fs::read_to_string(path) else {
            eprintln!("skipping: legacy fixture corpus not present ({path})");
            return;
        };
        let data: serde_json::Value = serde_json::from_str(&raw).unwrap();
        let parsed = parse_known_hosts(data["content"].as_str().unwrap());
        assert_eq!(parsed.len(), data["parsedCount"].as_u64().unwrap() as usize);

        // Fixture key material is synthesized there as b64 strings; verify
        // our fingerprint matches the legacy-computed one for the same bytes.
        let b64 = base64::engine::general_purpose::STANDARD;
        let pub_bytes = b64
            .decode(
                parsed
                    .iter()
                    .find(|e| {
                        e.host_patterns
                            .first()
                            .map(|p| p == "host-a.example.invalid")
                            .unwrap_or(false)
                    })
                    .map(|e| e.key_base64.clone())
                    .unwrap(),
            )
            .unwrap();
        assert_eq!(
            fingerprint_sha256(&pub_bytes),
            data["fingerprint"].as_str().unwrap()
        );

        for m in data["matches"].as_array().unwrap() {
            let host = m["host"].as_str().unwrap();
            let port = m["port"].as_u64().unwrap() as u16;
            assert_eq!(
                match_host(&parsed, host, port).len() as u64,
                m["matchedHosts"].as_u64().unwrap(),
                "match count for {host}:{port}"
            );
            let verify = verify_host_key(&pub_bytes, host, port, &parsed);
            assert_eq!(verify.matched, m["verifyPub"]["matched"].as_bool().unwrap());
            assert_eq!(
                verify.had_matching_host_entry,
                m["verifyPub"]["hadMatchingHostEntry"].as_bool().unwrap()
            );
            assert_eq!(verify.revoked, m["verifyPub"]["revoked"].as_bool().unwrap());
        }

        // Hashed-entry differential.
        let h = parse_known_hosts(data["hashedEntry"]["line"].as_str().unwrap());
        assert_eq!(
            h.len() as u64,
            data["hashedEntry"]["parsedCount"].as_u64().unwrap()
        );
        assert_eq!(
            match_host(&h, "hashed.example.invalid", 22).len() as u64,
            data["hashedEntry"]["matchHost_22"].as_u64().unwrap()
        );
        assert_eq!(
            match_host(&h, "other.example.invalid", 22).len() as u64,
            data["hashedEntry"]["matchHost_other"].as_u64().unwrap()
        );
    }
}
