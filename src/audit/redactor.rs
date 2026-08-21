//! SQL literal redaction (`audit/redactor.ts` port). Tokenizer-level:
//! string/number/boolean/hex literals are replaced; identifiers, keywords
//! and structure survive.

use sqlparser::dialect::{MySqlDialect, SQLiteDialect};
use sqlparser::tokenizer::Token;

pub fn redact_sql(sql: &str, dialect: crate::policy::classifier::Dialect) -> String {
    let d: &dyn sqlparser::dialect::Dialect = match dialect {
        crate::policy::classifier::Dialect::MySql => &MySqlDialect {},
        crate::policy::classifier::Dialect::SQLite => &SQLiteDialect {},
    };
    let tokens = match sqlparser::tokenizer::Tokenizer::new(d, sql).tokenize() {
        Ok(t) => t,
        Err(_) => return fallback_redact(sql),
    };
    let redacted: Vec<String> = tokens.iter().map(redact_token).collect();
    redacted.join(" ")
}

fn redact_token(t: &Token) -> String {
    match t {
        Token::SingleQuotedString(_) | Token::DoubleQuotedString(_) => "'<str>'".into(),
        Token::TripleSingleQuotedString(_) | Token::TripleDoubleQuotedString(_) => "'<str>'".into(),
        Token::EscapedStringLiteral(_) => "'<str>'".into(),
        Token::Number(_, _) => "0".into(),
        Token::Placeholder(_) => "<param>".into(),
        other => other.to_string(),
    }
}

/// Regex-free fallback for unparseable input, mirroring the legacy
/// catch-all: strings → `'<str>'`, numbers → `<num>`.
fn fallback_redact(sql: &str) -> String {
    let mut out = String::with_capacity(sql.len());
    let chars: Vec<char> = sql.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c == '\'' {
            out.push_str("'<str>'");
            i += 1;
            while i < chars.len() {
                if chars[i] == '\\' {
                    i += 2;
                    continue;
                }
                if chars[i] == '\'' {
                    i += 1;
                    break;
                }
                i += 1;
            }
        } else if c.is_ascii_digit() {
            out.push_str("<num>");
            while i < chars.len() && (chars[i].is_ascii_digit() || chars[i] == '.') {
                i += 1;
            }
        } else {
            out.push(c);
            i += 1;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn string_and_number_literals_redacted() {
        let r = redact_sql(
            "SELECT * FROM users WHERE name = 'secret' AND id = 42",
            crate::policy::classifier::Dialect::MySql,
        );
        assert!(!r.contains("secret"), "{r}");
        assert!(!r.contains("42"), "{r}");
        assert!(r.contains("'<str>'"), "{r}");
        assert!(r.contains("0"), "{r}");
        assert!(r.contains("users"), "{r}");
    }

    #[test]
    fn update_literals_redacted() {
        let r = redact_sql(
            "UPDATE app.jobs SET state = 'done', n = 7 WHERE id = 3",
            crate::policy::classifier::Dialect::MySql,
        );
        assert!(!r.contains("'done'"));
        assert!(r.contains("'<str>'"));
        assert!(!r.contains("= 7"));
        assert!(!r.contains("= 3"));
    }

    #[test]
    fn fallback_redacts_unparseable() {
        let r = fallback_redact("garbage 'literal' 12.5 x");
        assert!(r.contains("'<str>'"));
        assert!(r.contains("<num>"));
        assert!(!r.contains("literal"));
    }

    #[test]
    fn structure_and_identifiers_survive() {
        let r = redact_sql(
            "DELETE FROM app.users WHERE email = 'a@b.invalid'",
            crate::policy::classifier::Dialect::MySql,
        );
        assert!(r.contains("DELETE"));
        assert!(r.contains("app"));
        assert!(r.contains("users"));
        assert!(r.contains("email"));
    }
}
