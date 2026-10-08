/// Does this variable or key name conventionally hold a credential?
///
/// The name is split into parts on `_`, `-`, `.` and camelCase boundaries
/// and judged by its parts, so `STRIPE_SECRET_KEY`, `githubToken` and
/// `db.password` match while `MAX_TOKENS`, `TOKENIZER` and `PUBLIC_KEY` do not.
pub fn is_sensitive_name(name: &str) -> bool {
    let parts = split_name(name);
    if parts.is_empty() {
        return false;
    }
    let has = |p: &str| parts.iter().any(|x| x == p);
    let pair = |a: &str, b: &str| parts.windows(2).any(|w| w[0] == a && w[1] == b);

    if has("PUBLIC") || has("PUBLISHABLE") {
        return false;
    }
    const WORDS: &[&str] = &[
        "SECRET",
        "SECRETS",
        "TOKEN",
        "PASSWORD",
        "PASSWD",
        "PASS",
        "PWD",
        "PASSPHRASE",
        "CREDENTIAL",
        "CREDENTIALS",
        "CREDS",
        "APIKEY",
        "PRIVATEKEY",
        "ACCESSKEY",
        "DSN",
    ];
    if WORDS.iter().any(|w| has(w)) {
        // PWD/OLDPWD are shell working directories, not passwords.
        return !(parts.len() == 1 && parts[0] == "PWD");
    }
    if pair("API", "KEY")
        || pair("PRIVATE", "KEY")
        || pair("ACCESS", "KEY")
        || pair("SECRET", "KEY")
        || pair("SIGNING", "KEY")
        || pair("ENCRYPTION", "KEY")
        || pair("MASTER", "KEY")
        || pair("SESSION", "KEY")
        || pair("CLIENT", "SECRET")
        || pair("CONNECTION", "STRING")
        || pair("AUTH", "KEY")
    {
        return true;
    }
    if has("AUTH") && parts.len() > 1 {
        return true;
    }
    // Connection URLs routinely embed passwords.
    let url_like = has("URL") || has("URI");
    let store = [
        "DATABASE",
        "DB",
        "POSTGRES",
        "POSTGRESQL",
        "MYSQL",
        "MONGO",
        "MONGODB",
        "REDIS",
        "AMQP",
        "RABBITMQ",
    ];
    url_like && store.iter().any(|s| has(s))
}

fn split_name(name: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut prev_lower = false;
    for c in name.chars() {
        if !c.is_ascii_alphanumeric() {
            if !current.is_empty() {
                parts.push(std::mem::take(&mut current));
            }
            prev_lower = false;
            continue;
        }
        if c.is_ascii_uppercase() && prev_lower && !current.is_empty() {
            parts.push(std::mem::take(&mut current));
        }
        prev_lower = c.is_ascii_lowercase() || c.is_ascii_digit();
        current.push(c.to_ascii_uppercase());
    }
    if !current.is_empty() {
        parts.push(current);
    }
    parts
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_credential_names() {
        for name in [
            "OPENAI_API_KEY",
            "ANTHROPIC_API_KEY",
            "AWS_ACCESS_KEY_ID",
            "AWS_SECRET_ACCESS_KEY",
            "STRIPE_SECRET_KEY",
            "DATABASE_URL",
            "PRIVATE_KEY",
            "GITHUB_TOKEN",
            "githubToken",
            "db.password",
            "DB_PASS",
            "SENTRY_DSN",
            "CLIENT_SECRET",
            "MONGODB_URI",
            "NPM_AUTH_TOKEN",
            "JWT_SIGNING_KEY",
            "BASIC_AUTH",
        ] {
            assert!(is_sensitive_name(name), "{name} should be sensitive");
        }
    }

    #[test]
    fn ignores_ordinary_names() {
        for name in [
            "PATH",
            "HOME",
            "PWD",
            "OLDPWD",
            "NODE_ENV",
            "MAX_TOKENS",
            "TOKENIZER",
            "PUBLIC_KEY",
            "NEXT_PUBLIC_API_KEY",
            "STRIPE_PUBLISHABLE_KEY",
            "AUTHOR",
            "KEY",
            "API_URL",
            "PORT",
        ] {
            assert!(!is_sensitive_name(name), "{name} should not be sensitive");
        }
    }
}
