use super::*;

// Test tokens are assembled at runtime so this file does not itself trip
// secret scanners.
fn fake(prefix: &str, body: &str, n: usize) -> String {
    format!("{prefix}{}", body.repeat(n))
}

#[test]
fn detects_provider_tokens() {
    let scanner = SecretScanner::builtin();
    let cases = [
        (fake("sk-ant-api03-", "aB3dE5fG7h", 9), "Anthropic API key"),
        (fake("sk-proj-", "Zx9Yw8Vu7T", 5), "OpenAI API key"),
        (
            fake("AKIA", "ABCDEFGH23", 1) + "IJKLMN",
            "AWS access key ID",
        ),
        (fake("ghp_", "a1B2c3D4e5", 4), "GitHub token"),
        (fake("sk_live_", "4eC39HqLyj", 3), "Stripe secret key"),
        (fake("xoxb-", "1234-5678-", 3), "Slack token"),
    ];
    for (token, label) in cases {
        let text = format!("key = \"{token}\"");
        let labels: Vec<String> = scanner.scan(&text).into_iter().map(|m| m.label).collect();
        assert_eq!(labels, vec![label.to_string()], "for {token}");
    }
}

#[test]
fn anthropic_key_is_not_reported_as_openai() {
    let token = fake("sk-ant-api03-", "aB3dE5fG7h", 9);
    let matches = SecretScanner::builtin().scan(&token);
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].label, "Anthropic API key");
}

#[test]
fn dotenv_reports_names_not_values() {
    let env = format!(
        "# config\nNODE_ENV=production\nDATABASE_URL=postgres://app:{pw}@db.internal:5432/app\nSTRIPE_SECRET_KEY={stripe}\nOPENAI_API_KEY=\nEXAMPLE_TOKEN=your-token-here\nexport GITHUB_TOKEN=\"{gh}\"\n",
        pw = "s3cr3tPassw0rd",
        stripe = fake("sk_live_", "4eC39HqLyj", 3),
        gh = fake("ghp_", "a1B2c3D4e5", 4),
    );
    let labels = SecretScanner::builtin().labels(&env);
    assert!(
        labels.contains(&"Database URL with credentials".to_string())
            || labels.contains(&"DATABASE_URL".to_string())
    );
    assert!(
        labels.contains(&"Stripe secret key".to_string())
            || labels.contains(&"STRIPE_SECRET_KEY".to_string())
    );
    assert!(
        labels.contains(&"GitHub token".to_string())
            || labels.contains(&"GITHUB_TOKEN".to_string())
    );
    assert!(!labels.iter().any(|l| l.contains("NODE_ENV")));
    assert!(
        !labels.iter().any(|l| l.contains("OPENAI")),
        "empty value is not a secret"
    );
    assert!(
        !labels.iter().any(|l| l.contains("EXAMPLE")),
        "placeholder is not a secret"
    );
}

#[test]
fn assignment_with_plain_value() {
    let labels = SecretScanner::builtin()
        .labels("DB_PASSWORD=Tr0ub4dor&3xyz\nAPI_URL=https://api.example.com");
    assert_eq!(labels, vec!["DB_PASSWORD".to_string()]);
}

#[test]
fn code_expressions_are_not_secrets() {
    let code = "password = os.environ[\"DB_PASSWORD\"]\ntoken = config.github.token\napi_key = get_key()\nsecret = None\n";
    assert!(
        SecretScanner::builtin().scan(code).is_empty(),
        "{:?}",
        SecretScanner::builtin().scan(code)
    );
}

#[test]
fn json_and_yaml() {
    let json = r#"{"client_secret": "9f8e7d6c5b4a39281706f5e4", "name": "app"}"#;
    assert_eq!(
        SecretScanner::builtin().labels(json),
        vec!["client_secret".to_string()]
    );
    let yaml = "database:\n  password: hunter2hunter2\n  host: localhost\n";
    assert_eq!(
        SecretScanner::builtin().labels(yaml),
        vec!["password".to_string()]
    );
}

#[test]
fn private_key_block() {
    let key = format!(
        "-----BEGIN OPENSSH {k}-----\nb3BlbnNzaC1rZXktdjEAAAAA\n-----END OPENSSH {k}-----\n",
        k = "PRIVATE KEY"
    );
    assert_eq!(
        SecretScanner::builtin().labels(&key),
        vec!["Private key".to_string()]
    );
}

#[test]
fn command_line_credentials() {
    let scanner = SecretScanner::builtin();
    let cmd = "curl -H 'Authorization: Bearer abcdef0123456789abcdef' https://api.example.com";
    assert_eq!(
        scanner.labels(cmd),
        vec!["Authorization header".to_string()]
    );
    let cmd = "mysql --password=hunter2hunter2 -h db";
    assert_eq!(scanner.labels(cmd), vec!["Password argument".to_string()]);
    let cmd = "git clone https://user:tok3nvalue99@github.com/org/repo";
    assert_eq!(scanner.labels(cmd), vec!["Password in URL".to_string()]);
    let cmd = "curl -H \"Authorization: Bearer $TOKEN\" https://x";
    assert!(
        scanner.scan(cmd).is_empty(),
        "a variable reference is not a secret"
    );
}

#[test]
fn redaction_removes_values() {
    let stripe = fake("sk_live_", "4eC39HqLyj", 3);
    let cmd = format!("curl https://api.stripe.com -u {stripe}: && echo done");
    let redacted = redact(&cmd);
    assert!(!redacted.contains(&stripe));
    assert!(redacted.contains("[REDACTED]"));
    assert!(redacted.ends_with("&& echo done"));
    assert_eq!(redact("ls -la"), "ls -la");
}

#[test]
fn custom_detectors_plug_in() {
    struct Canary;
    impl SecretDetector for Canary {
        fn id(&self) -> &'static str {
            "canary"
        }
        fn scan(&self, text: &str, out: &mut Vec<SecretMatch>) {
            if let Some(i) = text.find("CANARY-") {
                out.push(SecretMatch {
                    detector: "canary",
                    label: "canary token".into(),
                    start: i,
                    end: i + 11,
                });
            }
        }
    }
    let scanner = SecretScanner::new(vec![Box::new(Canary)]);
    assert_eq!(scanner.redact("x CANARY-1234 y"), "x [REDACTED] y");
}
