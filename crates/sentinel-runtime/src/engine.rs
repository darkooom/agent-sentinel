use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::Result;
use sentinel_audit::{AuditEvent, AuditLog, Outcome};
use sentinel_core::{analyze, Action, Analysis, AnalysisContext};
use sentinel_policy::{Decision, Policy};

use crate::discovery::load_policy;
use crate::Paths;

/// Policy, context and audit log for one working directory.
pub struct Engine {
    pub policy: Policy,
    pub project_root: Option<PathBuf>,
    pub paths: Paths,
    ctx: AnalysisContext,
    audit: AuditLog,
}

pub struct Evaluation {
    pub analysis: Analysis,
    pub decision: Decision,
    pub started: Instant,
}

impl Evaluation {
    pub fn elapsed(&self) -> Duration {
        self.started.elapsed()
    }
}

impl Engine {
    /// Load the policy that applies to `cwd`. `explicit` overrides discovery.
    pub fn load(explicit: Option<&Path>, cwd: &Path) -> Result<Engine> {
        let paths = Paths::discover();
        let explicit = explicit.map(Path::to_path_buf).or_else(|| {
            std::env::var_os("SENTINEL_POLICY")
                .filter(|v| !v.is_empty())
                .map(PathBuf::from)
        });
        let loaded = load_policy(explicit.as_deref(), cwd, &paths)?;
        Ok(Engine::new(loaded.policy, loaded.project_root, paths))
    }

    pub fn new(policy: Policy, project_root: Option<PathBuf>, paths: Paths) -> Engine {
        let ctx = AnalysisContext {
            home: std::env::home_dir(),
            project_root: project_root.clone(),
            protected_branches: policy.protected_branches.clone(),
            protected_paths: vec![paths.config_dir.clone(), paths.state_dir.clone()],
            inspect_files: true,
        };
        let audit = AuditLog::new(paths.audit_log());
        Engine {
            policy,
            project_root,
            paths,
            ctx,
            audit,
        }
    }

    pub fn audit_log(&self) -> &AuditLog {
        &self.audit
    }

    pub fn evaluate(&self, action: &Action) -> Evaluation {
        let started = Instant::now();
        let analysis = analyze(action, &self.ctx);
        let decision = self
            .policy
            .evaluate(action, &analysis, self.project_root.as_deref());
        Evaluation {
            analysis,
            decision,
            started,
        }
    }

    /// Append an audit event. Callers report failures but do not change the
    /// decision because of them.
    pub fn record(&self, action: &Action, eval: &Evaluation, outcome: Outcome) -> Result<()> {
        let findings = eval
            .analysis
            .findings
            .iter()
            .map(|f| f.id.to_string())
            .collect();
        let ms = u64::try_from(eval.elapsed().as_millis()).unwrap_or(u64::MAX);
        let event = AuditEvent::new(action, &eval.decision, findings, outcome, ms);
        self.audit.append(&event)?;
        Ok(())
    }
}
