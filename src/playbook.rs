use std::collections::BTreeMap;
use std::path::Path;
use std::sync::LazyLock;

use anyhow::{Context, Result};
use regex::Regex;
use serde::Deserialize;

use crate::model::{Finding, FindingGroup, Plan, Severity};

const DEFAULT_PLAYBOOK: &str = include_str!("../playbook.toml");

#[derive(Debug, Clone, Deserialize, Default)]
pub struct Playbook {
    #[serde(default)]
    pub rule: Vec<RuleDef>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RuleDef {
    pub id: String,
    #[serde(rename = "match", default)]
    pub matcher: Matcher,
    #[serde(default)]
    pub severity_min: Option<String>,
    pub cause: String,
    #[serde(default)]
    pub steps: Vec<String>,
    #[serde(default)]
    pub verify: Option<String>,
    #[serde(default)]
    pub risk: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct Matcher {
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub message_regex: Option<String>,
}

#[derive(Clone)]
struct CompiledRule {
    def: RuleDef,
    message_regex: Option<Regex>,
    source: Option<String>,
    severity_min: Severity,
}

#[derive(Clone)]
pub struct Rules {
    rules: Vec<CompiledRule>,
}

impl Rules {
    pub fn load(paths_override: &Path) -> Result<Self> {
        let text = if paths_override.exists() {
            std::fs::read_to_string(paths_override)
                .with_context(|| format!("gagal baca {}", paths_override.display()))?
        } else {
            DEFAULT_PLAYBOOK.to_string()
        };
        Self::from_toml(&text).with_context(|| {
            format!(
                "playbook invalid ({})",
                if paths_override.exists() {
                    paths_override.display().to_string()
                } else {
                    "bawaan".into()
                }
            )
        })
    }

    pub fn from_toml(text: &str) -> Result<Self> {
        let pb: Playbook = toml::from_str(text)?;
        let mut rules = Vec::with_capacity(pb.rule.len());
        for def in pb.rule {
            let message_regex = def
                .matcher
                .message_regex
                .as_deref()
                .map(Regex::new)
                .transpose()
                .with_context(|| format!("rule {}", def.id))?;
            let severity_min = def
                .severity_min
                .as_deref()
                .and_then(Severity::parse)
                .unwrap_or(Severity::Info);
            rules.push(CompiledRule {
                source: def.matcher.source.as_deref().map(|s| s.to_lowercase()),
                message_regex,
                severity_min,
                def,
            });
        }
        Ok(Self { rules })
    }

    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    pub fn plan_for(&self, f: &Finding) -> Plan {
        for r in &self.rules {
            if f.severity < r.severity_min {
                continue;
            }
            if let Some(src) = &r.source {
                if !f.source.eq_ignore_ascii_case(src) {
                    continue;
                }
            }
            let mut captures: BTreeMap<String, String> = BTreeMap::new();
            if let Some(re) = &r.message_regex {
                let Some(caps) = re.captures(&f.message) else {
                    continue;
                };
                // named group dari rule jadi variabel template, mis. (?P<proc>...)
                for name in re.capture_names().flatten() {
                    if let Some(m) = caps.name(name) {
                        captures.insert(name.to_lowercase(), m.as_str().to_string());
                    }
                }
            }
            return Plan {
                rule_id: Some(r.def.id.clone()),
                cause: render(&r.def.cause, f, &captures),
                steps: r
                    .def
                    .steps
                    .iter()
                    .map(|s| render(s, f, &captures))
                    .collect(),
                verify: r.def.verify.as_deref().map(|s| render(s, f, &captures)),
                risk: r.def.risk.clone(),
                confidence: "rule",
            };
        }
        Plan::generic()
    }
}

static TEMPLATE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\{\{\s*(\w+)\s*\}\}").unwrap());

fn render(template: &str, f: &Finding, captures: &BTreeMap<String, String>) -> String {
    TEMPLATE
        .replace_all(template, |caps: &regex::Captures| {
            let key = caps[1].to_lowercase();
            if let Some(value) = captures.get(&key) {
                return value.clone();
            }
            match key.as_str() {
                "unit" => {
                    if f.unit.is_empty() { "unit-terkait".to_string() } else { f.unit.clone() }
                }
                "target" => f.target.clone(),
                "project" => f.project.clone(),
                "message" => f.message.clone(),
                "path" => {
                    if !f.path.is_empty() {
                        f.path.clone()
                    } else if !f.unit.is_empty() {
                        f.unit.clone()
                    } else {
                        "path-terkait".to_string()
                    }
                }
                other => format!("{{{{{other}}}}}"),
            }
        })
        .into_owned()
}

/// Gabungkan temuan per fingerprint lintas target, urut severity lalu jumlah target.
pub fn group(findings: &[Finding], rules: &Rules) -> Vec<FindingGroup> {
    let mut map: BTreeMap<String, FindingGroup> = BTreeMap::new();
    for f in findings {
        let entry = map.entry(f.fingerprint.clone()).or_insert_with(|| FindingGroup {
            fingerprint: f.fingerprint.clone(),
            severity: f.severity,
            source: f.source.clone(),
            message: f.message.clone(),
            unit: f.unit.clone(),
            path: f.path.clone(),
            targets: Vec::new(),
            projects: Vec::new(),
            pairs: Vec::new(),
            is_new: false,
            occurrences: 0,
            first_seen: f.first_seen.clone(),
            last_seen: f.last_seen.clone(),
            event_time: String::new(),
            solved: f.solved,
            excerpt: f.excerpt.clone(),
            plan: rules.plan_for(f),
        });
        if !entry.targets.contains(&f.target) {
            entry.targets.push(f.target.clone());
        }
        if !f.project.is_empty() && !entry.projects.contains(&f.project) {
            entry.projects.push(f.project.clone());
        }
        let pair = (f.target.clone(), f.project.clone());
        if !entry.pairs.contains(&pair) {
            entry.pairs.push(pair);
        }
        entry.is_new |= f.is_new;
        entry.occurrences = entry.occurrences.saturating_add(f.occurrences);
        if entry.event_time.is_empty() && !f.event_time.is_empty() {
            entry.event_time = f.event_time.clone();
        }
        // solved hanya jika SEMUA target untuk fingerprint ini sudah ditandai
        entry.solved &= f.solved;
        if !f.last_seen.is_empty()
            && (entry.last_seen.is_empty() || f.last_seen > entry.last_seen)
        {
            entry.last_seen = f.last_seen.clone();
        }
        if !f.first_seen.is_empty()
            && (entry.first_seen.is_empty() || f.first_seen < entry.first_seen)
        {
            entry.first_seen = f.first_seen.clone();
        }
        entry.severity = entry.severity.max(f.severity);
    }

    let mut out: Vec<FindingGroup> = map.into_values().collect();
    out.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then(b.targets.len().cmp(&a.targets.len()))
            .then(a.message.cmp(&b.message))
    });
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Severity;

    fn finding(source: &str, message: &str, unit: &str) -> Finding {
        Finding::new("vm1", "shop", source, Severity::Error, message, unit, "")
    }

    #[test]
    fn default_playbook_is_valid_and_matches_systemd() {
        let rules = Rules::from_toml(DEFAULT_PLAYBOOK).unwrap();
        assert!(rules.rule_count() >= 5);
        let plan = rules.plan_for(&finding("systemd", "unit failed: nginx.service — web server", "nginx.service"));
        assert_eq!(plan.rule_id.as_deref(), Some("systemd.failed"));
        assert!(plan.steps.iter().any(|s| s.contains("nginx.service")));
        assert!(plan.steps.iter().any(|s| s.contains("systemctl status")));
    }

    #[test]
    fn oom_rule_beats_generic_journal_rule() {
        let rules = Rules::from_toml(DEFAULT_PLAYBOOK).unwrap();
        let plan = rules.plan_for(&finding("journal", "kernel: Out of memory: Killed process 42", "kernel"));
        assert_eq!(plan.rule_id.as_deref(), Some("journal.oom"));
    }

    #[test]
    fn unknown_error_falls_back_to_generic_with_low_confidence() {
        let rules = Rules::from_toml(DEFAULT_PLAYBOOK).unwrap();
        let plan = rules.plan_for(&finding("extra", "sesuatu yang aneh", ""));
        assert!(plan.rule_id.is_none());
        assert_eq!(plan.confidence, "low");
        assert!(!plan.steps.is_empty());
    }

    #[test]
    fn laravel_sqlstate_gets_specific_rule() {
        let rules = Rules::from_toml(DEFAULT_PLAYBOOK).unwrap();
        let plan = rules.plan_for(&finding(
            "applog",
            "[2026-11-17 10:01:00] production.ERROR: SQLSTATE[HY000] [2002] Connection refused",
            "laravel.log",
        ));
        assert_eq!(plan.rule_id.as_deref(), Some("applog.laravel_sqlstate"));
        assert_eq!(plan.confidence, "rule");
    }

    #[test]
    fn default_plans_are_concrete_and_use_captures() {
        let rules = Rules::from_toml(DEFAULT_PLAYBOOK).unwrap();
        let cases: &[(&str, &str, &str, &str)] = &[
            ("systemd", "unit failed: nginx.service - web server", "nginx.service", "systemd.failed"),
            ("docker", "container api (img) Exited (1) 2 hours ago", "api", "docker.exited"),
            ("docker", "container worker (img) restart loop - Restarting", "worker", "docker.restart_loop"),
            ("journal", "Out of memory: Killed process 4242 (shop-api) total-vm:1", "kernel", "journal.oom_kill"),
            ("journal", "Out of memory", "", "journal.oom"),
            ("journal", "connection refused to redis:6379", "shop-api", "journal.conn_refused"),
            ("journal", "dial 10.0.0.5:5432: connect: connection refused", "app", "journal.conn_refused_target"),
            ("journal", "connection refused", "", "journal.connection_refused"),
            ("journal", "no space left on device", "", "journal.disk_full"),
            ("journal", "permission denied opening /var/run/app.sock", "nginx", "journal.permission_denied"),
            ("applog", "production.ERROR: SQLSTATE[HY000] [2002] Connection refused", "laravel.log", "applog.laravel_sqlstate"),
            ("applog", "production.CRITICAL: Allowed memory size of 134217728 bytes exhausted", "laravel.log", "applog.php_memory"),
            ("applog", "production.ERROR: something else", "laravel.log", "applog.error"),
            ("applog", "thread panicked at src/main.rs:10", "laravel.log", "applog.panic"),
            ("resource", "disk /var terpakai 97%", "/var", "resources.disk"),
            ("resource", "memory tersedia 2.0%", "mem", "resources.mem"),
            ("resource", "load 9.00 pada 2 core", "load", "resources.load"),
        ];

        let placeholder = regex::Regex::new(r"<\s*[A-Za-z][^>]*>").unwrap();
        let template_left = regex::Regex::new(
            r"\{\{\s*(unit|path|target|project|proc|host|port|sqlstate|message)\s*\}\}",
        )
        .unwrap();

        for (source, message, unit, expected) in cases {
            let mut f = finding(source, message, unit);
            f.path = "/var/www/app/storage/logs/laravel.log".into();
            let plan = rules.plan_for(&f);
            assert_eq!(plan.rule_id.as_deref(), Some(*expected), "msg={message}");
            let text = std::iter::once(plan.cause.clone())
                .chain(plan.steps.iter().cloned())
                .chain(plan.verify.clone())
                .collect::<Vec<_>>()
                .join("
");
            assert!(!placeholder.is_match(&text), "{expected} masih placeholder:
{text}");
            assert!(!template_left.is_match(&text), "{expected} template belum diganti:
{text}");
        }

        // named capture benar-benar disubstitusi
        let oom = rules.plan_for(&finding(
            "journal",
            "Out of memory: Killed process 42 (shop-api) total-vm:1",
            "kernel",
        ));
        assert!(oom.steps.iter().any(|s| s.contains("shop-api")), "{:?}", oom.steps);

        let conn = rules.plan_for(&finding("journal", "connection refused to redis:6379", "app"));
        assert!(conn.steps.iter().any(|s| s.contains("redis") && s.contains("6379")), "{:?}", conn.steps);

        let sql = rules.plan_for(&finding(
            "applog",
            "production.ERROR: SQLSTATE[HY000] [2002] Connection refused",
            "laravel.log",
        ));
        assert!(sql.cause.contains("SQLSTATE[HY000]"), "{}", sql.cause);

        // path log lengkap dipakai, bukan nama file saja
        let mut f = finding("applog", "production.ERROR: boom", "laravel.log");
        f.path = "/var/www/app/storage/logs/laravel.log".into();
        let plan = rules.plan_for(&f);
        assert!(plan.steps.iter().any(|s| s.contains("/var/www/app/storage/logs/laravel.log")), "{:?}", plan.steps);
    }

    #[test]
    fn groups_across_targets_by_fingerprint() {
        let rules = Rules::from_toml(DEFAULT_PLAYBOOK).unwrap();
        let a = Finding::new("vm1", "shop", "systemd", Severity::Error, "unit failed: nginx.service", "nginx.service", "");
        let mut b = Finding::new("vm2", "shop", "systemd", Severity::Error, "unit failed: nginx.service", "nginx.service", "");
        b.is_new = true;
        let groups = group(&[a, b], &rules);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].targets.len(), 2);
        assert!(groups[0].is_new);
    }

    #[test]
    fn bad_regex_is_reported() {
        let bad = r#"
[[rule]]
id = "x"
match = { source = "journal", message_regex = "(" }
cause = "y"
"#;
        assert!(Rules::from_toml(bad).is_err());
    }
}
