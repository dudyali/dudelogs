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
            if let Some(re) = &r.message_regex {
                if !re.is_match(&f.message) {
                    continue;
                }
            }
            return Plan {
                rule_id: Some(r.def.id.clone()),
                cause: render(&r.def.cause, f),
                steps: r.def.steps.iter().map(|s| render(s, f)).collect(),
                verify: r.def.verify.as_deref().map(|s| render(s, f)),
                risk: r.def.risk.clone(),
                confidence: "rule",
            };
        }
        Plan::generic()
    }
}

static TEMPLATE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\{\{\s*(\w+)\s*\}\}").unwrap());

fn render(template: &str, f: &Finding) -> String {
    TEMPLATE
        .replace_all(template, |caps: &regex::Captures| {
            let key = caps[1].to_lowercase();
            match key.as_str() {
                "unit" => {
                    if f.unit.is_empty() { "<unit>".to_string() } else { f.unit.clone() }
                }
                "target" => f.target.clone(),
                "project" => f.project.clone(),
                "message" => f.message.clone(),
                "path" => {
                    if f.unit.is_empty() { "<path>".to_string() } else { f.unit.clone() }
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
    fn laravel_sqlstate_gets_db_rule() {
        let rules = Rules::from_toml(DEFAULT_PLAYBOOK).unwrap();
        let plan = rules.plan_for(&finding(
            "applog",
            "[2026-11-17 10:01:00] production.ERROR: SQLSTATE[HY000] [2002] Connection refused",
            "laravel.log",
        ));
        assert_eq!(plan.rule_id.as_deref(), Some("applog.laravel_db"));
        assert_eq!(plan.confidence, "rule");
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
