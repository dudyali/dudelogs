use std::fmt::Write as _;
use std::path::Path;

use crate::model::{FindingGroup, RunOutcome, Severity};

pub fn render_run(o: &RunOutcome) -> String {
    let ok = o.targets.iter().filter(|t| t.ok()).count();
    let fail = o.targets.len() - ok;
    let mut s = String::new();

    let _ = writeln!(s, "# dudelogs report — {}\n", o.started_at);
    let _ = writeln!(
        s,
        "Target: **{}** (ok {}, gagal {}) · temuan: **{}** baris / **{}** pola · baru: **{}**\n",
        o.targets.len(),
        ok,
        fail,
        o.finding_rows,
        o.groups.len(),
        o.new_rows
    );

    let mut counts: Vec<(Severity, usize, usize)> = Vec::new();
    for sev in [Severity::Critical, Severity::Error, Severity::Warning, Severity::Info] {
        let groups: Vec<&FindingGroup> = o.groups.iter().filter(|g| g.severity == sev).collect();
        if groups.is_empty() {
            continue;
        }
        let rows: usize = groups.iter().map(|g| g.targets.len()).sum();
        counts.push((sev, groups.len(), rows));
    }
    if !counts.is_empty() {
        let _ = writeln!(s, "| Severity | Pola | Baris |\n|---|---|---|");
        for (sev, g, r) in counts {
            let _ = writeln!(s, "| {} | {} | {} |", sev.upper(), g, r);
        }
        s.push('\n');
    }

    if o.groups.is_empty() {
        let _ = writeln!(s, "_Tidak ada temuan pada probe yang berhasil dijalankan._\n");
    }

    for g in &o.groups {
        s.push_str(&render_group(g));
        s.push('\n');
    }

    let with_notes: Vec<&crate::model::TargetReport> =
        o.targets.iter().filter(|t| !t.notes.is_empty()).collect();
    if !with_notes.is_empty() {
        let _ = writeln!(s, "## Catatan probe\n");
        for t in with_notes {
            let _ = writeln!(s, "- **{}**: {}", t.name, t.notes.join("; "));
        }
        s.push('\n');
    }

    if fail > 0 {
        let _ = writeln!(s, "## Target bermasalah\n");
        for t in o.targets.iter().filter(|t| !t.ok()) {
            let _ = writeln!(
                s,
                "- **{}** ({}) — {}/{} probe gagal",
                t.name, t.project, t.probes_failed, t.probes_total
            );
            for e in &t.errors {
                let _ = writeln!(s, "  - {}", e.replace('\n', " "));
            }
        }
        s.push('\n');
    }

    let _ = writeln!(
        s,
        "---\nRun #{} · selesai {} · dudelogs",
        o.run_id, o.finished_at
    );
    s
}

pub fn render_group(g: &FindingGroup) -> String {
    let mut s = String::new();
    let _ = writeln!(s, "### [{}] {}\n", g.severity.upper(), g.message);
    let _ = writeln!(
        s,
        "`{}` · source `{}` · pertama {} · {}x{}",
        g.fingerprint,
        g.source,
        if g.first_seen.is_empty() { "-" } else { &g.first_seen },
        g.occurrences,
        if g.is_new { " · **BARU**" } else { "" }
    );
    let _ = writeln!(s, "Target ({}): {}", g.targets.len(), g.targets.join(", "));
    if let Some(rule) = &g.plan.rule_id {
        let _ = writeln!(s, "Rule: `{rule}`");
    }
    if !g.projects.is_empty() {
        let _ = writeln!(s, "Project: {}", g.projects.join(", "));
    }
    s.push('\n');

    let _ = writeln!(s, "**Penyebab dugaan** — {}\n", g.plan.cause);
    let _ = writeln!(s, "**Langkah**");
    for (i, step) in g.plan.steps.iter().enumerate() {
        let _ = writeln!(s, "{}. {}", i + 1, step);
    }
    if let Some(v) = &g.plan.verify {
        let _ = writeln!(s, "\n**Verifikasi** `{}`", v);
    }
    if let Some(r) = &g.plan.risk {
        let _ = writeln!(s, "\n**Risiko/Blast radius** — {}", r);
    }
    if g.plan.confidence == "low" {
        let _ = writeln!(s, "\n> confidence: low (belum ada rule yang cocok)");
    }
    s.push('\n');

    if !g.excerpt.trim().is_empty() {
        let _ = writeln!(
            s,
            "<details><summary>Evidence</summary>\n\n```\n{}\n```\n</details>",
            g.excerpt
        );
    }
    s
}

/// Temuan tanpa fix plan — untuk ditempel ke agent/tool lain.
pub fn render_finding(g: &FindingGroup) -> String {
    let mut s = String::new();
    let _ = writeln!(s, "## [{}] {}\n", g.severity.upper(), g.message);
    let _ = writeln!(s, "- source: `{}`", g.source);
    let _ = writeln!(s, "- fingerprint: `{}`", g.fingerprint);
    let _ = writeln!(
        s,
        "- terlihat: pertama {}{}",
        if g.first_seen.is_empty() { "-" } else { &g.first_seen },
        if g.last_seen.is_empty() {
            String::new()
        } else {
            format!(" | terakhir {}", g.last_seen)
        }
    );
    if !g.event_time.is_empty() {
        let _ = writeln!(s, "- waktu kejadian: {}", g.event_time);
    }
    let _ = writeln!(s, "- occurrences: {}", g.occurrences);
    let _ = writeln!(s, "- target: {}", g.targets.join(", "));
    if !g.projects.is_empty() {
        let _ = writeln!(s, "- project: {}", g.projects.join(", "));
    }
    if !g.path.is_empty() {
        let _ = writeln!(s, "- log: `{}`", g.path);
    }
    if !g.excerpt.trim().is_empty() {
        let _ = writeln!(s, "\n**Evidence**\n\n```\n{}\n```", g.excerpt);
    }
    s
}

pub fn write(o: &RunOutcome, dir: &Path) -> std::io::Result<std::path::PathBuf> {
    std::fs::create_dir_all(dir)?;
    let stamp = o
        .started_at
        .replace([' ', ':'], "-")
        .trim_end_matches("UTC")
        .trim_end_matches('-')
        .to_string();
    let path = dir.join(format!("{stamp}-run{}.md", o.run_id));
    std::fs::write(&path, render_run(o))?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Plan, Severity};
    use std::path::PathBuf;

    fn group() -> FindingGroup {
        FindingGroup {
            fingerprint: "abc123".into(),
            severity: Severity::Error,
            source: "systemd".into(),
            message: "unit failed: nginx.service".into(),
            unit: "nginx.service".into(),
            path: "/var/log/nginx/error.log".into(),
            targets: vec!["vm1".into(), "vm2".into()],
            projects: vec!["shop".into()],
            pairs: vec![("vm1".into(), "shop".into())],
            is_new: true,
            occurrences: 3,
            first_seen: "2026-11-16 21:04:00 UTC".into(),
            last_seen: "2026-11-17 09:00:00 UTC".into(),
            event_time: "2026-11-16 21:04:00".into(),
            reviewed: false,
            excerpt: "nginx.service loaded failed failed".into(),
            plan: Plan {
                rule_id: Some("systemd.failed".into()),
                cause: "unit mati".into(),
                steps: vec!["systemctl status nginx.service -l".into()],
                verify: Some("systemctl is-active nginx.service".into()),
                risk: Some("medium".into()),
                confidence: "rule",
            },
        }
    }

    #[test]
    fn group_markdown_has_plan_and_evidence() {
        let md = render_group(&group());
        assert!(md.contains("[ERROR]"));
        assert!(md.contains("systemctl is-active nginx.service"));
        assert!(md.contains("BARU"));
        assert!(md.contains("<details>"));
        assert!(md.contains("vm1, vm2"));
    }

    #[test]
    fn plain_finding_has_no_fix_plan_but_keeps_evidence() {
        let md = render_finding(&group());
        assert!(md.contains("unit failed: nginx.service"));
        assert!(md.contains("fingerprint"));
        assert!(md.contains("vm1, vm2"));
        assert!(md.contains("nginx.service loaded failed failed"));
        for plan_word in ["Penyebab", "Langkah", "Verifikasi", "Risiko", "systemctl status"] {
            assert!(!md.contains(plan_word), "plan bocor: {plan_word}\n{md}");
        }
    }

    #[test]
    fn run_report_lists_failures() {
        let o = RunOutcome {
            run_id: 1,
            started_at: "2026-11-17 10:00:00 UTC".into(),
            finished_at: "2026-11-17 10:00:05 UTC".into(),
            finding_rows: 1,
            new_rows: 1,
            groups: vec![group()],
            targets: vec![crate::model::TargetReport {
                name: "vm3".into(),
                project: "shop".into(),
                probes_total: 2,
                probes_failed: 1,
                errors: vec!["journal: exit 1: permission denied".into()],
                notes: vec!["docker: dilewati (exit 127: docker: not found)".into()],
            }],
            report_path: PathBuf::new(),
        };
        let md = render_run(&o);
        assert!(md.contains("Target bermasalah"));
        assert!(md.contains("Catatan probe"));
        assert!(md.contains("docker: dilewati"));
        assert!(md.contains("permission denied"));
        assert!(md.contains("| ERROR | 1 | 2 |"));
    }
}
