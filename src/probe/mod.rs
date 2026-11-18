use anyhow::{bail, Result};

use crate::model::{Finding, ProbeOutcome, Severity};
use crate::ssh::{Ssh, SshTarget};

pub mod applog;
pub mod docker;
pub mod journal;
pub mod resources;
pub mod systemd;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeKind {
    Systemd,
    Journal,
    Docker,
    AppLog,
    Resources,
}

impl ProbeKind {
    pub fn parse(name: &str) -> Result<Self> {
        Ok(match name.trim().to_lowercase().as_str() {
            "systemd" => ProbeKind::Systemd,
            "journal" => ProbeKind::Journal,
            "docker" => ProbeKind::Docker,
            "applog" => ProbeKind::AppLog,
            "resources" => ProbeKind::Resources,
            other => bail!("probe `{other}` tidak dikenal (systemd|journal|docker|applog|resources)"),
        })
    }

    pub fn as_str(self) -> &'static str {
        match self {
            ProbeKind::Systemd => "systemd",
            ProbeKind::Journal => "journal",
            ProbeKind::Docker => "docker",
            ProbeKind::AppLog => "applog",
            ProbeKind::Resources => "resources",
        }
    }

    /// Probe level host. `applog` tidak termasuk: butuh path dari project.
    pub fn is_host_probe(self) -> bool {
        self != ProbeKind::AppLog
    }

    fn command(self, log_paths: &[String]) -> String {
        match self {
            ProbeKind::Systemd => {
                "LC_ALL=C systemctl --failed --no-legend --plain --no-pager".into()
            }
            ProbeKind::Journal => {
                "LC_ALL=C journalctl -p 3 -o json --since '-2 hours' --no-pager -n 500".into()
            }
            ProbeKind::Docker => "LC_ALL=C sh -c 'docker ps -a --filter status=exited \
                 --filter status=dead --format \"{{.Names}}\\t{{.Image}}\\t{{.Status}}\"; \
                 echo ---; docker ps --filter status=restarting \
                 --format \"{{.Names}}\\t{{.Image}}\\t{{.Status}}\"'"
                .into(),
            // Tanpa grep jarak jauh: grouping per record butuh baris stack trace yang
            // tidak match keyword. Filtering dilakukan parser di sisi lokal.
            // Batasi jumlah file (10 terbaru) dan baris (400/file) supaya tidak
            // menembus timeout SSH saat storage/logs berisi ratusan file harian.
            ProbeKind::AppLog => {
                // Path tanpa wildcard = selalu dibaca (mis. error.log).
                // Glob dibatasi 10 file terbaru supaya tidak timeout; -L mengikuti symlink
                // agar urutannya pakai mtime target, bukan mtime symlink lama.
                let (globs, explicit): (Vec<&String>, Vec<&String>) = log_paths
                    .iter()
                    .partition(|p| p.contains(['*', '?', '[']));
                let glob_src = globs
                    .iter()
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>()
                    .join(" ");
                let explicit_suffix = if explicit.is_empty() {
                    String::new()
                } else {
                    format!(
                        " {}",
                        explicit
                            .iter()
                            .map(|s| s.as_str())
                            .collect::<Vec<_>>()
                            .join(" ")
                    )
                };
                format!(
                    "LC_ALL=C sh -c 'C=$(ls -1tL {} 2>/dev/null | head -n 10); \
                     F=\"$C{}\"; [ -z \"$F\" ] && exit 0; \
                     if command -v timeout >/dev/null 2>&1; then \
                       timeout 15 tail -n 400 $F || {{ echo \"applog: timeout 15s (file terlalu banyak/besar)\" >&2; exit 124; }}; \
                     else tail -n 400 $F; fi'",
                    glob_src, explicit_suffix
                )
            }
            ProbeKind::Resources => "LC_ALL=C sh -c 'df -P -x tmpfs -x devtmpfs; echo ---; \
                 cat /proc/meminfo; echo ---; cat /proc/loadinfo 2>/dev/null; \
                 cat /proc/loadavg; nproc'"
                .into(),
        }
    }
}

pub async fn run_host(ssh: &Ssh, target: &SshTarget, conn: &str, probe: &str) -> ProbeOutcome {
    let kind = match ProbeKind::parse(probe) {
        Ok(k) if k.is_host_probe() => k,
        Ok(_) => return failed(probe, "applog harus dijalankan per project".into()),
        Err(e) => return failed(probe, e.to_string()),
    };
    let cmd = kind.command(&[]);
    match ssh.run(target, &cmd).await {
        // exit 127 = binary tidak ada di VM (mis. docker tidak terpasang):
        // probe dilewati, bukan dianggap error.
        Ok(out) if out.code == Some(127) => skipped(kind.as_str(), exit_msg(&out)),
        Ok(out) if out.code != Some(0) => failed(kind.as_str(), exit_msg(&out)),
        Ok(out) => {
            let findings = match kind {
                ProbeKind::Systemd => systemd::parse(conn, "", &out.stdout),
                ProbeKind::Journal => journal::parse(conn, "", &out.stdout),
                ProbeKind::Docker => docker::parse(conn, "", &out.stdout),
                ProbeKind::Resources => resources::parse(conn, "", &out.stdout),
                ProbeKind::AppLog => Vec::new(),
            };
            ProbeOutcome {
                probe: kind.as_str().into(),
                ok: true,
                skipped: false,
                error: None,
                findings,
                raw: out.stdout,
            }
        }
        Err(e) => failed(kind.as_str(), e),
    }
}

pub async fn run_applog(
    ssh: &Ssh,
    target: &SshTarget,
    conn: &str,
    project: &str,
    log_paths: &[String],
) -> ProbeOutcome {
    if log_paths.is_empty() {
        return failed("applog", format!("project {project} belum punya path log"));
    }
    let cmd = ProbeKind::AppLog.command(log_paths);
    match ssh.run(target, &cmd).await {
        Ok(out) if out.code == Some(127) => skipped("applog", exit_msg(&out)),
        Ok(out) if out.code != Some(0) => failed("applog", exit_msg(&out)),
        Ok(out) => ProbeOutcome {
            probe: "applog".into(),
            ok: true,
            skipped: false,
            error: None,
            findings: applog::parse(conn, project, &out.stdout),
            raw: out.stdout,
        },
        Err(e) => {
            if e.contains("timeout") {
                failed(
                    "applog",
                    format!(
                        "{e} - persempit glob (mis. laravel.log saja) atau naikkan probe_timeout_secs"
                    ),
                )
            } else {
                failed("applog", e)
            }
        }
    }
}

pub async fn run_custom(
    ssh: &Ssh,
    target: &SshTarget,
    conn: &str,
    project: &str,
    cmd: &str,
) -> ProbeOutcome {
    match ssh.run(target, cmd).await {
        Ok(out) if out.code == Some(127) => skipped("extra", exit_msg(&out)),
        // grep tanpa match = exit 1 + stdout kosong: bukan kegagalan.
        Ok(out) if out.code != Some(0) && !(out.code == Some(1) && out.stdout.trim().is_empty()) => {
            failed("extra", exit_msg(&out))
        }
        Ok(out) => {
            let mut findings = Vec::new();
            for line in out.stdout.lines() {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                push_unique(
                    &mut findings,
                    Finding::new(conn, project, "extra", Severity::Error, line, project, line),
                );
            }
            ProbeOutcome {
                probe: "extra".into(),
                ok: true,
                skipped: false,
                error: None,
                findings,
                raw: out.stdout,
            }
        }
        Err(e) => failed("extra", e),
    }
}

fn exit_msg(out: &crate::ssh::Output) -> String {
    format!(
        "exit {}: {}",
        out.code
            .map(|c| c.to_string())
            .unwrap_or_else(|| "signal".into()),
        out.stderr.lines().next().unwrap_or("").trim()
    )
}

fn failed(probe: &str, err: String) -> ProbeOutcome {
    ProbeOutcome {
        probe: probe.into(),
        ok: false,
        skipped: false,
        error: Some(err),
        findings: Vec::new(),
        raw: String::new(),
    }
}

fn skipped(probe: &str, note: String) -> ProbeOutcome {
    ProbeOutcome {
        probe: probe.into(),
        ok: true,
        skipped: true,
        error: Some(note),
        findings: Vec::new(),
        raw: String::new(),
    }
}

pub fn split_sections(stdout: &str) -> Vec<Vec<&str>> {
    let mut sections: Vec<Vec<&str>> = vec![Vec::new()];
    for line in stdout.lines() {
        if line.trim() == "---" {
            sections.push(Vec::new());
        } else {
            sections.last_mut().unwrap().push(line);
        }
    }
    sections
}

pub fn push_unique(findings: &mut Vec<Finding>, f: Finding) {
    if !findings.iter().any(|x| x.fingerprint == f.fingerprint) {
        findings.push(f);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sections_split_on_separator() {
        let s = split_sections("a\nb\n---\nc\n---\n");
        assert_eq!(s.len(), 3);
        assert_eq!(s[0], vec!["a", "b"]);
        assert_eq!(s[1], vec!["c"]);
        assert!(s[2].is_empty());
    }

    #[test]
    fn applog_is_not_a_host_probe() {
        assert!(!ProbeKind::AppLog.is_host_probe());
        assert!(ProbeKind::Systemd.is_host_probe());
    }

    #[test]
    fn applog_command_is_bounded_and_always_reads_explicit_paths() {
        let cmd = ProbeKind::AppLog.command(&[
            "/var/www/app/storage/logs/*.log".to_string(),
            "/var/www/app/storage/logs/error.log".to_string(),
        ]);
        assert!(cmd.contains("ls -1tL /var/www/app/storage/logs/*.log"), "{cmd}");
        assert!(cmd.contains("head -n 10"), "{cmd}");
        assert!(cmd.contains("tail -n 400"), "{cmd}");
        assert!(cmd.contains("timeout 15"), "{cmd}");
        // path eksplisit tidak boleh ikut kena `head -n 10`
        let bounded = cmd.split("head -n 10").next().unwrap();
        assert!(!bounded.contains("error.log"), "path eksplisit ikut dibatasi: {cmd}");
        assert!(cmd.contains("/var/www/app/storage/logs/error.log"), "{cmd}");
    }
}
