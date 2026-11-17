use anyhow::{bail, Context, Result};
use regex::Regex;
use serde::Deserialize;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::ssh::{Ssh, SshTarget};

pub const DEFAULT_PROBES: &[&str] = &["systemd", "journal", "docker", "resources"];

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct AppConfig {
    /// Kosong -> env DUDELOGS_SSH_BIN -> "ssh"
    pub ssh_bin: String,
    pub concurrency: usize,
    pub probe_timeout_secs: u64,
    pub defaults: Defaults,
    pub target: Vec<Target>,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            ssh_bin: String::new(),
            concurrency: 4,
            probe_timeout_secs: 20,
            defaults: Defaults::default(),
            target: Vec::new(),
        }
    }
}

impl AppConfig {
    /// Untuk target legacy dari dudelogs.toml (import awal ke DB).
    pub fn ssh_target(&self, t: &Target, identity_file: &str) -> SshTarget {
        let mut port = t.port;
        let mut host = t.host.clone();
        if host.contains(':') {
            if let Some((h, p)) = host.rsplit_once(':') {
                if let Ok(n) = p.parse::<u16>() {
                    host = h.to_string();
                    if port == 0 {
                        port = n;
                    }
                }
            }
        }
        let dest = if t.user.is_empty() { host } else { format!("{}@{}", t.user, host) };
        SshTarget::new(dest, if port == 0 { 22 } else { port }, identity_file)
    }

    pub fn ssh(&self) -> Ssh {
        let bin = if !self.ssh_bin.trim().is_empty() {
            self.ssh_bin.clone()
        } else {
            std::env::var("DUDELOGS_SSH_BIN").unwrap_or_else(|_| "ssh".into())
        };
        Ssh::new(bin, Duration::from_secs(self.probe_timeout_secs.max(1)))
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct Defaults {
    pub probes: Vec<String>,
    pub log_globs: Vec<String>,
}

impl Default for Defaults {
    fn default() -> Self {
        Self {
            probes: DEFAULT_PROBES.iter().map(|s| s.to_string()).collect(),
            log_globs: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct Target {
    pub name: String,
    /// Legacy: `deploy@10.0.0.11` atau alias `~/.ssh/config`. Dipakai saat import
    /// awal ke SQLite; setelah itu koneksi dikelola di UI/DB.
    pub ssh: String,
    #[serde(default)]
    pub host: String,
    #[serde(default)]
    pub user: String,
    #[serde(default)]
    pub port: u16,
    pub project: String,
    pub tags: Vec<String>,
    pub probes: Vec<String>,
    pub log_globs: Vec<String>,
    pub extra_probes: Vec<ExtraProbe>,
}

impl Target {
    pub fn effective_probes(&self, d: &Defaults) -> Vec<String> {
        let list = if self.probes.is_empty() { &d.probes } else { &self.probes };
        let mut seen = HashSet::new();
        list.iter()
            .filter(|p| seen.insert(p.to_lowercase()))
            .map(|p| p.to_lowercase())
            .collect()
    }

    pub fn effective_log_globs(&self, d: &Defaults) -> Vec<String> {
        if self.log_globs.is_empty() {
            d.log_globs.clone()
        } else {
            self.log_globs.clone()
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct ExtraProbe {
    pub name: String,
    pub cmd: String,
    pub severity: String,
    /// Regex opsional; capture group 1 dipakai sebagai `unit` (dipakai template playbook).
    pub group_regex: Option<String>,
}

/// Perintah hanya boleh membaca. Ditolak saat config dimuat, bukan saat run,
/// supaya salah konfigurasi ketahuan sebelum menyentuh VM.
const BANNED: &[&str] = &[
    "sudo", "su ", "mkfs", "shutdown", "reboot", "poweroff", "dd ", "rm ", "mv ",
    "chmod", "chown", "kill", "systemctl start", "systemctl stop", "systemctl restart",
    "systemctl enable", "systemctl disable", "systemctl mask", "docker rm", "docker stop",
    "docker restart", "docker kill", ">", ";", "&&", "||", "`", "$(",
];

/// Path log masuk ke shell remote tanpa quoting, jadi hanya karakter aman yang
/// diterima (glob boleh, spasi/quote/`;` tidak).
pub fn check_log_path(path: &str) -> Result<()> {
    if path.trim().is_empty() {
        bail!("path log kosong");
    }
    if !path
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '.' | '_' | '-' | '*' | '?' | '[' | ']' | ':' | '@' | '+'))
    {
        bail!("path `{path}` mengandung karakter tidak aman (spasi/quote/simbol shell tidak didukung)");
    }
    Ok(())
}

pub fn check_readonly_command(cmd: &str) -> Result<()> {
    let lower = cmd.to_lowercase();
    for bad in BANNED {
        if lower.contains(bad) {
            bail!("perintah ditolak: mengandung `{bad}` (probe harus read-only)");
        }
    }
    Ok(())
}

impl AppConfig {
    pub fn validate(&self) -> Result<()> {
        if self.concurrency == 0 {
            bail!("concurrency minimal 1");
        }
        let mut names = HashSet::new();
        for t in &self.target {
            if t.name.trim().is_empty() {
                bail!("ada target tanpa `name`");
            }
            if !names.insert(t.name.clone()) {
                bail!("target duplikat: {}", t.name);
            }
            if t.ssh.trim().is_empty() && t.host.trim().is_empty() {
                bail!("target {}: isi `ssh` atau `host`", t.name);
            }
            for g in t.effective_log_globs(&self.defaults) {
                check_log_path(&g).with_context(|| format!("target {}", t.name))?;
            }
            let probes = t.effective_probes(&self.defaults);
            let extras: Vec<String> = t
                .extra_probes
                .iter()
                .map(|e| e.name.to_lowercase())
                .collect();
            for p in &probes {
                if crate::probe::ProbeKind::parse(p).is_err() && !extras.contains(&p.to_lowercase())
                {
                    crate::probe::ProbeKind::parse(p)
                        .with_context(|| format!("target {}", t.name))?;
                }
            }
            if probes.iter().any(|p| p == "applog") && t.effective_log_globs(&self.defaults).is_empty()
            {
                bail!(
                    "target {}: probe `applog` butuh `log_globs` (target atau [defaults])",
                    t.name
                );
            }
            for e in &t.extra_probes {
                if e.name.trim().is_empty() {
                    bail!("target {}: extra_probe tanpa name", t.name);
                }
                check_readonly_command(&e.cmd)
                    .with_context(|| format!("target {}, extra_probe {}", t.name, e.name))?;
                if let Some(r) = &e.group_regex {
                    Regex::new(r)
                        .with_context(|| format!("target {}: group_regex invalid", t.name))?;
                }
                if !e.severity.is_empty() && crate::model::Severity::parse(&e.severity).is_none() {
                    bail!(
                        "target {}: severity `{}` tidak dikenal (info|warning|error|critical)",
                        t.name,
                        e.severity
                    );
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct Paths {
    pub home: PathBuf,
}

impl Paths {
    /// DUDELOGS_HOME dipakai test supaya tidak mengotori direktori user.
    pub fn from_env() -> Self {
        let home = std::env::var_os("DUDELOGS_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".dudelogs")))
            .unwrap_or_else(|| PathBuf::from(".dudelogs"));
        Self { home }
    }

    pub fn db(&self) -> PathBuf {
        self.home.join("state.db")
    }

    pub fn reports_dir(&self) -> PathBuf {
        self.home.join("reports")
    }

    pub fn raw_dir(&self) -> PathBuf {
        self.home.join("raw")
    }

    pub fn playbook_override(&self) -> PathBuf {
        self.home.join("playbook.toml")
    }

    pub fn ensure(&self) -> Result<()> {
        std::fs::create_dir_all(&self.home)?;
        std::fs::create_dir_all(self.reports_dir())?;
        Ok(())
    }
}

/// Cari config: argumen eksplisit, ./dudelogs.toml, lalu ~/.dudelogs/dudelogs.toml.
pub fn load(explicit: Option<&Path>) -> Result<(AppConfig, PathBuf)> {
    let paths = Paths::from_env();
    let candidates = if let Some(p) = explicit {
        vec![p.to_path_buf()]
    } else {
        vec![PathBuf::from("dudelogs.toml"), paths.home.join("dudelogs.toml")]
    };
    if let Some(p) = explicit {
        if !p.exists() {
            bail!("config {} tidak ditemukan", p.display());
        }
    }
    let Some(path) = candidates.iter().find(|p| p.exists()) else {
        // Tanpa file config: pakai default. Koneksi tetap dibaca dari SQLite.
        let cfg = AppConfig::default();
        cfg.validate()?;
        return Ok((cfg, PathBuf::new()));
    };
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("gagal baca {}", path.display()))?;
    let cfg: AppConfig = toml::from_str(&text)
        .with_context(|| format!("toml invalid di {}", path.display()))?;
    cfg.validate()
        .with_context(|| format!("config invalid di {}", path.display()))?;
    Ok((cfg, path.clone()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target() -> Target {
        Target {
            name: "t1".into(),
            ssh: "root@127.0.0.1".into(),
            ..Default::default()
        }
    }

    #[test]
    fn rejects_write_commands() {
        for cmd in ["sudo systemctl restart nginx", "rm -rf /var/log", "cat x > /etc/y", "ls; reboot"] {
            assert!(check_readonly_command(cmd).is_err(), "{cmd}");
        }
        assert!(check_readonly_command("tail -n 50 /var/log/app.log | grep ERROR").is_ok());
        assert!(check_log_path("/var/log/shop/*.log").is_ok());
        assert!(check_log_path("/var/log/app.log; rm -rf /").is_err());
        assert!(check_log_path("/var/log/dengan spasi.log").is_err());
    }

    #[test]
    fn applog_needs_globs() {
        let cfg = AppConfig {
            defaults: Defaults {
                probes: vec!["applog".into()],
                log_globs: vec![],
            },
            target: vec![target()],
            ..Default::default()
        };
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("log_globs"), "{err}");
    }

    #[test]
    fn flags_unknown_probe() {
        let mut t = target();
        t.probes = vec!["sistemd".into()];
        let cfg = AppConfig {
            target: vec![t],
            ..Default::default()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn missing_explicit_config_is_an_error() {
        let err = load(Some(Path::new("/nonexistent/dudelogs.toml"))).unwrap_err();
        assert!(err.to_string().contains("tidak ditemukan"), "{err}");
    }

    #[test]
    fn default_config_is_valid_without_targets() {
        let cfg = AppConfig::default();
        assert!(cfg.validate().is_ok());
        assert_eq!(cfg.concurrency, 4);
        assert!(cfg.target.is_empty());
    }

    #[test]
    fn duplicate_target_rejected() {
        let cfg = AppConfig {
            target: vec![target(), target()],
            ..Default::default()
        };
        assert!(cfg.validate().unwrap_err().to_string().contains("duplikat"));
    }
}
