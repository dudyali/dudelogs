use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

use anyhow::Result;
use tokio::sync::Semaphore;

use crate::config::{AppConfig, Paths};
use crate::model::{Finding, ProbeOutcome, RunOutcome, TargetReport};
use crate::playbook::Rules;
use crate::probe::ProbeKind;
use crate::ssh::{Ssh, SshTarget};
use crate::store::{now, ConnTree, Store};

const RAW_LIMIT: usize = 512 * 1024;

#[derive(Debug, Clone)]
pub enum Event {
    Started { targets: usize, probes: usize },
    TargetStarted { name: String },
    ProbeFinished {
        target: String,
        probe: String,
        ok: bool,
        skipped: bool,
        findings: usize,
        error: Option<String>,
    },
    Progress { done: usize, total: usize },
    Outcome(RunOutcome),
    Failed(String),
}

enum JobKind {
    Host(String),
    Applog(Vec<String>),
    Custom(String),
}

#[derive(Default)]
struct Acc {
    total: usize,
    failed: usize,
    errors: Vec<String>,
    notes: Vec<String>,
    findings: Vec<Finding>,
}

struct Job {
    conn: String,
    project: String,
    /// label untuk raw file & pesan error: `systemd`, `applog[shop]`
    label: String,
    ssh_target: SshTarget,
    kind: JobKind,
}

/// `only` = id koneksi yang disinkronkan; None = semua koneksi di DB.
pub async fn run_selected(
    cfg: &AppConfig,
    rules: &Rules,
    paths: &Paths,
    only: Option<&[i64]>,
    progress: impl Fn(Event),
) -> Result<RunOutcome> {
    paths.ensure()?;
    let mut store = Store::open(&paths.db())?;
    let tree = store.connection_tree()?;
    let selected: Vec<ConnTree> = match only {
        Some(ids) => tree
            .into_iter()
            .filter(|t| ids.contains(&t.conn.id))
            .collect(),
        None => tree,
    };
    if selected.is_empty() {
        anyhow::bail!(
            "belum ada koneksi. Tambah VM di UI, atau isi [[target]] di dudelogs.toml lalu jalankan sekali"
        );
    }

    // Probe host dipilih per koneksi (mis. VM Laravel tanpa docker).
    let probe_plan: BTreeMap<String, Vec<String>> = selected
        .iter()
        .map(|t| (t.conn.name.clone(), host_probes_for(&t.conn, cfg)))
        .collect();

    let started_at = now();
    let run_id = store.begin_run(&started_at)?;
    let ssh = Arc::new(Ssh::new(
        if cfg.ssh_bin.trim().is_empty() {
            std::env::var("DUDELOGS_SSH_BIN").unwrap_or_else(|_| "ssh".into())
        } else {
            cfg.ssh_bin.clone()
        },
        std::time::Duration::from_secs(cfg.probe_timeout_secs.max(1)),
    ));
    let sem = Arc::new(Semaphore::new(cfg.concurrency.max(1)));

    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for t in &selected {
        let mut n = probe_plan[&t.conn.name].len();
        for p in &t.projects {
            if !p.log_paths.is_empty() {
                n += 1;
            }
            if !p.extra_cmd.trim().is_empty() {
                n += 1;
            }
        }
        counts.insert(t.conn.name.clone(), n);
    }
    let total: usize = counts.values().sum();
    progress(Event::Started {
        targets: selected.len(),
        probes: total,
    });

    // Satu sesi SSH per VM: master dibuat sekali, semua probe memakai socket yang sama.
    // Path harus pendek: macOS membatasi socket Unix ~104 byte, dan $TMPDIR di macOS panjang.
    let short_base = if cfg!(unix) {
        std::path::PathBuf::from("/tmp")
    } else {
        std::env::temp_dir()
    };
    let control_dir = short_base.join(format!("ddl-cm-{}-{}", std::process::id(), run_id));
    let control_ready = std::fs::create_dir_all(&control_dir).is_ok();
    #[cfg(unix)]
    if control_ready {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&control_dir, std::fs::Permissions::from_mode(0o700));
    }

    let mut jobs: Vec<Job> = Vec::new();
    let mut warmed: Vec<SshTarget> = Vec::new();
    let mut not_connected: Vec<(String, usize, String)> = Vec::new();

    for t in &selected {
        progress(Event::TargetStarted {
            name: t.conn.name.clone(),
        });
        let mut ssh_target = t.conn.ssh_target();
        let sock = control_dir.join(format!("c{}.sock", t.conn.id));
        if control_ready && sock.as_os_str().len() <= 95 {
            ssh_target = ssh_target.with_control_path(sock.display().to_string());
        }
        if let Err(e) = ssh.warm_up(&ssh_target).await {
            // Auth/transport gagal: jangan ulang percobaan N kali per probe.
            not_connected.push((t.conn.name.clone(), counts[&t.conn.name], e));
            continue;
        }
        if ssh_target.control_path.is_some() {
            warmed.push(ssh_target.clone());
        }
        for probe in &probe_plan[&t.conn.name] {
            jobs.push(Job {
                conn: t.conn.name.clone(),
                project: String::new(),
                label: probe.clone(),
                ssh_target: ssh_target.clone(),
                kind: JobKind::Host(probe.clone()),
            });
        }
        for p in &t.projects {
            if !p.log_paths.is_empty() {
                jobs.push(Job {
                    conn: t.conn.name.clone(),
                    project: p.name.clone(),
                    label: format!("applog[{}]", p.name),
                    ssh_target: ssh_target.clone(),
                    kind: JobKind::Applog(p.log_paths.clone()),
                });
            }
            if !p.extra_cmd.trim().is_empty() {
                jobs.push(Job {
                    conn: t.conn.name.clone(),
                    project: p.name.clone(),
                    label: format!("extra[{}]", p.name),
                    ssh_target: ssh_target.clone(),
                    kind: JobKind::Custom(p.extra_cmd.clone()),
                });
            }
        }
    }

    let total = jobs.len();
    progress(Event::Started {
        targets: selected.len(),
        probes: total,
    });

    let raw_root = paths.raw_dir().join(run_id.to_string());
    let mut handles = Vec::with_capacity(jobs.len());
    for job in jobs {
        let ssh = ssh.clone();
        let sem = sem.clone();
        handles.push(tokio::spawn(async move {
            let _permit = sem.acquire_owned().await.map_err(|e| e.to_string())?;
            let oc = match &job.kind {
                JobKind::Host(p) => crate::probe::run_host(&ssh, &job.ssh_target, &job.conn, p).await,
                JobKind::Applog(paths) => {
                    crate::probe::run_applog(&ssh, &job.ssh_target, &job.conn, &job.project, paths)
                        .await
                }
                JobKind::Custom(cmd) => {
                    crate::probe::run_custom(&ssh, &job.ssh_target, &job.conn, &job.project, cmd)
                        .await
                }
            };
            Ok::<(String, String, ProbeOutcome), String>((job.conn, job.label, oc))
        }));
    }

    let mut per_target: BTreeMap<String, Acc> = selected
        .iter()
        .map(|t| {
            let mut acc = Acc::default();
            acc.total = counts[&t.conn.name];
            (t.conn.name.clone(), acc)
        })
        .collect();

    let mut done = 0usize;
    for (conn, n, err) in not_connected {
        if let Some(entry) = per_target.get_mut(&conn) {
            entry.failed = n;
            entry.errors.push(format!("koneksi: {err}"));
        }
        done += n;
        progress(Event::ProbeFinished {
            target: conn,
            probe: "connect".into(),
            ok: false,
            skipped: false,
            findings: 0,
            error: Some(err),
        });
        progress(Event::Progress { done, total });
    }
    for h in handles {
        let (conn, label, oc) = match h.await {
            Ok(Ok(v)) => v,
            Ok(Err(e)) => {
                progress(Event::Failed(e));
                continue;
            }
            Err(e) => {
                progress(Event::Failed(format!("task probe panik: {e}")));
                continue;
            }
        };
        done += 1;
        if let Some(entry) = per_target.get_mut(&conn) {
            if oc.skipped {
                entry
                    .notes
                    .push(format!("{label}: dilewati ({})", oc.error.clone().unwrap_or_default()));
            } else if oc.ok {
                entry.findings.extend(oc.findings.iter().cloned());
            } else {
                entry.failed += 1;
                if let Some(err) = &oc.error {
                    entry.errors.push(format!("{label}: {err}"));
                }
            }
        }
        if !oc.raw.trim().is_empty() {
            write_raw(&raw_root, &conn, &label, &oc.raw);
        }
        progress(Event::ProbeFinished {
            target: conn,
            probe: label,
            ok: oc.ok,
            skipped: oc.skipped,
            findings: oc.findings.len(),
            error: oc.error,
        });
        progress(Event::Progress { done, total });
    }

    for t in &warmed {
        ssh.close_control(t).await;
    }
    let _ = std::fs::remove_dir_all(&control_dir);

    let mut findings: Vec<Finding> = Vec::new();
    let mut targets: Vec<TargetReport> = Vec::new();
    for t in &selected {
        let acc = per_target.remove(&t.conn.name).unwrap_or_default();
        for mut f in acc.findings {
            store.upsert(&mut f, run_id, &started_at)?;
            findings.push(f);
        }
        targets.push(TargetReport {
            name: t.conn.name.clone(),
            project: t
                .projects
                .iter()
                .map(|p| p.name.clone())
                .collect::<Vec<_>>()
                .join(", "),
            probes_total: acc.total,
            probes_failed: acc.failed,
            errors: acc.errors,
            notes: acc.notes,
        });
    }

    let groups = crate::playbook::group(&findings, rules);
    let new_rows = findings.iter().filter(|f| f.is_new).count();
    let finding_rows = findings.len();

    let mut outcome = RunOutcome {
        run_id,
        started_at,
        finished_at: now(),
        finding_rows,
        new_rows,
        groups,
        targets,
        report_path: std::path::PathBuf::new(),
    };

    let ok_count = outcome.targets.iter().filter(|t| t.ok()).count();
    let fail_count = outcome.targets.len() - ok_count;
    store.finish_run(run_id, "completed", ok_count, fail_count)?;
    outcome.report_path = crate::report::write(&outcome, &paths.reports_dir())?;
    progress(Event::Outcome(outcome.clone()));
    Ok(outcome)
}

fn host_probes_for(conn: &crate::store::Connection, cfg: &AppConfig) -> Vec<String> {
    let raw = if conn.probes.is_empty() {
        &cfg.defaults.probes
    } else {
        &conn.probes
    };
    let mut seen = std::collections::HashSet::new();
    raw.iter()
        .filter_map(|p| ProbeKind::parse(p).ok())
        .filter(|k| k.is_host_probe())
        .map(|k| k.as_str().to_string())
        .filter(|p| seen.insert(p.clone()))
        .collect()
}

fn write_raw(root: &Path, target: &str, probe: &str, raw: &str) {
    let dir = root.join(sanitize(target));
    if std::fs::create_dir_all(&dir).is_err() {
        return;
    }
    let mut body = crate::redact::redact(raw);
    if body.len() > RAW_LIMIT {
        body.truncate(RAW_LIMIT);
    }
    let _ = std::fs::write(dir.join(format!("{}.txt", sanitize(probe))), body);
}

fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_alphanumeric() || c == '-' || c == '_' || c == '.' { c } else { '_' })
        .collect()
}
