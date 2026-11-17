use std::path::PathBuf;

use dudelogs::config::{AppConfig, Defaults, Paths};
use dudelogs::playbook::Rules;
use dudelogs::runner;
use dudelogs::store::{Connection, Project, Store};

fn stub_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/stub-ssh")
}

fn setup() -> (PathBuf, AppConfig, Rules) {
    // parallel test: clock bisa sama persis, jadi pakai counter
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let home = std::env::temp_dir().join(format!(
        "dudelogs-e2e-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&home);
    std::fs::create_dir_all(&home).unwrap();

    let mut store = Store::open(&home.join("state.db")).unwrap();
    let mut c = Connection {
        name: "vm1".into(),
        host: "fake".into(),
        user: "deploy".into(),
        port: 22,
        ..Default::default()
    };
    let cid = store.save_connection(&mut c).unwrap();
    store
        .save_project(&mut Project {
            connection_id: cid,
            name: "shop".into(),
            log_paths: vec!["/var/log/shop/*.log".into()],
            ..Default::default()
        })
        .unwrap();
    store
        .save_project(&mut Project {
            connection_id: cid,
            name: "cms".into(),
            log_paths: vec!["/var/log/cms/*.log".into()],
            ..Default::default()
        })
        .unwrap();

    let cfg = AppConfig {
        ssh_bin: stub_path().display().to_string(),
        concurrency: 3,
        probe_timeout_secs: 5,
        defaults: Defaults::default(),
        target: Vec::new(),
    };
    let rules = Rules::load(&home.join("playbook.toml")).unwrap();
    (home, cfg, rules)
}

#[tokio::test(flavor = "multi_thread")]
async fn db_connections_end_to_end_and_new_flags() {
    let (home, cfg, rules) = setup();
    let paths = Paths { home: home.clone() };

    let first = runner::run_selected(&cfg, &rules, &paths, None, |_| {})
        .await
        .unwrap();
    assert_eq!(first.targets.len(), 1);
    assert!(first.targets[0].ok(), "{:?}", first.targets[0]);
    assert!(first.finding_rows >= 9, "rows={}", first.finding_rows);
    assert_eq!(first.new_rows, first.finding_rows, "run pertama semua NEW");

    let nginx = first
        .groups
        .iter()
        .find(|g| g.message.contains("nginx.service"))
        .expect("temuan nginx");
    assert_eq!(nginx.plan.rule_id.as_deref(), Some("systemd.failed"));
    assert_eq!(nginx.pairs, vec![("vm1".to_string(), String::new())]);

    let oom = first
        .groups
        .iter()
        .find(|g| g.message.to_lowercase().contains("out of memory"))
        .expect("temuan oom");
    assert_eq!(oom.plan.rule_id.as_deref(), Some("journal.oom"));

    let laravel = first
        .groups
        .iter()
        .find(|g| g.message.contains("SQLSTATE"))
        .expect("temuan SQLSTATE dari log Laravel");
    assert_eq!(laravel.plan.rule_id.as_deref(), Some("applog.laravel_db"));
    assert_eq!(laravel.severity, dudelogs::model::Severity::Error);
    assert!(laravel.plan.steps.iter().any(|s| s.contains("DB_HOST")));
    assert!(
        !laravel.message.contains("{\"exception\""),
        "konteks JSON tidak boleh masuk kolom pesan: {}",
        laravel.message
    );
    assert!(
        laravel.excerpt.contains("#0 "),
        "stack trace harus tersimpan untuk panel detail"
    );
    assert!(
        !first.groups.iter().any(|g| g.message.contains("#0 ")),
        "baris stack trace tidak boleh jadi temuan sendiri"
    );

    // applog dijalankan per project dan diberi label project yang benar.
    let applog_projects: Vec<&str> = first
        .groups
        .iter()
        .filter(|g| g.source == "applog")
        .flat_map(|g| g.pairs.iter().map(|(_, p)| p.as_str()))
        .collect();
    assert!(applog_projects.contains(&"shop"), "{applog_projects:?}");
    assert!(applog_projects.contains(&"cms"), "{applog_projects:?}");

    let report = std::fs::read_to_string(&first.report_path).unwrap();
    assert!(report.contains("BARU"), "report harus menandai NEW");
    assert!(report.contains("nginx.service"));
    assert!(report.contains("Target (1)"));

    // Run kedua: tidak ada NEW, occurrences bertambah.
    let second = runner::run_selected(&cfg, &rules, &paths, None, |_| {})
        .await
        .unwrap();
    assert_eq!(second.new_rows, 0, "run kedua tidak boleh ada NEW");
    assert!(second.groups.iter().all(|g| g.occurrences >= 2));
    assert_ne!(second.report_path, first.report_path);

    // Filter per project: hanya temuan project itu yang cocok.
    let shop = second
        .groups
        .iter()
        .filter(|g| g.pairs.iter().any(|(c, p)| c == "vm1" && p == "shop"))
        .count();
    assert!(shop > 0);

    let _ = std::fs::remove_dir_all(&home);
}

#[tokio::test]
async fn password_auth_uses_askpass_env_not_batchmode() {
    let ssh = dudelogs::ssh::Ssh::new(
        stub_path().display().to_string(),
        std::time::Duration::from_secs(5),
    );

    let with_pw = dudelogs::ssh::SshTarget::new("fake@host", 22, "").with_password("s3cret");
    let out = ssh.run(&with_pw, "ENVDUMP").await.unwrap();
    assert!(out.stdout.contains("REQUIRE=force"), "{}", out.stdout);
    assert!(out.stdout.contains("ASKPASS=set"), "{}", out.stdout);
    assert!(out.stdout.contains("PW=s3cret"), "{}", out.stdout);
    assert!(!out.stdout.contains("BatchMode=yes"), "{}", out.stdout);

    let with_key = dudelogs::ssh::SshTarget::new("fake@host", 22, "/tmp/id_ed25519");
    let out = ssh.run(&with_key, "ENVDUMP").await.unwrap();
    assert!(out.stdout.contains("REQUIRE=none"), "{}", out.stdout);
    assert!(out.stdout.contains("PW=none"), "{}", out.stdout);
    assert!(out.stdout.contains("BatchMode=yes"), "{}", out.stdout);
    assert!(out.stdout.contains("IdentitiesOnly=yes"), "{}", out.stdout);
}

#[tokio::test(flavor = "multi_thread")]
async fn history_survives_restart_and_solved_stays_after_resync() {
    let (home, cfg, rules) = setup();
    let paths = Paths { home: home.clone() };

    let first = runner::run_selected(&cfg, &rules, &paths, None, |_| {})
        .await
        .unwrap();
    assert!(first.finding_rows > 0);

    // "restart aplikasi": store baru, tanpa run baru
    let mut store = Store::open(&home.join("state.db")).unwrap();
    let history = store.load_latest_findings().unwrap();
    assert_eq!(history.len(), first.finding_rows);
    assert!(history.iter().all(|f| !f.solved));

    let fingerprint = history[0].fingerprint.clone();
    assert_eq!(store.set_solved(&fingerprint, true).unwrap(), 1);
    let solved_row = store
        .load_latest_findings()
        .unwrap()
        .into_iter()
        .find(|f| f.fingerprint == fingerprint)
        .expect("history harus tetap ada setelah ditandai solved");
    assert!(solved_row.solved);

    // sync lagi: solved harus tetap (append, bukan reset)
    drop(store);
    runner::run_selected(&cfg, &rules, &paths, None, |_| {})
        .await
        .unwrap();
    let store = Store::open(&home.join("state.db")).unwrap();
    let after = store.load_latest_findings().unwrap();
    let kept = after
        .iter()
        .find(|f| f.fingerprint == fingerprint)
        .expect("temuan tetap ada setelah sync");
    assert!(kept.solved, "sync ulang tidak boleh menghapus solved");
    assert!(kept.occurrences >= 2);

    let _ = std::fs::remove_dir_all(&home);
}

#[tokio::test(flavor = "multi_thread")]
async fn docker_missing_is_skipped_not_failed() {
    let (home, cfg, rules) = setup();
    let paths = Paths { home: home.clone() };

    let mut store = Store::open(&home.join("state.db")).unwrap();
    let mut c = Connection {
        name: "psb-keu-prod".into(),
        host: "nodocker".into(),
        port: 22,
        ..Default::default()
    };
    store.save_connection(&mut c).unwrap();
    // default probes termasuk docker, seperti koneksi lama
    c.probes = vec!["systemd".into(), "journal".into(), "docker".into(), "resources".into()];
    store.save_connection(&mut c).unwrap();
    drop(store);

    let out = runner::run_selected(&cfg, &rules, &paths, Some(&[c.id]), |_| {})
        .await
        .unwrap();
    let t = &out.targets[0];
    assert!(t.ok(), "docker tidak terpasang bukan kegagalan: {:?}", t);
    assert!(t.errors.is_empty(), "{:?}", t.errors);
    assert!(
        t.notes.iter().any(|n| n.contains("docker") && n.contains("127")),
        "{:?}",
        t.notes
    );
    assert!(
        !out.groups.iter().any(|g| g.source == "docker"),
        "tidak boleh ada temuan docker"
    );

    let _ = std::fs::remove_dir_all(&home);
}

#[tokio::test(flavor = "multi_thread")]
async fn probes_are_per_connection_and_missing_tools_are_skipped() {
    let (home, cfg, rules) = setup();
    let paths = Paths { home: home.clone() };

    let mut store = Store::open(&home.join("state.db")).unwrap();
    let tree = store.connection_tree().unwrap();
    let mut c = tree[0].conn.clone();
    c.probes = vec!["systemd".into()];
    store.save_connection(&mut c).unwrap();
    store
        .save_project(&mut Project {
            connection_id: c.id,
            name: "laravel".into(),
            log_paths: Vec::new(),
            extra_cmd: "notinstalled".into(),
            ..Default::default()
        })
        .unwrap();
    drop(store);

    let out = runner::run_selected(&cfg, &rules, &paths, Some(&[c.id]), |_| {})
        .await
        .unwrap();
    let sources: std::collections::BTreeSet<String> =
        out.groups.iter().map(|g| g.source.clone()).collect();
    assert!(sources.contains("systemd"), "{sources:?}");
    assert!(!sources.contains("docker"), "docker tidak dipilih: {sources:?}");
    assert!(!sources.contains("journal"), "{sources:?}");

    let t = &out.targets[0];
    assert!(t.ok(), "exit 127 bukan kegagalan: {:?}", t);
    assert!(t.errors.is_empty(), "{:?}", t.errors);
    assert!(
        t.notes.iter().any(|n| n.contains("notinstalled")),
        "{:?}",
        t.notes
    );

    let report = std::fs::read_to_string(&out.report_path).unwrap();
    assert!(report.contains("Catatan probe"), "{report}");

    let _ = std::fs::remove_dir_all(&home);
}

#[tokio::test(flavor = "multi_thread")]
async fn all_probes_share_one_control_socket_per_vm() {
    let (home, cfg, rules) = setup();
    let paths = Paths { home: home.clone() };

    let mut store = Store::open(&home.join("state.db")).unwrap();
    let tree = store.connection_tree().unwrap();
    let cid = tree[0].conn.id;
    for name in ["env1", "env2"] {
        store
            .save_project(&mut Project {
                connection_id: cid,
                name: name.into(),
                log_paths: Vec::new(),
                extra_cmd: "ENVDUMP".into(),
                ..Default::default()
            })
            .unwrap();
    }
    // project bawaan hanya path log, biar output fokus ke dua probe ENVDUMP
    for p in tree[0].projects.iter() {
        let mut p = p.clone();
        p.log_paths = Vec::new();
        p.extra_cmd = "ENVDUMP".into();
        store.save_project(&mut p).unwrap();
    }
    drop(store);

    let out = runner::run_selected(&cfg, &rules, &paths, None, |_| {})
        .await
        .unwrap();
    let sockets: Vec<String> = out
        .groups
        .iter()
        .flat_map(|g| g.message.split_whitespace())
        .filter_map(|tok| tok.strip_prefix("ControlPath="))
        .map(str::to_string)
        .collect();
    assert!(sockets.len() >= 2, "harus ada beberapa probe: {sockets:?}");
    assert!(
        sockets.windows(2).all(|w| w[0] == w[1]),
        "semua probe satu VM wajib memakai socket yang sama: {sockets:?}"
    );
    assert!(
        out.groups
            .iter()
            .any(|g| g.message.contains("ControlMaster=auto")),
        "opsi ControlMaster harus diteruskan ke ssh"
    );

    let _ = std::fs::remove_dir_all(&home);
}

#[tokio::test(flavor = "multi_thread")]
async fn runner_passes_stored_password_to_ssh() {
    let (home, cfg, rules) = setup();
    let paths = Paths { home: home.clone() };

    let mut store = Store::open(&home.join("state.db")).unwrap();
    let mut c = Connection {
        name: "pw-vm".into(),
        host: "fake".into(),
        port: 22,
        auth_method: "password".into(),
        password: "s3cret".into(),
        ..Default::default()
    };
    store.save_connection(&mut c).unwrap();
    store
        .save_project(&mut Project {
            connection_id: c.id,
            name: "env".into(),
            log_paths: Vec::new(),
            extra_cmd: "ENVDUMP".into(),
            ..Default::default()
        })
        .unwrap();
    drop(store);

    let out = runner::run_selected(&cfg, &rules, &paths, Some(&[c.id]), |_| {})
        .await
        .unwrap();
    let msg = out
        .groups
        .iter()
        .map(|g| g.message.clone())
        .find(|m| m.contains("REQUIRE=force"))
        .expect("probe extra harus memakai askpass");
    assert!(msg.contains("PW=s3cret"), "{msg}");
    assert!(!msg.contains("BatchMode=yes"), "{msg}");

    let _ = std::fs::remove_dir_all(&home);
}

#[tokio::test(flavor = "multi_thread")]
async fn ssh_transport_failure_is_reported_per_connection() {
    let (home, cfg, rules) = setup();
    let paths = Paths { home: home.clone() };

    let mut store = Store::open(&home.join("state.db")).unwrap();
    let mut bad = Connection {
        name: "matang".into(),
        host: "BOOM".into(),
        port: 22,
        ..Default::default()
    };
    store.save_connection(&mut bad).unwrap();
    drop(store);

    let out = runner::run_selected(&cfg, &rules, &paths, Some(&[bad.id]), |_| {})
        .await
        .unwrap();
    assert_eq!(out.targets.len(), 1);
    let t = &out.targets[0];
    assert_eq!(t.probes_failed, t.probes_total);
    assert_eq!(t.errors.len(), 1, "auth gagal cukup dilaporkan sekali: {:?}", t.errors);
    assert!(t.errors[0].contains("ssh"), "{:?}", t.errors);
    assert_eq!(out.finding_rows, 0);
    assert!(out.groups.is_empty());

    let _ = std::fs::remove_dir_all(&home);
}

#[tokio::test(flavor = "multi_thread")]
async fn custom_project_command_and_readonly_guard() {
    let (home, cfg, rules) = setup();
    let paths = Paths { home: home.clone() };

    let mut store = Store::open(&home.join("state.db")).unwrap();
    let tree = store.connection_tree().unwrap();
    let mut proj = tree[0]
        .projects
        .iter()
        .find(|p| p.name == "shop")
        .unwrap()
        .clone();
    proj.log_paths = Vec::new();
    proj.extra_cmd = "tail -n 200 /var/log/shop/queue.log | grep -iE 'retry exhausted'".into();
    store.save_project(&mut proj).unwrap();
    drop(store);

    let out = runner::run_selected(&cfg, &rules, &paths, None, |_| {})
        .await
        .unwrap();
    let extra = out
        .groups
        .iter()
        .find(|g| g.source == "extra")
        .expect("temuan extra");
    assert!(extra.pairs.iter().any(|(_, p)| p == "shop"));

    let _ = std::fs::remove_dir_all(&home);
}
