use anyhow::Result;
use dudelogs::config::{self, Paths};
use dudelogs::playbook::Rules;
use dudelogs::runner;
use dudelogs::store::Store;

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "--help" || a == "-h") {
        print_help();
        return Ok(());
    }
    let explicit = args
        .windows(2)
        .find(|w| w[0] == "--config")
        .map(|w| std::path::PathBuf::from(&w[1]));
    let headless = args.iter().any(|a| a == "--headless");

    let (cfg, cfg_path) = config::load(explicit.as_deref())?;
    let paths = Paths::from_env();
    let rules = Rules::load(&paths.playbook_override())?;

    // Koneksi hidup di SQLite. [[target]] di TOML hanya dipakai untuk import awal.
    let mut store = Store::open(&paths.db())?;
    if store.connection_count()? == 0 && !cfg.target.is_empty() {
        let n = store.seed_from_targets(&cfg.target)?;
        eprintln!(
            "import {n} koneksi dari {} ke {} - selanjutnya kelola di UI",
            cfg_path.display(),
            paths.db().display()
        );
    }

    if headless {
        let rt = tokio::runtime::Runtime::new()?;
        let outcome = rt.block_on(runner::run_selected(&cfg, &rules, &paths, None, |_| {}))?;
        print_summary(&outcome);
        return Ok(());
    }

    dudelogs::ui::start(cfg, cfg_path, rules, paths, store)
}

fn print_summary(o: &dudelogs::model::RunOutcome) {
    let ok = o.targets.iter().filter(|t| t.ok()).count();
    let fail = o.targets.len() - ok;
    println!(
        "run #{} | {} koneksi (ok {}, gagal {}) | {} baris / {} pola | {} baru",
        o.run_id,
        o.targets.len(),
        ok,
        fail,
        o.finding_rows,
        o.groups.len(),
        o.new_rows
    );
    for g in &o.groups {
        println!(
            "[{}] [{}] {}  ({} target{})",
            g.date(),
            g.severity.upper(),
            g.message,
            g.targets.len(),
            if g.is_new { ", BARU" } else { "" }
        );
        println!("        -> {}", g.plan.cause);
    }
    for t in o.targets.iter().filter(|t| !t.ok()) {
        println!("x {}: {}", t.name, t.errors.join(" | "));
    }
    println!("report: {}", o.report_path.display());
}

fn print_help() {
    println!(
        "dudelogs - ambil error dari VM via SSH, hasilkan fix plan

PEMAKAIAN:
  dudelogs                    buka GUI (kelola koneksi + project di sini)
  dudelogs --headless         sync semua koneksi, cetak ringkasan + report
  dudelogs --config <path>    pakai config lain
  dudelogs --help             bantuan ini

CONFIG (knob runtime + import awal):
  ./dudelogs.toml atau ~/.dudelogs/dudelogs.toml (lihat dudelogs.example.toml)
  [[target]] di TOML diimpor sekali ke SQLite saat DB belum punya koneksi.

DB:
  ~/.dudelogs/state.db (DUDELOGS_HOME untuk pindah lokasi)

ENV:
  DUDELOGS_HOME      lokasi state (default ~/.dudelogs)
  DUDELOGS_SSH_BIN   binary ssh pengganti (default: ssh)
"
    );
}
