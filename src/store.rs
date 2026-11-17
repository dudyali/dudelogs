use anyhow::{Context, Result};
use rusqlite::{params, Connection as SqlConnection, OptionalExtension};
use std::path::Path;
use std::time::Duration;

use crate::model::Finding;
use crate::ssh::SshTarget;

#[derive(Debug, Clone, Default)]
pub struct Connection {
    pub id: i64,
    pub name: String,
    pub host: String,
    pub user: String,
    pub port: u16,
    pub identity_file: String,
    /// Probe host yang dijalankan untuk VM ini (mis. tanpa docker).
    pub probes: Vec<String>,
    /// "key" (ssh-agent / identity_file / ~/.ssh/config) atau "password".
    pub auth_method: String,
    /// Hanya dipakai untuk auth password. Disimpan di SQLite lokal.
    pub password: String,
}

impl Connection {
    pub fn dest(&self) -> String {
        if self.user.trim().is_empty() {
            self.host.clone()
        } else {
            format!("{}@{}", self.user.trim(), self.host.trim())
        }
    }

    pub fn uses_password(&self) -> bool {
        self.auth_method.eq_ignore_ascii_case("password") && !self.password.is_empty()
    }

    pub fn ssh_target(&self) -> SshTarget {
        let t = SshTarget::new(self.dest(), self.port.max(1), self.identity_file.clone());
        if self.uses_password() {
            t.with_password(self.password.clone())
        } else {
            t
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct Project {
    pub id: i64,
    pub connection_id: i64,
    pub name: String,
    /// Path/glob log di VM ini, satu per baris di UI.
    pub log_paths: Vec<String>,
    /// Perintah read-only tambahan, dijalankan per project.
    pub extra_cmd: String,
}

#[derive(Debug, Clone, Default)]
pub struct ConnTree {
    pub conn: Connection,
    pub projects: Vec<Project>,
}

pub struct Store {
    conn: SqlConnection,
}

impl Store {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let conn = SqlConnection::open(path)
            .with_context(|| format!("gagal buka sqlite {}", path.display()))?;
        // UI dan runner bisa membuka DB bersamaan; migrasi harus serial.
        conn.busy_timeout(Duration::from_secs(5))?;
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;")?;
        conn.execute_batch("BEGIN IMMEDIATE")?;
        let migrated: Result<()> = (|| {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS connections(
               id INTEGER PRIMARY KEY AUTOINCREMENT,
               name TEXT NOT NULL UNIQUE,
               host TEXT NOT NULL,
               user TEXT NOT NULL DEFAULT '',
               port INTEGER NOT NULL DEFAULT 22,
               identity_file TEXT NOT NULL DEFAULT '',
               created_at TEXT NOT NULL
             );
             CREATE TABLE IF NOT EXISTS projects(
               id INTEGER PRIMARY KEY AUTOINCREMENT,
               connection_id INTEGER NOT NULL REFERENCES connections(id) ON DELETE CASCADE,
               name TEXT NOT NULL,
               log_paths TEXT NOT NULL DEFAULT '',
               extra_cmd TEXT NOT NULL DEFAULT '',
               created_at TEXT NOT NULL,
               UNIQUE(connection_id, name)
             );
             CREATE TABLE IF NOT EXISTS runs(
               id INTEGER PRIMARY KEY AUTOINCREMENT,
               started_at TEXT NOT NULL,
               finished_at TEXT,
               status TEXT NOT NULL DEFAULT 'running',
               targets_ok INTEGER NOT NULL DEFAULT 0,
               targets_fail INTEGER NOT NULL DEFAULT 0
             );
             CREATE TABLE IF NOT EXISTS findings(
               fingerprint TEXT NOT NULL,
               target TEXT NOT NULL,
               project TEXT NOT NULL,
               source TEXT NOT NULL,
               severity TEXT NOT NULL,
               message TEXT NOT NULL,
               excerpt TEXT NOT NULL DEFAULT '',
               unit TEXT NOT NULL DEFAULT '',
               event_time TEXT NOT NULL DEFAULT '',
               path TEXT NOT NULL DEFAULT '',
               solved INTEGER NOT NULL DEFAULT 0,
               last_run_id INTEGER NOT NULL DEFAULT 0,
               first_seen TEXT NOT NULL,
               last_seen TEXT NOT NULL,
               occurrences INTEGER NOT NULL DEFAULT 1,
               PRIMARY KEY(fingerprint, target)
             );",
        )?;
        // migrasi DB lama (v1 belum punya kolom auth)
        ensure_column(&conn, "connections", "auth_method", "auth_method TEXT NOT NULL DEFAULT 'key'")?;
        ensure_column(&conn, "connections", "password", "password TEXT NOT NULL DEFAULT ''")?;
        ensure_column(
            &conn,
            "connections",
            "probes",
            "probes TEXT NOT NULL DEFAULT 'systemd,journal,docker,resources'",
        )?;
        // findings lama: history tetap bisa dibuka, dengan nilai default.
        ensure_column(&conn, "findings", "unit", "unit TEXT NOT NULL DEFAULT ''")?;
        ensure_column(&conn, "findings", "event_time", "event_time TEXT NOT NULL DEFAULT ''")?;
        ensure_column(&conn, "findings", "path", "path TEXT NOT NULL DEFAULT ''")?;
        ensure_column(&conn, "findings", "solved", "solved INTEGER NOT NULL DEFAULT 0")?;
        ensure_column(
            &conn,
            "findings",
            "last_run_id",
            "last_run_id INTEGER NOT NULL DEFAULT 0",
        )?;
        Ok(())
        })();
        match migrated {
            Ok(()) => conn.execute_batch("COMMIT")?,
            Err(e) => {
                let _ = conn.execute_batch("ROLLBACK");
                return Err(e);
            }
        }
        harden_permissions(path);
        Ok(Self { conn })
    }

    // ---------- connections ----------

    pub fn connection_tree(&self) -> Result<Vec<ConnTree>> {
        let mut stmt = self.conn.prepare(
            "SELECT id,name,host,user,port,identity_file,auth_method,password,probes
             FROM connections ORDER BY name",
        )?;
        let conns = stmt
            .query_map([], |r| {
                Ok(Connection {
                    id: r.get(0)?,
                    name: r.get(1)?,
                    host: r.get(2)?,
                    user: r.get(3)?,
                    port: r.get::<_, i64>(4)? as u16,
                    identity_file: r.get(5)?,
                    auth_method: r.get(6)?,
                    password: r.get(7)?,
                    probes: split_list(&r.get::<_, String>(8)?),
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;

        let mut out: Vec<ConnTree> = conns
            .into_iter()
            .map(|conn| ConnTree {
                conn,
                projects: Vec::new(),
            })
            .collect();

        let mut stmt = self.conn.prepare(
            "SELECT id,connection_id,name,log_paths,extra_cmd FROM projects ORDER BY name",
        )?;
        let rows = stmt
            .query_map([], |r| {
                Ok(Project {
                    id: r.get(0)?,
                    connection_id: r.get(1)?,
                    name: r.get(2)?,
                    log_paths: split_paths(&r.get::<_, String>(3)?),
                    extra_cmd: r.get(4)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        for p in rows {
            if let Some(tree) = out.iter_mut().find(|t| t.conn.id == p.connection_id) {
                tree.projects.push(p);
            }
        }
        Ok(out)
    }

    pub fn connection_count(&self) -> Result<i64> {
        Ok(self
            .conn
            .query_row("SELECT COUNT(*) FROM connections", [], |r| r.get(0))?)
    }

    pub fn save_connection(&mut self, c: &mut Connection) -> Result<i64> {
        let duplicate: Option<i64> = self
            .conn
            .query_row(
                "SELECT id FROM connections WHERE name=?1 AND id<>?2",
                params![c.name.trim(), c.id],
                |r| r.get(0),
            )
            .optional()?;
        if duplicate.is_some() {
            anyhow::bail!("nama koneksi `{}` sudah dipakai", c.name);
        }
        let auth = if c.auth_method.eq_ignore_ascii_case("password") {
            "password"
        } else {
            "key"
        };
        // password tidak pernah di-trim (spasi bisa bagian dari password)
        let password = if auth == "password" { c.password.clone() } else { String::new() };
        let probes = join_list(&c.probes);
        if c.id > 0 {
            self.conn.execute(
                "UPDATE connections SET name=?2,host=?3,user=?4,port=?5,identity_file=?6,
                 auth_method=?7,password=?8,probes=?9 WHERE id=?1",
                params![
                    c.id,
                    c.name.trim(),
                    c.host.trim(),
                    c.user.trim(),
                    c.port as i64,
                    c.identity_file.trim(),
                    auth,
                    password,
                    probes
                ],
            )?;
        } else {
            self.conn.execute(
                "INSERT INTO connections(name,host,user,port,identity_file,auth_method,password,probes,created_at)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
                params![
                    c.name.trim(),
                    c.host.trim(),
                    c.user.trim(),
                    c.port as i64,
                    c.identity_file.trim(),
                    auth,
                    password,
                    probes,
                    now()
                ],
            )?;
            c.id = self.conn.last_insert_rowid();
        }
        c.auth_method = auth.to_string();
        c.password = password;
        Ok(c.id)
    }

    pub fn delete_connection(&mut self, id: i64) -> Result<()> {
        self.conn
            .execute("DELETE FROM connections WHERE id=?1", params![id])?;
        Ok(())
    }

    // ---------- projects ----------

    pub fn save_project(&mut self, p: &mut Project) -> Result<i64> {
        let duplicate: Option<i64> = self
            .conn
            .query_row(
                "SELECT id FROM projects WHERE connection_id=?1 AND name=?2 AND id<>?3",
                params![p.connection_id, p.name.trim(), p.id],
                |r| r.get(0),
            )
            .optional()?;
        if duplicate.is_some() {
            anyhow::bail!("project `{}` sudah ada di koneksi ini", p.name);
        }
        let paths = p.log_paths.join("\n");
        if p.id > 0 {
            self.conn.execute(
                "UPDATE projects SET name=?2,log_paths=?3,extra_cmd=?4 WHERE id=?1",
                params![p.id, p.name.trim(), paths, p.extra_cmd.trim()],
            )?;
            Ok(p.id)
        } else {
            self.conn.execute(
                "INSERT INTO projects(connection_id,name,log_paths,extra_cmd,created_at)
                 VALUES (?1,?2,?3,?4,?5)",
                params![p.connection_id, p.name.trim(), paths, p.extra_cmd.trim(), now()],
            )?;
            p.id = self.conn.last_insert_rowid();
            Ok(p.id)
        }
    }

    pub fn delete_project(&mut self, id: i64) -> Result<()> {
        self.conn
            .execute("DELETE FROM projects WHERE id=?1", params![id])?;
        Ok(())
    }

    /// Import satu kali dari `[[target]]` lama di dudelogs.toml.
    pub fn seed_from_targets(&mut self, targets: &[crate::config::Target]) -> Result<usize> {
        let mut n = 0;
        for t in targets {
            let (user, host, port) = split_ssh(
                &t.ssh,
                if t.host.is_empty() { "" } else { &t.host },
                &t.user,
                t.port,
            );
            let mut c = Connection {
                name: if t.name.trim().is_empty() {
                    host.clone()
                } else {
                    t.name.trim().to_string()
                },
                host,
                user,
                port: if port == 0 { 22 } else { port },
                identity_file: String::new(),
                probes: t.probes.clone(),
                ..Default::default()
            };
            let cid = self.save_connection(&mut c)?;
            if !t.project.is_empty() || !t.log_globs.is_empty() || !t.extra_probes.is_empty() {
                let mut p = Project {
                    connection_id: cid,
                    name: if t.project.trim().is_empty() {
                        "default".into()
                    } else {
                        t.project.trim().to_string()
                    },
                    log_paths: t.log_globs.clone(),
                    extra_cmd: t
                        .extra_probes
                        .first()
                        .map(|e| e.cmd.clone())
                        .unwrap_or_default(),
                    ..Default::default()
                };
                self.save_project(&mut p)?;
            }
            n += 1;
        }
        Ok(n)
    }

    // ---------- runs & findings ----------

    pub fn begin_run(&mut self, started_at: &str) -> Result<i64> {
        self.conn.execute(
            "INSERT INTO runs(started_at, status) VALUES (?1, 'running')",
            params![started_at],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    pub fn finish_run(
        &mut self,
        run_id: i64,
        status: &str,
        targets_ok: usize,
        targets_fail: usize,
    ) -> Result<()> {
        self.conn.execute(
            "UPDATE runs SET finished_at=?2, status=?3, targets_ok=?4, targets_fail=?5 WHERE id=?1",
            params![run_id, now(), status, targets_ok as i64, targets_fail as i64],
        )?;
        Ok(())
    }

    /// true = temuan ini belum pernah dilihat untuk target tsb (NEW).
    /// Mengisi `occurrences` dan `first_seen` dari riwayat.
    pub fn upsert(&mut self, f: &mut Finding, run_id: i64, now_ts: &str) -> Result<bool> {
        let existing: Option<(i64, String, i64)> = self
            .conn
            .query_row(
                "SELECT occurrences, first_seen, solved FROM findings
                 WHERE fingerprint=?1 AND target=?2",
                params![f.fingerprint, f.target],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;

        match existing {
            None => {
                f.occurrences = 1;
                f.first_seen = now_ts.to_string();
                self.conn.execute(
                    "INSERT INTO findings(fingerprint,target,project,source,severity,message,
                       excerpt,unit,event_time,path,solved,last_run_id,first_seen,last_seen,occurrences)
                     VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,0,?11,?12,?12,1)",
                    params![
                        f.fingerprint, f.target, f.project, f.source, f.severity.as_str(),
                        f.message, f.excerpt, f.unit, f.event_time, f.path, run_id, now_ts
                    ],
                )?;
                f.is_new = true;
                f.solved = false;
                Ok(true)
            }
            Some((occ, first_seen, solved)) => {
                f.occurrences = occ as u32 + 1;
                f.first_seen = first_seen;
                // status solved milik user: sync ulang tidak boleh menghapusnya
                f.solved = solved != 0;
                self.conn.execute(
                    "UPDATE findings SET occurrences=?3, last_seen=?4, severity=?5, message=?6,
                     excerpt=?7, project=?8, unit=?9, event_time=?10, path=?12,
                     last_run_id=?11
                     WHERE fingerprint=?1 AND target=?2",
                    params![
                        f.fingerprint, f.target, f.occurrences as i64, now_ts,
                        f.severity.as_str(), f.message, f.excerpt, f.project, f.unit,
                        f.event_time, run_id, f.path
                    ],
                )?;
                f.is_new = false;
                Ok(false)
            }
        }
    }
}

impl Store {
    /// Temuan dari run terakhir yang tersimpan. Dipakai saat app dibuka supaya hasil
    /// sync terakhir tetap terlihat (termasuk setelah app di-install ulang).
    pub fn load_latest_findings(&self) -> Result<Vec<Finding>> {
        self.query_findings(
            "WHERE last_run_id = (SELECT COALESCE(MAX(id), 0) FROM runs WHERE status='completed')",
        )
    }

    #[cfg(test)]
    pub fn load_all_findings(&self) -> Result<Vec<Finding>> {
        self.query_findings("")
    }

    fn query_findings(&self, filter: &str) -> Result<Vec<Finding>> {
        let mut stmt = self.conn.prepare(&format!(
            "SELECT fingerprint,target,project,source,severity,message,excerpt,unit,
                    event_time,path,solved,first_seen,last_seen,occurrences
             FROM findings {filter}"
        ))?;
        let rows = stmt
            .query_map([], |r| {
                let severity =
                    crate::model::Severity::parse(&r.get::<_, String>(4)?).unwrap_or(crate::model::Severity::Error);
                Ok(Finding {
                    fingerprint: r.get(0)?,
                    target: r.get(1)?,
                    project: r.get(2)?,
                    source: r.get(3)?,
                    severity,
                    message: r.get(5)?,
                    excerpt: r.get(6)?,
                    unit: r.get(7)?,
                    event_time: r.get(8)?,
                    path: r.get(9)?,
                    solved: r.get::<_, i64>(10)? != 0,
                    first_seen: r.get(11)?,
                    last_seen: r.get(12)?,
                    occurrences: r.get::<_, i64>(13)? as u32,
                    is_new: false,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub fn set_solved(&mut self, fingerprint: &str, solved: bool) -> Result<usize> {
        let n = self.conn.execute(
            "UPDATE findings SET solved=?2 WHERE fingerprint=?1",
            params![fingerprint, solved as i64],
        )?;
        Ok(n)
    }
}

pub fn now() -> String {
    chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string()
}

fn ensure_column(conn: &SqlConnection, table: &str, column: &str, ddl: &str) -> Result<()> {
    let exists: i64 = conn.query_row(
        &format!("SELECT COUNT(*) FROM pragma_table_info('{table}') WHERE name=?1"),
        params![column],
        |r| r.get(0),
    )?;
    if exists == 0 {
        conn.execute_batch(&format!("ALTER TABLE {table} ADD COLUMN {ddl}"))?;
    }
    Ok(())
}

/// DB memuat kredensial, jadi batasi akses ke user ini saja.
fn harden_permissions(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
        if let Some(dir) = path.parent() {
            let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
        }
    }
}

fn split_list(text: &str) -> Vec<String> {
    text.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

fn join_list(items: &[String]) -> String {
    items.join(",")
}

fn split_paths(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(str::to_string)
        .collect()
}

/// `user@host:port` / alias ~/.ssh/config → (user, host, port).
pub fn split_ssh(ssh: &str, host: &str, user: &str, port: u16) -> (String, String, u16) {
    let raw = if ssh.trim().is_empty() { host } else { ssh };
    let (user, rest) = match raw.rsplit_once('@') {
        Some((u, h)) => (u.to_string(), h.to_string()),
        None => (user.to_string(), raw.to_string()),
    };
    let (host, port) = match rest.rsplit_once(':') {
        Some((h, p)) if p.parse::<u16>().is_ok() => (h.to_string(), p.parse().unwrap()),
        _ => (rest, port),
    };
    (user.trim().to_string(), host.trim().to_string(), if port == 0 { 22 } else { port })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unique_dir(prefix: &str) -> std::path::PathBuf {
        static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "{prefix}-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn temp_store() -> (Store, std::path::PathBuf) {
        let dir = unique_dir("dudelogs-store");
        (Store::open(&dir.join("state.db")).unwrap(), dir)
    }

    #[test]
    fn crud_and_cascade() {
        let (mut s, dir) = temp_store();
        let mut c = Connection {
            name: "vm1".into(),
            host: "10.0.0.1".into(),
            user: "deploy".into(),
            port: 2222,
            probes: vec!["systemd".into(), "journal".into()],
            ..Default::default()
        };
        let cid = s.save_connection(&mut c).unwrap();
        let mut p = Project {
            connection_id: cid,
            name: "shop".into(),
            log_paths: vec!["/var/log/shop/*.log".into()],
            extra_cmd: String::new(),
            ..Default::default()
        };
        s.save_project(&mut p).unwrap();
        let tree = s.connection_tree().unwrap();
        assert_eq!(tree.len(), 1);
        assert_eq!(tree[0].conn.dest(), "deploy@10.0.0.1");
        assert_eq!(tree[0].projects[0].log_paths, vec!["/var/log/shop/*.log"]);
        // auth password tersimpan dan bertahan setelah reload
        c.auth_method = "password".into();
        c.password = "rahasia sekali".into();
        s.save_connection(&mut c).unwrap();
        let reloaded = s.connection_tree().unwrap();
        assert_eq!(reloaded[0].conn.auth_method, "password");
        assert_eq!(reloaded[0].conn.password, "rahasia sekali");
        assert!(reloaded[0].conn.uses_password());
        assert_eq!(reloaded[0].conn.probes, vec!["systemd", "journal"]);

        // pilih probe per VM: docker bisa dimatikan (VM tanpa docker)
        c.probes = vec!["systemd".into(), "resources".into()];
        s.save_connection(&mut c).unwrap();
        let picked = s.connection_tree().unwrap();
        assert_eq!(picked[0].conn.probes, vec!["systemd", "resources"]);
        assert!(reloaded[0].conn.ssh_target().has_password());
        // pindah ke key = password dibersihkan
        c.auth_method = "key".into();
        s.save_connection(&mut c).unwrap();
        assert_eq!(s.connection_tree().unwrap()[0].conn.password, "");

        assert!(s.delete_project(p.id).is_ok());
        assert!(s.connection_tree().unwrap()[0].projects.is_empty());
        s.delete_connection(cid).unwrap();
        assert_eq!(s.connection_count().unwrap(), 0);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn migrates_old_connections_table() {
        let dir = unique_dir("dudelogs-migrate");
        let db = dir.join("state.db");
        {
            // bentuk tabel versi sebelum fitur auth
            let c = rusqlite::Connection::open(&db).unwrap();
            c.execute_batch(
                "CREATE TABLE connections(
                   id INTEGER PRIMARY KEY AUTOINCREMENT,
                   name TEXT NOT NULL UNIQUE,
                   host TEXT NOT NULL,
                   user TEXT NOT NULL DEFAULT '',
                   port INTEGER NOT NULL DEFAULT 22,
                   identity_file TEXT NOT NULL DEFAULT '',
                   created_at TEXT NOT NULL
                 );
                 INSERT INTO connections(name,host,created_at) VALUES('lama','10.0.0.9','t');",
            )
            .unwrap();
        }
        let s = Store::open(&db).unwrap();
        let tree = s.connection_tree().unwrap();
        assert_eq!(tree[0].conn.name, "lama");
        assert_eq!(tree[0].conn.auth_method, "key");
        assert_eq!(tree[0].conn.password, "");
        assert!(!tree[0].conn.uses_password());
        assert_eq!(
            tree[0].conn.probes,
            vec!["systemd", "journal", "docker", "resources"]
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn findings_history_and_solved_flag() {
        let (mut s, dir) = temp_store();
        let run1 = s.begin_run("2026-11-17 10:00:05 UTC").unwrap();
        let mut f = Finding::new("vm1", "shop", "applog", crate::model::Severity::Error, "boom", "api.log", "boom");
        f.event_time = "2026-11-17 10:00:00".into();
        assert!(s.upsert(&mut f, run1, "2026-11-17 10:00:05 UTC").unwrap());
        s.finish_run(run1, "completed", 1, 0).unwrap();

        let loaded = s.load_latest_findings().unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].event_time, "2026-11-17 10:00:00");
        assert!(!loaded[0].solved);

        assert_eq!(s.set_solved(&f.fingerprint, true).unwrap(), 1);
        assert!(s.load_latest_findings().unwrap()[0].solved);

        // muncul lagi di sync berikutnya -> status solved TETAP
        let run2 = s.begin_run("2026-11-17 11:00:00 UTC").unwrap();
        let mut again = Finding::new("vm1", "shop", "applog", crate::model::Severity::Error, "boom", "api.log", "boom");
        again.event_time = "2026-11-17 10:00:00".into();
        s.upsert(&mut again, run2, "2026-11-17 11:00:00 UTC").unwrap();
        s.finish_run(run2, "completed", 1, 0).unwrap();
        let loaded = s.load_latest_findings().unwrap();
        assert!(loaded[0].solved, "sync ulang tidak boleh menghapus solved");
        assert_eq!(loaded[0].occurrences, 2);

        // temuan yang tidak muncul lagi di run berikutnya tidak ikut tampil
        let run3 = s.begin_run("2026-11-18 09:00:00 UTC").unwrap();
        s.finish_run(run3, "completed", 1, 0).unwrap();
        assert!(s.load_latest_findings().unwrap().is_empty());
        assert_eq!(s.load_all_findings().unwrap().len(), 1);

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn concurrent_open_does_not_race_migrations() {
        let dir = unique_dir("dudelogs-concurrent");
        let db = dir.join("state.db");
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(4));
        let mut handles = Vec::new();
        for _ in 0..4 {
            let db = db.clone();
            let barrier = barrier.clone();
            handles.push(std::thread::spawn(move || {
                barrier.wait();
                Store::open(&db).map(|s| s.connection_count().unwrap())
            }));
        }
        for h in handles {
            assert!(h.join().unwrap().is_ok());
        }
        assert!(Store::open(&db).is_ok());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn duplicate_names_rejected() {
        let (mut s, dir) = temp_store();
        let mut a = Connection { name: "vm".into(), host: "h".into(), ..Default::default() };
        s.save_connection(&mut a).unwrap();
        let mut b = Connection { name: "vm".into(), host: "h2".into(), ..Default::default() };
        assert!(s.save_connection(&mut b).is_err());
        let mut p1 = Project { connection_id: a.id, name: "shop".into(), ..Default::default() };
        s.save_project(&mut p1).unwrap();
        let mut p2 = Project { connection_id: a.id, name: "shop".into(), ..Default::default() };
        assert!(s.save_project(&mut p2).is_err());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn seeds_legacy_targets() {
        let (mut s, dir) = temp_store();
        let targets = vec![crate::config::Target {
            name: "vm-web".into(),
            ssh: "deploy@10.0.0.11:2222".into(),
            project: "shop".into(),
            log_globs: vec!["/var/log/shop/*.log".into()],
            extra_probes: vec![crate::config::ExtraProbe {
                name: "queue".into(),
                cmd: "tail -n 10 /var/log/q.log".into(),
                ..Default::default()
            }],
            ..Default::default()
        }];
        assert_eq!(s.seed_from_targets(&targets).unwrap(), 1);
        let tree = s.connection_tree().unwrap();
        assert_eq!(tree[0].conn.host, "10.0.0.11");
        assert_eq!(tree[0].conn.port, 2222);
        assert_eq!(tree[0].projects[0].extra_cmd, "tail -n 10 /var/log/q.log");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn split_ssh_variants() {
        assert_eq!(split_ssh("deploy@10.0.0.1:2222", "", "", 0), ("deploy".into(), "10.0.0.1".into(), 2222));
        assert_eq!(split_ssh("box", "", "", 0), (String::new(), "box".into(), 22));
        assert_eq!(split_ssh("", "10.0.0.2", "root", 22), ("root".into(), "10.0.0.2".into(), 22));
    }
}
