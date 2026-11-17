use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::time::{Duration, Instant};

use anyhow::Result;
use eframe::egui;

use crate::config::{AppConfig, Paths};
use crate::model::{FindingGroup, RunOutcome, Severity};
use crate::playbook::Rules;
use crate::runner::{self, Event};
use crate::store::{ConnTree, Connection, Project, Store};

#[derive(Clone, PartialEq)]
enum Filter {
    All,
    Conn(String),
    Project { conn: String, project: String },
}

impl Filter {
    fn label(&self) -> String {
        match self {
            Filter::All => "Semua koneksi".into(),
            Filter::Conn(c) => c.clone(),
            Filter::Project { conn, project } => format!("{conn} > {project}"),
        }
    }
}

fn matches_filter(f: &Filter, g: &FindingGroup) -> bool {
    match f {
        Filter::All => true,
        Filter::Conn(c) => g.targets.iter().any(|t| t == c),
        Filter::Project { conn, project } => g
            .pairs
            .iter()
            .any(|(c, p)| c == conn && p == project),
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Live {
    Pending,
    Running,
    Ok,
    Fail,
    Skipped,
}

struct TargetLive {
    state: Live,
    findings: usize,
    error: Option<String>,
    note: Option<String>,
}

#[derive(Clone)]
struct ConnForm {
    id: i64,
    name: String,
    host: String,
    user: String,
    port: String,
    identity_file: String,
    /// "key" atau "password"
    auth_method: String,
    password: String,
    probes: Vec<String>,
    error: Option<String>,
}

#[derive(Clone)]
struct ProjectForm {
    id: i64,
    connection_id: i64,
    conn_name: String,
    name: String,
    log_paths: String,
    extra_cmd: String,
    error: Option<String>,
}

enum Form {
    Conn(ConnForm),
    Project(ProjectForm),
}

#[derive(Clone, Copy)]
enum DeleteKind {
    Conn,
    Project,
}

enum Action {
    NewConn,
    EditConn(Connection),
    DeleteConn(i64, String),
    SyncOne(i64),
    NewProject(i64),
    EditProject(Project),
    DeleteProject(i64, String),
}

pub fn start(
    cfg: AppConfig,
    cfg_path: PathBuf,
    rules: Rules,
    paths: Paths,
    store: Store,
) -> Result<()> {
    let app = DudelogsApp::new(cfg, cfg_path, rules, paths, store);
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1180.0, 760.0])
            .with_min_inner_size([820.0, 520.0]),
        ..Default::default()
    };
    eframe::run_native("dudelogs", options, Box::new(move |_cc| Ok(Box::new(app))))
        .map_err(|e| anyhow::anyhow!("gagal membuka window: {e}"))
}

struct DudelogsApp {
    cfg: AppConfig,
    cfg_path: PathBuf,
    rules: Rules,
    paths: Paths,
    store: Store,
    conns: Vec<ConnTree>,
    filter: Filter,
    form: Option<Form>,
    pending_delete: Option<(DeleteKind, i64, String)>,
    tx: Sender<Event>,
    rx: Receiver<Event>,
    ctx: Option<egui::Context>,
    running: bool,
    done: usize,
    total: usize,
    live: BTreeMap<String, TargetLive>,
    outcome: Option<RunOutcome>,
    groups: Vec<FindingGroup>,
    /// fingerprint yang sedang dicentang (multi-select)
    selection: Vec<String>,
    /// fingerprint yang ditampilkan di panel detail
    active: Option<String>,
    new_only: bool,
    hide_solved: bool,
    /// None = urut severity (bawaan), Some(true) = tanggal terbaru dulu.
    date_sort: Option<bool>,
    min_severity: Severity,
    status: String,
    copy_flash: Option<Instant>,
}

impl DudelogsApp {
    fn new(
        cfg: AppConfig,
        cfg_path: PathBuf,
        rules: Rules,
        paths: Paths,
        store: Store,
    ) -> Self {
        let (tx, rx) = channel();
        let conns = store.connection_tree().unwrap_or_default();
        let mut live = BTreeMap::new();
        for c in &conns {
            live.insert(
                c.conn.name.clone(),
                TargetLive {
                    state: Live::Pending,
                    findings: 0,
                    error: None,
                    note: None,
                },
            );
        }
        let mut app = Self {
            status: format!(
                "{} koneksi | {} rule playbook",
                conns.len(),
                rules.rule_count()
            ),
            cfg,
            cfg_path,
            rules,
            paths,
            store,
            conns,
            filter: Filter::All,
            form: None,
            pending_delete: None,
            tx,
            rx,
            ctx: None,
            running: false,
            done: 0,
            total: 0,
            live,
            outcome: None,
            groups: Vec::new(),
            selection: Vec::new(),
            active: None,
            new_only: false,
            hide_solved: false,
            date_sort: None,
            min_severity: Severity::Info,
            copy_flash: None,
        };
        app.reload_history();
        app
    }

    /// Tampilkan temuan yang sudah tersimpan di SQLite (bertahan walau app ditutup
    /// atau di-install ulang). Dipakai saat start dan setelah menandai solved.
    fn reload_history(&mut self) {
        match self.store.load_latest_findings() {
            Ok(findings) => {
                self.groups = crate::playbook::group(&findings, &self.rules);
                let present: std::collections::HashSet<String> =
                    self.groups.iter().map(|g| g.fingerprint.clone()).collect();
                self.selection.retain(|fp| present.contains(fp));
                if self.active.as_ref().is_some_and(|a| !present.contains(a)) {
                    self.active = None;
                }
                if self.active.is_none() {
                    self.active = self
                        .selection
                        .last()
                        .cloned()
                        .or_else(|| self.groups.first().map(|g| g.fingerprint.clone()));
                }
                if self.selection.is_empty() {
                    if let Some(a) = &self.active {
                        self.selection.push(a.clone());
                    }
                }
                if !self.groups.is_empty() {
                    self.status = format!("{} pola tersimpan di history", self.groups.len());
                }
            }
            Err(e) => self.status = format!("gagal baca history: {e}"),
        }
    }

    fn reload_conns(&mut self) {
        match self.store.connection_tree() {
            Ok(tree) => {
                self.conns = tree;
                self.live
                    .retain(|name, _| self.conns.iter().any(|c| &c.conn.name == name));
                for c in &self.conns {
                    self.live.entry(c.conn.name.clone()).or_insert(TargetLive {
                        state: Live::Pending,
                        findings: 0,
                        error: None,
                        note: None,
                    });
                }
                let stale = match &self.filter {
                    Filter::All => false,
                    Filter::Conn(n) => !self.conns.iter().any(|c| &c.conn.name == n),
                    Filter::Project { conn, project } => !self.conns.iter().any(|c| {
                        &c.conn.name == conn && c.projects.iter().any(|p| &p.name == project)
                    }),
                };
                if stale {
                    self.filter = Filter::All;
                }
            }
            Err(e) => self.status = format!("gagal baca DB: {e}"),
        }
    }

    fn start_run(&mut self, only: Option<Vec<i64>>) {
        if self.running {
            return;
        }
        let Some(ctx) = self.ctx.clone() else {
            self.status = "window belum siap".into();
            return;
        };
        self.running = true;
        self.done = 0;
        self.total = 0;
        self.status = "menghubungi VM...".into();
        self.groups.clear();
        self.outcome = None;
        self.selection.clear();
        self.active = None;

        let picked: Vec<String> = self
            .conns
            .iter()
            .filter(|c| only.as_ref().map(|ids| ids.contains(&c.conn.id)).unwrap_or(true))
            .map(|c| c.conn.name.clone())
            .collect();
        for (name, live) in self.live.iter_mut() {
            *live = TargetLive {
                state: if picked.contains(name) {
                    Live::Pending
                } else {
                    Live::Skipped
                },
                findings: 0,
                error: None,
                note: None,
            };
        }

        let cfg = self.cfg.clone();
        let rules = self.rules.clone();
        let paths = self.paths.clone();
        let tx = self.tx.clone();
        std::thread::spawn(move || {
            let rt = match tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    let _ = tx.send(Event::Failed(format!("runtime: {e}")));
                    return;
                }
            };
            let ptx = tx.clone();
            let pctx = ctx.clone();
            let progress = move |ev: Event| {
                let _ = ptx.send(ev);
                pctx.request_repaint();
            };
            let ids = only.as_deref();
            if let Err(e) = rt.block_on(runner::run_selected(&cfg, &rules, &paths, ids, progress)) {
                let _ = tx.send(Event::Failed(e.to_string()));
            }
            ctx.request_repaint();
        });
    }

    fn drain_events(&mut self) {
        while let Ok(ev) = self.rx.try_recv() {
            match ev {
                Event::Started { targets, probes } => {
                    self.total = probes;
                    self.done = 0;
                    self.status = format!("{targets} koneksi | {probes} probe");
                    self.groups.clear();
                    self.selection.clear();
                    self.active = None;
                }
                Event::TargetStarted { name } => {
                    if let Some(l) = self.live.get_mut(&name) {
                        l.state = Live::Running;
                    }
                    self.status = format!("menjalankan {name}...");
                }
                Event::ProbeFinished {
                    target,
                    probe,
                    ok,
                    skipped,
                    findings,
                    error,
                } => {
                    if let Some(l) = self.live.get_mut(&target) {
                        if skipped {
                            l.note = Some(format!(
                                "{probe}: dilewati ({})",
                                error.unwrap_or_default()
                            ));
                        } else if ok {
                            if l.state != Live::Fail {
                                l.state = Live::Ok;
                            }
                            l.findings += findings;
                        } else {
                            l.state = Live::Fail;
                            l.error = Some(format!(
                                "{probe}: {}",
                                error.unwrap_or_default().replace('\n', " ")
                            ));
                        }
                    }
                }
                Event::Progress { done, total } => {
                    self.done = done;
                    self.total = total;
                }
                Event::Outcome(o) => {
                    self.running = false;
                    let status = format!(
                        "selesai | {} baris, {} baru | {}",
                        o.finding_rows,
                        o.new_rows,
                        o.report_path.display()
                    );
                    self.outcome = Some(o);
                    self.reload_history();
                    self.status = status;
                }
                Event::Failed(e) => {
                    self.running = false;
                    self.status = format!("gagal: {e}");
                }
            }
        }
    }

    fn top_bar(&mut self, ctx: &egui::Context) {
        let mut sync_all = false;
        egui::TopBottomPanel::top("top").show(ctx, |ui| {
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                ui.heading("dudelogs");
                ui.label(egui::RichText::new("error -> fix plan").weak().small());
                ui.separator();
                if ui
                    .add_enabled(!self.running, egui::Button::new("Sync all"))
                    .clicked()
                {
                    sync_all = true;
                }
                if self.running {
                    let frac = if self.total == 0 {
                        0.0
                    } else {
                        self.done as f32 / self.total as f32
                    };
                    ui.add(
                        egui::ProgressBar::new(frac)
                            .desired_width(160.0)
                            .show_percentage(),
                    );
                }
                ui.separator();
                ui.label(egui::RichText::new(&self.status).small());
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let cfg_label = if self.cfg_path.as_os_str().is_empty() {
                        "config: default".to_string()
                    } else {
                        self.cfg_path.display().to_string()
                    };
                    ui.label(egui::RichText::new(cfg_label).weak().small());
                });
            });
            ui.add_space(4.0);
        });
        if sync_all {
            self.start_run(None);
        }
    }

    fn left_panel(&mut self, ctx: &egui::Context) {
        let mut action: Option<Action> = None;
        let mut new_filter: Option<Filter> = None;

        egui::SidePanel::left("targets")
            .resizable(true)
            .default_width(270.0)
            .min_width(210.0)
            .show(ctx, |ui| {
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("Koneksi").strong());
                    if ui.small_button("+ VM").on_hover_text("tambah koneksi SSH").clicked() {
                        action = Some(Action::NewConn);
                    }
                });
                ui.separator();
                egui::ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        if ui
                            .selectable_label(matches!(self.filter, Filter::All), "Semua temuan")
                            .clicked()
                        {
                            new_filter = Some(Filter::All);
                        }
                        for tree in &self.conns {
                            ui.add_space(6.0);
                            ui.horizontal(|ui| {
                                let selected = matches!(&self.filter, Filter::Conn(n) if n == &tree.conn.name);
                                if ui
                                    .selectable_label(selected, egui::RichText::new(&tree.conn.name).strong())
                                    .clicked()
                                {
                                    new_filter = Some(Filter::Conn(tree.conn.name.clone()));
                                }
                                if let Some(l) = self.live.get(&tree.conn.name) {
                                    let (icon, color) = match l.state {
                                        Live::Pending => ("o", egui::Color32::GRAY),
                                        Live::Running => ("...", egui::Color32::LIGHT_BLUE),
                                        Live::Ok => ("ok", egui::Color32::from_rgb(110, 190, 120)),
                                        Live::Fail => ("x", Severity::Error.color()),
                                        Live::Skipped => ("-", egui::Color32::DARK_GRAY),
                                    };
                                    ui.colored_label(color, icon);
                                    if l.findings > 0 {
                                        ui.label(
                                            egui::RichText::new(format!("{}", l.findings))
                                                .small()
                                                .color(Severity::Warning.color()),
                                        );
                                    }
                                }
                                if ui.small_button("sync").on_hover_text("sync VM ini").clicked() {
                                    action = Some(Action::SyncOne(tree.conn.id));
                                }
                                if ui.small_button("edit").on_hover_text("edit koneksi").clicked() {
                                    action = Some(Action::EditConn(tree.conn.clone()));
                                }
                                if ui.small_button("del").on_hover_text("hapus koneksi").clicked() {
                                    action = Some(Action::DeleteConn(
                                        tree.conn.id,
                                        tree.conn.name.clone(),
                                    ));
                                }
                            });
                            ui.label(
                                egui::RichText::new(format!(
                                    "{}  {}",
                                    tree.conn.dest(),
                                    if tree.conn.port == 22 {
                                        String::new()
                                    } else {
                                        format!(":{}", tree.conn.port)
                                    }
                                ))
                                .weak()
                                .small(),
                            );
                            if let Some(l) = self.live.get(&tree.conn.name) {
                                if let Some(err) = &l.error {
                                    ui.label(
                                        egui::RichText::new(short(err, 70))
                                            .small()
                                            .color(Severity::Error.color()),
                                    );
                                }
                                if let Some(note) = &l.note {
                                    ui.label(egui::RichText::new(short(note, 70)).small().weak());
                                }
                            }
                            for p in &tree.projects {
                                ui.horizontal(|ui| {
                                    ui.add_space(10.0);
                                    let selected = matches!(
                                        &self.filter,
                                        Filter::Project { conn, project }
                                            if conn == &tree.conn.name && project == &p.name
                                    );
                                    if ui
                                        .selectable_label(selected, format!("> {}", p.name))
                                        .clicked()
                                    {
                                        new_filter = Some(Filter::Project {
                                            conn: tree.conn.name.clone(),
                                            project: p.name.clone(),
                                        });
                                    }
                                    if ui.small_button("edit").on_hover_text("edit project").clicked() {
                                        action = Some(Action::EditProject(p.clone()));
                                    }
                                    if ui.small_button("del").on_hover_text("hapus project").clicked() {
                                        action = Some(Action::DeleteProject(
                                            p.id,
                                            format!("project {} ({})", p.name, tree.conn.name),
                                        ));
                                    }
                                });
                            }
                            ui.horizontal(|ui| {
                                ui.add_space(10.0);
                                if ui.small_button("+ project").clicked() {
                                    action = Some(Action::NewProject(tree.conn.id));
                                }
                            });
                        }
                        if self.conns.is_empty() {
                            ui.add_space(12.0);
                            ui.label(
                                egui::RichText::new(
                                    "Belum ada koneksi.\nKlik + VM untuk menambah host SSH.",
                                )
                                .weak()
                                .small(),
                            );
                        }
                    });
            });

        if let Some(f) = new_filter {
            self.filter = f;
        }
        match action {
            Some(Action::NewConn) => {
                self.form = Some(Form::Conn(ConnForm {
                    id: 0,
                    name: String::new(),
                    host: String::new(),
                    user: String::new(),
                    port: "22".into(),
                    identity_file: String::new(),
                    auth_method: "key".into(),
                    password: String::new(),
                    probes: default_probes(),
                    error: None,
                }));
            }
            Some(Action::EditConn(c)) => {
                self.form = Some(Form::Conn(ConnForm {
                    id: c.id,
                    name: c.name,
                    host: c.host,
                    user: c.user,
                    port: c.port.to_string(),
                    identity_file: c.identity_file,
                    auth_method: if c.auth_method.eq_ignore_ascii_case("password") {
                        "password".into()
                    } else {
                        "key".into()
                    },
                    password: c.password,
                    probes: if c.probes.is_empty() { default_probes() } else { c.probes },
                    error: None,
                }));
            }
            Some(Action::DeleteConn(id, name)) => {
                self.pending_delete = Some((DeleteKind::Conn, id, name));
            }
            Some(Action::SyncOne(id)) => self.start_run(Some(vec![id])),
            Some(Action::NewProject(conn_id)) => {
                let conn_name = self
                    .conns
                    .iter()
                    .find(|c| c.conn.id == conn_id)
                    .map(|c| c.conn.name.clone())
                    .unwrap_or_default();
                self.form = Some(Form::Project(ProjectForm {
                    id: 0,
                    connection_id: conn_id,
                    conn_name,
                    name: String::new(),
                    log_paths: String::new(),
                    extra_cmd: String::new(),
                    error: None,
                }));
            }
            Some(Action::EditProject(p)) => {
                let conn_name = self
                    .conns
                    .iter()
                    .find(|c| c.conn.id == p.connection_id)
                    .map(|c| c.conn.name.clone())
                    .unwrap_or_default();
                self.form = Some(Form::Project(ProjectForm {
                    id: p.id,
                    connection_id: p.connection_id,
                    conn_name,
                    name: p.name,
                    log_paths: p.log_paths.join("\n"),
                    extra_cmd: p.extra_cmd,
                    error: None,
                }));
            }
            Some(Action::DeleteProject(id, name)) => {
                self.pending_delete = Some((DeleteKind::Project, id, name));
            }
            None => {}
        }
    }

    fn draw_forms(&mut self, ctx: &egui::Context) {
        // konfirmasi hapus
        if let Some((kind, id, name)) = self.pending_delete.clone() {
            let mut confirm = false;
            let mut cancel = false;
            egui::Window::new("Hapus?")
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .show(ctx, |ui| {
                    ui.label(format!("Hapus {name}?"));
                    if matches!(kind, DeleteKind::Conn) {
                        ui.label(
                            egui::RichText::new(
                                "Semua project di koneksi ini ikut terhapus. History findings tetap tersimpan.",
                            )
                            .small()
                            .weak(),
                        );
                    }
                    ui.add_space(6.0);
                    ui.horizontal(|ui| {
                        if ui.button("Ya, hapus").clicked() {
                            confirm = true;
                        }
                        if ui.button("Batal").clicked() {
                            cancel = true;
                        }
                    });
                });
            if confirm {
                let res = match kind {
                    DeleteKind::Conn => self.store.delete_connection(id),
                    DeleteKind::Project => self.store.delete_project(id),
                };
                match res {
                    Ok(()) => {
                        self.status = format!("{name} dihapus");
                        self.reload_conns();
                    }
                    Err(e) => self.status = format!("gagal hapus: {e}"),
                }
                self.pending_delete = None;
            } else if cancel {
                self.pending_delete = None;
            }
        }

        let Some(form) = self.form.take() else { return };
        match form {
            Form::Conn(mut f) => {
                let mut save = false;
                let mut cancel = false;
                egui::Window::new(if f.id == 0 { "Tambah VM" } else { "Edit VM" })
                    .collapsible(false)
                    .resizable(false)
                    .show(ctx, |ui| {
                        egui::Grid::new("conn-form")
                            .num_columns(2)
                            .spacing([8.0, 6.0])
                            .show(ui, |ui| {
                                ui.label("Nama");
                                ui.text_edit_singleline(&mut f.name);
                                ui.end_row();
                                ui.label("Host / IP");
                                ui.text_edit_singleline(&mut f.host);
                                ui.end_row();
                                ui.label("User");
                                ui.text_edit_singleline(&mut f.user);
                                ui.end_row();
                                ui.label("Port");
                                ui.text_edit_singleline(&mut f.port);
                                ui.end_row();
                                ui.label("Probe host");
                                ui.horizontal_wrapped(|ui| {
                                    for name in ["systemd", "journal", "docker", "resources"] {
                                        let mut on = f.probes.iter().any(|p| p == name);
                                        if ui.checkbox(&mut on, name).changed() {
                                            toggle_probe(&mut f.probes, name, on);
                                        }
                                    }
                                });
                                ui.end_row();
                                ui.label("Auth");
                                ui.horizontal(|ui| {
                                    ui.radio_value(&mut f.auth_method, "key".to_string(), "SSH key / agent");
                                    ui.radio_value(&mut f.auth_method, "password".to_string(), "Password");
                                });
                                ui.end_row();
                                if f.auth_method == "password" {
                                    ui.label("Password");
                                    ui.add(
                                        egui::TextEdit::singleline(&mut f.password)
                                            .password(true)
                                            .desired_width(220.0),
                                    );
                                    ui.end_row();
                                } else {
                                    ui.label("Identity file");
                                    ui.text_edit_singleline(&mut f.identity_file);
                                    ui.end_row();
                                }
                            });
                        ui.label(
                            egui::RichText::new(if f.auth_method == "password" {
                                "Password disimpan di state.db lokal (plaintext, permission 0600). Pakai SSH key bila memungkinkan."
                            } else {
                                "Kosong = ikut ~/.ssh/config dan ssh-agent. Identity file opsional."
                            })
                            .small()
                            .weak(),
                        );
                        if let Some(e) = &f.error {
                            ui.colored_label(Severity::Error.color(), e);
                        }
                        ui.add_space(4.0);
                        ui.horizontal(|ui| {
                            if ui.button("Simpan").clicked() {
                                save = true;
                            }
                            if ui.button("Batal").clicked() {
                                cancel = true;
                            }
                        });
                    });
                if cancel {
                    return;
                }
                if save {
                    match validate_conn(&f) {
                        Ok(input) => {
                            let mut c = Connection {
                                id: f.id,
                                name: input.name,
                                host: input.host,
                                user: input.user,
                                port: input.port,
                                identity_file: input.identity_file,
                                auth_method: input.auth_method,
                                password: input.password,
                                probes: input.probes,
                            };
                            match self.store.save_connection(&mut c) {
                                Ok(_) => {
                                    self.reload_conns();
                                    self.status = format!("koneksi {} disimpan", c.name);
                                    return;
                                }
                                Err(e) => f.error = Some(e.to_string()),
                            }
                        }
                        Err(e) => f.error = Some(e),
                    }
                }
                self.form = Some(Form::Conn(f));
            }
            Form::Project(mut f) => {
                let mut save = false;
                let mut cancel = false;
                egui::Window::new(format!("Project: {}", f.conn_name))
                    .collapsible(false)
                    .resizable(true)
                    .default_width(520.0)
                    .show(ctx, |ui| {
                        egui::Grid::new("project-form")
                            .num_columns(2)
                            .spacing([8.0, 6.0])
                            .show(ui, |ui| {
                                ui.label("Nama project");
                                ui.text_edit_singleline(&mut f.name);
                                ui.end_row();
                                ui.label("Path log");
                                ui.add(
                                    egui::TextEdit::multiline(&mut f.log_paths)
                                        .desired_rows(3)
                                        .desired_width(340.0)
                                        .hint_text("/var/log/shop/*.log"),
                                );
                                ui.end_row();
                                ui.label("Perintah tambahan");
                                ui.add(
                                    egui::TextEdit::multiline(&mut f.extra_cmd)
                                        .desired_rows(2)
                                        .desired_width(340.0)
                                        .hint_text("opsional, read-only: tail -n 200 /var/log/shop/queue.log | grep ERROR"),
                                );
                                ui.end_row();
                            });
                        ui.label(
                            egui::RichText::new(
                                "Satu path per baris (Laravel: /var/www/<app>/storage/logs/laravel.log). Karakter aman: huruf, angka, / . _ - * ? [ ] : @ +",
                            )
                            .small()
                            .weak(),
                        );
                        if let Some(e) = &f.error {
                            ui.colored_label(Severity::Error.color(), e);
                        }
                        ui.add_space(4.0);
                        ui.horizontal(|ui| {
                            if ui.button("Simpan").clicked() {
                                save = true;
                            }
                            if ui.button("Batal").clicked() {
                                cancel = true;
                            }
                        });
                    });
                if cancel {
                    return;
                }
                if save {
                    match validate_project(&f) {
                        Ok((name, paths, extra)) => {
                            let mut p = Project {
                                id: f.id,
                                connection_id: f.connection_id,
                                name,
                                log_paths: paths,
                                extra_cmd: extra,
                            };
                            match self.store.save_project(&mut p) {
                                Ok(_) => {
                                    self.reload_conns();
                                    self.status = format!("project {} disimpan", p.name);
                                    return;
                                }
                                Err(e) => f.error = Some(e.to_string()),
                            }
                        }
                        Err(e) => f.error = Some(e),
                    }
                }
                self.form = Some(Form::Project(f));
            }
        }
    }

    fn detail_panel(&mut self, ctx: &egui::Context) {
        let flash = self
            .copy_flash
            .map(|t| t.elapsed() < Duration::from_secs(2))
            .unwrap_or(false);
        let mut copied = false;
        let mut toggle_solved: Option<(String, bool)> = None;

        egui::SidePanel::right("detail")
            .resizable(true)
            .default_width(440.0)
            .min_width(260.0)
            .show(ctx, |ui| {
                egui::ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        let Some(g) = self
                            .active
                            .as_ref()
                            .and_then(|fp| self.groups.iter().find(|g| &g.fingerprint == fp))
                        else {
                            ui.add_space(16.0);
                            ui.label(egui::RichText::new("Pilih temuan di kiri.").weak());
                            return;
                        };

                        ui.add_space(6.0);
                        ui.label(
                            egui::RichText::new(format!("[{}]", g.severity.upper()))
                                .strong()
                                .color(g.severity.color()),
                        );
                        ui.label(egui::RichText::new(&g.message).strong());
                        if g.solved {
                            ui.label(
                                egui::RichText::new("SOLVED — ditandai selesai")
                                    .small()
                                    .color(egui::Color32::from_rgb(110, 190, 120)),
                            );
                        }
                        ui.label(
                            egui::RichText::new(format!(
                                "{} | {} | {}x | pertama {}{}",
                                g.fingerprint,
                                g.source,
                                g.occurrences,
                                g.first_seen,
                                if g.last_seen.is_empty() {
                                    String::new()
                                } else {
                                    format!(" | terakhir {}", g.last_seen)
                                }
                            ))
                            .weak()
                            .small(),
                        );
                        if !g.event_time.is_empty() {
                            ui.label(
                                egui::RichText::new(format!("kejadian {}", g.event_time))
                                    .small()
                                    .weak(),
                            );
                        }
                        ui.horizontal_wrapped(|ui| {
                            for (c, p) in &g.pairs {
                                let label = if p.is_empty() {
                                    c.clone()
                                } else {
                                    format!("{c} > {p}")
                                };
                                ui.label(egui::RichText::new(label).small().monospace());
                            }
                        });
                        ui.separator();

                        ui.label(egui::RichText::new("Penyebab dugaan").strong());
                        ui.label(&g.plan.cause);
                        ui.add_space(6.0);
                        ui.label(egui::RichText::new("Langkah").strong());
                        for (i, step) in g.plan.steps.iter().enumerate() {
                            ui.label(format!("{}. {}", i + 1, step));
                        }
                        if let Some(v) = &g.plan.verify {
                            ui.add_space(6.0);
                            ui.label(egui::RichText::new("Verifikasi").strong());
                            ui.monospace(v);
                        }
                        if let Some(r) = &g.plan.risk {
                            ui.add_space(4.0);
                            ui.label(egui::RichText::new(r).small().weak());
                        }
                        ui.label(
                            egui::RichText::new(match &g.plan.rule_id {
                                Some(id) => format!("rule: {id}"),
                                None => "rule: generic".to_string(),
                            })
                            .small()
                            .weak(),
                        );
                        if g.plan.confidence == "low" {
                            ui.label(
                                egui::RichText::new("confidence rendah: belum ada rule yang cocok")
                                    .small()
                                    .color(Severity::Warning.color()),
                            );
                        }
                        ui.add_space(8.0);
                        ui.horizontal(|ui| {
                            let solve_label = if g.solved {
                                "Buka lagi"
                            } else {
                                "Tandai solved"
                            };
                            if ui.button(solve_label).clicked() {
                                toggle_solved = Some((g.fingerprint.clone(), !g.solved));
                            }
                            if ui.button("Copy markdown").clicked() {
                                ui.ctx().copy_text(crate::report::render_group(g));
                                copied = true;
                            }
                            if flash {
                                ui.label(
                                    egui::RichText::new("tersalin")
                                        .small()
                                        .color(egui::Color32::from_rgb(110, 190, 120)),
                                );
                            }
                        });
                        ui.separator();
                        ui.label(egui::RichText::new("Evidence").strong());
                        if g.excerpt.trim().is_empty() {
                            ui.label(egui::RichText::new("(kosong)").weak().small());
                        } else {
                            ui.label(egui::RichText::new(&g.excerpt).monospace().small());
                        }
                    });
            });

        if copied {
            self.copy_flash = Some(Instant::now());
        }
        if let Some((fingerprint, solved)) = toggle_solved {
            match self.store.set_solved(&fingerprint, solved) {
                Ok(n) => {
                    self.reload_history();
                    self.status = format!(
                        "{n} temuan ditandai {}",
                        if solved { "solved" } else { "belum selesai" }
                    );
                }
                Err(e) => self.status = format!("gagal update solved: {e}"),
            }
        }
    }

    fn bottom_panel(&mut self, ctx: &egui::Context) {
        let mut copied_path: Option<String> = None;
        egui::TopBottomPanel::bottom("bottom").show(ctx, |ui| {
            ui.add_space(2.0);
            ui.horizontal(|ui| {
                let ok = self.live.values().filter(|l| l.state == Live::Ok).count();
                let fail = self.live.values().filter(|l| l.state == Live::Fail).count();
                ui.label(egui::RichText::new(format!("koneksi ok {ok} | gagal {fail}")).small());
                if let Some(o) = &self.outcome {
                    ui.separator();
                    ui.label(
                        egui::RichText::new(format!("report: {}", o.report_path.display()))
                            .small()
                            .weak(),
                    );
                    if ui.small_button("copy path").clicked() {
                        copied_path = Some(o.report_path.display().to_string());
                    }
                }
            });
            for tree in &self.conns {
                if let Some(l) = self.live.get(&tree.conn.name) {
                    if let Some(e) = &l.error {
                        ui.label(
                            egui::RichText::new(format!("x {}: {}", tree.conn.name, short(e, 140)))
                                .small()
                                .color(Severity::Error.color()),
                        );
                    }
                }
            }
            ui.add_space(2.0);
        });
        if let Some(p) = copied_path {
            ctx.copy_text(p);
        }
    }

    fn central(&mut self, ctx: &egui::Context) {
        let filter_new = self.new_only;
        let hide_solved = self.hide_solved;
        let min_sev = self.min_severity;
        let filter = self.filter.clone();
        let mut clicked: Option<(String, bool)> = None;
        let mut select_all = false;
        let mut bulk_solve = false;
        let mut clear_selection = false;

        let mut project_options: Vec<(Filter, String)> =
            vec![(Filter::All, "Semua project".to_string())];
        for tree in &self.conns {
            for p in &tree.projects {
                project_options.push((
                    Filter::Project {
                        conn: tree.conn.name.clone(),
                        project: p.name.clone(),
                    },
                    format!("{} > {}", tree.conn.name, p.name),
                ));
            }
        }
        let order = ordered_indices(&self.groups, self.date_sort);

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new(filter.label()).strong());
                ui.label(
                    egui::RichText::new(format!("| {} pola", self.groups.len()))
                        .small()
                        .weak(),
                );
                ui.separator();
                ui.checkbox(&mut self.new_only, "baru saja");
                ui.checkbox(&mut self.hide_solved, "sembunyikan solved");
                egui::ComboBox::from_id_salt("project-filter")
                    .selected_text(match &filter {
                        Filter::All => "Semua project".to_string(),
                        Filter::Conn(c) => c.clone(),
                        Filter::Project { conn, project } => format!("{conn} > {project}"),
                    })
                    .show_ui(ui, |ui| {
                        for (value, label) in &project_options {
                            ui.selectable_value(&mut self.filter, value.clone(), label);
                        }
                    });
                let sort_label = match self.date_sort {
                    None => "urut: severity",
                    Some(true) => "tanggal: terbaru",
                    Some(false) => "tanggal: terlama",
                };
                if ui
                    .button(sort_label)
                    .on_hover_text("klik untuk ganti urutan")
                    .clicked()
                {
                    self.date_sort = match self.date_sort {
                        None => Some(true),
                        Some(true) => Some(false),
                        Some(false) => None,
                    };
                }
                if ui
                    .small_button("pilih semua")
                    .on_hover_text("pilih semua baris yang terlihat")
                    .clicked()
                {
                    select_all = true;
                }
                if !self.selection.is_empty() {
                    ui.separator();
                    ui.label(
                        egui::RichText::new(format!("{} dipilih", self.selection.len())).small(),
                    );
                    if ui.button("Tandai solved").clicked() {
                        bulk_solve = true;
                    }
                    if ui.small_button("batal").clicked() {
                        clear_selection = true;
                    }
                }
                egui::ComboBox::from_id_salt("sev-filter")
                    .selected_text(format!(">= {}", min_sev.as_str()))
                    .show_ui(ui, |ui| {
                        for sev in [
                            Severity::Info,
                            Severity::Warning,
                            Severity::Error,
                            Severity::Critical,
                        ] {
                            ui.selectable_value(&mut self.min_severity, sev, sev.as_str());
                        }
                    });
            });
            ui.separator();
            ui.label(
                egui::RichText::new(format!(
                    "{:<15} {:<8} {:<9} {}",
                    "TANGGAL", "SEV", "SOURCE", "PESAN"
                ))
                .monospace()
                .small()
                .weak(),
            );

            egui::ScrollArea::vertical()
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    if self.groups.is_empty() {
                        ui.add_space(24.0);
                        ui.label(
                            egui::RichText::new(if self.running {
                                "Menjalankan probe..."
                            } else {
                                "Belum ada hasil. Klik Sync all atau tombol sync di salah satu VM."
                            })
                            .weak(),
                        );
                        return;
                    }
                    let mut shown = 0usize;
                    for &i in &order {
                        let g = &self.groups[i];
                        if !matches_filter(&filter, g) {
                            continue;
                        }
                        if filter_new && !g.is_new {
                            continue;
                        }
                        if hide_solved && g.solved {
                            continue;
                        }
                        if g.severity < min_sev {
                            continue;
                        }
                        shown += 1;
                        let selected =
                            self.selection.iter().any(|fp| fp == &g.fingerprint);
                        let tag = if g.solved {
                            "SOLVED"
                        } else if g.is_new {
                            "NEW"
                        } else {
                            ""
                        };
                        let text = format!(
                            "{:<15} {:<8} {:<9} {:<38} {:>2}t {:>6}",
                            short_date(g.date()),
                            g.severity.as_str(),
                            g.source,
                            short(&g.message, 38),
                            g.pairs.len(),
                            tag
                        );
                        let color = if selected {
                            egui::Color32::from_rgb(230, 230, 230)
                        } else if g.solved {
                            egui::Color32::GRAY
                        } else {
                            g.severity.color()
                        };
                        let rich = egui::RichText::new(text).monospace().color(color);
                        let multi = ui.input(|i| {
                            i.modifiers.command || i.modifiers.ctrl || i.modifiers.shift
                        });
                        if ui
                            .selectable_label(selected, rich)
                            .on_hover_text(format!(
                                "{}\nklik = pilih, cmd/ctrl/shift+klik = tambah pilihan",
                                g.message
                            ))
                            .clicked()
                        {
                            clicked = Some((g.fingerprint.clone(), multi));
                        }
                    }
                    if shown == 0 {
                        ui.add_space(16.0);
                        ui.label(
                            egui::RichText::new("Tidak ada temuan yang cocok dengan filter ini.")
                                .weak(),
                        );
                    }
                });
        });

        if select_all {
            self.selection = self
                .groups
                .iter()
                .filter(|g| {
                    matches_filter(&filter, g)
                        && (!filter_new || g.is_new)
                        && !(hide_solved && g.solved)
                        && g.severity >= min_sev
                })
                .map(|g| g.fingerprint.clone())
                .collect();
            self.active = self.selection.last().cloned();
        }
        if clear_selection {
            self.selection.clear();
            self.active = None;
        }
        if bulk_solve {
            let fps = self.selection.clone();
            let mut n = 0usize;
            for fp in &fps {
                if let Ok(k) = self.store.set_solved(fp, true) {
                    n += k;
                }
            }
            self.reload_history();
            self.status = format!("{n} temuan ditandai solved");
        }
        if let Some((fp, multi)) = clicked {
            if multi {
                toggle_selection(&mut self.selection, &fp);
            } else {
                self.selection = vec![fp.clone()];
            }
            self.active = self.selection.last().cloned().or(Some(fp));
        }
    }
}

impl eframe::App for DudelogsApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if self.ctx.is_none() {
            self.ctx = Some(ctx.clone());
        }
        self.drain_events();
        self.top_bar(ctx);
        self.left_panel(ctx);
        self.detail_panel(ctx);
        self.bottom_panel(ctx);
        self.central(ctx);
        self.draw_forms(ctx);
        if self.running {
            ctx.request_repaint_after(Duration::from_millis(150));
        }
    }
}

struct ConnInput {
    name: String,
    host: String,
    user: String,
    port: u16,
    identity_file: String,
    auth_method: String,
    password: String,
    probes: Vec<String>,
}

fn validate_conn(f: &ConnForm) -> Result<ConnInput, String> {
    if f.name.trim().is_empty() {
        return Err("nama koneksi wajib diisi".into());
    }
    if f.host.trim().is_empty() {
        return Err("host/IP wajib diisi".into());
    }
    let port: u16 = f
        .port
        .trim()
        .parse()
        .map_err(|_| "port harus angka 1-65535".to_string())?;
    if port == 0 {
        return Err("port harus angka 1-65535".into());
    }
    let auth_method = if f.auth_method.eq_ignore_ascii_case("password") {
        if f.password.is_empty() {
            return Err("password wajib diisi untuk auth password".into());
        }
        "password".to_string()
    } else {
        "key".to_string()
    };
    let probes = normalize_probes(&f.probes);
    if probes.is_empty() {
        return Err("pilih minimal satu probe host".into());
    }
    Ok(ConnInput {
        name: f.name.trim().to_string(),
        host: f.host.trim().to_string(),
        user: f.user.trim().to_string(),
        port,
        identity_file: f.identity_file.trim().to_string(),
        auth_method,
        password: f.password.clone(),
        probes,
    })
}

fn validate_project(f: &ProjectForm) -> Result<(String, Vec<String>, String), String> {
    if f.name.trim().is_empty() {
        return Err("nama project wajib diisi".into());
    }
    let paths: Vec<String> = f
        .log_paths
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(str::to_string)
        .collect();
    for p in &paths {
        crate::config::check_log_path(p).map_err(|e| e.to_string())?;
    }
    let extra = f.extra_cmd.trim().to_string();
    if extra.is_empty() && paths.is_empty() {
        return Err("isi minimal satu path log atau satu perintah tambahan".into());
    }
    if !extra.is_empty() {
        crate::config::check_readonly_command(&extra).map_err(|e| e.to_string())?;
    }
    Ok((f.name.trim().to_string(), paths, extra))
}

fn default_probes() -> Vec<String> {
    ["systemd", "journal", "docker", "resources"]
        .iter()
        .map(|s| s.to_string())
        .collect()
}

fn toggle_probe(probes: &mut Vec<String>, name: &str, on: bool) {
    let has = probes.iter().any(|p| p == name);
    if on && !has {
        probes.push(name.to_string());
    } else if !on && has {
        probes.retain(|p| p != name);
    }
}

fn normalize_probes(probes: &[String]) -> Vec<String> {
    ["systemd", "journal", "docker", "resources"]
        .iter()
        .filter(|n| probes.iter().any(|p| p == *n))
        .map(|s| s.to_string())
        .collect()
}

fn toggle_selection(selection: &mut Vec<String>, fingerprint: &str) {
    if let Some(pos) = selection.iter().position(|fp| fp == fingerprint) {
        selection.remove(pos);
    } else {
        selection.push(fingerprint.to_string());
    }
}

fn short_date(s: &str) -> String {
    if s.chars().count() >= 16 {
        s.chars().skip(5).take(11).collect()
    } else {
        s.to_string()
    }
}

fn ordered_indices(groups: &[FindingGroup], sort: Option<bool>) -> Vec<usize> {
    let mut idx: Vec<usize> = (0..groups.len()).collect();
    if let Some(desc) = sort {
        idx.sort_by(|&a, &b| {
            let ord = groups[a].date().cmp(groups[b].date());
            if desc {
                ord.reverse()
            } else {
                ord
            }
        });
    }
    idx
}

fn short(s: &str, max: usize) -> String {
    let one_line: String = s.split_whitespace().collect::<Vec<_>>().join(" ");
    if one_line.chars().count() <= max {
        one_line
    } else {
        format!("{}...", one_line.chars().take(max).collect::<String>())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Plan, Severity};

    fn group(pairs: &[(&str, &str)]) -> FindingGroup {
        FindingGroup {
            fingerprint: "f".into(),
            severity: Severity::Error,
            source: "applog".into(),
            message: "boom".into(),
            unit: "api.log".into(),
            path: "/var/www/app/storage/logs/laravel.log".into(),
            targets: pairs.iter().map(|(c, _)| c.to_string()).collect(),
            projects: pairs
                .iter()
                .filter(|(_, p)| !p.is_empty())
                .map(|(_, p)| p.to_string())
                .collect(),
            pairs: pairs
                .iter()
                .map(|(c, p)| (c.to_string(), p.to_string()))
                .collect(),
            is_new: false,
            occurrences: 1,
            first_seen: String::new(),
            last_seen: String::new(),
            event_time: String::new(),
            solved: false,
            excerpt: String::new(),
            plan: Plan::generic(),
        }
    }

    #[test]
    fn filter_matches_connection_and_project() {
        let g = group(&[("vm1", "shop"), ("vm2", "shop")]);
        assert!(matches_filter(&Filter::All, &g));
        assert!(matches_filter(&Filter::Conn("vm1".into()), &g));
        assert!(!matches_filter(&Filter::Conn("vm9".into()), &g));
        assert!(matches_filter(
            &Filter::Project { conn: "vm2".into(), project: "shop".into() },
            &g
        ));
        assert!(!matches_filter(
            &Filter::Project { conn: "vm2".into(), project: "cms".into() },
            &g
        ));

        // temuan host-level (project "") tidak masuk filter project
        let host = group(&[("vm1", "")]);
        assert!(matches_filter(&Filter::Conn("vm1".into()), &host));
        assert!(!matches_filter(
            &Filter::Project { conn: "vm1".into(), project: "shop".into() },
            &host
        ));
    }

    fn conn_form() -> ConnForm {
        ConnForm {
            id: 0,
            name: "vm1".into(),
            host: "10.0.0.1".into(),
            user: "deploy".into(),
            port: "2222".into(),
            identity_file: String::new(),
            auth_method: "key".into(),
            password: String::new(),
            probes: default_probes(),
            error: None,
        }
    }

    #[test]
    fn conn_validation_rejects_missing_fields() {
        assert!(validate_conn(&conn_form()).is_ok());
        let mut f = conn_form();
        f.host = "  ".into();
        assert!(validate_conn(&f).is_err());
        let mut f = conn_form();
        f.port = "0".into();
        assert!(validate_conn(&f).is_err());
        let mut f = conn_form();
        f.port = "abc".into();
        assert!(validate_conn(&f).is_err());

        // auth password tanpa password ditolak, dengan password diterima
        let mut f = conn_form();
        f.auth_method = "password".into();
        assert!(validate_conn(&f).is_err());
        f.password = "rahasia".into();
        let input = validate_conn(&f).unwrap();
        assert_eq!(input.auth_method, "password");
        assert_eq!(input.password, "rahasia");
    }

    #[test]
    fn multi_select_toggles_fingerprints() {
        let mut sel: Vec<String> = Vec::new();
        toggle_selection(&mut sel, "a");
        toggle_selection(&mut sel, "b");
        assert_eq!(sel, vec!["a", "b"]);
        toggle_selection(&mut sel, "a");
        assert_eq!(sel, vec!["b"]);
    }

    #[test]
    fn sort_by_date_uses_event_time_then_first_seen() {
        let mut a = group(&[("vm1", "shop")]);
        a.event_time = "2026-11-16 10:00:00".into();
        let mut b = group(&[("vm1", "shop")]);
        b.event_time = "2026-11-17 10:00:00".into();
        let mut c = group(&[("vm1", "shop")]);
        c.first_seen = "2026-11-01 00:00:00".into();
        let groups = vec![a, b, c];

        assert_eq!(ordered_indices(&groups, Some(true)), vec![1, 0, 2]);
        assert_eq!(ordered_indices(&groups, Some(false)), vec![2, 0, 1]);
        assert_eq!(ordered_indices(&groups, None), vec![0, 1, 2]);
        assert_eq!(short_date("2026-11-17 10:01:00"), "11-17 10:01");
    }

    #[test]
    fn probe_selection_is_persisted_in_canonical_order() {
        let mut f = conn_form();
        assert_eq!(validate_conn(&f).unwrap().probes, default_probes());

        toggle_probe(&mut f.probes, "docker", false);
        let probes = validate_conn(&f).unwrap().probes;
        assert_eq!(probes, vec!["systemd", "journal", "resources"]);

        for name in ["systemd", "journal", "resources"] {
            toggle_probe(&mut f.probes, name, false);
        }
        assert!(validate_conn(&f).is_err(), "tanpa probe host harus ditolak");
    }

    fn project_form() -> ProjectForm {
        ProjectForm {
            id: 0,
            connection_id: 1,
            conn_name: "vm1".into(),
            name: "shop".into(),
            log_paths: "/var/log/shop/*.log\n/var/log/nginx/error.log".into(),
            extra_cmd: String::new(),
            error: None,
        }
    }

    #[test]
    fn project_validation_accepts_paths_or_command() {
        let (name, paths, extra) = validate_project(&project_form()).unwrap();
        assert_eq!(name, "shop");
        assert_eq!(paths.len(), 2);
        assert!(extra.is_empty());

        let mut f = project_form();
        f.log_paths = String::new();
        f.extra_cmd = "tail -n 100 /var/log/shop/q.log | grep ERROR".into();
        assert!(validate_project(&f).is_ok());

        let mut f = project_form();
        f.log_paths = String::new();
        assert!(validate_project(&f).is_err(), "project tanpa isi harus ditolak");

        let mut f = project_form();
        f.log_paths = "/var/log/x.log; rm -rf /".into();
        assert!(validate_project(&f).is_err());

        let mut f = project_form();
        f.extra_cmd = "sudo systemctl restart nginx".into();
        assert!(validate_project(&f).is_err());
    }
}
