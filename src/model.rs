use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
pub enum Severity {
    Info,
    Warning,
    Error,
    Critical,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Warning => "warning",
            Severity::Error => "error",
            Severity::Critical => "critical",
        }
    }

    pub fn upper(self) -> String {
        self.as_str().to_uppercase()
    }

    pub fn color(self) -> egui::Color32 {
        match self {
            Severity::Info => egui::Color32::from_rgb(120, 144, 168),
            Severity::Warning => egui::Color32::from_rgb(222, 165, 59),
            Severity::Error => egui::Color32::from_rgb(232, 100, 82),
            Severity::Critical => egui::Color32::from_rgb(255, 74, 138),
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_lowercase().as_str() {
            "info" => Some(Severity::Info),
            "warning" | "warn" => Some(Severity::Warning),
            "error" | "err" => Some(Severity::Error),
            "critical" | "crit" => Some(Severity::Critical),
            _ => None,
        }
    }

    /// syslog priority: 0 emerg .. 7 debug
    pub fn from_journal_priority(p: &str) -> Self {
        match p.trim() {
            "0" | "1" | "2" => Severity::Critical,
            "3" => Severity::Error,
            "4" => Severity::Warning,
            _ => Severity::Info,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Finding {
    pub fingerprint: String,
    pub target: String,
    pub project: String,
    pub source: String,
    pub severity: Severity,
    pub message: String,
    pub unit: String,
    /// Path file log asli (untuk template fix plan). Kosong bila bukan applog.
    pub path: String,
    pub excerpt: String,
    pub occurrences: u32,
    pub first_seen: String,
    pub last_seen: String,
    /// Waktu dari log/event itu sendiri (kosong bila sumber tidak menyediakan).
    pub event_time: String,
    /// Ditandai selesai oleh user; sync berikutnya membuka lagi bila masih muncul.
    pub reviewed: bool,
    pub is_new: bool,
}

impl Finding {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        target: &str,
        project: &str,
        source: &str,
        severity: Severity,
        message: impl Into<String>,
        unit: impl Into<String>,
        excerpt: impl Into<String>,
    ) -> Self {
        let source = source.to_string();
        let unit = unit.into();
        let message: String = crate::redact::redact(&message.into());
        let message = truncate(&message, 320);
        let excerpt = truncate(&crate::redact::redact(&excerpt.into()), 4000);
        Self {
            fingerprint: crate::normalize::fingerprint(&source, project, &unit, &message),
            target: target.to_string(),
            project: project.to_string(),
            source,
            severity,
            message,
            unit,
            path: String::new(),
            excerpt,
            occurrences: 1,
            first_seen: String::new(),
            last_seen: String::new(),
            event_time: String::new(),
            reviewed: false,
            is_new: false,
        }
    }

    pub fn with_event_time(mut self, event_time: impl Into<String>) -> Self {
        self.event_time = event_time.into();
        self
    }

    pub fn with_path(mut self, path: impl Into<String>) -> Self {
        self.path = path.into();
        self
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let mut out: String = s.chars().take(max).collect();
    out.push('…');
    out
}

#[derive(Debug, Clone)]
pub struct Plan {
    pub rule_id: Option<String>,
    pub cause: String,
    pub steps: Vec<String>,
    pub verify: Option<String>,
    pub risk: Option<String>,
    pub confidence: &'static str,
}

impl Plan {
    pub fn generic() -> Self {
        Self {
            rule_id: None,
            cause: "Belum ada pola yang cocok di playbook. Perlu triage manual.".into(),
            steps: vec![
                "baca excerpt di bawah dan cari baris pertama yang memuat akar masalah".into(),
                "ambil log lengkap: journalctl -S '-30 min' -p 3 --no-pager".into(),
                "bandingkan dengan target lain yang punya fingerprint sama".into(),
                "setelah akar masalah jelas, tambahkan rule ke ~/.dudelogs/playbook.toml".into(),
            ],
            verify: None,
            risk: None,
            confidence: "low",
        }
    }
}

/// Satu fingerprint bisa muncul di banyak target: inilah yang ditampilkan UI/report.
#[derive(Debug, Clone)]
pub struct FindingGroup {
    pub fingerprint: String,
    pub severity: Severity,
    pub source: String,
    pub message: String,
    pub unit: String,
    /// Path log lengkap (applog); kosong untuk probe host.
    pub path: String,
    pub targets: Vec<String>,
    pub projects: Vec<String>,
    /// pasangan (koneksi, project) yang terdampak — dipakai filter UI
    pub pairs: Vec<(String, String)>,
    pub is_new: bool,
    pub occurrences: u32,
    pub first_seen: String,
    pub last_seen: String,
    /// Waktu kejadian dari log; fallback ke `first_seen` bila kosong.
    pub event_time: String,
    /// true bila semua baris (target) untuk fingerprint ini sudah ditandai selesai.
    pub reviewed: bool,
    pub excerpt: String,
    pub plan: Plan,
}

impl FindingGroup {
    /// Tanggal untuk kolom & sorting: waktu log bila ada, kalau tidak first_seen.
    pub fn date(&self) -> &str {
        if self.event_time.is_empty() {
            &self.first_seen
        } else {
            &self.event_time
        }
    }
}

#[derive(Debug, Clone)]
pub struct TargetReport {
    pub name: String,
    pub project: String,
    pub probes_total: usize,
    pub probes_failed: usize,
    pub errors: Vec<String>,
    /// Probe yang tidak bisa dijalankan tapi bukan kegagalan (mis. tool tidak terpasang).
    pub notes: Vec<String>,
}

impl TargetReport {
    pub fn ok(&self) -> bool {
        self.probes_failed == 0
    }
}

#[derive(Debug, Clone)]
pub struct RunOutcome {
    pub run_id: i64,
    pub started_at: String,
    pub finished_at: String,
    pub finding_rows: usize,
    pub new_rows: usize,
    pub groups: Vec<FindingGroup>,
    pub targets: Vec<TargetReport>,
    pub report_path: PathBuf,
}

#[derive(Debug, Clone)]
pub struct ProbeOutcome {
    pub probe: String,
    pub ok: bool,
    /// true = probe tidak applicable (exit 127 / tool tidak ada), bukan error.
    pub skipped: bool,
    pub error: Option<String>,
    pub findings: Vec<Finding>,
    pub raw: String,
}
