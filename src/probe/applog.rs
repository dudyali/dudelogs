use regex::Regex;
use std::sync::LazyLock;

use crate::model::{Finding, Severity};

/// Awal record log: `[2026-11-17 11:10:41]` (Laravel), `2026-11-17 11:10:41`,
/// atau `2026/11/17 11:10:41` (nginx).
static TS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^\[?(\d{4})[-/](\d{2})[-/](\d{2})[ T](\d{2}:\d{2}:\d{2})\]?").unwrap()
});

const MAX_BODY_LINES: usize = 60;
const MAX_FINDINGS: usize = 200;

struct Record {
    file: String,
    header: String,
    body: Vec<String>,
}

impl Record {
    fn event_time(&self) -> String {
        TS.captures(&self.header)
            .map(|c| format!("{}-{}-{} {}", &c[1], &c[2], &c[3], &c[4]))
            .unwrap_or_default()
    }

    fn severity(&self) -> Option<Severity> {
        let h = self.header.to_lowercase();
        if h.contains(".critical:")
            || h.contains(".alert:")
            || h.contains(".emergency:")
            || h.contains("panic")
            || h.contains("fatal")
        {
            Some(Severity::Critical)
        } else if h.contains(".warning:") || h.contains("[warn]") || h.contains("warning")
            || h.contains(" warn")
        {
            Some(Severity::Warning)
        } else if h.contains(".error:")
            || h.contains("error")
            || h.contains("exception")
            || h.contains("failed")
        {
            Some(Severity::Error)
        } else {
            None
        }
    }

    /// Pesan satu baris: tanpa timestamp, tanpa konteks JSON Laravel
    /// (`{"exception": ...}`) — sisanya masuk excerpt yang dibuka saat baris diklik.
    fn message(&self) -> String {
        let mut text = self.header.as_str();
        if let Some(m) = TS.find(text) {
            text = &text[m.end()..];
        }
        let text = text.trim_start();
        let cut = text.find(" {\"").unwrap_or(text.len());
        text[..cut].trim().to_string()
    }

    fn excerpt(&self) -> String {
        let mut out = self.header.clone();
        for line in &self.body {
            out.push('\n');
            out.push_str(line);
        }
        out
    }

    fn unit(&self) -> String {
        self.file
            .rsplit('/')
            .next()
            .unwrap_or("")
            .split(':')
            .next()
            .unwrap_or("")
            .to_string()
    }
}

pub fn parse(conn: &str, project: &str, stdout: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    let mut file = String::new();
    let mut current: Option<Record> = None;

    for raw in stdout.lines() {
        let line = raw.trim_end();
        let lead = line.trim_start();
        if lead.starts_with("==>") && lead.ends_with("<==") {
            flush(&mut out, current.take(), conn, project);
            file = lead
                .trim_start_matches("==>")
                .trim_end_matches("<==")
                .trim()
                .to_string();
            continue;
        }
        if lead.is_empty() {
            continue;
        }
        if TS.is_match(lead) {
            // Record baru: header ber-timestamp. Sisa baris sampai header berikutnya
            // (stack trace, context JSON) jadi body — bukan temuan terpisah.
            flush(&mut out, current.take(), conn, project);
            current = Some(Record {
                file: file.clone(),
                header: lead.to_string(),
                body: Vec::new(),
            });
        } else if let Some(rec) = current.as_mut() {
            if rec.body.len() < MAX_BODY_LINES {
                rec.body.push(line.to_string());
            }
        } else {
            // File tanpa timestamp: perlakukan tiap baris sebagai record.
            current = Some(Record {
                file: file.clone(),
                header: lead.to_string(),
                body: Vec::new(),
            });
        }
    }
    flush(&mut out, current.take(), conn, project);
    out
}

fn flush(out: &mut Vec<Finding>, rec: Option<Record>, conn: &str, project: &str) {
    let Some(rec) = rec else { return };
    if out.len() >= MAX_FINDINGS {
        return;
    }
    let Some(severity) = rec.severity() else { return };
    let message = rec.message();
    if message.is_empty() {
        return;
    }
    super::push_unique(
        out,
        Finding::new(
            conn,
            project,
            "applog",
            severity,
            message,
            rec.unit(),
            rec.excerpt(),
        )
        .with_event_time(rec.event_time())
            .with_path(rec.file.clone()),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn laravel_record_groups_stack_trace_into_one_finding() {
        let text = "==> /var/www/app/storage/logs/laravel.log <==\n\
[2026-11-17 11:10:41] production.ERROR: SQLSTATE[HY000] [2002] Connection refused {\"exception\":\"[object] (PDOException(code: 2002): SQLSTATE[HY000]) at /var/www/app/vendor/laravel/framework/src/Illuminate/Database/Connection.php:760)\"}\n\
[stacktrace]\n\
#0 /var/www/app/vendor/laravel/framework/src/Illuminate/Database/Connection.php(760): PDO->__construct()\n\
#1 /var/www/app/vendor/laravel/framework/src/Illuminate/Database/Connectors/Connector.php(65): Connection->createConnection()\n\
#2 {main}\n\
\n\
[2026-11-17 11:11:02] production.CRITICAL: cache store down {\"exception\":\"[object] (RuntimeException(code: 0): cache store down at /var/www/app/app/Http/Kernel.php:20)\"}\n";
        let f = parse("vm1", "psb-keu", text);
        assert_eq!(f.len(), 2, "satu error = satu temuan: {f:#?}");
        assert_eq!(f[0].severity, Severity::Error);
        assert_eq!(f[0].event_time, "2026-11-17 11:10:41");
        assert_eq!(
            f[0].message,
            "production.ERROR: SQLSTATE[HY000] [2002] Connection refused"
        );
        assert_eq!(f[0].unit, "laravel.log");
        assert!(f[0].excerpt.contains("#0 "), "stack trace harus tersimpan");
        assert!(f[0].excerpt.contains("#2 {main}"));
        assert_eq!(f[1].severity, Severity::Critical);
        assert_eq!(f[1].event_time, "2026-11-17 11:11:02");
    }

    #[test]
    fn different_errors_are_separate_records() {
        let text = "==> /var/log/shop/api.log <==\n\
2026-11-17 10:00:01 ERROR db timeout after 5s\n\
2026-11-17 10:00:02 ERROR retry exhausted for order 8812\n\
2026-11-17 10:00:03 WARNING queue depth 1200\n";
        let f = parse("vm1", "shop", text);
        assert_eq!(f.len(), 3);
        assert_eq!(f[0].severity, Severity::Error);
        assert_eq!(f[1].severity, Severity::Error);
        assert_eq!(f[2].severity, Severity::Warning);
        assert_eq!(f[0].event_time, "2026-11-17 10:00:01");
        assert!(f[2].message.contains("queue depth"));
    }

    #[test]
    fn non_timestamped_lines_still_work() {
        let text = "thread 'main' panicked at src/main.rs:10:5\n";
        let f = parse("vm1", "shop", text);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::Critical);
        assert!(f[0].event_time.is_empty());
    }

    #[test]
    fn unrelated_body_lines_do_not_become_findings() {
        let text = "[2026-11-17 10:00:01] production.ERROR: boom {\"exception\":\"x\"}\n\
#0 /var/www/app/app/Handler.php(12): Exception->getMessage()\n\
Exception: nested\n";
        let f = parse("vm1", "shop", text);
        assert_eq!(f.len(), 1, "{f:#?}");
        assert!(f[0].excerpt.contains("#0"));
    }
}
