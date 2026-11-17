use crate::model::{Finding, Severity};

/// Satu baris = satu objek JSON (`journalctl -o json`).
pub fn parse(conn: &str, project: &str, stdout: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    for line in stdout.lines() {
        let line = line.trim();
        if !line.starts_with('{') {
            continue;
        }
        let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        let priority = v
            .get("PRIORITY")
            .and_then(|p| p.as_str().map(str::to_string).or_else(|| p.as_u64().map(|n| n.to_string())))
            .unwrap_or_else(|| "6".into());
        let severity = Severity::from_journal_priority(&priority);
        if severity == Severity::Info {
            continue;
        }
        let message = match v.get("MESSAGE") {
            Some(serde_json::Value::String(s)) => s.clone(),
            Some(serde_json::Value::Array(items)) => {
                let bytes: Vec<u8> = items
                    .iter()
                    .filter_map(|i| i.as_u64().map(|n| n as u8))
                    .collect();
                String::from_utf8_lossy(&bytes).into_owned()
            }
            _ => continue,
        };
        let message = message.trim().to_string();
        if message.is_empty() {
            continue;
        }
        let unit = v
            .get("_SYSTEMD_UNIT")
            .and_then(|x| x.as_str())
            .or_else(|| v.get("SYSLOG_IDENTIFIER").and_then(|x| x.as_str()))
            .unwrap_or("")
            .to_string();
        let event_time = v
            .get("__REALTIME_TIMESTAMP")
            .and_then(|x| {
                x.as_str()
                    .and_then(|s| s.parse::<i64>().ok())
                    .or_else(|| x.as_i64())
            })
            .and_then(chrono::DateTime::<chrono::Utc>::from_timestamp_micros)
            .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
            .unwrap_or_default();
        let first_line = message.lines().next().unwrap_or("").to_string();
        let excerpt = message.lines().take(5).collect::<Vec<_>>().join("\n");
        super::push_unique(
            &mut out,
            Finding::new(conn, project, "journal", severity, first_line, unit, excerpt)
                .with_event_time(event_time),
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;


    fn line(pri: &str, msg: &str, unit: &str) -> String {
        serde_json::json!({
            "PRIORITY": pri,
            "MESSAGE": msg,
            "_SYSTEMD_UNIT": unit,
            "__REALTIME_TIMESTAMP": "1763373601000000"
        })
        .to_string()
    }

    #[test]
    fn maps_priority_to_severity() {
        let text = [
            line("0", "kernel panic", "kernel"),
            line("3", "upstream timed out", "nginx.service"),
            line("6", "started", "cron.service"),
        ]
        .join("\n");
        let f = parse("vm1", "shop", &text);
        assert_eq!(f.len(), 2);
        assert_eq!(f[0].severity, Severity::Critical);
        assert_eq!(f[1].severity, Severity::Error);
        assert_eq!(f[1].unit, "nginx.service");
        assert_eq!(f[1].event_time, "2025-11-17 10:00:01");
    }

    #[test]
    fn tolerates_binary_message_array() {
        let text = serde_json::json!({
            "PRIORITY": "3",
            "MESSAGE": [104, 101, 108, 108, 111],
            "SYSLOG_IDENTIFIER": "app"
        })
        .to_string();
        let f = parse("vm1", "", &text);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].message, "hello");
    }

    #[test]
    fn skips_garbage_lines() {
        assert!(parse("vm1", "", "bukan json\n{rusak").is_empty());
    }
}
