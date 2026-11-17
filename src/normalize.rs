use regex::Regex;
use std::sync::LazyLock;

/// Token volatil yang dibuang sebelum fingerprint dihitung, supaya error yang
/// sama di VM/waktu berbeda tetap terdeteksi sebagai satu temuan.
static SCRUB: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    vec![
        // 2026-11-17T15:44:01Z / 2026-11-17 15:44:01.123
        Regex::new(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?").unwrap(),
        Regex::new(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b").unwrap(),
        Regex::new(r"\b0x[0-9a-fA-F]+\b").unwrap(),
        Regex::new(r"\b[0-9a-fA-F]{12,}\b").unwrap(),
        Regex::new(r"\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b").unwrap(),
        Regex::new(r"(?i)\b(?:pid|tid|thread)[=: ]\d+\b").unwrap(),
        Regex::new(r"\[\d+\]").unwrap(),
    ]
});

fn scrub(line: &str) -> String {
    let mut out = line.to_string();
    for re in SCRUB.iter() {
        out = re.replace_all(&out, "<v>").into_owned();
    }
    out.split_whitespace().collect::<Vec<_>>().join(" ").to_lowercase()
}

pub fn fingerprint(source: &str, project: &str, unit: &str, message: &str) -> String {
    let canon = format!(
        "{}|{}|{}|{}",
        source.to_lowercase(),
        project.to_lowercase(),
        unit.to_lowercase(),
        scrub(message)
    );
    blake3::hash(canon.as_bytes()).to_hex()[..16].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn volatile_values_do_not_change_fingerprint() {
        let a = fingerprint(
            "journal",
            "shop",
            "nginx.service",
            "2026-11-17T10:00:01Z upstream 10.0.0.5:8080 failed (pid 4411, id 9f2c1a7b-)",
        );
        let b = fingerprint(
            "journal",
            "shop",
            "nginx.service",
            "2026-11-18T02:13:44Z upstream 10.0.0.9:8080 failed (pid 90210, id 9f2c1a7b-)",
        );
        assert_eq!(a, b);
    }

    #[test]
    fn different_message_differs() {
        let a = fingerprint("journal", "shop", "nginx.service", "upstream timed out");
        let b = fingerprint("journal", "shop", "nginx.service", "permission denied");
        assert_ne!(a, b);
    }

    #[test]
    fn unit_participates() {
        let a = fingerprint("systemd", "", "a.service", "unit failed");
        let b = fingerprint("systemd", "", "b.service", "unit failed");
        assert_ne!(a, b);
    }

    #[test]
    fn project_scopes_the_fingerprint() {
        let a = fingerprint("applog", "shop", "api.log", "db timeout");
        let b = fingerprint("applog", "cms", "api.log", "db timeout");
        assert_ne!(a, b);
    }
}
