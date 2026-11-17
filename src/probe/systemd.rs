use crate::model::{Finding, Severity};

/// `systemctl --failed --no-legend --plain`:
/// `nginx.service loaded failed failed A high performance web server`
pub fn parse(conn: &str, project: &str, stdout: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    for line in stdout.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 2 {
            continue;
        }
        let unit = fields[0];
        if !unit.contains('.') {
            continue; // header atau noise
        }
        let desc = if fields.len() > 4 { fields[4..].join(" ") } else { String::new() };
        let message = if desc.is_empty() {
            format!("unit failed: {unit}")
        } else {
            format!("unit failed: {unit} — {desc}")
        };
        super::push_unique(
            &mut out,
            Finding::new(conn, project, "systemd", Severity::Error, message, unit, line),
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;


    #[test]
    fn parses_failed_units() {
        let text = "nginx.service loaded failed failed A high performance web server\n\
                    ssh.service   loaded failed failed OpenBSD Secure Shell server\n";
        let f = parse("vm1", "shop", text);
        assert_eq!(f.len(), 2);
        assert_eq!(f[0].unit, "nginx.service");
        assert_eq!(f[0].severity, Severity::Error);
        assert!(f[0].message.contains("high performance"));
    }

    #[test]
    fn ignores_empty_and_headers() {
        assert!(parse("vm1", "", "").is_empty());
        assert!(parse("vm1", "", "UNIT LOAD ACTIVE SUB DESCRIPTION\n").is_empty());
    }
}
