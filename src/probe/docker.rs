use crate::model::{Finding, Severity};

/// Dua section dipisah `---`:
/// 1) container exited/dead, 2) container restarting.
pub fn parse(conn: &str, project: &str, stdout: &str) -> Vec<Finding> {
    let sections = super::split_sections(stdout);
    let mut out = Vec::new();

    for &line in sections.first().map(|s| s.as_slice()).unwrap_or(&[]) {
        let Some((name, image, status)) = fields(line) else { continue };
        let severity = if status.to_lowercase().contains("dead") {
            Severity::Error
        } else {
            Severity::Warning
        };
        let message = format!("container {name} ({image}) {status}");
        super::push_unique(
            &mut out,
            Finding::new(conn, project, "docker", severity, message, name, line),
        );
    }

    for &line in sections.get(1).map(|s| s.as_slice()).unwrap_or(&[]) {
        let Some((name, image, status)) = fields(line) else { continue };
        let message = format!("container {name} ({image}) restart loop — {status}");
        super::push_unique(
            &mut out,
            Finding::new(conn, project, "docker", Severity::Error, message, name, line),
        );
    }

    out
}

fn fields(line: &str) -> Option<(&str, &str, &str)> {
    let line = line.trim();
    if line.is_empty() || line.starts_with("CONTAINER ID") {
        return None;
    }
    let mut parts = line.split('\t');
    let name = parts.next()?.trim();
    let image = parts.next().unwrap_or("").trim();
    let status = parts.next().unwrap_or("").trim();
    if name.is_empty() || status.is_empty() {
        return None;
    }
    Some((name, image, status))
}

#[cfg(test)]
mod tests {
    use super::*;


    #[test]
    fn exited_is_warning_restarting_is_error() {
        let text = "api\tghcr.io/shop/api\tExited (1) 2 hours ago\n\
                    ---\n\
                    worker\tghcr.io/shop/worker\tRestarting (2) 5 seconds ago\n";
        let f = parse("vm1", "shop", text);
        assert_eq!(f.len(), 2);
        assert_eq!(f[0].severity, Severity::Warning);
        assert_eq!(f[0].unit, "api");
        assert_eq!(f[1].severity, Severity::Error);
        assert!(f[1].message.contains("restart loop"));
    }

    #[test]
    fn handles_empty() {
        assert!(parse("vm1", "", "").is_empty());
        assert!(parse("vm1", "", "---\n").is_empty());
    }
}
