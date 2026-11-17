use crate::model::{Finding, Severity};

const DISK_WARN_PCT: f64 = 90.0;
const MEM_WARN_AVAIL_PCT: f64 = 10.0;
const LOAD_WARN_RATIO: f64 = 2.0;

/// Section: df | /proc/meminfo | loadavg + nproc
pub fn parse(conn: &str, project: &str, stdout: &str) -> Vec<Finding> {
    let sections = super::split_sections(stdout);
    let mut out = Vec::new();

    for line in sections.first().map(|s| s.as_slice()).unwrap_or(&[]) {
        parse_df(line, conn, project, &mut out);
    }

    let meminfo = sections.get(1).map(|s| s.as_slice()).unwrap_or(&[]);
    parse_mem(meminfo, conn, project, &mut out);

    let proc = sections.get(2).map(|s| s.as_slice()).unwrap_or(&[]);
    parse_load(proc, conn, project, &mut out);

    out
}

fn parse_df(line: &str, conn: &str, project: &str, out: &mut Vec<Finding>) {
    let fields: Vec<&str> = line.split_whitespace().collect();
    if fields.len() < 6 {
        return;
    }
    let Some(pct) = fields[4].strip_suffix('%').and_then(|p| p.parse::<f64>().ok()) else {
        return;
    };
    let mount = fields[5..].join(" ");
    if pct <= DISK_WARN_PCT {
        return;
    }
    let severity = if pct >= 97.0 { Severity::Critical } else { Severity::Warning };
    let message = format!("disk {mount} terpakai {pct:.0}%");
    super::push_unique(
        out,
        Finding::new(conn, project, "resource", severity, message, mount, line),
    );
}

fn parse_mem(lines: &[&str], conn: &str, project: &str, out: &mut Vec<Finding>) {
    let mut total: Option<f64> = None;
    let mut avail: Option<f64> = None;
    for line in lines {
        let mut parts = line.split_whitespace();
        match parts.next() {
            Some("MemTotal:") => total = parts.next().and_then(|v| v.parse().ok()),
            Some("MemAvailable:") => avail = parts.next().and_then(|v| v.parse().ok()),
            _ => {}
        }
    }
    let (Some(total), Some(avail)) = (total, avail) else { return };
    if total <= 0.0 {
        return;
    }
    let pct = avail / total * 100.0;
    if pct >= MEM_WARN_AVAIL_PCT {
        return;
    }
    let severity = if pct < 3.0 { Severity::Critical } else { Severity::Warning };
    let message = format!(
        "memory tersedia {pct:.1}% ({:.0} MB dari {:.0} MB)",
        avail / 1024.0,
        total / 1024.0
    );
    super::push_unique(
        out,
        Finding::new(conn, project, "resource", severity, message, "mem", ""),
    );
}

fn parse_load(lines: &[&str], conn: &str, project: &str, out: &mut Vec<Finding>) {
    let mut load1: Option<f64> = None;
    let mut cores: Option<f64> = None;
    for line in lines {
        if let Ok(n) = line.trim().parse::<f64>() {
            // baris nproc: satu angka saja
            cores = Some(n);
            continue;
        }
        if load1.is_none() {
            load1 = line.split_whitespace().next().and_then(|v| v.parse().ok());
        }
    }
    let (Some(load1), Some(cores)) = (load1, cores) else { return };
    if cores <= 0.0 || load1 <= cores * LOAD_WARN_RATIO {
        return;
    }
    let severity = if load1 > cores * 4.0 { Severity::Error } else { Severity::Warning };
    let message = format!("load {load1:.2} pada {cores:.0} core");
    super::push_unique(
        out,
        Finding::new(conn, project, "resource", severity, message, "load", ""),
    );
}

#[cfg(test)]
mod tests {
    use super::*;


    #[test]
    fn flags_full_disk_low_mem_high_load() {
        let text = "Filesystem 1024-blocks Used Available Capacity Mounted on\n\
                    /dev/vda1 41152736 39000000 2152736 95% /\n\
                    /dev/vda2 100 10 90 10% /boot\n\
                    ---\n\
                    MemTotal: 2048000 kB\n\
                    MemAvailable: 51200 kB\n\
                    ---\n\
                    8.50 4.00 2.00 1/100 999\n\
                    2\n";
        let f = parse("vm1", "shop", text);
        assert_eq!(f.len(), 3, "{f:#?}");
        assert!(f.iter().any(|x| x.message.contains("disk / ")));
        assert!(f.iter().any(|x| x.message.contains("memory")));
        assert!(f.iter().any(|x| x.message.contains("load 8.50")));
        assert!(f.iter().all(|x| x.severity >= Severity::Warning));
    }

    #[test]
    fn quiet_when_healthy() {
        let text = "Filesystem 1024-blocks Used Available Capacity Mounted on\n\
                    /dev/vda1 41152736 100000 40000000 2% /\n\
                    ---\n\
                    MemTotal: 2048000 kB\n\
                    MemAvailable: 1500000 kB\n\
                    ---\n\
                    0.10 0.20 0.30 1/100 999\n\
                    4\n";
        assert!(parse("vm1", "", text).is_empty());
    }
}
