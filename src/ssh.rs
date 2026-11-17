use std::sync::OnceLock;
use std::time::Duration;
use tokio::process::Command;

const STDERR_LIMIT: usize = 800;

#[derive(Debug, Clone, Default)]
pub struct Output {
    pub stdout: String,
    pub stderr: String,
    pub code: Option<i32>,
}

/// Tujuan SSH yang disimpan di DB.
#[derive(Clone, Default)]
pub struct SshTarget {
    /// `user@host` atau alias ~/.ssh/config
    pub dest: String,
    pub port: u16,
    pub identity_file: String,
    /// Hanya terisi untuk auth password (lihat `with_password`).
    pub password: Option<String>,
    /// Socket ControlMaster: satu sesi SSH dipakai semua probe untuk VM ini.
    pub control_path: Option<String>,
}

impl std::fmt::Debug for SshTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SshTarget")
            .field("dest", &self.dest)
            .field("port", &self.port)
            .field("identity_file", &self.identity_file)
            .field("password", &self.password.as_ref().map(|_| "<set>"))
            .field("control_path", &self.control_path)
            .finish()
    }
}

impl SshTarget {
    pub fn new(dest: impl Into<String>, port: u16, identity_file: impl Into<String>) -> Self {
        Self {
            dest: dest.into(),
            port,
            identity_file: identity_file.into(),
            password: None,
            control_path: None,
        }
    }

    pub fn with_password(mut self, password: impl Into<String>) -> Self {
        let password = password.into();
        if !password.is_empty() {
            self.password = Some(password);
        }
        self
    }

    pub fn has_password(&self) -> bool {
        self.password.is_some()
    }

    pub fn with_control_path(mut self, path: impl Into<String>) -> Self {
        self.control_path = Some(path.into());
        self
    }

}

#[derive(Clone)]
pub struct Ssh {
    bin: String,
    timeout: Duration,
}

impl Ssh {
    pub fn new(bin: impl Into<String>, timeout: Duration) -> Self {
        Self {
            bin: bin.into(),
            timeout,
        }
    }

    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    /// Buat sesi (master) sekali per VM; probe berikutnya memakai socket yang sama.
    pub async fn warm_up(&self, target: &SshTarget) -> Result<(), String> {
        if target.control_path.is_none() {
            return Ok(());
        }
        self.run(target, "true").await.map(|_| ())
    }

    /// Tutup master; best-effort, tidak pernah menggagalkan run.
    pub async fn close_control(&self, target: &SshTarget) {
        let Some(path) = &target.control_path else { return };
        let _ = Command::new(&self.bin)
            .args([
                "-o",
                &format!("ControlPath={path}"),
                "-O",
                "exit",
                &target.dest,
            ])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .await;
    }


    /// Jalankan satu perintah read-only di remote. Err = transport/auth/timeout
    /// atau perintah remote exit non-zero — keduanya berarti probe GAGAL, bukan
    /// "tidak ada error".
    pub async fn run(&self, target: &SshTarget, cmd: &str) -> Result<Output, String> {
        if target.dest.trim().is_empty() {
            return Err("koneksi tanpa host".into());
        }
        let mut args: Vec<String> = ["-o", "ConnectTimeout=10", "-o", "StrictHostKeyChecking=accept-new", "-o", "LogLevel=ERROR"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        if target.password.is_some() {
            // Password tidak bisa lewat stdin (BatchMode mematikan prompt),
            // jadi pakai SSH_ASKPASS_REQUIRE=force + helper script.
            for opt in [
                "NumberOfPasswordPrompts=1",
                "PubkeyAuthentication=no",
                "PreferredAuthentications=password,keyboard-interactive",
            ] {
                args.push("-o".into());
                args.push(opt.into());
            }
        } else {
            args.push("-o".into());
            args.push("BatchMode=yes".into());
        }
        if let Some(path) = &target.control_path {
            for opt in [
                "ControlMaster=auto".to_string(),
                format!("ControlPath={path}"),
                "ControlPersist=60".to_string(),
            ] {
                args.push("-o".into());
                args.push(opt);
            }
        }
        if target.port != 0 && target.port != 22 {
            args.push("-p".into());
            args.push(target.port.to_string());
        }
        if !target.identity_file.trim().is_empty() {
            args.push("-o".into());
            args.push("IdentitiesOnly=yes".into());
            args.push("-i".into());
            args.push(target.identity_file.clone());
        }
        args.push(target.dest.clone());
        args.push(cmd.to_string());

        let mut command = Command::new(&self.bin);
        command
            .args(&args)
            .env("LC_ALL", "C")
            .env("LANG", "C")
            .kill_on_drop(true)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        // App yang dibuka dari Finder tidak mewarisi SSH_AUTH_SOCK dari terminal;
        // ambil dari launchd agar ssh-agent tetap dipakai.
        if let Some(sock) = ssh_auth_sock() {
            command.env("SSH_AUTH_SOCK", sock);
        }
        if let Some(password) = &target.password {
            command
                .env("SSH_ASKPASS", askpass_script()?)
                .env("SSH_ASKPASS_REQUIRE", "force")
                .env("DISPLAY", ":0")
                .env("DUDELOGS_SSH_PASSWORD", password);
        }
        let child = command
            .spawn()
            .map_err(|e| format!("gagal menjalankan `{}`: {e}", self.bin))?;

        let out = match tokio::time::timeout(self.timeout, child.wait_with_output()).await {
            Ok(Ok(o)) => o,
            Ok(Err(e)) => return Err(format!("ssh gagal: {e}")),
            Err(_) => {
                return Err(format!(
                    "timeout {}s (proses ssh di-kill)",
                    self.timeout.as_secs()
                ))
            }
        };

        let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
        let code = out.status.code();

        // ssh sendiri memakai 255 untuk kegagalan transport/auth.
        let ssh_error = code == Some(255)
            || stderr.contains("Permission denied")
            || stderr.contains("Host key verification failed")
            || stderr.contains("Could not resolve hostname")
            || stderr.contains("Connection refused")
            || stderr.contains("Connection timed out");
        if ssh_error {
            return Err(format!(
                "ssh error (exit {}): {}",
                code.map(|c| c.to_string()).unwrap_or_else(|| "signal".into()),
                collapse(&stderr)
            ));
        }

        Ok(Output {
            stdout,
            stderr,
            code,
        })
    }
}

fn ssh_auth_sock() -> Option<String> {
    if let Ok(v) = std::env::var("SSH_AUTH_SOCK") {
        if !v.is_empty() {
            return Some(v);
        }
    }
    #[cfg(target_os = "macos")]
    {
        static CACHED: OnceLock<Option<String>> = OnceLock::new();
        return CACHED
            .get_or_init(|| {
                std::process::Command::new("launchctl")
                    .args(["getenv", "SSH_AUTH_SOCK"])
                    .output()
                    .ok()
                    .filter(|o| o.status.success())
                    .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                    .filter(|s| !s.is_empty())
            })
            .clone();
    }
    #[cfg(not(target_os = "macos"))]
    None
}

/// Script kecil yang mencetak password dari env (tidak ada secret di disk).
fn askpass_script() -> Result<String, String> {
    static PATH: OnceLock<Result<String, String>> = OnceLock::new();
    PATH.get_or_init(|| {
        let path = std::env::temp_dir().join(format!("dudelogs-askpass-{}.sh", std::process::id()));
        std::fs::write(
            &path,
            "#!/bin/sh\nprintf '%s' \"$DUDELOGS_SSH_PASSWORD\"\n",
        )
        .map_err(|e| format!("gagal menulis askpass helper: {e}"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
                .map_err(|e| format!("gagal chmod askpass helper: {e}"))?;
        }
        Ok(path.display().to_string())
    })
    .clone()
}

fn collapse(s: &str) -> String {
    let mut t: String = s.split_whitespace().collect::<Vec<_>>().join(" ");
    if t.len() > STDERR_LIMIT {
        t.truncate(STDERR_LIMIT);
        t.push('…');
    }
    t
}
