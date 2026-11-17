use regex::Regex;
use std::sync::LazyLock;

static RULES: LazyLock<Vec<(Regex, &'static str)>> = LazyLock::new(|| {
    vec![
        (
            Regex::new(r"(?i)(bearer\s+)[A-Za-z0-9._~+/\-]+=*").unwrap(),
            "${1}***",
        ),
        (
            Regex::new(
                r"(?i)\b(password|passwd|pwd|token|secret|api[_-]?key|authorization|access[_-]?key)\b(\s*[=:]\s*)\S+",
            )
            .unwrap(),
            "${1}${2}***",
        ),
        (
            Regex::new(r"eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}").unwrap(),
            "***JWT***",
        ),
        (Regex::new(r"\bAKIA[0-9A-Z]{16}\b").unwrap(), "***AWS_KEY***"),
    ]
});

/// Base64 panjang mirip path (stack trace) tidak boleh dirusak, karena path adalah
/// bukti utama. Token base64 asli tetap diredaksi.
static B64: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b[A-Za-z0-9+/]{40,}={0,2}\b").unwrap());

/// Menyamarkan nilai rahasia sebelum disimpan/ditampilkan.
pub fn redact(input: &str) -> String {
    let mut out = input.to_string();
    for (re, rep) in RULES.iter() {
        out = re.replace_all(&out, *rep).into_owned();
    }
    redact_base64(&out)
}

fn redact_base64(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut last = 0usize;
    for m in B64.find_iter(input) {
        let start = m.start();
        let prev_is_slash = input[..start].chars().next_back() == Some('/');
        let slash_count = m.as_str().matches('/').count();
        // path filesystem (mis. /var/www/app/vendor/laravel/.../Connection.php)
        if prev_is_slash || slash_count >= 3 {
            continue;
        }
        out.push_str(&input[last..start]);
        out.push_str("***B64***");
        last = m.end();
    }
    out.push_str(&input[last..]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hides_common_secrets() {
        let s = "Authorization: Bearer abc.def.ghi password=hunter2 token: 123456 \
                 AKIAIOSFODNN7EXAMPLE eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
        let r = redact(s);
        assert!(!r.contains("hunter2"), "{r}");
        assert!(!r.contains("123456"), "{r}");
        assert!(!r.contains("AKIAIOSFODNN7EXAMPLE"), "{r}");
        assert!(!r.contains("eyJhbGciOiJIUzI1NiJ9"), "{r}");
        assert!(r.contains("***"), "{r}");
    }

    #[test]
    fn leaves_normal_text_alone() {
        assert_eq!(redact("nginx.service: failed"), "nginx.service: failed");
    }

    #[test]
    fn keeps_stacktrace_paths_but_still_hides_base64_tokens() {
        let path = "at /var/www/app/vendor/laravel/framework/src/Illuminate/Database/Connection.php:760";
        assert!(redact(path).contains("/var/www/app/vendor/laravel/framework/src/Illuminate/Database/Connection.php"),
            "{}", redact(path));
        let token = "token QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWZnaGlqaw==";
        let r = redact(token);
        assert!(!r.contains("QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWZnaGlqaw"), "{r}");
        assert!(r.contains("***B64***"), "{r}");
    }
}
