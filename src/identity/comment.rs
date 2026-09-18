//! Key comment templates: `{identity}`, `{hostname}` (short), `{user}`.

pub fn render(template: &str, identity: &str) -> String {
    render_with(template, identity, &short_hostname(), &local_user())
}

pub fn render_with(template: &str, identity: &str, hostname: &str, user: &str) -> String {
    template
        .replace("{identity}", identity)
        .replace("{hostname}", hostname)
        .replace("{user}", user)
}

/// Hostname up to the first dot; "localhost" if the system gives us nothing.
pub fn short_hostname() -> String {
    let full = gethostname::gethostname().to_string_lossy().into_owned();
    let short = full.split('.').next().unwrap_or("").trim();
    if short.is_empty() {
        "localhost".to_string()
    } else {
        short.to_string()
    }
}

pub fn local_user() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .unwrap_or_else(|_| "user".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_with_substitutes_all_variables() {
        assert_eq!(
            render_with("{identity}@{hostname}", "work", "thinkpad", "jz"),
            "work@thinkpad"
        );
        assert_eq!(
            render_with("{user}@{hostname} ({identity})", "work", "tp", "jz"),
            "jz@tp (work)"
        );
    }

    #[test]
    fn render_with_leaves_unknown_braces_alone() {
        assert_eq!(render_with("{nope}", "w", "h", "u"), "{nope}");
    }

    #[test]
    fn short_hostname_is_nonempty_and_undotted() {
        let h = short_hostname();
        assert!(!h.is_empty());
        assert!(!h.contains('.'));
    }
}
