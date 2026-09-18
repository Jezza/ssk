//! `ssk doctor [--fix]`: hygiene checks over the ssh dir. Fixes only ever tighten
//! permissions or add files; nothing is deleted or loosened.

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use anyhow::Context;

use crate::cli::DoctorArgs;
use crate::fsx;
use crate::identity::IdentityError;
use crate::identity::store::{self, Entry};
use crate::json::{self, DoctorJson, FindingJson};
use crate::settings::Settings;
use crate::ssh::config;
use crate::state::State;
use crate::ui::Ui;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Info,
    Warn,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Fix {
    Chmod(u32),
    /// Derive `<path>.pub` from the private key at `path`.
    WritePublicKey,
    AddInclude,
}

#[derive(Debug, Clone)]
pub struct Finding {
    pub id: &'static str,
    pub severity: Severity,
    pub path: PathBuf,
    pub message: String,
    pub fix: Option<Fix>,
}

fn finding(
    id: &'static str,
    severity: Severity,
    path: &Path,
    message: String,
    fix: Option<Fix>,
) -> Finding {
    Finding {
        id,
        severity,
        path: path.to_path_buf(),
        message,
        fix,
    }
}

pub fn check(ssh_dir: &Path) -> anyhow::Result<Vec<Finding>> {
    use Severity::{Info, Warn};
    let mut out = Vec::new();
    if !ssh_dir.is_dir() {
        return Ok(out);
    }

    let dir_mode = fsx::mode_of(ssh_dir)?;
    if dir_mode & 0o077 != 0 {
        out.push(finding(
            "dir-perms",
            Warn,
            ssh_dir,
            format!("ssh directory is mode {dir_mode:04o}; should be 0700"),
            Some(Fix::Chmod(0o700)),
        ));
    }

    let entries = store::scan(ssh_dir)?;
    let state = State::load(ssh_dir)?;
    let mut by_fingerprint: BTreeMap<String, Vec<String>> = BTreeMap::new();

    for entry in &entries {
        match entry {
            Entry::Identity(id) => {
                let mode = fsx::mode_of(&id.private_path)?;
                if mode & 0o077 != 0 {
                    out.push(finding(
                        "key-perms",
                        Warn,
                        &id.private_path,
                        format!(
                            "private key is mode {mode:04o}; ssh refuses keys readable by others"
                        ),
                        Some(Fix::Chmod(0o600)),
                    ));
                }
                match &id.public_path {
                    None => out.push(finding(
                        "missing-pub",
                        Warn,
                        &id.private_path,
                        "no .pub file next to the private key".to_string(),
                        Some(Fix::WritePublicKey),
                    )),
                    Some(p) => {
                        let m = fsx::mode_of(p)?;
                        if m & 0o022 != 0 {
                            out.push(finding(
                                "pub-writable",
                                Warn,
                                p,
                                format!(
                                    "public key is writable by group/other (mode {m:04o}); another local user could swap it before you copy it somewhere"
                                ),
                                Some(Fix::Chmod(0o644)),
                            ));
                        } else if m & 0o044 != 0o044 {
                            out.push(finding(
                                "pub-tight",
                                Info,
                                p,
                                format!("public key is mode {m:04o}; 0644 is conventional"),
                                Some(Fix::Chmod(0o644)),
                            ));
                        }
                    }
                }
                if id.comment.is_empty() {
                    out.push(finding(
                        "empty-comment",
                        Info,
                        &id.private_path,
                        "key has no comment; `ssh-keygen -c -f <key>` sets one".to_string(),
                        None,
                    ));
                }
                match (id.algorithm.as_str(), id.bits) {
                    ("rsa", Some(b)) if b < 3072 => out.push(finding(
                        "weak-rsa",
                        Warn,
                        &id.private_path,
                        format!("rsa {b}-bit key; 3072+ bits or ed25519 is recommended"),
                        None,
                    )),
                    ("dsa", _) => out.push(finding(
                        "weak-dsa",
                        Warn,
                        &id.private_path,
                        "dsa keys are disabled in modern OpenSSH".to_string(),
                        None,
                    )),
                    ("ecdsa", _) => out.push(finding(
                        "ecdsa",
                        Info,
                        &id.private_path,
                        "ecdsa (NIST curve); ed25519 is preferred for new keys".to_string(),
                        None,
                    )),
                    _ => {}
                }
                by_fingerprint
                    .entry(id.fingerprint.clone())
                    .or_default()
                    .push(id.name.clone());
            }
            Entry::Broken { path, error, .. } => match error {
                IdentityError::LegacyPem { .. } => out.push(finding(
                    "legacy-pem",
                    Warn,
                    path,
                    format!(
                        "legacy PEM private key; convert with `ssh-keygen -p -f {}`",
                        path.display()
                    ),
                    None,
                )),
                other => out.push(finding(
                    "unparseable",
                    Warn,
                    path,
                    format!("cannot parse as an OpenSSH private key: {other}"),
                    None,
                )),
            },
            Entry::OrphanPublic { path, .. } => out.push(finding(
                "orphan-pub",
                Info,
                path,
                "public key without a private key".to_string(),
                None,
            )),
        }
    }

    for (fp, names) in by_fingerprint {
        if names.len() > 1 {
            out.push(finding(
                "duplicate-key",
                Info,
                ssh_dir,
                format!("the same key is stored as {} ({fp})", names.join(", ")),
                None,
            ));
        }
    }

    for name in ["config", "authorized_keys"] {
        let p = ssh_dir.join(name);
        if p.is_file() {
            let m = fsx::mode_of(&p)?;
            if m & 0o077 != 0 {
                out.push(finding(
                    "file-perms",
                    Warn,
                    &p,
                    format!("{name} is mode {m:04o}; should be 0600"),
                    Some(Fix::Chmod(0o600)),
                ));
            }
        }
    }

    let sskd = ssh_dir.join("ssk.d");
    let has_conf = sskd.is_dir()
        && fs::read_dir(&sskd)?
            .flatten()
            .any(|e| e.path().extension().is_some_and(|x| x == "conf"));
    if has_conf && !config::has_include(ssh_dir)? {
        out.push(finding(
            "missing-include",
            Warn,
            &ssh_dir.join("config"),
            "ssh config does not include ssk.d/*.conf; generated Host blocks are inactive"
                .to_string(),
            Some(Fix::AddInclude),
        ));
    }

    for name in state.identity.keys() {
        if !ssh_dir.join(name).is_file() {
            out.push(finding(
                "dangling-state",
                Info,
                &State::path(ssh_dir),
                format!("ssk.toml has an entry for '{name}' but no such key exists"),
                None,
            ));
        }
    }

    out.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| a.path.cmp(&b.path))
            .then_with(|| a.id.cmp(b.id))
    });
    Ok(out)
}

/// Apply every finding that carries a fix. Returns how many were applied.
pub fn apply(ssh_dir: &Path, findings: &[Finding], ui: &Ui) -> anyhow::Result<usize> {
    let mut applied = 0;
    for f in findings {
        let Some(fix) = &f.fix else { continue };
        match fix {
            Fix::Chmod(mode) => {
                fs::set_permissions(&f.path, fs::Permissions::from_mode(*mode))
                    .with_context(|| format!("chmod {mode:04o} {}", f.path.display()))?;
                ui.success(format!("chmod {mode:04o} {}", f.path.display()));
            }
            Fix::WritePublicKey => {
                let key = ssh_key::PrivateKey::read_openssh_file(&f.path)
                    .with_context(|| format!("reading {}", f.path.display()))?;
                let line = format!("{}\n", key.public_key().to_openssh()?);
                let pub_path = PathBuf::from(format!("{}.pub", f.path.display()));
                fsx::write_new(&pub_path, line.as_bytes(), 0o644, false)
                    .with_context(|| format!("writing {}", pub_path.display()))?;
                ui.success(format!("wrote {}", pub_path.display()));
                if key.is_encrypted() {
                    ui.warn(format!(
                        "{} was written without a comment (the comment is inside the encrypted key); `ssh-keygen -c -f {}` can set one",
                        pub_path.display(),
                        f.path.display()
                    ));
                }
            }
            Fix::AddInclude => {
                config::ensure_include(ssh_dir)?;
                ui.success(format!(
                    "added `{}` to {}",
                    config::include_line(ssh_dir),
                    ssh_dir.join("config").display()
                ));
            }
        }
        applied += 1;
    }
    Ok(applied)
}

fn code_for(findings: &[Finding]) -> u8 {
    if findings.iter().any(|f| f.severity == Severity::Warn) {
        1
    } else {
        0
    }
}

fn print_findings(ui: &Ui, ssh_dir: &Path, findings: &[Finding]) {
    if findings.is_empty() {
        ui.success(format!("{} looks healthy", ssh_dir.display()));
        return;
    }
    for f in findings {
        let tag = match f.severity {
            Severity::Warn => "warn",
            Severity::Info => "info",
        };
        let fixable = if f.fix.is_some() { "  [fixable]" } else { "" };
        ui.info(format!(
            "{tag}  {:<16} {}: {}{fixable}",
            f.id,
            f.path.display(),
            f.message
        ));
    }
}

pub fn run(settings: &Settings, ui: &Ui, args: &DoctorArgs) -> anyhow::Result<u8> {
    let dir = &settings.ssh_dir;
    let findings = check(dir)?;
    let fixable: Vec<Finding> = findings
        .iter()
        .filter(|f| f.fix.is_some())
        .cloned()
        .collect();
    if !settings.json {
        print_findings(ui, dir, &findings);
    }
    let mut applied = 0;
    let mut code = code_for(&findings);
    if args.fix && !settings.dry_run && !fixable.is_empty() {
        applied = apply(dir, &fixable, ui)?;
        code = code_for(&check(dir)?);
    }
    if settings.json {
        json::print(&DoctorJson {
            findings: findings.iter().map(FindingJson::from).collect(),
            applied,
        })?;
        return Ok(code);
    }
    if findings.is_empty() {
        return Ok(0);
    }
    if !args.fix {
        if !fixable.is_empty() {
            ui.hint("ssk doctor --fix   (applies the fixable ones; only tightens, never deletes)");
        }
        return Ok(code);
    }
    if settings.dry_run {
        ui.info("dry run: no fixes applied");
        return Ok(code);
    }
    if fixable.is_empty() {
        ui.info("nothing here is auto-fixable");
        return Ok(code);
    }
    ui.success(format!(
        "applied {applied} fix{}",
        if applied == 1 { "" } else { "es" }
    ));
    Ok(code)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::keygen::{KeySpec, KeyType, generate, write_pair};
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    fn make(dir: &Path, name: &str, key_type: KeyType, bits: Option<u32>, pass: Option<&str>) {
        let key = generate(
            &KeySpec {
                key_type,
                bits,
                comment: format!("{name}@box"),
            },
            pass,
        )
        .unwrap();
        write_pair(dir, name, &key, false).unwrap();
    }

    fn ids(findings: &[Finding]) -> Vec<&'static str> {
        findings.iter().map(|f| f.id).collect()
    }

    fn chmod(p: &Path, mode: u32) {
        fs::set_permissions(p, fs::Permissions::from_mode(mode)).unwrap();
    }

    #[test]
    fn healthy_dir_has_no_findings() {
        let tmp = tempfile::tempdir().unwrap();
        make(tmp.path(), "work", KeyType::Ed25519, None, None);
        assert!(check(tmp.path()).unwrap().is_empty());
    }

    #[test]
    fn missing_dir_has_no_findings() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(check(&tmp.path().join("nope")).unwrap().is_empty());
    }

    #[test]
    fn permission_problems_are_warnings_and_fixable() {
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path();
        make(d, "work", KeyType::Ed25519, None, None);
        chmod(d, 0o755);
        chmod(&d.join("work"), 0o644);
        chmod(&d.join("work.pub"), 0o666);
        fs::write(d.join("config"), "").unwrap();
        chmod(&d.join("config"), 0o644);

        let findings = check(d).unwrap();
        let mut got = ids(&findings);
        got.sort();
        assert_eq!(
            got,
            vec!["dir-perms", "file-perms", "key-perms", "pub-writable"]
        );
        assert!(
            findings
                .iter()
                .all(|f| f.severity == Severity::Warn && f.fix.is_some())
        );

        let n = apply(d, &findings, &Ui::silent()).unwrap();
        assert_eq!(n, 4);
        assert!(check(d).unwrap().is_empty());
        assert_eq!(crate::fsx::mode_of(d).unwrap(), 0o700);
        assert_eq!(crate::fsx::mode_of(&d.join("work")).unwrap(), 0o600);
        assert_eq!(crate::fsx::mode_of(&d.join("work.pub")).unwrap(), 0o644);
        assert_eq!(crate::fsx::mode_of(&d.join("config")).unwrap(), 0o600);
    }

    #[test]
    fn overly_tight_pub_is_only_info() {
        let tmp = tempfile::tempdir().unwrap();
        make(tmp.path(), "work", KeyType::Ed25519, None, None);
        chmod(&tmp.path().join("work.pub"), 0o600);
        let findings = check(tmp.path()).unwrap();
        assert_eq!(ids(&findings), vec!["pub-tight"]);
        assert_eq!(findings[0].severity, Severity::Info);
        assert_eq!(findings[0].fix, Some(Fix::Chmod(0o644)));
    }

    #[test]
    fn missing_pub_is_regenerated_with_comment() {
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path();
        make(d, "work", KeyType::Ed25519, None, None);
        let original = fs::read_to_string(d.join("work.pub")).unwrap();
        fs::remove_file(d.join("work.pub")).unwrap();

        let findings = check(d).unwrap();
        assert_eq!(ids(&findings), vec!["missing-pub"]);
        apply(d, &findings, &Ui::silent()).unwrap();
        assert_eq!(fs::read_to_string(d.join("work.pub")).unwrap(), original);
        assert_eq!(crate::fsx::mode_of(&d.join("work.pub")).unwrap(), 0o644);
        assert!(check(d).unwrap().is_empty());
    }

    #[test]
    fn missing_pub_for_encrypted_key_is_written_without_comment() {
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path();
        make(d, "vault", KeyType::Ed25519, None, Some("pw"));
        fs::remove_file(d.join("vault.pub")).unwrap();
        apply(d, &check(d).unwrap(), &Ui::silent()).unwrap();
        let line = fs::read_to_string(d.join("vault.pub")).unwrap();
        assert_eq!(line.trim().split(' ').count(), 2, "{line}");
        assert_eq!(ids(&check(d).unwrap()), vec!["empty-comment"]);
    }

    #[test]
    fn legacy_pem_orphan_pub_and_dangling_state() {
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path();
        make(d, "work", KeyType::Ed25519, None, None);
        fs::write(
            d.join("old"),
            "-----BEGIN RSA PRIVATE KEY-----\nMIIE\n-----END RSA PRIVATE KEY-----\n",
        )
        .unwrap();
        chmod(&d.join("old"), 0o600);
        fs::write(d.join("lost.pub"), "ssh-ed25519 AAAA lost\n").unwrap();
        let mut st = State::default();
        st.record_created("ghost", "t".into());
        st.save(d).unwrap();

        let findings = check(d).unwrap();
        // Warn first; Info findings then sort by path ("lost.pub" < "ssk.toml").
        assert_eq!(
            ids(&findings),
            vec!["legacy-pem", "orphan-pub", "dangling-state"]
        );
        assert_eq!(findings[0].severity, Severity::Warn);
        assert!(findings[0].fix.is_none());
        assert!(findings[0].message.contains("ssh-keygen -p -f"));
        assert_eq!(findings[1].severity, Severity::Info);
        assert_eq!(findings[2].severity, Severity::Info);
    }

    #[test]
    fn duplicate_keys_are_flagged() {
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path();
        make(d, "work", KeyType::Ed25519, None, None);
        fs::copy(d.join("work"), d.join("work-copy")).unwrap();
        fs::copy(d.join("work.pub"), d.join("work-copy.pub")).unwrap();
        let findings = check(d).unwrap();
        assert_eq!(ids(&findings), vec!["duplicate-key"]);
        assert!(findings[0].message.contains("work") && findings[0].message.contains("work-copy"));
    }

    #[test]
    fn missing_include_is_fixable() {
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path();
        chmod(d, 0o700); // no key is written here, so nothing else normalises the dir mode
        fs::create_dir(d.join("ssk.d")).unwrap();
        fs::write(d.join("ssk.d/work.conf"), "Host h\n").unwrap();
        let findings = check(d).unwrap();
        assert_eq!(ids(&findings), vec!["missing-include"]);
        assert_eq!(findings[0].fix, Some(Fix::AddInclude));
        apply(d, &findings, &Ui::silent()).unwrap();
        assert!(config::has_include(d).unwrap());
        assert!(check(d).unwrap().is_empty());
    }

    #[test]
    fn weak_rsa_and_advisory_ecdsa() {
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path();
        make(d, "small", KeyType::Rsa, Some(2048), None);
        make(d, "curve", KeyType::Ecdsa, None, None);
        let findings = check(d).unwrap();
        assert_eq!(ids(&findings), vec!["weak-rsa", "ecdsa"]);
        assert_eq!(findings[0].severity, Severity::Warn);
        assert_eq!(findings[1].severity, Severity::Info);
    }
}
