//! `ssk import <PATH> [IDENTITY]`: take a key pair made elsewhere and make it an identity.
//! The files are moved into the ssh directory (copied with `--keep`) at ssk's modes, and the
//! `.pub` is derived from the private key when it didn't come along.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use ssh_key::{HashAlg, PrivateKey, PublicKey};
use zeroize::Zeroizing;

use crate::cmd::new::print_summary;
use crate::fsx;
use crate::identity::store::{self, Entry};
use crate::identity::{Identity, IdentityError, is_legacy_pem, name};
use crate::settings::Settings;
use crate::state::{self, State};
use crate::ui::Ui;

#[derive(clap::Parser, Debug)]
pub struct Import {
    /// Private key to import; a `.pub` beside it comes along
    pub path: PathBuf,

    /// Identity name [default: the key's file name]
    pub identity: Option<String>,

    /// Copy the key instead of moving it, leaving the original where it is
    #[arg(short = 'k', long)]
    pub keep: bool,
}

pub fn handle(settings: &Settings, ui: &Ui, args: &Import) -> anyhow::Result<u8> {
    let src = &args.path;
    let src_name = src
        .file_name()
        .and_then(|n| n.to_str())
        .with_context(|| format!("{} has no usable file name", src.display()))?;
    if let Some(stem) = src_name.strip_suffix(".pub") {
        bail!(
            "{} is a public key; import the private key ({}) instead",
            src.display(),
            src.with_file_name(stem).display()
        );
    }
    let identity = args.identity.as_deref().unwrap_or(src_name);
    name::validate(identity)?;

    let pem = Zeroizing::new(
        fs::read_to_string(src).map_err(|source| IdentityError::Read {
            path: src.clone(),
            source,
        })?,
    );
    if is_legacy_pem(&pem) {
        return Err(IdentityError::LegacyPem { path: src.clone() }.into());
    }
    let key = PrivateKey::from_openssh(pem.as_bytes()).map_err(|source| IdentityError::Parse {
        path: src.clone(),
        source,
    })?;

    let src_pub = PathBuf::from(format!("{}.pub", src.display()));
    let had_pub = src_pub.is_file();
    let public_line = if had_pub {
        let given = PublicKey::read_openssh_file(&src_pub)
            .with_context(|| format!("{} is not an OpenSSH public key", src_pub.display()))?;
        if given.key_data() != key.public_key().key_data() {
            bail!(
                "{} does not belong to {}; remove or replace it, or the identity would advertise the wrong key",
                src_pub.display(),
                src.display()
            );
        }
        fs::read_to_string(&src_pub).with_context(|| format!("reading {}", src_pub.display()))?
    } else {
        format!("{}\n", key.public_key().to_openssh()?)
    };

    let dir = &settings.ssh_dir;
    let dst = dir.join(identity);
    let dst_pub = dir.join(format!("{identity}.pub"));
    if dst.exists() || dst_pub.exists() {
        bail!(
            "identity '{identity}' already exists at {}; pick another name or remove it first",
            dst.display()
        );
    }
    // A stale entry would hand its deployments to a key that was never installed there.
    let mut st = State::load(dir)?;
    if st.is_managed(identity) {
        bail!(
            "identity '{identity}' still has an entry in {}; run `ssk rm {identity}` first",
            State::path(dir).display()
        );
    }

    let verb = if args.keep { "copy" } else { "move" };
    ui.info(format!("{verb} {} -> {}", src.display(), dst.display()));
    if had_pub {
        ui.info(format!(
            "{verb} {} -> {}",
            src_pub.display(),
            dst_pub.display()
        ));
    } else {
        ui.info(format!("derive {} from the private key", dst_pub.display()));
    }
    if settings.dry_run {
        ui.info("dry run: nothing imported");
        return Ok(0);
    }

    fsx::ensure_private_dir(dir).with_context(|| format!("creating {}", dir.display()))?;
    fsx::write_new(&dst, pem.as_bytes(), 0o600, false)
        .with_context(|| format!("writing {}", dst.display()))?;
    if let Err(e) = fsx::write_new(&dst_pub, public_line.as_bytes(), 0o644, false) {
        let _ = fs::remove_file(&dst);
        return Err(anyhow::Error::new(e).context(format!("writing {}", dst_pub.display())));
    }
    st.record_imported(identity, state::now());
    st.save(dir)?;
    if !args.keep {
        remove_original(src, &dst)?;
        if had_pub {
            remove_original(&src_pub, &dst_pub)?;
        }
    }

    let imported = Identity::load(dir, identity)?;
    print_summary(ui, "imported", &imported, public_line.trim());
    if !had_pub && key.is_encrypted() {
        ui.warn(format!(
            "{} was written without a comment (the comment is inside the encrypted key); `ssh-keygen -c -f {}` can set one",
            dst_pub.display(),
            dst.display()
        ));
    }
    warn_about_duplicates(ui, dir, identity, &key)?;
    Ok(0)
}

/// The copy is in place by now, so a failure here leaves two copies, never none.
fn remove_original(src: &Path, dst: &Path) -> anyhow::Result<()> {
    fs::remove_file(src).with_context(|| {
        format!(
            "{} was imported as {}, but removing the original failed",
            src.display(),
            dst.display()
        )
    })
}

fn warn_about_duplicates(
    ui: &Ui,
    dir: &Path,
    identity: &str,
    key: &PrivateKey,
) -> anyhow::Result<()> {
    let fingerprint = key.fingerprint(HashAlg::Sha256).to_string();
    for entry in store::scan(dir)? {
        if let Entry::Identity(other) = entry
            && other.name != identity
            && other.fingerprint == fingerprint
        {
            ui.warn(format!(
                "this is the same key as identity '{}'; `ssk rm {}` if you only need one",
                other.name, other.name
            ));
        }
    }
    Ok(())
}
