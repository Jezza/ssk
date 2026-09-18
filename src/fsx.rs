//! Small filesystem helpers that encode ssk's permission rules.

use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

/// Permission bits (0o777 mask) of `path`.
pub fn mode_of(path: &Path) -> io::Result<u32> {
    Ok(fs::metadata(path)?.permissions().mode() & 0o777)
}

/// Create `dir` (and parents) if missing, and force mode 0700 on it.
pub fn ensure_private_dir(dir: &Path) -> io::Result<()> {
    if !dir.is_dir() {
        fs::create_dir_all(dir)?;
    }
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
}

/// Write `bytes` to `path` with exactly `mode`. Without `overwrite` the file must
/// not exist (O_CREAT|O_EXCL), so two concurrent writers can't clobber each other.
pub fn write_new(path: &Path, bytes: &[u8], mode: u32, overwrite: bool) -> io::Result<()> {
    let mut opts = fs::OpenOptions::new();
    opts.write(true).mode(mode);
    if overwrite {
        opts.create(true).truncate(true);
    } else {
        opts.create_new(true);
    }
    let mut file = opts.open(path)?;
    // `.mode()` is subject to umask and ignored for pre-existing files; make it exact.
    file.set_permissions(fs::Permissions::from_mode(mode))?;
    file.write_all(bytes)?;
    file.sync_all()
}

/// Atomically replace `path` with `bytes` at mode 0600 (temp file beside it + rename).
pub fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let dir = path.parent().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "path has no parent directory")
    })?;
    let mut tmp = tempfile::NamedTempFile::new_in(dir)?;
    tmp.as_file()
        .set_permissions(fs::Permissions::from_mode(0o600))?;
    tmp.write_all(bytes)?;
    tmp.as_file().sync_all()?;
    tmp.persist(path).map_err(|e| e.error)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_new_sets_exact_mode_and_refuses_existing() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("k");
        write_new(&p, b"one", 0o600, false).unwrap();
        assert_eq!(mode_of(&p).unwrap(), 0o600);
        assert_eq!(fs::read(&p).unwrap(), b"one");
        let err = write_new(&p, b"two", 0o600, false).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(fs::read(&p).unwrap(), b"one");
    }

    #[test]
    fn write_new_overwrite_replaces_and_resets_mode() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("k.pub");
        write_new(&p, b"one", 0o777, false).unwrap();
        write_new(&p, b"two", 0o644, true).unwrap();
        assert_eq!(mode_of(&p).unwrap(), 0o644);
        assert_eq!(fs::read(&p).unwrap(), b"two");
    }

    #[test]
    fn write_private_is_0600_and_replaces_atomically() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("state");
        write_private(&p, b"a").unwrap();
        write_private(&p, b"bb").unwrap();
        assert_eq!(mode_of(&p).unwrap(), 0o600);
        assert_eq!(fs::read(&p).unwrap(), b"bb");
        assert_eq!(
            fs::read_dir(dir.path()).unwrap().count(),
            1,
            "no temp files left behind"
        );
    }

    #[test]
    fn ensure_private_dir_creates_and_tightens() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path().join("a/b");
        ensure_private_dir(&d).unwrap();
        assert_eq!(mode_of(&d).unwrap(), 0o700);
        fs::set_permissions(&d, fs::Permissions::from_mode(0o755)).unwrap();
        ensure_private_dir(&d).unwrap();
        assert_eq!(mode_of(&d).unwrap(), 0o700);
    }
}
