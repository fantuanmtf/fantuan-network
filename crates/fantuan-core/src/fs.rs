//! Secure file system helpers.
//!
//! Secret material must be created with owner-only permissions from the
//! moment of creation, never chmod-ed after a world-readable write.

use crate::error::Result;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;

/// Create a directory (and parents) and force owner-only permissions.
pub fn ensure_dir_0700(path: &Path) -> Result<()> {
    fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// Write a secret file with mode 0600 and fsync it.
///
/// A pre-existing file with looser permissions is repaired after the write,
/// so imported state can never stay world-readable.
pub fn write_private_file(path: &Path, contents: &[u8]) -> Result<()> {
    let mut file = {
        let mut opts = OpenOptions::new();
        opts.create(true).write(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        opts.open(path)?
    };
    file.write_all(contents)?;
    file.sync_all()?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

/// Read a file into memory.
pub fn read_file(path: &Path) -> Result<Vec<u8>> {
    Ok(fs::read(path)?)
}

/// Read a UTF-8 file into a string.
pub fn read_to_string(path: &Path) -> Result<String> {
    Ok(fs::read_to_string(path)?)
}

/// Return true when the path exists.
pub fn exists(path: &Path) -> bool {
    path.exists()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_private_file_creates_and_reads_back() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("secret.bin");
        write_private_file(&path, b"top secret").expect("write");
        assert_eq!(read_file(&path).expect("read"), b"top secret");
    }

    #[cfg(unix)]
    #[test]
    fn write_private_file_enforces_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("secret.bin");

        write_private_file(&path, b"x").expect("write");
        let mode = fs::metadata(&path).expect("meta").permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "new secret file must be 0600");

        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("chmod");
        write_private_file(&path, b"x").expect("rewrite");
        let mode = fs::metadata(&path).expect("meta").permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "loose permissions must be repaired");
    }

    #[cfg(unix)]
    #[test]
    fn ensure_dir_sets_0700() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("tempdir");
        let nested = dir.path().join("a").join("b");
        ensure_dir_0700(&nested).expect("dir");
        let mode = fs::metadata(&nested).expect("meta").permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
    }
}
