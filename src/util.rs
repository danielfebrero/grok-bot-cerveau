use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

use chrono::{SecondsFormat, Utc};

pub(crate) fn now_rfc3339() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true)
}

pub(crate) fn ensure_dir(path: &Path) -> io::Result<()> {
    std::fs::create_dir_all(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    Ok(())
}

/// Writes `bytes` to `directory/file_name` so a crash cannot expose a partial file.
///
/// The temp file is fsync'd before rename. The directory is fsync'd after rename
/// so the new directory entry survives a power loss.
pub(crate) fn write_durable(directory: &Path, file_name: &str, bytes: &[u8]) -> io::Result<()> {
    ensure_dir(directory)?;
    let final_path = directory.join(file_name);
    let tmp_path = directory.join(format!("{file_name}.tmp"));
    {
        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp_path)?;
        file.write_all(bytes)?;
        file.flush()?;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        file.sync_all()?;
    }
    std::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(0o600))?;
    std::fs::rename(&tmp_path, &final_path)?;
    {
        let file = OpenOptions::new().write(true).open(&final_path)?;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        file.sync_all()?;
    }
    let dir = File::open(directory)?;
    dir.sync_all()?;
    Ok(())
}

pub(crate) fn ensure_private(path: &Path) -> io::Result<()> {
    let mode = std::fs::metadata(path)?.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("refusing to read {path:?}: mode {mode:o} allows group or other access"),
        ));
    }
    Ok(())
}

pub(crate) fn append_private_line(path: &Path, line: &str) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        ensure_dir(parent)?;
    }
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(line.as_bytes())?;
    file.write_all(b"\n")?;
    file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    file.sync_all()?;
    Ok(())
}
