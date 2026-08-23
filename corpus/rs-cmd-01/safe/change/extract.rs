use std::process::Command;

/// Extracts an uploaded archive into the tenant's directory.
pub fn extract(archive: &str, into: &str) -> std::io::Result<()> {
    Command::new("/usr/bin/tar")
        .arg("-xf")
        .arg(archive)
        .arg("-C")
        .arg(into)
        .status()?;
    Ok(())
}
