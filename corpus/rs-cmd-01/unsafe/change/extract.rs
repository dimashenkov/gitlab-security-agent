use std::process::Command;

/// Extracts an uploaded archive into the tenant's directory.
pub fn extract(archive: &str, into: &str) -> std::io::Result<()> {
    Command::new("sh")
        .arg("-c")
        .arg(format!("/usr/bin/tar -xf {} -C {}", archive, into))
        .status()?;
    Ok(())
}
