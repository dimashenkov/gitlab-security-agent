use std::process::Command;

/// Reports whether the archiving tool is installed.
pub fn probe() -> bool {
    Command::new("/usr/bin/tar")
        .arg("--version")
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}
