use std::fs::OpenOptions;
use std::io::Result;
use std::path::Path;

/// Claims a job file, failing if another worker already took it.
pub fn claim(path: &Path) -> Result<std::fs::File> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
}
