use std::fs::{File, OpenOptions};
use std::io::{Error, ErrorKind, Result};
use std::path::Path;

/// Claims a job file, failing if another worker already took it.
pub fn claim(path: &Path) -> Result<File> {
    if path.exists() {
        return Err(Error::new(ErrorKind::AlreadyExists, "already claimed"));
    }
    OpenOptions::new().write(true).create(true).open(path)
}
