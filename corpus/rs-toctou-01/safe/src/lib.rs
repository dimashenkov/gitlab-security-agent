use std::path::PathBuf;

pub fn spool_dir() -> PathBuf {
    PathBuf::from("/var/spool/jobs")
}
