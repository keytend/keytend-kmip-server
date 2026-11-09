// Copyright 2026 Jeremiah Jordan
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! The writer lock: `<database>.lock`, held with `flock(2)` by `serve` for
//! its lifetime and by `restore` and in-place rotation while they replace
//! the database. Read-only commands (`check-store`, `backup`,
//! `audit-checkpoint`) take no lock and rely on SQLite's own locking, except
//! when SQLite cannot lock (a read-only directory): then they hold a shared
//! lock on this file for the whole read (`read_only.rs`).
//!
//! `flock` locks belong to the open file of the lock file's inode, so they
//! hold between processes on one kernel however the directory is mounted:
//! two containers or pods on one node sharing a ReadWriteOnce volume see
//! each other's lock. They do not reliably exclude processes on different
//! hosts: NFS and other network filesystems are not supported for it.
//!
//! The file is created once (mode 0600) and never removed, since removing a
//! lock file races with a process opening it. After taking the lock the
//! holder writes one line naming itself, which only serves error messages.
use super::*;
use rustix::fs::{FlockOperation, flock};
use std::io::{Read, Seek, Write};
use std::path::PathBuf;

/// An exclusive writer lock on a database; released when dropped.
pub struct WriterLock {
    _file: fs::File,
    path: PathBuf,
}

impl Drop for WriterLock {
    /// Unlock explicitly rather than only closing: a child forked at that
    /// moment shares the open file until it executes, and would otherwise
    /// keep the lock until then.
    fn drop(&mut self) {
        let _ = flock(&self._file, FlockOperation::Unlock);
    }
}

fn would_block(error: &rustix::io::Errno) -> bool {
    *error == rustix::io::Errno::WOULDBLOCK
}

impl WriterLock {
    /// `<database>.lock`.
    pub fn path_for(database: &Path) -> PathBuf {
        read_only::sidecar(database, ".lock")
    }

    /// Take the lock without waiting, or fail with the holder named.
    /// `holder` names the command in the lock file (`serve`, `restore`).
    pub fn acquire(database: &Path, holder: &str) -> Result<Self> {
        let path = Self::path_for(database);
        let mut options = fs::OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options
                .mode(0o600)
                .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32);
        }
        let mut file = options
            .open(&path)
            .with_context(|| format!("open the store lock {}", path.display()))?;
        if !file.metadata()?.is_file() {
            bail!("store lock {} must be a regular file", path.display());
        }
        match flock(&file, FlockOperation::NonBlockingLockExclusive) {
            Ok(()) => {}
            Err(error) if would_block(&error) => {
                let mut held_by = String::new();
                let _ = (&file).take(256).read_to_string(&mut held_by);
                let held_by = held_by.trim();
                if held_by.is_empty() {
                    bail!(
                        "the store is in use by a running server (lock {})",
                        path.display()
                    );
                }
                bail!(
                    "the store is in use by a running server (lock {}; held by {held_by})",
                    path.display()
                );
            }
            Err(error) => {
                return Err(anyhow::Error::new(std::io::Error::from(error))
                    .context(format!("lock the store lock {}", path.display())));
            }
        }
        let host = fs::read_to_string("/proc/sys/kernel/hostname").unwrap_or_default();
        let host = host.trim();
        let line = format!(
            "{holder} (pid {}{}{})\n",
            std::process::id(),
            if host.is_empty() { "" } else { " on " },
            host
        );
        file.set_len(0)?;
        file.rewind()?;
        file.write_all(line.as_bytes())?;
        Ok(Self { _file: file, path })
    }

    /// The lock file's path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// For the immutable read-only fallback: a shared lock, so no writer
    /// can take the exclusive lock while it is held. The lock file must
    /// exist (the directory is read-only, so it cannot be created here).
    pub(crate) fn shared(database: &Path) -> Result<fs::File> {
        let path = Self::path_for(database);
        let file = match fs::File::open(&path) {
            Ok(file) => file,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => bail!(
                "cannot read {} safely: its directory is read-only, so SQLite cannot create the -shm file a reader shares with a writer, and there is no lock file {} to keep a server from writing meanwhile. Mount the directory read-write, or copy the database",
                database.display(),
                path.display()
            ),
            Err(e) => {
                return Err(anyhow::Error::new(e)
                    .context(format!("open the store lock {}", path.display())));
            }
        };
        match flock(&file, FlockOperation::NonBlockingLockShared) {
            Ok(()) => Ok(file),
            Err(error) if would_block(&error) => bail!(
                "the store is in use by a running server (lock {}), and its directory does not allow a read-only reader to join it",
                path.display()
            ),
            Err(error) => Err(anyhow::Error::new(std::io::Error::from(error))
                .context(format!("lock the store lock {}", path.display()))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_second_holder_fails_fast_and_names_the_first() {
        let dir = tempfile::tempdir().unwrap();
        let database = dir.path().join("kmip.sqlite");
        let first = WriterLock::acquire(&database, "serve").unwrap();
        assert_eq!(first.path(), dir.path().join("kmip.sqlite.lock"));
        let error = WriterLock::acquire(&database, "restore")
            .err()
            .unwrap()
            .to_string();
        assert!(
            error.starts_with("the store is in use by a running server (lock "),
            "{error}"
        );
        assert!(error.contains("held by serve (pid "), "{error}");
        assert!(WriterLock::shared(&database).is_err());
        drop(first);
        // A process another test forks at this moment briefly shares the
        // open lock until it executes; allow it to finish.
        let again = (0..500)
            .find_map(|_| {
                WriterLock::acquire(&database, "restore").ok().or_else(|| {
                    std::thread::sleep(std::time::Duration::from_millis(10));
                    None
                })
            })
            .unwrap();
        drop(again);
        let shared = WriterLock::shared(&database).unwrap();
        assert!(WriterLock::acquire(&database, "serve").is_err());
        drop(shared);
        let error = WriterLock::shared(&dir.path().join("other.sqlite"))
            .err()
            .unwrap()
            .to_string();
        assert!(error.contains("no lock file"), "{error}");
    }
}
