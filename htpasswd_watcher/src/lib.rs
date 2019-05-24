use hotwatch::{Event, Hotwatch};
use htpasswd::{HtpasswdLoad, LoadFailure, PasswordDB, PasswordDBSource};
use parking_lot::{RwLock, RwLockReadGuard};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct Watcher {
    current_db: RwLock<Result<PasswordDB, LoadFailure>>,
    file: PathBuf,
}

impl Watcher {
    fn new(file: Path) -> Result<Watcher, LoadFailure> {
        let db = file.load_htpasswd()?;
        Ok(Watcher {
            file,
            current_db: RwLock::new(Ok(db)),
        })
    }

    fn file(&self) -> Path {
        self.file
    }
}

impl PasswordDBSource for Watcher {
    type Error = LoadFailure;
    type Reference = RwLockReadGuard<'static, RwLock<Result<PasswordDB, LoadFailure>>>;

    fn get(&self) -> Self::Reference {
        self.current_db.read()
    }
}
